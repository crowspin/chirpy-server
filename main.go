package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/crowspin/chirpy-server/internal/auth"
	"github.com/crowspin/chirpy-server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const (
	FILEPATHROOT         = "."
	PORT                 = "8080"
	ACCESSTOKENLIFETIME  = time.Hour
	REFRESHTOKENLIFETIME = time.Duration(60*24) * time.Hour
)

type apiConfig struct {
	fileserverHits  atomic.Int32
	dbQueries       *database.Queries
	platform        string
	authTokenSecret string
	polkaKey        string
}

func main() {
	godotenv.Load()
	dbUrl := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	tokensecret := os.Getenv("TOKEN_SECRET")
	polkakey := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		fmt.Println("Couldn't open connection to database!")
		os.Exit(1)
	}
	dbQueries := database.New(db)

	apiCfg := apiConfig{
		dbQueries:       dbQueries,
		platform:        platform,
		authTokenSecret: tokensecret,
		polkaKey:        polkakey,
	}
	servemux := http.ServeMux{}
	servemux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(FILEPATHROOT)))))
	servemux.HandleFunc("GET /api/healthz", endpoint_healthz)
	servemux.HandleFunc("GET /admin/metrics", apiCfg.endpoint_metrics)
	servemux.HandleFunc("POST /admin/reset", apiCfg.endpoint_reset)
	servemux.HandleFunc("POST /api/users", apiCfg.endpoint_users_post)
	servemux.HandleFunc("PUT /api/users", apiCfg.endpoint_users_put)
	servemux.HandleFunc("POST /api/login", apiCfg.endpoint_login)
	servemux.HandleFunc("POST /api/refresh", apiCfg.endpoint_refresh)
	servemux.HandleFunc("POST /api/revoke", apiCfg.endpoint_revoke)
	servemux.HandleFunc("POST /api/chirps", apiCfg.endpoint_chirps_post)
	servemux.HandleFunc("GET /api/chirps", apiCfg.endpoint_chirps_get)
	servemux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.endpoint_chirps_get_one)
	servemux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.endpoint_chirps_delete)
	servemux.HandleFunc("POST /api/polka/webhooks", apiCfg.endpoint_polka_webhooks)

	server := &http.Server{
		Addr:    ":" + PORT,
		Handler: &servemux,
	}
	log.Printf("Serving files from %s on port: %s\n", FILEPATHROOT, PORT)
	go func() {
		time.Sleep(15 * time.Second)
		ctx, rel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rel()
		server.Shutdown(ctx)
	}()
	log.Fatal(server.ListenAndServe())
}

func endpoint_healthz(respWr http.ResponseWriter, req *http.Request) {
	respWr.Header().Set("Content-Type", "text/plain; charset=utf-8")
	respWr.WriteHeader(200)
	respWr.Write([]byte("OK"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) endpoint_metrics(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "text/html")
	resp.WriteHeader(200)
	resp.Write(fmt.Appendf(nil, `
		<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
		</html>
	`, cfg.fileserverHits.Load()))
}

func (cfg *apiConfig) endpoint_reset(resp http.ResponseWriter, req *http.Request) {
	if cfg.platform != "dev" {
		resp.WriteHeader(403)
		return
	}
	resp.WriteHeader(200)
	cfg.fileserverHits.Store(0)
	cfg.dbQueries.ClearUsers(req.Context())
}

func respondWithError(rw http.ResponseWriter, code int, msg string) {
	type errorMessage struct {
		M string `json:"error"`
	}
	body := errorMessage{M: msg}
	dat, err := json.Marshal(body)
	if err != nil {
		log.Printf("Error producing error json: %s", err)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	rw.Write(dat)
}

func respondWithJSON(rw http.ResponseWriter, code int, payload any) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error encoding response: %s", err)
		respondWithError(rw, 500, "Something went wrong")
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	rw.Write(dat)
}

func cleanChirpProfanity(in *Chirp) {
	profanity := []string{"kerfuffle", "sharbert", "fornax"}
	clean := []string{}
	for v := range strings.SplitSeq(in.Body, " ") {
		if slices.Contains(profanity, strings.ToLower(v)) {
			clean = append(clean, "****")
		} else {
			clean = append(clean, v)
		}
	}
	in.Body = strings.Join(clean, " ")
}

type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"password"`
	Token          string    `json:"token"`
	IsChirpyRed    bool      `json:"is_chirpy_red"`
}

func (cfg *apiConfig) endpoint_users_post(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	msg := User{}
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(rw, 500, "Something went wrong")
		return
	}

	if msg.Email == "" || msg.HashedPassword == "" {
		log.Println("Invalid request, required values not supplied")
		respondWithError(rw, 500, "Invalid request, required values not supplied")
		return
	}

	hash, err := auth.HashPassword(msg.HashedPassword)
	if err != nil {
		log.Printf("Error operating on supplied password: %s", err)
		respondWithError(rw, 500, "Error operating on supplied password")
		return
	}

	user, err := cfg.dbQueries.CreateUser(req.Context(), database.CreateUserParams{
		Email:          msg.Email,
		HashedPassword: hash,
	})
	if err != nil {
		log.Printf("Error executing query: %s", err)
		respondWithError(rw, 500, fmt.Sprintf("Error executing query: %s", err))
		return
	}
	usr_struct := User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
	respondWithJSON(rw, 201, usr_struct)
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UserID    uuid.UUID `json:"user_id"`
	Body      string    `json:"body"`
	Token     string    `json:"token"`
}

func (cfg *apiConfig) endpoint_chirps_post(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	msg := Chirp{}
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(rw, 500, "Something went wrong")
		return
	}

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(rw, 401, "No auth token supplied")
	}

	userId, err := auth.ValidateJWT(token, cfg.authTokenSecret)
	if err != nil {
		respondWithError(rw, 401, err.Error())
		return
	}

	if len(msg.Body) > 140 {
		respondWithError(rw, 400, "Chirp is too long")
		return
	}
	cleanChirpProfanity(&msg)

	dat, err := cfg.dbQueries.CreateChirp(req.Context(), database.CreateChirpParams{
		UserID: userId,
		Body:   msg.Body,
	})
	if err != nil {
		log.Printf("Error executing query: %s", err)
		respondWithError(rw, 500, fmt.Sprintf("Error executing query: %s", err))
		return
	}
	chirpBack := Chirp{
		ID:        dat.ID,
		UserID:    dat.UserID,
		CreatedAt: dat.CreatedAt,
		UpdatedAt: dat.UpdatedAt,
		Body:      dat.Body,
	}

	respondWithJSON(rw, 201, chirpBack)
}

func (cfg *apiConfig) endpoint_chirps_get(rw http.ResponseWriter, req *http.Request) {
	dat, err := cfg.dbQueries.FetchAllChirps(req.Context())
	if err != nil {
		log.Printf("Error executing query: %s", err)
		respondWithError(rw, 500, fmt.Sprintf("Error executing query: %s", err))
		return
	}
	chirpBack := make([]Chirp, len(dat))
	for it, val := range dat {
		chirpBack[it] = Chirp{
			ID:        val.ID,
			UserID:    val.UserID,
			CreatedAt: val.CreatedAt,
			UpdatedAt: val.UpdatedAt,
			Body:      val.Body,
		}
	}

	respondWithJSON(rw, 200, chirpBack)
}

func (cfg *apiConfig) endpoint_chirps_get_one(rw http.ResponseWriter, req *http.Request) {
	uu, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error parsing UUID from request: %s", err)
		rw.WriteHeader(404)
		return
	}

	dat, err := cfg.dbQueries.FetchOneChirp(req.Context(), uu)
	if err != nil {
		log.Printf("Error executing query: %s", err)
		rw.WriteHeader(404)
		return
	}
	chirpBack := Chirp{
		ID:        dat.ID,
		UserID:    dat.UserID,
		CreatedAt: dat.CreatedAt,
		UpdatedAt: dat.UpdatedAt,
		Body:      dat.Body,
	}

	respondWithJSON(rw, 200, chirpBack)
}

type LoginResponse struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

func (cfg *apiConfig) endpoint_login(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	msg := User{}
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(rw, 500, "Something went wrong")
		return
	}

	rv, err := cfg.dbQueries.FetchUserByEmail(req.Context(), msg.Email)
	if err != nil {
		respondWithError(rw, 401, "Incorrect email or password")
		return
	}

	if success, err := auth.CheckPasswordHash(msg.HashedPassword, rv.HashedPassword); err != nil || !success {
		respondWithError(rw, 401, "Incorrect email or password")
		return
	}

	token, err := auth.MakeJWT(rv.ID, cfg.authTokenSecret, ACCESSTOKENLIFETIME)
	if err != nil {
		respondWithError(rw, 500, "Failed to produce JWT")
		return
	}

	dbreftok, err := cfg.dbQueries.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token:     auth.MakeRefeshToken(),
		UserID:    rv.ID,
		ExpiresAt: time.Now().Add(REFRESHTOKENLIFETIME),
	})
	if err != nil {
		respondWithError(rw, 500, "Failed to insert new refresh token")
		return
	}

	respondWithJSON(rw, 200, LoginResponse{
		ID:           dbreftok.UserID,
		CreatedAt:    dbreftok.CreatedAt,
		UpdatedAt:    dbreftok.UpdatedAt,
		Email:        rv.Email,
		Token:        token,
		RefreshToken: dbreftok.Token,
		IsChirpyRed:  rv.IsChirpyRed,
	})
}

func (cfg *apiConfig) endpoint_refresh(rw http.ResponseWriter, req *http.Request) {
	reftok, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(rw, 401, "Refresh token not found")
		return
	}
	dbrow, err := cfg.dbQueries.FetchRefreshToken(req.Context(), reftok)
	if err != nil {
		respondWithError(rw, 401, "Refresh token invalid")
		return
	}
	acctok, err := auth.MakeJWT(dbrow.UserID, cfg.authTokenSecret, ACCESSTOKENLIFETIME)
	if err != nil {
		respondWithError(rw, 500, "Failed to produce access token")
		return
	}
	respondWithJSON(rw, 200, struct {
		Token string `json:"token"`
	}{Token: acctok})
}

func (cfg *apiConfig) endpoint_revoke(rw http.ResponseWriter, req *http.Request) {
	reftok, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(rw, 401, "Refresh token not found")
		return
	}
	dbrow, err := cfg.dbQueries.FetchRefreshToken(req.Context(), reftok)
	if err != nil {
		respondWithError(rw, 401, "Refresh token invalid")
		return
	}
	dbrow, err = cfg.dbQueries.RevokeRefreshToken(req.Context(), dbrow.UserID)
	if err != nil {
		respondWithError(rw, 500, "Failed to revoke token")
		return
	}
	rw.WriteHeader(204)
}

type UpdateUserData struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (cfg *apiConfig) endpoint_users_put(rw http.ResponseWriter, req *http.Request) {
	userId, code, err := cfg.validateAccessTokenInHeader(req)
	if err != nil {
		respondWithError(rw, code, err.Error())
		return
	}

	decoder := json.NewDecoder(req.Body)
	msg := UpdateUserData{}
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(rw, 500, "Something went wrong")
		return
	}

	if msg.Email == "" || msg.Password == "" {
		respondWithError(rw, 401, "Invalid use of resource")
		return
	}

	hash, err := auth.HashPassword(msg.Password)
	if err != nil {
		respondWithError(rw, 500, "Error operating on supplied password")
		return
	}

	userback, err := cfg.dbQueries.UpdateUserLogin(req.Context(), database.UpdateUserLoginParams{
		ID:             userId,
		Email:          msg.Email,
		HashedPassword: hash,
	})
	if err != nil {
		respondWithError(rw, 500, "Error occurred while updating database")
		return
	}

	respondWithJSON(rw, 200, User{
		ID:          userback.ID,
		CreatedAt:   userback.CreatedAt,
		UpdatedAt:   userback.UpdatedAt,
		Email:       userback.Email,
		IsChirpyRed: userback.IsChirpyRed,
	})
}

func (cfg *apiConfig) validateAccessTokenInHeader(req *http.Request) (uuid.UUID, int, error) {
	acctok, err := auth.GetBearerToken(req.Header)
	if err != nil {
		return uuid.UUID{}, 401, fmt.Errorf("access token not found: %v", err)
	}

	userId, err := auth.ValidateJWT(acctok, cfg.authTokenSecret)
	if err != nil {
		return uuid.UUID{}, 401, fmt.Errorf("invalid access token: %v", err)
	}
	return userId, 0, nil
}

func (cfg *apiConfig) endpoint_chirps_delete(rw http.ResponseWriter, req *http.Request) {
	userID, code, err := cfg.validateAccessTokenInHeader(req)
	if err != nil {
		respondWithError(rw, code, err.Error())
		return
	}

	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		respondWithError(rw, 404, fmt.Sprintf("Error parsing UUID from request: %s", err))
		return
	}

	//seriously this is supposed to be a "difficulty 8" lesson, so i figured i'd ought to make it hard and learn something
	rv, err := cfg.dbQueries.DeleteChirp(req.Context(), database.DeleteChirpParams{
		ID:     chirpID,
		UserID: userID,
	})
	if err != nil {
		respondWithError(rw, 404, "Chirp not found.")
		return
	}
	if rv.Deletedct == 0 {
		respondWithError(rw, 403, "You do not have authorization!")
		return
	}
	rw.WriteHeader(204)
}

type WebhookData struct {
	UserID uuid.UUID `json:"user_id"`
}

type WebhookBody struct {
	Event string      `json:"event"`
	Data  WebhookData `json:"data"`
}

func (cfg *apiConfig) endpoint_polka_webhooks(rw http.ResponseWriter, req *http.Request) {
	WEBHOOKS := map[string]func(http.ResponseWriter, *http.Request, WebhookData){
		"user.upgraded": cfg.polka_upgrade_user,
	}

	decoder := json.NewDecoder(req.Body)
	msg := WebhookBody{}
	if err := decoder.Decode(&msg); err != nil {
		respondWithError(rw, 500, "Couldn't decode request body")
		return
	}

	key, err := auth.GetAPIKey(req.Header)
	if err != nil || key != cfg.polkaKey {
		respondWithError(rw, 401, "API Key mismatch")
		return
	}

	if f, ok := WEBHOOKS[msg.Event]; ok {
		f(rw, req, msg.Data)
	} else {
		rw.WriteHeader(204)
	}
}

func (cfg *apiConfig) polka_upgrade_user(rw http.ResponseWriter, req *http.Request, data WebhookData) {
	_, err := cfg.dbQueries.UpdateChirpyRedStatus(req.Context(), database.UpdateChirpyRedStatusParams{
		ID:          data.UserID,
		IsChirpyRed: true,
	})
	if err != nil {
		respondWithError(rw, 404, "User ID invalid")
	} else {
		rw.WriteHeader(204)
	}
}
