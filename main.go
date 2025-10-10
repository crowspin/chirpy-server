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

	"github.com/crowspin/chirpy-server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const (
	FILEPATHROOT = "."
	PORT         = "8080"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
}

func main() {
	godotenv.Load()
	dbUrl := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		fmt.Println("Couldn't open connection to database!")
		os.Exit(1)
	}
	dbQueries := database.New(db)

	apiCfg := apiConfig{
		dbQueries: dbQueries,
		platform:  platform,
	}
	servemux := http.ServeMux{}
	servemux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(FILEPATHROOT)))))
	servemux.HandleFunc("GET /api/healthz", endpoint_healthz)
	servemux.HandleFunc("GET /admin/metrics", apiCfg.endpoint_metrics)
	servemux.HandleFunc("POST /admin/reset", apiCfg.endpoint_reset)
	servemux.HandleFunc("POST /api/users", apiCfg.endpoint_users)
	servemux.HandleFunc("POST /api/chirps", apiCfg.endpoint_chirps)

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
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (cfg *apiConfig) endpoint_users(rw http.ResponseWriter, req *http.Request) {
	type email_in struct {
		Email string `json:"email"`
	}

	decoder := json.NewDecoder(req.Body)
	msg := email_in{}
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(rw, 500, "Something went wrong")
		return
	}

	user, err := cfg.dbQueries.CreateUser(req.Context(), msg.Email)
	if err != nil {
		log.Printf("Error executing query: %s", err)
		respondWithError(rw, 500, fmt.Sprintf("Error executing query: %s", err))
		return
	}
	usr_struct := User(user)
	respondWithJSON(rw, 201, usr_struct)
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UserID    uuid.UUID `json:"user_id"`
	Body      string    `json:"body"`
}

func (cfg *apiConfig) endpoint_chirps(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	msg := Chirp{}
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(rw, 500, "Something went wrong")
		return
	}

	if len(msg.Body) > 140 {
		respondWithError(rw, 400, "Chirp is too long")
		return
	}
	cleanChirpProfanity(&msg)

	dat, err := cfg.dbQueries.CreateChirp(req.Context(), database.CreateChirpParams{
		UserID: msg.UserID,
		Body:   msg.Body,
	})
	if err != nil {
		log.Printf("Error executing query: %s", err)
		respondWithError(rw, 500, fmt.Sprintf("Error executing query: %s", err))
		return
	}
	chirpBack := Chirp(dat)

	respondWithJSON(rw, 201, chirpBack)
}
