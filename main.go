package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

const (
	FILEPATHROOT = "."
	PORT         = "8080"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func main() {
	apiCfg := apiConfig{}
	servemux := http.ServeMux{}
	servemux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(FILEPATHROOT)))))
	servemux.HandleFunc("GET /api/healthz", endpoint_healthz)
	servemux.HandleFunc("GET /admin/metrics", apiCfg.endpoint_metrics)
	servemux.HandleFunc("POST /admin/reset", apiCfg.endpoint_reset)
	servemux.HandleFunc("POST /api/validate_chirp", endpoint_validate_chirp)

	server := &http.Server{
		Addr:    ":" + PORT,
		Handler: &servemux,
	}
	log.Printf("Serving files from %s on port: %s\n", FILEPATHROOT, PORT)
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
	resp.WriteHeader(200)
	cfg.fileserverHits.Store(0)
}

func endpoint_validate_chirp(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	msg := struct {
		Body string `json:"body"`
	}{}
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respondWithError(resp, 500, "Something went wrong")
		return
	}

	if len(msg.Body) > 140 {
		respondWithError(resp, 400, "Chirp is too long")
		return
	}

	respondWithJSON(resp, 200, struct {
		Valid bool `json:"valid"`
	}{Valid: true})
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

	rw.WriteHeader(code)
	rw.Write(dat)
}
