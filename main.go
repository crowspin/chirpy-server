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

	type chirp struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(req.Body)
	msg := chirp{}
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		if dat := produce_error_json("Something went wrong"); dat != nil {
			resp.Write(dat)
		}
		resp.WriteHeader(500)
		return
	}

	if len(msg.Body) > 140 {
		resp.WriteHeader(400)
		if dat := produce_error_json("Chirp is too long"); dat != nil {
			resp.Write(dat)
		}
		return
	}

	type success struct {
		Valid bool `json:"valid"`
	}
	rv := success{Valid: true}
	dat, err := json.Marshal(rv)
	if err != nil {
		log.Printf("Error encoding response: %s", err)
		if dat := produce_error_json("Something went wrong"); dat != nil {
			resp.Write(dat)
		}
		resp.WriteHeader(500)
		return
	}

	resp.WriteHeader(200)
	resp.Write(dat)
}

func produce_error_json(val string) []byte {
	type errorMessage struct {
		M string `json:"error"`
	}
	body := errorMessage{M: val}
	dat, err := json.Marshal(body)
	if err != nil {
		log.Printf("Error producing error json: %s", err)
		return nil
	}
	return dat
}
