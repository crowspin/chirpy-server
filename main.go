package main

import (
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
