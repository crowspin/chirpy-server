package main

import (
	"log"
	"net/http"
)

const (
	FILEPATHROOT = "."
	PORT         = "8080"
)

func endpoint_healthz(respWr http.ResponseWriter, req *http.Request) {
	respWr.Header().Set("Content-Type", "text/plain; charset=utf-8")
	respWr.WriteHeader(200)
	respWr.Write([]byte("OK"))
}

func main() {
	servemux := http.ServeMux{}
	servemux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir(FILEPATHROOT))))
	servemux.HandleFunc("/healthz", endpoint_healthz)

	server := &http.Server{
		Addr:    ":" + PORT,
		Handler: &servemux,
	}
	log.Printf("Serving files from %s on port: %s\n", FILEPATHROOT, PORT)
	log.Fatal(server.ListenAndServe())
}
