package main

import (
	"log"
	"net/http"
)

const (
	FILEPATHROOT = "."
	PORT         = "8080"
)

func main() {
	servemux := http.ServeMux{}
	servemux.Handle("/", http.FileServer(http.Dir(FILEPATHROOT)))

	server := &http.Server{
		Addr:    ":" + PORT,
		Handler: &servemux,
	}
	log.Printf("Serving files from %s on port: %s\n", FILEPATHROOT, PORT)
	log.Fatal(server.ListenAndServe())
}
