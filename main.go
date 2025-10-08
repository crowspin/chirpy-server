package main

import (
	"net/http"
)

func main() {
	servemux := http.ServeMux{}
	servemux.Handle("/", http.FileServer(http.Dir(".")))

	server := http.Server{
		Addr:    ":8080",
		Handler: &servemux,
	}
	server.ListenAndServe()
}
