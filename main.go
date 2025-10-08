package main

import (
	"net/http"
)

func main() {
	servemux := http.ServeMux{}
	server := http.Server{
		Addr:    ":8080",
		Handler: &servemux,
	}
	server.ListenAndServe()
}
