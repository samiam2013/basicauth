package main

import (
	"net/http"

	"log"

	"github.com/samiam2013/basicauth"
)

func main() {
	indexFunc := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret homepage"))
	}

	basicAuth, err := basicauth.Builder(
		map[string]string{"baduser": "badpassword"},
		basicauth.WithUnsafeHTTP())
	if err != nil {
		log.Fatalf("Failed to build basic auth middleware %v", err)
	}

	wrapped := basicAuth(indexFunc)

	if err := http.ListenAndServe(":8080", wrapped); err != nil {
		log.Printf("Server was stopped: %v", err)
	}
}
