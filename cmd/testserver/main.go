package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/samiam2013/basicauth"
)

func main() {
	indexFunc := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret homepage"))
	}

	basicAuth, err := basicauth.BasicAuthBuilder(map[string]string{"baduser": "badpassword"}, true)
	if err != nil {
		log.Fatalf("Failed to build basic auth middleware %v", err)
	}

	wrapped := basicAuth(indexFunc)

	if err := http.ListenAndServe(":8080", wrapped); err != nil {
		log.WithError(err).Error("Server was stopped.")
	}
}
