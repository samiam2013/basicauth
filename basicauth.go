package basicauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
)

type BasicAuthConfig struct {
	unsafe bool // allow HTTP setup without proxy headers
}

type Option func(*BasicAuthConfig)

func WithUnsafeHTTP() Option {
	return func(bac *BasicAuthConfig) {
		bac.unsafe = true
	}
}

// Builder is a factory-type function that returns middleware
// that middleware function can be handed an http.HandlerFunc and returns one
// anything that middleware is wrapped around should require and authenticate
// with constant-time comparison basic auth
func Builder(providedCreds map[string]string, opts ...Option) (func(http.HandlerFunc) http.HandlerFunc, error) {
	conf := &BasicAuthConfig{}
	for _, o := range opts {
		o(conf)
	}
	// pre-parse the credentials shas into a map and delete providedCreds
	hashedCreds := make(map[[32]byte][32]byte)
	for provUser, provPass := range providedCreds {
		provUserHash := sha256.Sum256([]byte(truncPadTo(provUser, 32)))
		provPassHash := sha256.Sum256([]byte(truncPadTo(provPass, 32)))
		hashedCreds[provUserHash] = provPassHash
		delete(providedCreds, provUser)
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			likelyProxy := false
			for _, proxyHeader := range []string{"via", "forwarded", "x-forwarded-for", "client-ip"} {
				if _, ok := r.Header[proxyHeader]; ok {
					likelyProxy = true
				}
			}
			if (!(r.TLS != nil && r.TLS.HandshakeComplete) && !likelyProxy) && !conf.unsafe {
				http.Error(w, "basicauth middleware detected likely unprotected connection",
					http.StatusInternalServerError)
				return
			}

			inputUser, inputPass, ok := r.BasicAuth()
			if ok {
				// Calculate SHA-256 hashes for the provided and expected
				// usernames and passwords.
				expectedHash := hashedCreds[sha256.Sum256([]byte(truncPadTo(inputUser, 32)))]
				passwordHash := sha256.Sum256([]byte(truncPadTo(inputPass, 32)))

				// Use the subtle.ConstantTimeCompare() function to evaluate both the
				// password before checking the return values to avoid leaking information.
				if subtle.ConstantTimeCompare(passwordHash[:], expectedHash[:]) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	}, nil
}

func truncPadTo(input string, n int) string {
	var output string
	switch {
	case len(input) > n:
		output = input[:n]
	case len(input) < n:
		output = input
		for i := len(input); i < n; i++ {
			output += "~"
		}
	default:
		output = input
	}
	return output
}
