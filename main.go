package basicauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
)

// BasicAuthBuilder is a factory-type function that returns middleware
// that middleware function can be handed an http.HandlerFunc and returns one
// anything that middleware is wrapped around should require and authenticate
// with constant-time comparison basic auth
func BasicAuthBuilder(providedCreds map[string]string, unsafe bool) (func(http.HandlerFunc) http.HandlerFunc, error) {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			likelyProxy := false
			for _, proxyHeader := range []string{"via", "forwarded", "x-forwarded-for", "client-ip"} {
				if _, ok := r.Header[proxyHeader]; ok {
					likelyProxy = true
				}
			}
			if (!(r.TLS != nil && r.TLS.HandshakeComplete) && !likelyProxy) && !unsafe {
				http.Error(w, "basicauth middleware detected likely unprotected connection",
					http.StatusInternalServerError)
				return
			}
			for providedUser, providedPass := range providedCreds {
				inputUser, inputPass, ok := r.BasicAuth()
				// TODO pad or truncate the lenght of the user/pass
				if ok {
					// Calculate SHA-256 hashes for the provided and expected
					// usernames and passwords.
					usernameHash := sha256.Sum256([]byte(inputUser))
					passwordHash := sha256.Sum256([]byte(inputPass))
					expectedUsernameHash := sha256.Sum256([]byte(providedUser))
					expectedPasswordHash := sha256.Sum256([]byte(providedPass))

					// Use the subtle.ConstantTimeCompare() function to evaluate both the
					// username and password before checking the return values to avoid leaking information.
					usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:])
					passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:])

					if (usernameMatch & passwordMatch) == 1 {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	}, nil
}
