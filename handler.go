// handler.go
package http_signature_auth

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

func NewSignatureAuthHandler(keysDB *Keys, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok, err := VerifySignature(keysDB, r)
		if err != nil {
			log.Debug().Msgf("error when verifying signature: %s", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !ok {
			log.Debug().Msgf("Unauthorized request from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		log.Debug().Msgf("Authorized request from %s", r.RemoteAddr)
		handlerFunc(w, r)
	}
}
