// handler.go
package http_signature_auth

import (
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog/log"
)

func NewSignatureAuthHandler(keysDB KeysDB, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Debug().Msgf("Received request from %s", r.RemoteAddr)
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Error().Msgf("cannot dump request: %s", err)
		} else {
			log.Debug().Msgf("%q", dump)
		}

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
