// handler.go
package http_signature_auth

import (
	"net/http"
)

func NewSignatureAuthHandler(keysDB *Keys, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok, err := VerifySignature(keysDB, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handlerFunc(w, r)
	}
}
