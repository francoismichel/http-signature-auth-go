package http_signature_auth

import (
	"crypto/tls"
	"fmt"
)

type SignatureNotFound struct {
}

func (e SignatureNotFound) Error() string {
	return "Signature not found"
}

type MalformedHTTPSignatureAuth struct {
	Msg string
}

func (e MalformedHTTPSignatureAuth) Error() string {
	return "Malformed HTTP Signature Auth: " + e.Msg
}

type InvalidTLSSignatureSchemeFormat struct {
	Value string
}

func (e InvalidTLSSignatureSchemeFormat) Error() string {
	return "Invalid signature scheme format: " + e.Value
}

type TLSSignatureSchemeNotSupported struct {
	Scheme tls.SignatureScheme
	Reason string
}

func (e TLSSignatureSchemeNotSupported) Error() string {
	str := fmt.Sprintf("Signature scheme not supported: %s", e.Scheme.String())
	if e.Reason != "" {
		str += " (" + e.Reason + ")"
	}
	return str
}

type InvalidPublicKeyFormat struct {
	scheme tls.SignatureScheme
}

func (e InvalidPublicKeyFormat) Error() string {
	return fmt.Sprintf("Invalid public key format for signature scheme %s", e.scheme)
}

type UnsupportedKeyType struct {
	Type string
}

func (e UnsupportedKeyType) Error() string {
	return "Unsupported public key type: " + e.Type
}

type PublicKeysMismatch struct {
	keyID KeyID
}

func (e PublicKeysMismatch) Error() string {
	return fmt.Sprintf("The proposed key with key ID %s does not match the public key in the database", e.keyID)
}
