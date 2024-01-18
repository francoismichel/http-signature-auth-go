package http_signature_auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"fmt"
)

var b64Encoder = base64.RawStdEncoding

type KeyID string

func (k KeyID) String() string {
	return fmt.Sprintf("<%s>", b64Encoder.EncodeToString([]byte(k)))
}

type KeyType int

const (
	RSA KeyType = iota
	ECDSA
	EdDSA
)

func IsPubkeySupported(key crypto.PublicKey) bool {
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

func GetKeyType(scheme tls.SignatureScheme) (KeyType, error) {
	switch scheme {
	case tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512:
		return RSA, nil
	case tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512:
		return ECDSA, nil
	case tls.Ed25519:
		return EdDSA, nil
	default:
		return 0, TLSSignatureSchemeNotSupported{Scheme: scheme, Reason: ""}
	}
}

// currently a simple wrapper around map, but that could be make
// thread safe or so in the future
type Keys struct {
	idToKeys map[KeyID]crypto.PublicKey
}

func NewKeysDatabase() *Keys {
	return &Keys{
		idToKeys: make(map[KeyID]crypto.PublicKey),
	}
}

// AddKey adds a public key with the given Key ID to the database of keys.
// Returns nil if no previous key was present with this ID, otherwise returns
// the previous key.
func (k *Keys) AddKey(id KeyID, key crypto.PublicKey) crypto.PublicKey {
	previousKey := k.idToKeys[id]
	k.idToKeys[id] = key
	return previousKey
}

// RemoveKey removes the public key with the given Key ID from the database
func (k *Keys) RemoveKey(id KeyID) crypto.PublicKey {
	previousKey := k.idToKeys[id]
	delete(k.idToKeys, id)
	return previousKey
}

// GetKey returns the public key with the given Key ID from the database
// Returns nil if none was found
func (k *Keys) GetKey(id KeyID) crypto.PublicKey {
	return k.idToKeys[id]
}
