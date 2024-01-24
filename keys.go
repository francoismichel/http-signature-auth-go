package http_signature_auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"sync"
)

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

type SyncMap[K comparable, V any] struct {
	inner sync.Map
}

func NewSyncMap[K comparable, V any]() SyncMap[K, V] {
	return SyncMap[K, V]{
		inner: sync.Map{},
	}
}

func (m *SyncMap[K, V]) Get(key K) (V, bool) {
	val, ok := m.inner.Load(key)
	if val == nil {
		// we can't return nil for *any* type, so we create a zero value for the type and return it, instead of nil
		var zero V
		return zero, ok
	}
	return val.(V), ok
}

func (m *SyncMap[K, V]) Insert(key K, val V) {
	m.inner.Store(key, val)
}

func (m *SyncMap[K, V]) Remove(key K) {
	m.inner.Delete(key)
}

type KeysDB interface {
	AddKey(id KeyID, key crypto.PublicKey) crypto.PublicKey
	RemoveKey(id KeyID) crypto.PublicKey
	GetKey(id KeyID) crypto.PublicKey
}

// currently a simple wrapper around a SyncMap
type MemoryKeysDB struct {
	idToKeys SyncMap[KeyID, crypto.PublicKey]
}

func NewMemoryKeysDatabase() KeysDB {
	return &MemoryKeysDB{
		idToKeys: SyncMap[KeyID, crypto.PublicKey]{},
	}
}

// AddKey adds a public key with the given Key ID to the database of keys.
// Returns nil if no previous key was present with this ID, otherwise returns
// the previous key.
func (k *MemoryKeysDB) AddKey(id KeyID, key crypto.PublicKey) crypto.PublicKey {
	previousKey, _ := k.idToKeys.Get(id)
	k.idToKeys.Insert(id, key)
	return previousKey
}

// RemoveKey removes the public key with the given Key ID from the database
func (k *MemoryKeysDB) RemoveKey(id KeyID) crypto.PublicKey {
	previousKey, _ := k.idToKeys.Get(id)
	k.idToKeys.Remove(id)
	return previousKey
}

// GetKey returns the public key with the given Key ID from the database
// Returns nil if none was found
func (k *MemoryKeysDB) GetKey(id KeyID) crypto.PublicKey {
	key, ok := k.idToKeys.Get(id)
	if !ok {
		return nil
	}
	return key
}
