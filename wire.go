package http_signature_auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"strconv"

	"github.com/rs/zerolog/log"
)

// ParseKeyID parses the given base64-encoded string into a KeyID
// The id parameter must be a valid base64-encoded string following
// the base64url encoding scheme *without padding* as defined in RFC
// 4648, Section 5.
func ParseKeyID(idBase64 string) (KeyID, error) {
	decodedKeyID, err := b64Encoder.DecodeString(idBase64)
	if err != nil {
		return "", err
	}
	return KeyID(decodedKeyID), nil
}

func parseSignatureScheme(schemeStr string) (tls.SignatureScheme, error) {
	if len(schemeStr) == 0 {
		return 0, InvalidTLSSignatureSchemeFormat{schemeStr}
	}

	if schemeStr != "0" && schemeStr[0] == '0' {
		return 0, InvalidTLSSignatureSchemeFormat{schemeStr}
	}

	scheme64, err := strconv.ParseUint(schemeStr, 10, 16)
	if err != nil {
		return 0, err
	}

	scheme := tls.SignatureScheme(scheme64)
	return scheme, nil
}

// ParseAndValidateSignatureScheme parses the given string into a tls.SignatureScheme
// and ensures it only corresponds to a supported signature scheme such as the ones defined
// in https://www.ietf.org/archive/id/draft-ietf-httpbis-unprompted-auth-05.html
func ParseAndValidateSignatureScheme(schemeStr string) (tls.SignatureScheme, error) {
	scheme, err := parseSignatureScheme(schemeStr)
	if err != nil {
		return 0, err
	}
	switch scheme {
	case tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512, // RSASSA-PSS
		tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512, // ECDSA
		tls.Ed25519: // EdDSA
		return scheme, nil
	default:
		return 0, TLSSignatureSchemeNotSupported{Scheme: scheme, Reason: "Unsupported signature scheme"}
	}
}

func ParsePublicKey(keyBase64 string, signatureScheme tls.SignatureScheme) (crypto.PublicKey, error) {
	rawPubkey, err := b64Encoder.DecodeString(keyBase64)
	if err != nil {
		return nil, err
	}
	keyType, err := GetKeyType(signatureScheme)
	if err != nil {
		return nil, err
	}
	var pubkey crypto.PublicKey
	switch keyType {
	case RSA:
		pubkey, err = x509.ParsePKCS1PublicKey(rawPubkey)
	case ECDSA:
		// the ecdh package implements the ECDSA format specified in RFC8446 Section 4.2.8.2
		// which is the one used for Unprompted auth
		pubkey, err = ParseUncompressedPoint(rawPubkey, signatureScheme)
	case EdDSA:
		pubkey = ed25519.PublicKey(rawPubkey)
	}
	return pubkey, err
}

func SerializePublicKey(out []byte, pubkey crypto.PublicKey) ([]byte, error) {
	var err error
	switch key := pubkey.(type) {
	case *rsa.PublicKey:
		out = append(out, x509.MarshalPKCS1PublicKey(key)...)
	case *ecdsa.PublicKey:
		out, err = SerializeUncompressedPoint(out, key)
	case ed25519.PublicKey:
		out, err = key, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubkey)
	}
	return out, err
}

// ParseUncompressedPoint parses the given public key in uncompressed point format
// (cf RFC8446 Section 4.2.8.2) into an ECDSA public key
func ParseUncompressedPoint(uncompressedPoint []byte, scheme tls.SignatureScheme) (*ecdsa.PublicKey, error) {
	// This function is already implemented in ecdh.P256/P384/P512().NewPublicKey(rawPubkey)
	// but this function does not return an ECDSA public key. returning an ECDH public key
	// should work, though, but we'll check that later once we've got working implementations.
	// This code is inspired by crypto/internal/nistec/p384.go's SetBytes() function
	var coordinatesLength = 0
	var curve elliptic.Curve
	switch scheme {
	case tls.ECDSAWithP256AndSHA256:
		coordinatesLength = 32
		curve = elliptic.P256()
	case tls.ECDSAWithP384AndSHA384:
		coordinatesLength = 48
		curve = elliptic.P384()
	case tls.ECDSAWithP521AndSHA512:
		coordinatesLength = 66
		curve = elliptic.P521()
	default:
		return nil, TLSSignatureSchemeNotSupported{Scheme: scheme, Reason: "Unsupported signature scheme"}
	}
	if len(uncompressedPoint) != 1+2*coordinatesLength || uncompressedPoint[0] != 4 {
		log.Debug().Msgf("len(uncompressedPoint)=%d, coordinatesLength=%d, uncompressedPoint[0]=%d", len(uncompressedPoint), coordinatesLength, uncompressedPoint[0])
		return nil, InvalidPublicKeyFormat{scheme}
	}
	x := new(big.Int).SetBytes(uncompressedPoint[1 : 1+coordinatesLength])
	y := new(big.Int).SetBytes(uncompressedPoint[1+coordinatesLength:])
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// ParseUncompressedPoint parses the given public key in uncompressed point format
// (cf RFC8446 Section 4.2.8.2) into an ECDSA public key
func SerializeUncompressedPoint(out []byte, pubkey *ecdsa.PublicKey) ([]byte, error) {
	ecdhKey, err := pubkey.ECDH()
	if err != nil {
		return nil, err
	}
	out = append(out, ecdhKey.Bytes()...)
	return out, nil
}
