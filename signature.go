package http_signature_auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/quicvarint"
)

var SIGNATURE_HEADER_PART_1 [64]byte = [64]byte{
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
}

var SIGNATURE_HEADER = append(SIGNATURE_HEADER_PART_1[:], []byte("HTTP Signature Authentication\x00")...)

type PubkeyEqual interface {
	Equal(crypto.PublicKey) bool
}

func GetHash(scheme tls.SignatureScheme) (crypto.Hash, error) {
	var hash crypto.Hash
	switch scheme {
	case tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256:
		hash = crypto.SHA256
	case tls.PSSWithSHA384, tls.ECDSAWithP384AndSHA384:
		hash = crypto.SHA384
	case tls.PSSWithSHA512, tls.ECDSAWithP521AndSHA512:
		hash = crypto.SHA512
	default:
		return 0, TLSSignatureSchemeNotSupported{Scheme: scheme, Reason: "Unsupported signature scheme"}
	}
	if !hash.Available() {
		return 0, TLSSignatureSchemeNotSupported{Scheme: scheme, Reason: "Hash not available on the system"}
	}
	return hash, nil
}

//   Signature Algorithm (16),
//   Key ID Length (i),
//   Key ID (..),
//   Public Key Length (i),
//   Public Key (..),
//   Scheme Length (i),
//   Scheme (..),
//   Host Length (i),
//   Host (..),
//   Port (16),
//   Realm Length (i),
//   Realm (..),

func PrepareTLSExporterInput(signatureScheme tls.SignatureScheme, keyID KeyID, pubKey crypto.PublicKey, httpScheme string, httpHost string, httpPort uint16, httpRealm string) (out []byte, err error) {
	// Encode signatureScheme in network endian
	buf := make([]byte, 2)
	// Signature Algorithm
	binary.BigEndian.PutUint16(buf, uint16(signatureScheme))
	out = append(out, buf...)

	// Key ID
	out = quicvarint.Append(out, uint64(len(keyID)))
	out = append(out, keyID...)

	var pubkeyBytes []byte
	pubkeyBytes, err = SerializePublicKey(nil, pubKey)
	if err != nil {
		return out, err
	}
	// Public Key
	out = quicvarint.Append(out, uint64(len(pubkeyBytes)))
	out = append(out, pubkeyBytes...)

	// Scheme
	out = quicvarint.Append(out, uint64(len(httpScheme)))
	out = append(out, []byte(httpScheme)...)

	// Host
	out = quicvarint.Append(out, uint64(len(httpHost)))
	out = append(out, []byte(httpHost)...)

	// Port
	binary.BigEndian.PutUint16(buf, httpPort)
	out = append(out, buf...)

	// Realm
	out = quicvarint.Append(out, uint64(len(httpRealm)))
	out = append(out, []byte(httpRealm)...)

	// TODO: Implement the rest of the function

	return out, nil
}

// from draft-05:
// The key exporter output is 48 bytes long. Of those, the first 32 bytes are part of
// the input to the signature and the next 16 bytes are sent alongside the signature.
// This allows the recipient to confirm that the exporter produces the right values.
type TLSExporterMaterial struct {
	signatureInput [32]byte
	verification   [16]byte
}

func GenerateTLSExporterMaterial(tls *tls.ConnectionState, signatureScheme tls.SignatureScheme, keyID KeyID, pubKey crypto.PublicKey, httpScheme string, httpHost string, httpPort uint16, httpRealm string) (TLSExporterMaterial, error) {
	var material TLSExporterMaterial
	var err error
	exporterInput, err := PrepareTLSExporterInput(signatureScheme, keyID, pubKey, httpScheme, httpHost, httpPort, httpRealm)
	if err != nil {
		return material, err
	}
	exporterOutput, err := tls.ExportKeyingMaterial("EXPORTER-HTTP-Signature-Authentication", exporterInput, 48)
	if err != nil {
		return material, err
	}

	copy(material.signatureInput[:], exporterOutput[:32])
	copy(material.verification[:], exporterOutput[32:])

	return material, err
}

type Signature struct {
	keyID                KeyID
	pubkey               crypto.PublicKey
	proof                []byte
	exporterVerification []byte
	signatureScheme      tls.SignatureScheme
}

// SerializeSignatureAuthorizationValue serializes the signature into a string
// that can be used in the Authorization header.
// The returned value takes the form
// k, a, v and p are base64url-encoded
// s is base10-encoded
// "Signature k=<keyID>,a=<pubkey>,s=<signatureScheme>,v=<exporterVerification>,p=<proof>"
func (s *Signature) SerializeSignatureAuthorizationValue() (string, error) {
	pubkeyBytes, err := SerializePublicKey(nil, s.pubkey)
	if err != nil {
		return "", err
	}
	var out string
	out += "Signature "
	out += "k=" + b64Encoder.EncodeToString([]byte(s.keyID)) + ","
	out += "a=" + b64Encoder.EncodeToString(pubkeyBytes) + ","
	out += "s=" + strconv.FormatUint(uint64(s.signatureScheme), 10) + ","
	out += "v=" + b64Encoder.EncodeToString(s.exporterVerification) + ","
	out += "p=" + b64Encoder.EncodeToString(s.proof)
	return out, nil
}

func NewSignatureFromRequest(tls *tls.ConnectionState, r *http.Request, keyID KeyID, privKey crypto.PrivateKey, pubkey crypto.PublicKey, signatureScheme tls.SignatureScheme) (*Signature, error) {
	portStr := r.URL.Port()
	if portStr == "" {
		if r.URL.Scheme == "http" {
			portStr = "80"
		} else if r.URL.Scheme == "https" {
			portStr = "443"
		} else {
			return nil, errors.New("Unknown scheme: " + r.URL.Scheme)
		}
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	// TODO: Implement realm
	material, err := GenerateTLSExporterMaterial(tls, signatureScheme, keyID, pubkey, r.URL.Scheme, r.URL.Hostname(), uint16(port), "")
	if err != nil {
		return nil, err
	}
	return NewSignatureWithMaterial(&material, keyID, privKey, pubkey, signatureScheme)
}

func NewSignatureWithMaterial(material *TLSExporterMaterial, keyID KeyID, privKey crypto.PrivateKey, pubkey crypto.PublicKey, signatureScheme tls.SignatureScheme) (*Signature, error) {
	if !IsPubkeySupported(pubkey) {
		return nil, UnsupportedKeyType{Type: fmt.Sprintf("%T", pubkey)}
	}
	
	signaturePayload := append(SIGNATURE_HEADER, material.signatureInput[:]...)

	var proof []byte
	var digest []byte
	var signer crypto.Signer
	var opts crypto.SignerOpts
	
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		cryptoHash, err := GetHash(signatureScheme)
		if err != nil {
			return nil, err
		}
		signer = k
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: cryptoHash}
		// sign the payload
		hash := cryptoHash.New()
		hash.Write(signaturePayload)
		digest = hash.Sum(nil)
	case *ecdsa.PrivateKey:
		cryptoHash, err := GetHash(signatureScheme)
		if err != nil {
			return nil, err
		}
		signer = k
		opts = cryptoHash
		// sign the payload
		hash := cryptoHash.New()
		hash.Write(signaturePayload)
		digest = hash.Sum(nil)
	case ed25519.PrivateKey:
		signer = k
		opts = crypto.Hash(0)
		digest = signaturePayload
	default:
		return nil, UnsupportedKeyType{Type: fmt.Sprintf("%T", k)}
	}

	proof, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}

	return &Signature{
		keyID:                keyID,
		pubkey:               pubkey,
		proof:                proof,
		exporterVerification: material.verification[:],
		signatureScheme:      signatureScheme,
	}, nil
}

// ExtractSignature extracts the HTTP signature from the Authorization header
// It may return a nil signature with a nil error if no signature was found.
// It returns a non-nil error if the Signature was present in the
// Authorization header but was malformed.
//
// example from the draft:
//
//	Authorization: Signature \
//	  k=YmFzZW1lbnQ, \
//	  a=VGhpcyBpcyBhIHB1YmxpYyBrZXkgaW4gdXNlIGhlcmU, \
//	  s=2055, \
//	  v=dmVyaWZpY2F0aW9uXzE2Qg, \
//	  p=SW5zZXJ0IHNpZ25hdHVyZSBvZiBub25jZSBoZXJlIHdo \
//	    aWNoIHRha2VzIDUxMiBiaXRzIGZvciBFZDI1NTE5IQ
func ExtractSignature(r *http.Request) (*Signature, error) {
	authHeader := r.Header.Get("Authorization")
	const prefix = "Signature "
	if strings.HasPrefix(authHeader, prefix) {
		// Extract the parameters from the Authorization header
		parameters := authHeader[len(prefix):]

		parametersPresent := make(map[string]bool)
		fields := strings.Split(parameters, ",")

		signature := &Signature{}

		for _, field := range fields {
			keyValue := strings.Split(field, "=")
			if len(keyValue) != 2 {
				return nil, MalformedHTTPSignatureAuth{Msg: "parameters should be in k=v format, received: " + field}
			}

			key, value := keyValue[0], keyValue[1]
			if present := parametersPresent[key]; present {
				// we assume that parameters cannot be repeated
				return nil, MalformedHTTPSignatureAuth{Msg: "duplicate parameter: " + key}
			}

			var err error
			switch key {
			case "k":
				signature.keyID, err = ParseKeyID(value)
			case "a":
				signature.pubkey, err = ParsePublicKey(value, signature.signatureScheme)
			case "s":
				signature.signatureScheme, err = ParseAndValidateSignatureScheme(value)
			case "v":
				signature.exporterVerification, err = b64Encoder.DecodeString(value)
			case "p":
				signature.proof, err = b64Encoder.DecodeString(value)
			default:
				return nil, MalformedHTTPSignatureAuth{Msg: "Unknown parameter: " + key}
			}
			if err != nil {
				return nil, err
			}
			parametersPresent[key] = true
		}

		if len(parametersPresent) != 5 {
			return nil, MalformedHTTPSignatureAuth{Msg: "Expected 5 parameters, received " + fmt.Sprint(len(parametersPresent))}
		}
	}
	return nil, nil
}

func ValidateSignature(keysDB *Keys, r *http.Request) (bool, error) {
	signatureCandidate, err := ExtractSignature(r)
	if err != nil {
		return false, err
	}

	if signatureCandidate == nil {
		return false, nil
	}

	portStr := r.URL.Port()
	// if the port is empty in the URL, do we get the actual port from the server or do we set
	// 80 for http and 443 for https ?
	if portStr == "" {
		if r.URL.Scheme == "http" {
			portStr = "80"
		} else if r.URL.Scheme == "https" {
			portStr = "443"
		} else {
			return false, MalformedHTTPSignatureAuth{Msg: "Unknown scheme: " + r.URL.Scheme}
		}
	}

	var port uint64
	port, err = strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return false, MalformedHTTPSignatureAuth{Msg: "Invalid port: " + portStr}
	}

	material, err := GenerateTLSExporterMaterial(r.TLS, signatureCandidate.signatureScheme,
		signatureCandidate.keyID, signatureCandidate.pubkey, r.URL.Scheme, r.URL.Hostname(),
		uint16(port), "") // TODO: Implement realm
	if err != nil {
		return false, err
	}
	return ValidateSignatureWithMaterial(keysDB, signatureCandidate, &material)
}

func ValidateSignatureWithMaterial(keysDB *Keys, signatureCandidate *Signature, material *TLSExporterMaterial) (bool, error) {
	key := keysDB.GetKey(signatureCandidate.keyID)
	if key == nil {
		log.Println("key not present in the database")
		return false, nil
	}
	if !IsPubkeySupported(key) {
		return false, UnsupportedKeyType{Type: fmt.Sprintf("%T", key)}
	}

	if !key.(PubkeyEqual).Equal(signatureCandidate.pubkey) {
		return false, PublicKeysMismatch{keyID: signatureCandidate.keyID}
	}

	signaturePayload := append(SIGNATURE_HEADER, material.signatureInput[:]...)

	// there seems to be no pretty way to verify the signature
	// from the pubkey and signature scheme in the TLS package,
	// so let's do it ourselves
	switch k := key.(type) {
	case *rsa.PublicKey:
		cryptoHash, err := GetHash(signatureCandidate.signatureScheme)
		if err != nil {
			return false, err
		}
		hash := cryptoHash.New()
		hash.Write(signaturePayload)
		digest := hash.Sum(nil)
		pssErr := rsa.VerifyPSS(k, cryptoHash, digest, signatureCandidate.proof, nil)
		if pssErr != nil {
			fmt.Fprintln(os.Stderr, "Error verifying RSA-PSS signature:", pssErr)
		}
		return pssErr == nil, nil
	case *ecdsa.PublicKey:
		cryptoHash, err := GetHash(signatureCandidate.signatureScheme)
		if err != nil {
			return false, err
		}
		hash := cryptoHash.New()
		hash.Write(signaturePayload)
		digest := hash.Sum(nil)
		return ecdsa.VerifyASN1(k, digest, signatureCandidate.proof), nil
	case ed25519.PublicKey:
		return ed25519.Verify(k, signaturePayload, signatureCandidate.proof), nil
	default:
		return false, UnsupportedKeyType{Type: fmt.Sprintf("%T", k)}
	}
}
