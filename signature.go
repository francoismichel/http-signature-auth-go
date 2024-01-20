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
	"net/http"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/quicvarint"
	"github.com/rs/zerolog/log"
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

func GetPortFromRequest(r *http.Request, httpScheme string) (uint16, error) {
	portStr := ""
	switch httpScheme {
	case "http":
		portStr = "80"
	case "https":
		portStr = "443"
	default:
		return 0, errors.New("Unknown scheme: " + httpScheme)
	}

	// retrieve the port from the request (for HTTP/2, the Host field may also come from the :authority pseudo-header)
	hostPort := strings.Split(r.Host, ":")
	if len(hostPort) == 2 && hostPort[1] != "" {
		portStr = hostPort[1]
	} else if len(hostPort) > 2 {
		return 0, errors.New("Invalid Host header format: " + r.Host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(port), nil
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

func (m *TLSExporterMaterial) String() string {
	return fmt.Sprintf("signatureInput=%s, verification=%s", b64Encoder.EncodeToString(m.signatureInput[:]), b64Encoder.EncodeToString(m.verification[:]))
}

func GenerateTLSExporterMaterial(tls *tls.ConnectionState, signatureScheme tls.SignatureScheme, keyID KeyID, pubKey crypto.PublicKey, httpScheme string, httpHost string, httpPort uint16, httpRealm string) (TLSExporterMaterial, error) {
	var material TLSExporterMaterial
	var err error

	log.Debug().Msgf("generate TLS exporter material: signatureScheme=%s, keyID=%s, httpScheme=%s, httpHost=%s, httpPort=%d, httpRealm=%s", signatureScheme, b64Encoder.EncodeToString([]byte(keyID)), httpScheme, httpHost, httpPort, httpRealm)
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

func (s *Signature) KeyID() KeyID {
	return s.keyID
}

func (s *Signature) PublicKey() crypto.PublicKey {
	return s.pubkey
}

func (s *Signature) SignatureScheme() tls.SignatureScheme {
	return s.signatureScheme
}

// SignatureAuthorizationHeader serializes the signature into a string
// that can be used in the Authorization header.
// The returned value takes the form
// k, a, v and p are base64url-encoded
// s is base10-encoded
// "Signature k=<keyID>,a=<pubkey>,s=<signatureScheme>,v=<exporterVerification>,p=<proof>"
func (s *Signature) SignatureAuthorizationHeader() (string, error) {
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

func NewSignatureForRequest(tls *tls.ConnectionState, r *http.Request, keyID KeyID, signer crypto.Signer, signatureScheme tls.SignatureScheme) (*Signature, error) {
	// from the doc:
	// For server requests, the URL is parsed from the URI
	// supplied on the Request-Line as stored in RequestURI.  For
	// most requests, fields other than Path and RawQuery will be
	// empty. (See RFC 7230, Section 5.3)
	// so the scheme will probably be empty, but we let the upstream
	// code set a specific scheme if needed
	httpScheme := r.URL.Scheme
	if httpScheme == "" {
		// assume https by default
		httpScheme = "https"
	}

	port, err := GetPortFromRequest(r, httpScheme)
	if err != nil {
		return nil, err
	}
	// TODO: Implement realm
	material, err := GenerateTLSExporterMaterial(tls, signatureScheme, keyID, signer.Public(), httpScheme, r.Host, uint16(port), "")
	if err != nil {
		return nil, err
	}
	return NewSignatureWithMaterial(&material, keyID, signer, signatureScheme)
}

func NewSignatureWithMaterial(material *TLSExporterMaterial, keyID KeyID, signer crypto.Signer, signatureScheme tls.SignatureScheme) (*Signature, error) {
	log.Debug().Msgf("generate new signature, keyID=%s, signatureScheme=%s, material=<%s>", b64Encoder.EncodeToString([]byte(keyID)), signatureScheme, material)
	pubkey := signer.Public()
	if !IsPubkeySupported(pubkey) {
		return nil, UnsupportedKeyType{Type: fmt.Sprintf("%T", pubkey)}
	}

	log.Debug().Msgf("pubkey type %T is supported", pubkey)

	signaturePayload := append(SIGNATURE_HEADER, material.signatureInput[:]...)

	var proof []byte
	var digest []byte
	var opts crypto.SignerOpts

	switch k := signer.(type) {
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
	case ed25519.PrivateKey, *ed25519.PrivateKey:
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

// ParseSignatureAuthorizationContent parses the given Authorization header content
// into a Signature. content must be a value Signature Authorization header content,
// i.e. it must start with "Signature " and follow the specification in
// https://www.ietf.org/archive/id/draft-ietf-httpbis-unprompted-auth-05.html
func ParseSignatureAuthorizationContent(content string) (*Signature, error) {
	const prefix = "Signature "
	if strings.HasPrefix(content, prefix) {
		// Extract the parameters from the Authorization header
		parameters := content[len(prefix):]

		parametersPresent := make(map[string]bool)
		fields := strings.Split(parameters, ",")

		signature := &Signature{}

		pubkeyBase64 := ""
		var err error
		for _, fieldWithSpaces := range fields {
			field := strings.TrimSpace(fieldWithSpaces)

			keyValue := strings.Split(field, "=")
			if len(keyValue) != 2 {
				return nil, MalformedHTTPSignatureAuth{Msg: "parameters should be in k=v format, received: " + field}
			}

			key, value := keyValue[0], keyValue[1]
			if present := parametersPresent[key]; present {
				// we assume that parameters cannot be repeated
				return nil, MalformedHTTPSignatureAuth{Msg: "duplicate parameter: " + key}
			}

			switch key {
			case "k":
				signature.keyID, err = ParseKeyID(value)
			case "a":
				pubkeyBase64 = value
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

		// we handle the public key separaterly as it could depend on the signature scheme
		// that is also present in the as an authentication parameter
		if parametersPresent["a"] && pubkeyBase64 != "" {
			signature.pubkey, err = ParsePublicKey(pubkeyBase64, signature.signatureScheme)
			if err != nil {
				return nil, err
			}
		}

		if len(parametersPresent) != 5 {
			return nil, MalformedHTTPSignatureAuth{Msg: "Expected 5 parameters, received " + fmt.Sprint(len(parametersPresent))}
		}
		return signature, nil
	}
	return nil, MalformedHTTPSignatureAuth{Msg: "Authorization header content does not start with " + prefix}
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
	return ParseSignatureAuthorizationContent(authHeader)
}

func VerifySignature(keysDB *Keys, r *http.Request) (bool, error) {
	signatureCandidate, err := ExtractSignature(r)
	if err != nil {
		return false, err
	}

	if signatureCandidate == nil {
		return false, nil
	}

	httpScheme := r.URL.Scheme
	if httpScheme == "" {
		// assume https by default
		httpScheme = "https"
	}

	port, err := GetPortFromRequest(r, httpScheme)
	if err != nil {
		return false, fmt.Errorf(fmt.Sprintf("incalid port: %s", err))
	}

	material, err := GenerateTLSExporterMaterial(r.TLS, signatureCandidate.signatureScheme,
		signatureCandidate.keyID, signatureCandidate.pubkey, httpScheme, r.Host,
		uint16(port), "") // TODO: Implement realm
	if err != nil {
		return false, err
	}
	return VerifySignatureWithMaterial(keysDB, signatureCandidate, &material)
}

func VerifySignatureWithMaterial(keysDB *Keys, signatureCandidate *Signature, material *TLSExporterMaterial) (bool, error) {
	log.Debug().Msgf("Verifying signature with key ID %s, proof=%s, exporter_material=<%s>", b64Encoder.EncodeToString([]byte(signatureCandidate.keyID)),
		b64Encoder.EncodeToString(signatureCandidate.proof), material)
	key := keysDB.GetKey(signatureCandidate.keyID)
	if key == nil {
		log.Debug().Msgf("key %s not present in the database", signatureCandidate.keyID)
		return false, nil
	}
	if !IsPubkeySupported(key) {
		return false, UnsupportedKeyType{Type: fmt.Sprintf("%T", key)}
	}

	if !key.(PubkeyEqual).Equal(signatureCandidate.pubkey) {
		// do not return error, as this is not a problem with the signature per-se
		log.Debug().Msgf("%s", PublicKeysMismatch{keyID: signatureCandidate.keyID})
		return false, nil
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
		log.Debug().Msgf("Verifying RSA-PSS signature with hash %s, digest=%s", cryptoHash, b64Encoder.EncodeToString(digest))
		pssErr := rsa.VerifyPSS(k, cryptoHash, digest, signatureCandidate.proof, nil)
		if pssErr != nil {
			log.Debug().Msgf("Error verifying RSA-PSS signature: %s", pssErr)
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
