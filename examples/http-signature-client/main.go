package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http2"
	"golang.org/x/term"

	http_signature_auth "github.com/francoismichel/http-signature-auth-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func GuessSignatureScheme(signer crypto.Signer) (tls.SignatureScheme, error) {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		return tls.PSSWithSHA256, nil
	case *ecdsa.PublicKey:
		return tls.ECDSAWithP256AndSHA256, nil
	case ed25519.PublicKey:
		return tls.Ed25519, nil
	default:
		return 0, errors.New("unsupported public key type")
	}
}

func main() {
	doHTTP1Dot1 := flag.Bool("http1.1", false, "if set, use HTTP/2 (using TCP) instead of HTTP/3 (using QUIC)")
	doHTTP2 := flag.Bool("http2", false, "if set, use HTTP/1.1 (using TCP) instead of HTTP/3 (using QUIC)")
	privateKeyArg := flag.String("privkey", "", "path the an OpenSSH-parsable private key file that will be used to authenticate the client")
	keyIDArg := flag.String("keyid", "", "The keyID that identifies that key to the server. The server must know this keyID as well. " + 
										 "This argument contains the raw bytes of the key, not encoded." +
										 "If not set, a keyID is generated as he sha256 sum sshPubKey.Marshal()")
	insecure := flag.Bool("insecure", false, "if set, skips the TLS certificates verification")
	signatureSchemeArg := flag.Int("signature-scheme", -1, "sets the signature scheme integer value "+
		"see the supported schemes at https://www.ietf.org/archive/id/draft-ietf-httpbis-unprompted-auth-05.html"+
		"(see the values at https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme)")
	verbose := flag.Bool("v", false, "verbose mode, displays sent and received HTTP headers")
	flag.Parse()

	if *doHTTP1Dot1 && *doHTTP2 {
		flag.Usage()
		log.Fatal().Msgf("Cannot use both -http1.1 and -http2 at the same time, either one, the other or none")
	}

	useTCP := *doHTTP1Dot1 || *doHTTP2

	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	if len(flag.Args()) == 0 {
		flag.Usage()
		log.Fatal().Msgf("Missing URL")
	} else if len(flag.Args()) > 1 {
		flag.Usage()
		log.Fatal().Msgf("Too many arguments")
	}

	if *privateKeyArg == "" {
		log.Fatal().Msgf("Missing -privkey")
	}

	request, err := http.NewRequest("GET", flag.Args()[0], nil)
	if err != nil {
		log.Fatal().Msgf("could not build request from URL: %s", err)
	}

	privateKeyBytes, err := os.ReadFile(*privateKeyArg)
	if err != nil {
		log.Fatal().Msgf("could not read private key file: %s", err)
	}

	abstractPrivateKey, err := ssh.ParseRawPrivateKey(privateKeyBytes)
	if _, ok := err.(*ssh.PassphraseMissingError); ok {
		fmt.Printf("passphrase for private key stored in %s:\n", *privateKeyArg)
		var passphraseBytes []byte
		passphraseBytes, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			log.Fatal().Msgf("could not get passphrase: %s", err)
		}
		abstractPrivateKey, err = ssh.ParseRawPrivateKeyWithPassphrase(privateKeyBytes, passphraseBytes)
	}

	if err != nil {
		log.Printf("%T", err)
		log.Fatal().Msgf("could not parse private key: %s", err)
	}

	signer, ok := abstractPrivateKey.(crypto.Signer)
	if !ok {
		log.Fatal().Msgf("private key is not a crypto.Signer, it is of type %T\n", abstractPrivateKey)
	}

	// get the SSH pubkey so that we can generate the key ID from sha256(sshPubKey.Marshal())
	sshPubKey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		log.Fatal().Msgf("could not get SSH public key from private key: %s", err)

	}
	keyID := []byte(*keyIDArg)
	if *keyIDArg == "" {
		sha := sha256.Sum256(sshPubKey.Marshal())
		keyID = sha[:]
	}

	var signatureScheme tls.SignatureScheme
	if *signatureSchemeArg == -1 {
		guessedSignatureScheme, err := GuessSignatureScheme(signer)
		if err != nil {
			log.Fatal().Msgf("could not guess signature scheme: %s", err)
		}
		signatureScheme = guessedSignatureScheme
	} else {
		if *signatureSchemeArg < 0 || *signatureSchemeArg > 0xFFFF {
			log.Fatal().Msgf("bad signature scheme value: %d", *signatureSchemeArg)
		}
		signatureScheme = tls.SignatureScheme(*signatureSchemeArg)
	}

	var roundTripper http.RoundTripper
	tlsConf := tls.Config{
		InsecureSkipVerify: *insecure,
	}
	port := "443"
	if request.URL.Port() != "" {
		port = request.URL.Port()
	}

	var connState tls.ConnectionState
	var response *http.Response
	if useTCP {
		// setting NextProtos to nil enables both HTTP/1.1 and H2
		// but if we're in this if, that means the user selected either HTTP/1.1 or H2
		if *doHTTP1Dot1 {
			tlsConf.NextProtos = []string{"http/1.1"}
		} else {
			tlsConf.NextProtos = []string{"h2"}
		}

		// establish a TCP+TLS session
		log.Debug().Msgf("Establish TCP+TLS session to %s:%s", request.URL.Hostname(), port)
		tlsConn, err := tls.Dial("tcp", request.URL.Hostname()+":"+port, &tlsConf)
		if err != nil {
			log.Fatal().Msgf("could not connect to server using TLS: %s", err)
		}
		defer tlsConn.Close()

		connState = tlsConn.ConnectionState()

		transport := &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				return tlsConn, nil
			},
		}

		// Weird that I need to use this, but if I don't, http2 just isn't parsed on the client
		// and the connection breaks
		if *doHTTP2 {
			http2.ConfigureTransport(transport)
		}
		roundTripper = transport
	} else {
		// we must set NextProtos to "h3" to enable HTTP/3
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		// establish a QUIC connection
		log.Debug().Msgf("Establish QUIC connection to %s:%s", request.URL.Hostname(), port)
		qConn, err := quic.DialAddr(context.Background(), request.URL.Hostname()+":"+port, &tlsConf, nil)
		if err != nil {
			log.Fatal().Msgf("could establish QUIC connection: %s", err)
		}

		connState = qConn.ConnectionState().TLS

		roundTripper = &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				return qConn.(quic.EarlyConnection), nil
			},
		}
	}

	signature, err := http_signature_auth.NewSignatureForRequest(&connState, request, http_signature_auth.KeyID(keyID), signer, signatureScheme)
	if err != nil {
		log.Fatal().Msgf("could not generate signature for request: %s", err)
	}

	authHeaderValue, err := signature.SignatureAuthorizationHeader()
	if err != nil {
		log.Fatal().Msgf("could not generate signature authorization header: %s", err)
	}

	request.Header.Set("Authorization", authHeaderValue)

	if *verbose {
		log.Debug().Msgf("Sending request %s %s", request.Method, request.URL.String())
		log.Debug().Msgf("Headers:")
		for key, val := range request.Header {
			log.Debug().Msgf("    %s: %s", key, val)
		}
	}

	response, err = roundTripper.RoundTrip(request)
	log.Debug().Msgf("negotiated protocol is %s", connState.NegotiatedProtocol)
	if err != nil {
		log.Fatal().Msgf("could not perform request: %s", err)
	}
	defer response.Body.Close()
	fmt.Println("Got response", response.Status)
	log.Debug().Msgf("Headers:")
	for key, val := range response.Header {
		log.Debug().Msgf("    %s: %s", key, val)
	}
	bodyContent, err := io.ReadAll(response.Body)
	if err != nil {
		log.Error().Msgf("Could not read body content")
	}
	if bodyContent != nil {
		fmt.Println("Body:")
		fmt.Println(string(bodyContent))
	}
}
