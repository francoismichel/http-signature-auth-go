package main

import (
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
	"golang.org/x/term"

	http_signature_auth "github.com/francoismichel/http-signature-auth-go"
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
	privateKeyArg := flag.String("privkey", "", "path the an OpenSSH-parsable private key file that will be used to authenticate the client")
	insecure := flag.Bool("insecure", false, "if set, skips the TLS certificates verification")
	signatureSchemeArg := flag.Int("signature-scheme", -1, "sets the signature scheme integer value "+
		"see the supported schemes at https://www.ietf.org/archive/id/draft-ietf-httpbis-unprompted-auth-05.html"+
		"(see the values at https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme)")
	verbose := flag.Bool("v", false, "verbose mode, displays sent and received HTTP headers")
	flag.Parse()


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

	tlsConf := tls.Config{
		InsecureSkipVerify: *insecure,
	}
	port := "443"
	if request.URL.Port() != "" {
		port = request.URL.Port()
	}
	tlsConn, err := tls.Dial("tcp", request.URL.Hostname()+":"+port, &tlsConf)
	if err != nil {
		log.Fatal().Msgf("could not connect to server using TLS: %s", err)
	}
	defer tlsConn.Close()

	connState := tlsConn.ConnectionState()

	client := &http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				return tlsConn, nil
			},
		},
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
	keyID := sha256.Sum256(sshPubKey.Marshal())

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

	signature, err := http_signature_auth.NewSignatureForRequest(&connState, request, http_signature_auth.KeyID(keyID[:]), signer, signatureScheme)
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
	
	response, err := client.Do(request)
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
