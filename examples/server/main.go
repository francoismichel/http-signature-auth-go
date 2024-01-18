package main

import (
	"bufio"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/caddyserver/certmagic"
	http_signature_auth "github.com/francoismichel/http-signature-auth-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)


func ParseAuthorizedKeysFile(file *os.File) (keyIDs []http_signature_auth.KeyID, keys []crypto.PublicKey, err error) {
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber += 1
		line := scanner.Text()
		if len(strings.TrimSpace(line)) == 0 {
			log.Printf("%s:%d: skip empty line", file.Name(), lineNumber)
			continue
		} else if line[0] == '#' {
			// commented line
			log.Printf("%s:%d: skip commented key", file.Name(), lineNumber)
			continue
		}
		sshPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		var pubkey crypto.PublicKey
		if sshCpk, ok := sshPubkey.(ssh.CryptoPublicKey); ok {
			pubkey = sshCpk.CryptoPublicKey()
		} else {
			log.Printf("%s:%d: skip SSH public key that cannot be converted into a crypto.PublicKey", file.Name(), lineNumber)
			continue
		}
		if err == nil {
			keyID := sha256.Sum256(sshPubkey.Marshal())
			keys = append(keys, pubkey)
			keyIDs = append(keyIDs, http_signature_auth.KeyID(keyID[:]))
		} else {
			log.Printf("cannot parse identity line: %s: %s", err.Error(), line)
		}
	}
	return keyIDs, keys, nil
}

func main() {
	bindAddr := flag.String("bind", "[::]:443", "the address:port pair to listen to, e.g. 0.0.0.0:443")
	certMagicDomain := flag.String("certmagic", "", "if set, generates a LetsEncrypt certificate for the given domain using certmagic and use it. Requires a DNS record pointing to this server")
	certPath := flag.String("cert", "", "the filename of the server certificate (or fullchain)")
	keyPath := flag.String("key", "", "the filename of the certificate private key")
	authorizedKeys := flag.String("authorized-keys", "", "path to an OpenSSH authorized keys file that will be used to authenticate the client")
	verbose := flag.Bool("v", false, "if set, verbose mode")

	flag.Parse()

	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if *authorizedKeys == "" {
		log.Fatal().Msgf("Missing -authorized-keys")
	}
	authorizedKeysFile, err := os.Open(*authorizedKeys)
	if err != nil {
		log.Fatal().Msgf("could not open authorized keys file %s: %s", *authorizedKeys, err)
	}
	keyIDs, keys, err := ParseAuthorizedKeysFile(authorizedKeysFile)
	if err != nil {
		log.Fatal().Msgf("could not parse authorized keys file %s: %s", *authorizedKeys, err)
	}

	keysDB := http_signature_auth.NewKeysDatabase()
	for i := range keys {
		keysDB.AddKey(keyIDs[i], keys[i])
	}

	tlsConfig := &tls.Config{}
	if *certMagicDomain != "" {
		certmagic.Default.Logger = certmagic.Default.Logger.Named("github.com/caddyserver/certmagic")

		var err error
		fmt.Fprintln(os.Stderr, "Generate public certificates...")
		tlsConfig, err = certmagic.TLS([]string{*certMagicDomain})
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate public certificates: %s\n", err)
			os.Exit(-1)
		}
		fmt.Fprintln(os.Stderr, "Successfully generated public certificates")
	}

	if *certPath != "" && *keyPath != "" {
		certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not load -cert and -key pair: %s\n", err)
			os.Exit(-1)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
	}


	tlsConfig.NextProtos = []string{"http/1.1", "h2", "h3"}

	mux := http.NewServeMux()
	handler := http_signature_auth.NewSignatureAuthHandler(keysDB, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	mux.Handle("/signature/draft-ietf-httpbis-unprompted-auth-05", handler)
	server := http.Server{
		TLSConfig: tlsConfig,
		Addr: 	*bindAddr,
		Handler: mux,
	}
	log.Info().Msgf("Start HTTPS over TLS on %s", *bindAddr)
	go func() {
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatal().Msgf("cannot listen and serve TLS: %s", err)
		}
	}()
	log.Info().Msgf("Start HTTPS over QUIC on %s", *bindAddr)
	quicServer := http3.Server{
		TLSConfig: tlsConfig,
		Addr: *bindAddr,
		Handler: mux,
	}
	err = quicServer.ListenAndServe()
	if err != nil {
		log.Fatal().Msgf("cannot listen and serve TLS: %s", err)
	}
}