# http-signature-auth-go
Implements https://www.ietf.org/archive/id/draft-ietf-httpbis-unprompted-auth-05.html
HTTP1.1, HTTP/2 and HTTP/3 servers can place their resources behind
HTTP Signature authentication by using the HTTP handler provided by this library.
This is currently only for interop purpose and not production use yet.

# Examples

## Server: Serving an HTTP URL behind Signature Authentication

~~~~go
keysDB := http_signature_auth.NewKeysDatabase()
var keys []crypto.PublicKey = ...
for i := range keys {
    keysDB.AddKey(keyIDs[i], keys[i])
}
mux := http.NewServeMux()
handler := http_signature_auth.NewSignatureAuthHandler(keysDB, func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
})
mux.Handle("/my-protected-resource", handler)
server := http.Server{
    TLSConfig: tlsConfig,
    Addr:      *bindAddr,
    Handler:   mux,
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
    Addr:      *bindAddr,
    Handler:   mux,
}
err = quicServer.ListenAndServe()
~~~~

## Client: Accessing a resource through HTTP/3 using Signature Auth (using quic-go)

~~~~go
request, err := http.NewRequest("GET", "https://example.org", nil)
if err != nil {
    log.Fatal().Msgf("could not build request from URL: %s", err)
}

var signer *rsa.PrivateKey = ... // also works with ecdsa and ed25519

// we must set NextProtos to "h3" to enable HTTP/3
tlsConf := &tls.Config{
    NextProtos: []string{http3.NextProtoH3}
}
// establish a QUIC connection
log.Debug().Msgf("Establish QUIC connection to %s:%s", request.URL.Hostname(), port)
qConn, err := quic.DialAddr(context.Background(), request.Host, &tlsConf, nil)
if err != nil {
    log.Fatal().Msgf("could establish QUIC connection: %s", err)
}

tlsConnState := qConn.ConnectionState().TLS

roundTripper := &http3.RoundTripper{
    Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
        return qConn.(quic.EarlyConnection), nil
    },
}


signature, err := http_signature_auth.NewSignatureForRequest(&tlsConnState, request, http_signature_auth.KeyID(keyID[:]), signer, signatureScheme)
if err != nil {
    log.Fatal().Msgf("could not generate signature for request: %s", err)
}

authHeaderValue, err := signature.SignatureAuthorizationHeader()
if err != nil {
    log.Fatal().Msgf("could not generate signature authorization header: %s", err)
}

request.Header.Set("Authorization", authHeaderValue)
response, err := roundTripper.RoundTrip(request)
log.Debug().Msgf("negotiated protocol is %s", connState.NegotiatedProtocol)
if err != nil {
    log.Fatal().Msgf("could not perform request: %s", err)
}
defer response.Body.Close()
fmt.Println("Got response", response.Status)
bodyContent, err := io.ReadAll(response.Body)
if err != nil {
    log.Error().Msgf("Could not read body content")
}
if bodyContent != nil {
    fmt.Println("Body:")
    fmt.Println(string(bodyContent))
}
~~~~