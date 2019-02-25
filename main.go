package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "io"
    "log"
    "math/big"
    "net/http"
    "os"
    "os/user"
    "path/filepath"
    "time"
)

var blockedRequestKeys = map[string]bool {
    "Forwarded": true,
    "X-Forwarded-For": true,
    "X-Forwarded-Host": true,
    "X-Forwarded-Proto": true,
}

var certFile = ".config/mkhttps.cert"
var keyFile = ".config/mkhttps.pem"

func main() {
    usr, err := user.Current()
    if err != nil { panic(err) }
    certFile = filepath.Join(usr.HomeDir, certFile)
    keyFile  = filepath.Join(usr.HomeDir, keyFile)

    if len(os.Args) != 3 {
        _, _ = fmt.Fprintln(os.Stderr, "Usage: mkhttps <src> <dst>")
        os.Exit(1)
    }

    if _, err := os.Stat(keyFile); err != nil {
        mkcert()
    }

    handler := http.DefaultServeMux
    
    handler.HandleFunc("/", handleFunc)
    
    s := &http.Server{
        Addr:    os.Args[2],
        Handler: handler,
    }

    log.Print("Listening")
    log.Fatal(s.ListenAndServeTLS(certFile, keyFile))
}

func handleFunc(w http.ResponseWriter, r *http.Request) {
    fmt.Printf("--> %v %v\n", r.Method, r.URL)
    
    // Construct filtered header to send to origin server
    hh := http.Header{}
    for k, v := range r.Header {
        if blockedRequestKeys[k] {
            continue
        }
        hh[k] = v
    }

    r.URL.Host = os.Args[1]
    
    // Construct request to send to origin server
    rr := http.Request {
        Method: r.Method,
        URL: r.URL,
        Header: hh,
        Body: r.Body,
    }
    
    // Forward request to origin server
    resp, err := http.DefaultTransport.RoundTrip(&rr)
    if err != nil {
        http.Error(w, "Could not reach origin server", 500)
        return
    }
    defer resp.Body.Close()

    log.Printf("<-- %v\n", resp.Status)
    
    resp.Header = w.Header()
    w.WriteHeader(resp.StatusCode)
    _, err = io.Copy(w, resp.Body)
    if err != nil {
        log.Print(err)
    }
}

//noinspection ALL
func mkcert() {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { panic(err) }

    notBefore := time.Now()
    notAfter := notBefore.Add(3 * 365 * 24 * time.Hour)

    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil { panic(err) }

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"mkhttps"},
        },
        NotBefore: notBefore,
        NotAfter:  notAfter,

        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
    if err != nil { panic(err) }

    certOut, err := os.Create(certFile)
    if err != nil { panic(err) }
    defer certOut.Close()

    if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
        panic(err)
    }

    privBytes, err := x509.MarshalECPrivateKey(priv)
    if err != nil { panic(err) }
    privBlock :=  &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}

    keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    defer keyOut.Close()
    if err != nil { panic(err) }
    if err := pem.Encode(keyOut, privBlock); err != nil { panic(err) }

    log.Print("Created new keypair: ", keyFile)
}
