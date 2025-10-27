package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

func mustEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	if def != "" {
		return def
	}
	log.Fatalf("missing env %s", k)
	return ""
}

func main() {
	target := mustEnv("TARGET_URL", "https://serviceA:8443/protected")
	clientCert := mustEnv("CLIENT_CERT", "/certs/serviceB.crt")
	clientKey := mustEnv("CLIENT_KEY", "/certs/serviceB.key")
	caCert := mustEnv("CA_CERT", "/certs/ca.crt")
	intervalStr := os.Getenv("CALL_INTERVAL")
	if intervalStr == "" {
		intervalStr = "5"
	}
	interval, _ := strconv.Atoi(intervalStr)
	if interval <= 0 {
		interval = 5
	}

	// mTLS client
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		log.Fatalf("load client cert: %v", err)
	}
	caPEM, err := os.ReadFile(caCert)
	if err != nil {
		log.Fatalf("read ca: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
		},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	log.Printf("ServiceB calling %s every %ds", target, interval)
	t := time.NewTicker(time.Duration(interval) * time.Second)
	defer t.Stop()

	for {
		resp, err := client.Get(target)
		if err != nil {
			log.Printf("call error: %v", err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("status=%d body=%s", resp.StatusCode, string(body))
		}
		<-t.C
	}
}
