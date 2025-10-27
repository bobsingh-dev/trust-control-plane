package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type opaInput struct {
	Input struct {
		Identity string `json:"identity"`
		Attested bool   `json:"attested"`
	} `json:"input"`
}
type opaDecision struct {
	Result bool `json:"result"`
}
type auditRecord struct {
	Timestamp   string `json:"ts"`
	CallerID    string `json:"caller_id"`
	Attested    bool   `json:"attested"`
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason"`
	Path        string `json:"path"`
	Method      string `json:"method"`
	TLSVerified bool   `json:"tls_verified"`
}

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

func extractSPIFFEFromCert(r *http.Request) (string, bool) {
	state := r.TLS
	if state == nil || len(state.PeerCertificates) == 0 {
		return "", false
	}
	cert := state.PeerCertificates[0]
	for _, u := range cert.URIs {
		if strings.EqualFold(u.Scheme, "spiffe") {
			return u.String(), true
		}
	}
	return "", false
}

func callOPA(opaURL, identity string, attested bool) (bool, error) {
	payload := opaInput{}
	payload.Input.Identity = identity
	payload.Input.Attested = attested
	b, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", opaURL, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return false, errors.New("opa error: " + string(body))
	}
	var dec opaDecision
	if err := json.Unmarshal(body, &dec); err != nil {
		return false, err
	}
	return dec.Result, nil
}

func appendAudit(auditPath string, rec auditRecord) {
	_ = os.MkdirAll(filepath.Dir(auditPath), 0o755)
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("audit open err: %v", err)
		return
	}
	defer f.Close()
	j, _ := json.Marshal(rec)
	f.Write(append(j, '\n'))
}

func main() {
	opaURL := mustEnv("OPA_URL", "")
	auditPath := mustEnv("AUDIT_PATH", "/shared/audit.jsonl")
	serverCert := mustEnv("SERVER_CERT", "/certs/serviceA.crt")
	serverKey := mustEnv("SERVER_KEY", "/certs/serviceA.key")
	caCertPath := mustEnv("CA_CERT", "/certs/ca.crt")
	expectCaller := os.Getenv("IDENTITY_EXPECT")

	// TLS server requiring client cert (mTLS)
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("read ca: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatal("bad ca pem")
	}
	tlsCfg := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}).Methods("GET")

	r.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		id, ok := extractSPIFFEFromCert(r)
		tlsVerified := ok

		allowed, err := callOPA(opaURL, id, tlsVerified)
		rec := auditRecord{
			Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
			CallerID:    id,
			Attested:    tlsVerified,
			Allowed:     allowed,
			Path:        r.URL.Path,
			Method:      r.Method,
			TLSVerified: tlsVerified,
		}
		if err != nil {
			rec.Allowed = false
			rec.Reason = "opa_error: " + err.Error()
		} else if expectCaller != "" && id != expectCaller {
			rec.Reason = "unexpected identity"
		}

		appendAudit(auditPath, rec)

		if rec.Allowed {
			log.Printf("✅ access granted to %s", id)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok","message":"access granted"}`))
			return
		}
		log.Printf("🚫 access denied to %s (reason=%s)", id, rec.Reason)
		http.Error(w, "access denied", http.StatusForbidden)
	}).Methods("GET")

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   r,
		TLSConfig: tlsCfg,
	}

	log.Println("ServiceA listening on :8443 (mTLS required)")
	if err := srv.ListenAndServeTLS(serverCert, serverKey); err != nil {
		log.Fatal(err)
	}
}
