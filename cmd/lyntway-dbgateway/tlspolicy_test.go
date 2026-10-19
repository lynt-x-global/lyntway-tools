package main

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheURLDecidesWhetherCertificatesAreChecked(t *testing.T) {
	for url, want := range map[string]bool{
		"postgres://u:p@db.example.com/app":                          true,
		"postgres://u:p@db.example.com/app?sslmode=verify-full":      true,
		"postgres://u:p@db.example.com/app?sslmode=require":          false,
		"mysql://u:p@db.example.com/app?tls=skip-verify":             false,
		"mongodb://db.example.com/?tlsInsecure=true":                 false,
		"mongodb://db.example.com/?tlsAllowInvalidCertificates=true": false,
		"db.example.com:5432":                                        true,
	} {
		p, err := tlsPolicyFor(url)
		if err != nil || p.verify != want {
			t.Errorf("%s: verify=%v err=%v, want %v", url, p.verify, err, want)
		}
	}
	if _, err := tlsPolicyFor("postgres://h/db?sslrootcert=/no/such/file.pem"); err == nil {
		t.Error("a missing CA file was accepted")
	}
}

// A server whose certificate this machine does not trust is refused by
// default, and reached once its CA is named or the URL opts out.
func TestAnUntrustedDatabaseIsRefusedUnlessTold(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	dial := func(rawURL string) error {
		p, err := tlsPolicyFor(rawURL)
		if err != nil {
			return err
		}
		conn, err := dialUpstream(dbUpstream{Name: "db", Host: host, Port: port, TLS: true, VerifyTLS: p.verify, RootCAs: p.rootCAs})
		if err == nil {
			conn.Close()
		}
		return err
	}

	err := dial("postgres://u:p@" + host + "/app")
	if err == nil || !strings.Contains(err.Error(), "sslrootcert") {
		t.Fatalf("an untrusted certificate: %v", err)
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := dial("postgres://u:p@" + host + "/app?sslrootcert=" + caPath); err != nil {
		t.Fatalf("with the CA named: %v", err)
	}
	if err := dial("postgres://u:p@" + host + "/app?sslmode=require"); err != nil {
		t.Fatalf("with checking turned off: %v", err)
	}
}
