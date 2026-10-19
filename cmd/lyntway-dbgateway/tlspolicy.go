package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
)

// Checking who we are talking to.
//
// The gateway used to encrypt every upstream connection without checking
// the certificate, on the reasoning that sslmode=require is what most
// database clients default to. That reasoning is about clients; this is a
// gateway holding the database credentials of whoever points it at a
// database, and an unverified connection hands those credentials to
// anybody able to answer on the address. So certificates are verified
// unless the connection URL says otherwise, the way the database's own
// clients let it:
//
//   - PostgreSQL: sslmode=require (or prefer/allow) encrypts without
//     checking; verify-ca and verify-full check. sslrootcert names a CA.
//   - MySQL: tls=skip-verify encrypts without checking.
//   - MongoDB: tlsInsecure=true or tlsAllowInvalidCertificates=true.
//     tlsCAFile names a CA.
//
// A provider whose certificates chain to a private CA (RDS, some Supabase
// endpoints) needs its CA named, or the URL marked explicitly; the error
// says which.

type tlsPolicy struct {
	verify  bool
	rootCAs *x509.CertPool
	caFile  string
}

func tlsPolicyFor(rawURL string) (tlsPolicy, error) {
	p := tlsPolicy{verify: true}
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return p, nil
	}
	q := u.Query()
	switch strings.ToLower(q.Get("sslmode")) {
	case "require", "prefer", "allow":
		p.verify = false
	}
	if strings.EqualFold(q.Get("tls"), "skip-verify") {
		p.verify = false
	}
	for _, k := range []string{"tlsInsecure", "tlsAllowInvalidCertificates"} {
		if strings.EqualFold(q.Get(k), "true") {
			p.verify = false
		}
	}
	for _, k := range []string{"sslrootcert", "tlsCAFile"} {
		if path := q.Get(k); path != "" {
			pem, err := os.ReadFile(path)
			if err != nil {
				return p, fmt.Errorf("reading the CA file %s: %w", path, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return p, fmt.Errorf("the CA file %s holds no PEM certificates", path)
			}
			p.rootCAs, p.caFile = pool, path
		}
	}
	return p, nil
}

// tlsConfigFor is the client configuration for one upstream.
func tlsConfigFor(u dbUpstream) *tls.Config {
	return &tls.Config{
		ServerName:         u.Host,
		RootCAs:            u.RootCAs,
		InsecureSkipVerify: !u.VerifyTLS, //nolint:gosec // only where the upstream's URL asked for it; logged at load.
		MinVersion:         tls.VersionTLS12,
	}
}

// explainTLSError turns a verification failure into what to do about it.
func explainTLSError(u dbUpstream, err error) error {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	switch {
	case errors.As(err, &unknown):
		return fmt.Errorf("%s's certificate is signed by an authority this machine does not trust: "+
			"add its CA to the URL (sslrootcert=/path/ca.pem, or tlsCAFile= for MongoDB), or mark the URL "+
			"sslmode=require to encrypt without checking who answers: %w", u.Name, err)
	case errors.As(err, &hostname):
		return fmt.Errorf("%s's certificate is not for %s: %w", u.Name, u.Host, err)
	}
	return err
}

// warnUnverified says, once per load, which upstreams are not checked.
func warnUnverified(u dbUpstream) {
	if u.TLS && !u.VerifyTLS {
		log.Printf("lyntway-dbgateway: WARNING %s: the connection is encrypted but the server's certificate is not checked, because its URL asks for that; anyone who can answer on %s receives the database credentials", u.Name, u.Host)
	}
}
