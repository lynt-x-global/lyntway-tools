// Command lyntway-dbgateway governs database wire-protocol traffic.
//
// # Why a separate binary
//
// Databases speak binary wire protocols over TCP, not HTTP. The gateway
// cannot proxy them as HTTP reverse-proxy traffic, and the MCP shim
// cannot see them because they are not JSON-RPC over stdio. A dedicated
// listener that understands PostgreSQL, MySQL and MongoDB framing is the
// only way to issue receipts for database traffic.
//
// # What it does
//
// It fetches registered databases from the Lyntway console, listens on
// TCP ports for each protocol, and proxies connections to the real
// database. Every query passing through is governed: sensitive values
// are detected, receipts are issued, and finding summaries are reported
// to the account.
//
// # Content never leaves this process
//
// Detection happens here. Only classes and counts are reported to the
// account, via /v1/attest, exactly as the MCP shim reports. The queries,
// the results, and any values found in them stay on this machine. There
// is no switch that changes this.
//
// # What the receipts say
//
// Every message is forwarded as it arrived. The gateway does not rewrite
// wire-protocol binary, so its receipts never claim a substitution: a
// finding is recorded as log_only, and a policy that blocks still blocks.
// Receipts are signed with a key kept in ~/.lyntway and published beside
// the receipt file as <stem>-keys.json, in the form lyntway-verify
// -keys reads; the chain position is kept beside it so a restart continues
// the chain rather than starting another at seq 0.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return 0
	}
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "-help") {
		fmt.Fprint(os.Stdout, usage)
		return 0
	}

	origin := os.Getenv("LYNTWAY_URL")
	key := os.Getenv("LYNTWAY_KEY")
	if origin != "" {
		origin = strings.TrimRight(origin, "/")
	}

	listenPG := envOr("LYNTWAY_LISTEN_PG", ":15432")
	listenMY := envOr("LYNTWAY_LISTEN_MY", ":13306")
	listenMG := envOr("LYNTWAY_LISTEN_MG", ":27018")
	receiptsPath := envOr("LYNTWAY_RECEIPTS", "./receipts.jsonl")

	keyPath, err := signingKeyPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-dbgateway: %v\n", err)
		return 2
	}
	g, err := newGovernor(governorConfig{
		receipts: receiptsPath,
		keyPath:  keyPath,
		origin:   origin,
		key:      key,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "lyntway-dbgateway: %v\n", err)
		return 2
	}
	defer g.close()

	umap := &UpstreamMap{entries: make(map[string]dbUpstream)}

	envUpstreams := os.Getenv("LYNTWAY_UPSTREAMS")

	// Fetch from the console API first — this is the primary source.
	if origin != "" && key != "" {
		if err := refreshUpstreams(origin, key, umap); err != nil {
			log.Printf("lyntway-dbgateway: console fetch: %v (using env upstreams only)", err)
		}
	}

	// LYNTWAY_UPSTREAMS overrides console entries for the same name.
	// The env var carries the full connection string (with database
	// name, credentials), which the console URL does not store.
	// Format: name=url,name=url,...
	// Example: neon=postgresql://user:pass@host:5432/db,prod=mysql://host:3306/db
	if envUpstreams != "" {
		parseEnvUpstreams(envUpstreams, umap)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var listeners []net.Listener
	var wg sync.WaitGroup

	// Start one listener per protocol.
	for _, spec := range []struct {
		addr  string
		proxy ProtocolProxy
	}{
		{listenPG, &pgProxy{}},
		{listenMY, &myProxy{}},
		{listenMG, &mgProxy{}},
	} {
		ln, err := net.Listen("tcp", spec.addr)
		if err != nil {
			log.Printf("lyntway-dbgateway: cannot listen on %s for %s: %v", spec.addr, spec.proxy.Name(), err)
			continue
		}
		listeners = append(listeners, ln)
		log.Printf("lyntway-dbgateway: %s listening on %s", spec.proxy.Name(), spec.addr)

		wg.Add(1)
		go func(ln net.Listener, p ProtocolProxy) {
			defer wg.Done()
			acceptLoop(ln, p, umap, g)
		}(ln, spec.proxy)
	}

	if len(listeners) == 0 {
		fmt.Fprintln(os.Stderr, "lyntway-dbgateway: no listeners started")
		return 2
	}

	// Refresh upstreams periodically when console credentials are set.
	if origin != "" && key != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := refreshUpstreams(origin, key, umap); err != nil {
						log.Printf("lyntway-dbgateway: upstream refresh: %v", err)
					}
					// Re-apply env upstreams after each console refresh
					// so they are not overwritten.
					if envUpstreams != "" {
						parseEnvUpstreams(envUpstreams, umap)
					}
				}
			}
		}()
	}

	<-ctx.Done()
	log.Println("lyntway-dbgateway: shutting down")
	for _, ln := range listeners {
		ln.Close()
	}
	wg.Wait()
	return 0
}

// dbUpstream is one registered database, as fetched from the console.
type dbUpstream struct {
	Name     string
	Host     string // hostname for TLS SNI
	DialHost string // IP or hostname to actually connect to (bypasses hosts file)
	Port     string
	Protocol string // "postgresql", "mysql", "mongodb"
	TLS      bool   // connect to upstream with TLS
	Database string // database name from the connection URL (empty if not provided)

	// VerifyTLS checks the server's certificate; RootCAs replaces the
	// system roots when the URL names a CA. See tlspolicy.go.
	VerifyTLS bool
	RootCAs   *x509.CertPool
}

// UpstreamMap is a thread-safe map of database name to upstream info,
// refreshed periodically from the console.
type UpstreamMap struct {
	mu      sync.RWMutex
	entries map[string]dbUpstream
}

func (m *UpstreamMap) get(name string) (dbUpstream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.entries[name]
	return u, ok
}

// allForProtocol returns all upstreams matching a protocol.
func (m *UpstreamMap) allForProtocol(proto string) []dbUpstream {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []dbUpstream
	for _, u := range m.entries {
		if u.Protocol == proto {
			out = append(out, u)
		}
	}
	return out
}

func (m *UpstreamMap) replace(entries map[string]dbUpstream) {
	m.mu.Lock()
	m.entries = entries
	m.mu.Unlock()
}

// refreshUpstreams fetches registered databases via the API-key endpoint.
func refreshUpstreams(origin, key string, umap *UpstreamMap) error {
	req, err := http.NewRequest(http.MethodGet, origin+"/v1/upstreams", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("upstreams endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var upstreams []struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Surface string `json:"surface"`
	}
	if err := json.Unmarshal(body, &upstreams); err != nil {
		return fmt.Errorf("parsing upstreams: %w", err)
	}

	entries := make(map[string]dbUpstream)
	for _, u := range upstreams {
		if u.Surface != "database" {
			continue
		}
		host, port, proto := parseDBURL(u.URL, u.Name)
		if host == "" {
			continue
		}
		// mongodb+srv:// uses SRV DNS to discover the actual server.
		if proto == "mongodb" {
			if srvHost, srvPort, err := resolveSRV(host); err == nil {
				log.Printf("lyntway-dbgateway: SRV %s → %s:%s", host, srvHost, srvPort)
				host = srvHost
				port = srvPort
			}
		}
		useTLS := strings.Contains(u.URL, "://") ||
			containsAny(strings.ToLower(host), "neon.tech", "supabase", "rds.amazonaws", "azure", "cloudsql",
				"mongo.ondigitalocean", "docdb.amazonaws")
		dialHost := host
		if useTLS {
			if ip := resolveBypassingHosts(host); ip != host {
				dialHost = ip
			}
		}
		policy, err := tlsPolicyFor(u.URL)
		if err != nil {
			log.Printf("lyntway-dbgateway: skipping %s: %v", u.Name, err)
			continue
		}
		entries[u.Name] = dbUpstream{
			Name:      u.Name,
			Host:      host,
			DialHost:  dialHost,
			Port:      port,
			Protocol:  proto,
			TLS:       useTLS,
			Database:  parseDBName(u.URL),
			VerifyTLS: policy.verify,
			RootCAs:   policy.rootCAs,
		}
		warnUnverified(entries[u.Name])
	}
	umap.replace(entries)
	log.Printf("lyntway-dbgateway: %d database upstream(s) loaded", len(entries))
	return nil
}

// parseDBURL extracts host, port and protocol from a database URL or
// hostname. Protocol is inferred from the URL scheme or from naming
// heuristics when no scheme is present.
func parseDBURL(raw, name string) (host, port, proto string) {
	lower := strings.ToLower(raw)

	// Explicit scheme.
	switch {
	case strings.HasPrefix(lower, "postgresql://") || strings.HasPrefix(lower, "postgres://"):
		h, p := parseHostPort(raw[strings.Index(raw, "://")+3:], "5432")
		return h, p, "postgresql"
	case strings.HasPrefix(lower, "mysql://"):
		h, p := parseHostPort(raw[len("mysql://"):], "3306")
		return h, p, "mysql"
	case strings.HasPrefix(lower, "mongodb://") || strings.HasPrefix(lower, "mongodb+srv://"):
		h, p := parseHostPort(raw[strings.Index(raw, "://")+3:], "27017")
		return h, p, "mongodb"
	}

	// Strip https:// or http:// — the connect page registers databases
	// with an https:// prefix when no database-specific scheme is given.
	stripped := raw
	if strings.HasPrefix(lower, "https://") {
		stripped = raw[len("https://"):]
	} else if strings.HasPrefix(lower, "http://") {
		stripped = raw[len("http://"):]
	}

	// Guess protocol from the hostname or the registered name.
	h, p := parseHostPort(stripped, "")
	lowerName := strings.ToLower(name)
	lowerHost := strings.ToLower(h)

	switch {
	case containsAny(lowerHost, "mongo", "docdb", "cosmosdb") ||
		containsAny(lowerName, "mongo", "docdb", "cosmosdb"):
		if p == "" {
			p = "27017"
		}
		return h, p, "mongodb"
	case containsAny(lowerHost, "mysql", "maria", "tidb", "planetscale", "psdb", "aiven") ||
		containsAny(lowerName, "mysql", "maria"):
		if p == "" {
			p = "3306"
		}
		return h, p, "mysql"
	default:
		// Port is a reliable signal when hostname is ambiguous — an RDS
		// instance on port 3306 is MySQL regardless of hostname.
		if p == "3306" {
			return h, p, "mysql"
		}
		if p == "27017" {
			return h, p, "mongodb"
		}
		// PostgreSQL is the safe default — it is what most cloud databases
		// are, and a wrong guess will fail loudly at the protocol level
		// rather than silently.
		if p == "" {
			p = "5432"
		}
		return h, p, "postgresql"
	}
}

// parseHostPort extracts host and port from the authority part of a URL,
// stripping credentials and path.
func parseHostPort(authority, defaultPort string) (string, string) {
	// Strip credentials.
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	// Strip path and query.
	for _, sep := range []string{"/", "?"} {
		if i := strings.Index(authority, sep); i >= 0 {
			authority = authority[:i]
		}
	}
	return parseHostPort2(authority, defaultPort)
}

// parseHostPort2 splits host:port, applying a default.
func parseHostPort2(addr, defaultPort string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port — the whole thing is the host.
		return addr, defaultPort
	}
	if port == "" {
		port = defaultPort
	}
	return host, port
}

// parseDBName extracts the database name from a connection URL path.
//
//	postgresql://user:pass@host:5432/mydb     → "mydb"
//	https://host:5432/mydb                    → "mydb"
//	https://host:5432                         → ""
//	host:5432                                 → ""
func parseDBName(rawURL string) string {
	// Find the authority section.
	var rest string
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rest = rawURL[i+3:]
	} else {
		// Bare host:port — no path.
		return ""
	}

	// Strip credentials.
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}

	// Find the path after host:port.
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return ""
	}
	dbPart := rest[slash+1:]

	// Strip query parameters.
	if q := strings.IndexByte(dbPart, '?'); q >= 0 {
		dbPart = dbPart[:q]
	}
	return dbPart
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// parseEnvUpstreams reads LYNTWAY_UPSTREAMS and adds entries to the map.
// Format: name=url,name=url,...
// Example: neon=postgresql://user:pass@host:5432/db
// parseEnvUpstreams reads LYNTWAY_UPSTREAMS and adds entries to the map.
// Format: name=url,name=url,...
// Example: neon=postgresql://user:pass@host:5432/db
//
// Cloud databases require TLS, so any URL with an explicit scheme gets
// TLS turned on. The proxy connects with TLS and sends the hostname as
// SNI, which is how Neon, Supabase, and others route connections.
func parseEnvUpstreams(env string, umap *UpstreamMap) {
	for _, pair := range strings.Split(env, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, rawURL, ok := strings.Cut(pair, "=")
		if !ok || name == "" || rawURL == "" {
			log.Printf("lyntway-dbgateway: ignoring malformed upstream %q", pair)
			continue
		}
		host, port, proto := parseDBURL(rawURL, name)
		if host == "" {
			log.Printf("lyntway-dbgateway: cannot parse upstream URL for %q", name)
			continue
		}
		// mongodb+srv:// uses SRV DNS to discover the actual server.
		if proto == "mongodb" && strings.HasPrefix(strings.ToLower(rawURL), "mongodb+srv://") {
			if srvHost, srvPort, err := resolveSRV(host); err == nil {
				log.Printf("lyntway-dbgateway: SRV %s → %s:%s", host, srvHost, srvPort)
				host = srvHost
				port = srvPort
			} else {
				log.Printf("lyntway-dbgateway: SRV lookup for %s failed: %v (using direct)", host, err)
			}
		}
		// Cloud databases require TLS. Enable it when a scheme is present
		// (explicit URL) or when the host looks like a cloud provider.
		useTLS := strings.Contains(rawURL, "://") ||
			containsAny(strings.ToLower(host), "neon.tech", "supabase", "rds.amazonaws", "azure", "cloudsql",
				"mongo.ondigitalocean", "docdb.amazonaws")

		// Resolve the real IP now, because the hosts file may redirect
		// database hostnames to a local address (the Lyntway CLI does
		// this for CONNECT interception).
		dialHost := host
		if useTLS {
			if ip := resolveBypassingHosts(host); ip != host {
				dialHost = ip
				log.Printf("lyntway-dbgateway: resolved %s → %s (bypassing hosts file)", host, ip)
			}
		}

		policy, err := tlsPolicyFor(rawURL)
		if err != nil {
			log.Printf("lyntway-dbgateway: skipping %s: %v", name, err)
			continue
		}
		entry := dbUpstream{Name: name, Host: host, DialHost: dialHost, Port: port, Protocol: proto, TLS: useTLS,
			Database: parseDBName(rawURL), VerifyTLS: policy.verify, RootCAs: policy.rootCAs}
		warnUnverified(entry)
		umap.mu.Lock()
		umap.entries[name] = entry
		umap.mu.Unlock()
		log.Printf("lyntway-dbgateway: upstream %s → %s:%s (%s, tls=%v)", name, host, port, proto, useTLS)
	}
}

// signingKeyPath is where the seed lives: the same directory the CLI keeps
// its settings in, so one place holds everything this machine remembers.
func signingKeyPath() (string, error) {
	if p := os.Getenv("LYNTWAY_SIGNING_KEY"); p != "" {
		return p, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("this machine has no home directory to keep a signing key in: %w", err)
	}
	return filepath.Join(h, ".lyntway", "dbgateway-signing.key"), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

const usage = `lyntway-dbgateway — govern database wire-protocol traffic

Usage:
  LYNTWAY_UPSTREAMS="neon=postgresql://host:5432/db" lyntway-dbgateway

Listens on TCP ports for PostgreSQL, MySQL and MongoDB wire protocols,
proxies connections to real databases, and issues receipts for every query.

Environment:
  LYNTWAY_UPSTREAMS   Database upstreams (name=url,name=url)
  LYNTWAY_URL         Lyntway server origin (optional, for /v1/attest)
  LYNTWAY_KEY         API key (optional, for /v1/attest)
  LYNTWAY_LISTEN_PG   PostgreSQL listener (default :15432)
  LYNTWAY_LISTEN_MY   MySQL listener (default :13306)
  LYNTWAY_LISTEN_MG   MongoDB listener (default :27018)
  LYNTWAY_RECEIPTS    Receipt file (default ./receipts.jsonl); the public key
                      is published beside it as <stem>-keys.json (stem: the receipts file without its extension)
  LYNTWAY_SIGNING_KEY Signing seed (default ~/.lyntway/dbgateway-signing.key)

Flags:
  -version    print the version and exit
  -h, -help   show this message
`
