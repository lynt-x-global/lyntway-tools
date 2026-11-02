package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Reading a thing named on the command line and deciding what Lyntway can
// do with it.
//
// # Why the list of what works is short, and written down
//
// `lyntway connect <anything>` is the promise, and the honest version of
// it names the protocols that are actually proxied rather than implying
// every URL with a scheme. The database gateway speaks three wire
// protocols — cmd/lyntway-dbgateway has pgproxy.go, myproxy.go and
// mgproxy.go and nothing else — so a redis:// URL is refused here by
// name. Accepting it, starting a gateway that cannot speak it and letting
// the connection fail at the first query would be worse than saying no:
// the person would be debugging their database instead of reading our
// output.
//
// # Why the local port is decided here
//
// The gateway's listeners default to :15432, :13306 and :27018, and the
// rewritten connection string has to agree with them. Keeping both
// numbers in one table is the only way they cannot drift — they drifted
// once already in a draft, and a connection string pointing at a port
// nothing listens on looks exactly like the gateway being broken.

// connectKind is what sort of thing was named.
type connectKind string

const (
	kindDatabase connectKind = "database"
	kindHTTP     connectKind = "http"
	kindRefused  connectKind = "refused"
)

// connectable is one target named on the command line.
type connectable struct {
	// Raw is what was typed, kept so the report can quote it back
	// without the password in it — Redacted does that.
	Raw  string
	Kind connectKind

	// Driver is the dbgateway's name for the wire protocol:
	// "postgresql", "mysql" or "mongodb". Empty for anything else.
	Driver string

	// Scheme is the scheme as typed, which is not always the driver.
	// The gateway resolves mongodb+srv:// through SRV DNS and turns TLS
	// on whenever a scheme is present, so normalising this to the driver
	// would lose the SRV lookup and silently dial the wrong port.
	Scheme string

	// Host and Port are the upstream as given. Port is empty when the
	// URL omitted it, which the hosted Postgres providers all do.
	Host string
	Port string

	// LocalPort is where the gateway listens for this driver, so the
	// rewritten connection string and the gateway agree.
	LocalPort string

	// Why explains a refusal, in the terms of somebody who now has to
	// solve it another way.
	Why string
}

// dbDriver maps a URL scheme to the gateway's driver name, its default
// upstream port and the local port the gateway listens on.
//
// Ports are the dbgateway's own defaults (LYNTWAY_LISTEN_PG, _MY, _MG).
var dbDriver = map[string]struct {
	Driver      string
	DefaultPort string
	LocalPort   string
}{
	"postgres":    {"postgresql", "5432", "15432"},
	"postgresql":  {"postgresql", "5432", "15432"},
	"mysql":       {"mysql", "3306", "13306"},
	"mariadb":     {"mysql", "3306", "13306"},
	"mongodb":     {"mongodb", "27017", "27018"},
	"mongodb+srv": {"mongodb", "27017", "27018"},
}

// refusedScheme is a protocol somebody will reasonably try and that
// nothing here speaks. Named individually so the message can say what to
// do instead, rather than "unsupported".
var refusedScheme = map[string]string{
	"redis":  "the database gateway speaks PostgreSQL, MySQL and MongoDB. Redis is not proxied, so there is nothing here that would see those commands.",
	"rediss": "the database gateway speaks PostgreSQL, MySQL and MongoDB. Redis is not proxied, so there is nothing here that would see those commands.",
	"amqp":   "message brokers are not proxied. Only PostgreSQL, MySQL, MongoDB and HTTP APIs are.",
	"amqps":  "message brokers are not proxied. Only PostgreSQL, MySQL, MongoDB and HTTP APIs are.",
	"ssh":    "SSH is not proxied. `lyntway guard` governs a command you run, which is the nearest thing that exists.",
	"ftp":    "file transfer is not proxied. Only PostgreSQL, MySQL, MongoDB and HTTP APIs are.",
	"smtp":   "mail is a separate surface and is not reached this way.",
}

// readConnectable decides what a named target is.
//
// Returns kindRefused with Why set rather than an error, because a refusal
// is a report with advice in it and not a usage mistake.
func readConnectable(arg string) (connectable, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return connectable{}, fmt.Errorf("nothing to connect")
	}

	u, err := url.Parse(arg)
	if err != nil || u.Scheme == "" {
		return connectable{Raw: arg, Kind: kindRefused,
			Why: "this does not read as a URL. A database is named by its connection " +
				"string (postgres://…, mysql://…, mongodb://…) and an API by its base " +
				"address (https://…).",
		}, nil
	}

	scheme := strings.ToLower(u.Scheme)

	if why, ok := refusedScheme[scheme]; ok {
		return connectable{Raw: arg, Kind: kindRefused, Why: why}, nil
	}

	if d, ok := dbDriver[scheme]; ok {
		host, port := splitHostPort(u.Host)
		if host == "" {
			return connectable{Raw: arg, Kind: kindRefused,
				Why: "this connection string has no host in it.",
			}, nil
		}
		// The port is left empty rather than filled in when the URL
		// omitted it. Neon, Supabase's direct host and Mongo's +srv form
		// all do, and inventing 5432 for an +srv record — which resolves
		// to its own port — would produce an upstream that cannot be
		// reached.
		if port == "" && scheme != "mongodb+srv" {
			port = d.DefaultPort
		}
		return connectable{
			Raw: arg, Kind: kindDatabase, Driver: d.Driver, Scheme: scheme,
			Host: host, Port: port, LocalPort: d.LocalPort,
		}, nil
	}

	if scheme == "http" || scheme == "https" {
		host, port := splitHostPort(u.Host)
		if host == "" {
			return connectable{Raw: arg, Kind: kindRefused,
				Why: "this address has no host in it.",
			}, nil
		}
		return connectable{Raw: arg, Kind: kindHTTP, Host: host, Port: port}, nil
	}

	return connectable{Raw: arg, Kind: kindRefused,
		Why: fmt.Sprintf("%q is not a protocol anything here speaks. PostgreSQL, MySQL, "+
			"MongoDB and HTTP APIs are.", scheme),
	}, nil
}

// splitHostPort separates a URL's host from its port without the error
// return of net.SplitHostPort, which fails on a host that has no port —
// the common case for every hosted Postgres provider.
func splitHostPort(hostport string) (host, port string) {
	if hostport == "" {
		return "", ""
	}
	// An IPv6 literal is bracketed, so the last colon outside the
	// brackets is the separator.
	if strings.HasPrefix(hostport, "[") {
		if end := strings.LastIndex(hostport, "]"); end >= 0 {
			host = hostport[:end+1]
			if rest := hostport[end+1:]; strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
	}
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[:i], hostport[i+1:]
	}
	return hostport, ""
}

// Redacted is the target with any password removed, for printing.
//
// The whole point of this tool is that a credential does not get copied
// into places it was not already, and a terminal that scrolls into a
// screenshot is one of those places.
func (c connectable) Redacted() string {
	u, err := url.Parse(c.Raw)
	if err != nil || u.User == nil {
		return c.Raw
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return c.Raw
	}
	u.User = url.UserPassword(u.User.Username(), "…")
	// url.String() percent-encodes the elision; put it back so the line
	// reads as a connection string and not as an escape sequence.
	return strings.Replace(u.String(), "%E2%80%A6", "…", 1)
}

// Upstream is the name=url pair the gateway's LYNTWAY_UPSTREAMS takes.
//
// The password is deliberately not here. The gateway dials the upstream
// with the credentials the client presents, so the connection string it
// needs is the address only — which is also why this can be written into
// a config file that is not a secret.
func (c connectable) Upstream(name string) string {
	hostport := c.Host
	if c.Port != "" {
		hostport += ":" + c.Port
	}
	scheme := c.Scheme
	if scheme == "" {
		scheme = c.Driver
	}
	return name + "=" + scheme + "://" + hostport
}

// The registered upstreams file.
//
// `lyntway-dbgateway` takes its databases from LYNTWAY_UPSTREAMS or from
// the console's /v1/upstreams, and neither is reachable from `connect`:
// an environment variable set by one process does not survive into the
// next, and the console endpoint needs an account for something that
// works perfectly well without one. So a file, in the same directory as
// everything else this tool owns, and the gateway reads it when the
// variable is unset.
//
// Deliberately not a secret. Each line is name=scheme://host:port with no
// credential in it — the client presents those, and the gateway only
// needs to know where to dial. 0600 anyway, because the list of a
// company's internal database hostnames is not something to leave
// readable either.

const upstreamsFile = "upstreams"

func upstreamsPath() (string, error) {
	h := home()
	if h == "" {
		return "", fmt.Errorf("this machine has no home directory to write to")
	}
	return filepath.Join(h, ".lyntway", upstreamsFile), nil
}

// readUpstreamLines returns the registered upstreams, in file order.
//
// A missing file is no upstreams and not an error: the gateway has to
// start on a machine where `connect` has never run.
func readUpstreamLines(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// writeUpstream adds or replaces one upstream by name and returns the
// full list as it now stands.
//
// Replaces rather than appends on a repeated name, because connecting the
// same database twice is somebody correcting a typo, and two lines with
// one name would leave which of them wins up to map iteration order.
func writeUpstream(path, line string) ([]string, error) {
	name, _, ok := strings.Cut(line, "=")
	if !ok || name == "" {
		return nil, fmt.Errorf("an upstream has to read name=url, not %q", line)
	}
	existing, err := readUpstreamLines(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(existing)+1)
	for _, e := range existing {
		if n, _, _ := strings.Cut(e, "="); n != name {
			out = append(out, e)
		}
	}
	out = append(out, line)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	body := "# Databases `lyntway connect` registered. No credentials here:\n" +
		"# the client presents those and the gateway only dials the address.\n" +
		strings.Join(out, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return nil, err
	}
	return out, nil
}
