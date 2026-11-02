package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shapes the hosted providers actually hand out.
//
// Written from their own connection dialogs rather than from the RFC,
// because the RFC form is not what anybody pastes: Neon and Supabase's
// pooler omit the port, Mongo's +srv form has no port at all and resolves
// through SRV DNS, and the dbgateway turns TLS on from the presence of a
// scheme. A classifier that normalised those would dial the wrong port on
// the three most common managed databases in the world.
func TestReadConnectableOnRealProviderURLs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		in        string
		kind      connectKind
		driver    string
		host      string
		port      string
		localPort string
	}{
		{
			name: "neon, no port", kind: kindDatabase, driver: "postgresql",
			in:   "postgres://appuser:pw@ep-cool-shape-123456.us-east-2.aws.neon.tech/neondb?sslmode=require",
			host: "ep-cool-shape-123456.us-east-2.aws.neon.tech", port: "5432", localPort: "15432",
		},
		{
			name: "supabase pooler, explicit port", kind: kindDatabase, driver: "postgresql",
			in:   "postgresql://postgres.abcdefghij:pw@aws-0-us-east-1.pooler.supabase.com:6543/postgres",
			host: "aws-0-us-east-1.pooler.supabase.com", port: "6543", localPort: "15432",
		},
		{
			name: "planetscale mysql", kind: kindDatabase, driver: "mysql",
			in:   "mysql://abc123:pw@aws.connect.psdb.cloud/mydb",
			host: "aws.connect.psdb.cloud", port: "3306", localPort: "13306",
		},
		{
			// +srv must keep an empty port: the SRV record carries it,
			// and filling in 27017 sends the gateway to a port the
			// cluster does not answer on.
			name: "mongo atlas srv", kind: kindDatabase, driver: "mongodb",
			in:   "mongodb+srv://appuser:pw@cluster0.ab1cd.mongodb.net/app",
			host: "cluster0.ab1cd.mongodb.net", port: "", localPort: "27018",
		},
		{
			name: "mongo direct", kind: kindDatabase, driver: "mongodb",
			in:   "mongodb://appuser:pw@db.internal:27017/app",
			host: "db.internal", port: "27017", localPort: "27018",
		},
		{
			name: "an http api", kind: kindHTTP,
			in: "https://api.example.com/v1", host: "api.example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readConnectable(tc.in)
			if err != nil {
				t.Fatalf("readConnectable: %v", err)
			}
			if got.Kind != tc.kind {
				t.Errorf("kind = %q, want %q (why: %s)", got.Kind, tc.kind, got.Why)
			}
			if got.Driver != tc.driver {
				t.Errorf("driver = %q, want %q", got.Driver, tc.driver)
			}
			if got.Host != tc.host {
				t.Errorf("host = %q, want %q", got.Host, tc.host)
			}
			if got.Port != tc.port {
				t.Errorf("port = %q, want %q", got.Port, tc.port)
			}
			if got.LocalPort != tc.localPort {
				t.Errorf("local port = %q, want %q", got.LocalPort, tc.localPort)
			}
		})
	}
}

// What is refused has to be refused by name.
//
// "connect to anything" is the promise and three wire protocols are what
// is built. A redis:// URL accepted here would start a gateway that
// cannot speak it and fail at the first command, which puts somebody in
// their database's logs instead of ours.
func TestRefusedProtocolsSayWhatToDoInstead(t *testing.T) {
	for _, in := range []string{
		"redis://default:pw@gusc1-cool-123.upstash.io:6379",
		"rediss://default:pw@host:6380",
		"amqps://user:pw@broker.example.com",
		"ssh://user@host",
		"not a url at all",
		"gopher://host/1",
	} {
		got, err := readConnectable(in)
		if err != nil {
			t.Fatalf("readConnectable(%q): %v", in, err)
		}
		if got.Kind != kindRefused {
			t.Errorf("readConnectable(%q) kind = %q, want refused", in, got.Kind)
		}
		if got.Why == "" {
			t.Errorf("readConnectable(%q) refused with no reason, which is the one thing a refusal may not do", in)
		}
	}
}

// A password must not reach the terminal. Every other rule in this tool
// is about not copying a credential somewhere it was not already, and a
// scrollback that ends up in a screenshot is one of those places.
func TestRedactedKeepsThePasswordOut(t *testing.T) {
	const pw = "Kp7mQx2vLr9t"
	for _, in := range []string{
		"postgres://appuser:" + pw + "@ep-cool.neon.tech/neondb",
		"mongodb+srv://appuser:" + pw + "@cluster0.ab1cd.mongodb.net/app",
		"mysql://abc:" + pw + "@aws.connect.psdb.cloud/mydb",
	} {
		c, err := readConnectable(in)
		if err != nil {
			t.Fatalf("readConnectable: %v", err)
		}
		red := c.Redacted()
		if strings.Contains(red, pw) {
			t.Errorf("Redacted() leaked the password:\n  %s", red)
		}
		if !strings.Contains(red, c.Host) {
			t.Errorf("Redacted() dropped the host, so the line names nothing:\n  %s", red)
		}
	}
}

// The upstream the gateway is given carries no credential, and keeps the
// scheme as typed so mongodb+srv still resolves through SRV.
func TestUpstreamCarriesNoCredentialAndKeepsTheScheme(t *testing.T) {
	c, err := readConnectable("mongodb+srv://appuser:Kp7mQx2vLr9t@cluster0.ab1cd.mongodb.net/app")
	if err != nil {
		t.Fatalf("readConnectable: %v", err)
	}
	got := c.Upstream("atlas")
	if strings.Contains(got, "Kp7mQx2vLr9t") || strings.Contains(got, "appuser") {
		t.Errorf("Upstream() carried a credential: %s", got)
	}
	if want := "atlas=mongodb+srv://cluster0.ab1cd.mongodb.net"; got != want {
		t.Errorf("Upstream() = %q, want %q", got, want)
	}
}

// The CLI writes the upstreams file and the gateway reads it, and they
// are two binaries in two directories that cannot import each other.
//
// So the path is written twice, and this reads the gateway's source to
// check the two agree. Same shape as extension/embed_test.go, and for the
// same reason: a rename that updated one side would leave the gateway
// reading a file nobody writes, with no error anywhere — `connect` would
// report success and no database would ever be proxied.
func TestGatewayReadsTheFileTheCLIWrites(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "lyntway-dbgateway", "main.go"))
	if err != nil {
		t.Fatalf("reading the gateway's source: %v", err)
	}
	src := string(body)

	// The CLI's own path, decomposed the way the gateway builds it.
	ours, err := upstreamsPath()
	if err != nil {
		t.Skipf("no home directory on this machine: %v", err)
	}
	dir := filepath.Base(filepath.Dir(ours)) // ".lyntway"
	base := filepath.Base(ours)              // "upstreams"

	for _, want := range []string{
		`filepath.Join(h, "` + dir + `", "` + base + `")`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the gateway does not build the path the CLI writes.\n"+
				"  CLI writes:   %s\n"+
				"  expected the gateway's source to contain: %s\n"+
				"If the path moved, both sides have to move.", ours, want)
		}
	}

	// And it has to actually read it, not merely name it.
	if !strings.Contains(src, "registeredUpstreams()") {
		t.Error("the gateway names the file but never calls registeredUpstreams()")
	}
}

// A repeated name replaces rather than appends. Connecting the same
// database twice is somebody fixing a typo, and two lines sharing a name
// would leave which one wins to map iteration order.
func TestWriteUpstreamReplacesByName(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lyntway", "upstreams")

	if _, err := writeUpstream(path, "db=postgres://old.example.com:5432"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	lines, err := writeUpstream(path, "db=postgres://new.example.com:5432")
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("got %d upstreams, want 1: %v", len(lines), lines)
	}
	if lines[0] != "db=postgres://new.example.com:5432" {
		t.Errorf("got %q, want the second write to have replaced the first", lines[0])
	}

	// A second name is additive, not a replacement.
	lines, err = writeUpstream(path, "other=mysql://m.example.com:3306")
	if err != nil {
		t.Fatalf("third write: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("got %d upstreams, want 2: %v", len(lines), lines)
	}
}

// No credential may reach that file. It is not a secret by design, which
// is only true while nothing writes one into it.
func TestUpstreamsFileNeverCarriesACredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lyntway", "upstreams")
	const pw = "Kp7mQx2vLr9t"

	c, err := readConnectable("postgres://appuser:" + pw + "@ep-cool.neon.tech:5432/neondb")
	if err != nil {
		t.Fatalf("readConnectable: %v", err)
	}
	if _, err := writeUpstream(path, c.Upstream(upstreamName(c))); err != nil {
		t.Fatalf("writeUpstream: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading it back: %v", err)
	}
	if strings.Contains(string(body), pw) {
		t.Errorf("the upstreams file carries a password:\n%s", body)
	}
	if strings.Contains(string(body), "appuser") {
		t.Errorf("the upstreams file carries a username:\n%s", body)
	}
}
