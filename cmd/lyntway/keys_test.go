package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// capture routes a command's output and prompts through buffers, and
// returns what it printed. Every migration test ends by asserting that
// the key values are not in that text: last4 is what a person sees.
func capture(t *testing.T, in string, run func()) string {
	t.Helper()
	var out bytes.Buffer
	prevOut, prevIn := stdout, stdin
	stdout, stdin = &out, strings.NewReader(in)
	input = nil
	defer func() { stdout, stdin = prevOut, prevIn; input = nil }()
	run()
	return out.String()
}

func TestEnvLinesAreReadInTheFormsFoundInPractice(t *testing.T) {
	cases := []struct {
		line       string
		key, value string
		export     bool
	}{
		{`OPENAI_API_KEY=sk-abc123`, "OPENAI_API_KEY", "sk-abc123", false},
		{`export OPENAI_API_KEY=sk-abc123`, "OPENAI_API_KEY", "sk-abc123", true},
		{`OPENAI_API_KEY="sk-abc123"`, "OPENAI_API_KEY", "sk-abc123", false},
		{`OPENAI_API_KEY='sk-abc123'`, "OPENAI_API_KEY", "sk-abc123", false},
		{`OPENAI_API_KEY=sk-abc123 # production`, "OPENAI_API_KEY", "sk-abc123", false},
		{`OPENAI_API_KEY="sk-abc#123"`, "OPENAI_API_KEY", "sk-abc#123", false},
		{`  OPENAI_API_KEY = sk-abc123  `, "OPENAI_API_KEY", "sk-abc123", false},
		{`# OPENAI_API_KEY=sk-abc123`, "", "", false},
		{``, "", "", false},
		{`not an assignment`, "", "", false},
		{`1BAD=value`, "", "", false},
	}
	for _, c := range cases {
		k, v, e := parseEnvLine(c.line)
		if k != c.key || v != c.value || e != c.export {
			t.Errorf("%q: got (%q, %q, %v), want (%q, %q, %v)", c.line, k, v, e, c.key, c.value, c.export)
		}
	}
}

func TestProviderKeysAreRecognisedByNameAndByShape(t *testing.T) {
	extra := []string{"lawmatics"}
	cases := []struct {
		key, value string
		upstream   string
		skip       bool
		found      bool
	}{
		{"OPENAI_API_KEY", "sk-proj-abcdefgh1234", "openai", false, true},
		{"ANTHROPIC_API_KEY", "sk-ant-api03-abcdefgh", "anthropic", false, true},
		{"GOOGLE_API_KEY", "AIzaSyAbcdefghijk", "gemini", false, true},
		{"XAI_API_KEY", "xai-abcdefghijk", "xai", false, true},
		{"MISTRAL_API_KEY", "abcdefghijklmnop", "mistral", false, true},
		{"COMPOSIO_API_KEY", "abcdefghijklmnop", "composio", false, true},
		{"ARCADE_API_KEY", "abcdefghijklmnop", "arcade", false, true},
		// By value alone: a key under a name this does not know.
		{"MY_LLM_KEY", "sk-ant-api03-abcdefgh", "anthropic", false, true},
		{"LLM_KEY", "sk-proj-abcdefgh1234", "openai", false, true},
		// By an upstream the server lists.
		{"LAWMATICS_API_KEY", "lm_abcdefghijk", "lawmatics", false, true},
		// Not ours to touch.
		{"DATABASE_URL", "postgres://x:y@z/db", "", false, false},
		{"STRIPE_API_KEY", "sk_live_abcdefgh", "", false, false},
		// Recognised, and left alone with a reason.
		{"OPENAI_API_KEY", "sk-ant-api03-abcdefgh", "", true, true},
		{"OPENAI_API_KEY", "your-key-here", "", true, true},
		{"OPENAI_API_KEY", "<paste here>", "", true, true},
		{"OPENAI_API_KEY", "lyk_mine~sk-abcdefgh", "", true, true},
		{"OPENAI_API_KEY", "lyk_mine", "", true, true},
		{"OPENAI_API_KEY", "", "", false, false},
	}
	for _, c := range cases {
		up, skip, ok := classify(c.key, c.value, extra, "lyk_mine")
		if ok != c.found || up != c.upstream || (skip != "") != c.skip {
			t.Errorf("%s=%s: got (%q, skip=%q, %v), want (%q, skip=%v, %v)", c.key, c.value, up, skip, ok, c.upstream, c.skip, c.found)
		}
	}
}

// fakeServer is enough of the console API for a migration: it lists
// upstreams, lists stored keys, and remembers what was posted.
type fakeServer struct {
	mu       sync.Mutex
	stored   []map[string]string
	existing []map[string]string
	unauth   bool

	// logStatus is what POST /v1/log answers; zero means the endpoint is
	// not there, which is what an older deployment looks like.
	logStatus int
	logged    []byte
}

func (f *fakeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/upstreams", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "lawmatics", "url": "https://api.lawmatics.com"}})
	})
	mux.HandleFunc("GET /v1/keys/providers", func(w http.ResponseWriter, r *http.Request) {
		if f.unauth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		keys := f.existing
		if keys == nil {
			keys = []map[string]string{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"available": true, "keys": keys})
	})
	mux.HandleFunc("POST /v1/log", func(w http.ResponseWriter, r *http.Request) {
		if f.logStatus == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		// The real endpoint's checks, so the seam is tested: it refused
		// the first build's surface while this fake took anything.
		var req struct {
			Tool   string `json:"tool"`
			Action struct {
				Surface string `json:"surface"`
			} `json:"action"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Tool == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"missing_tool","message":"tool is required"}`)
			return
		}
		switch req.Action.Surface {
		case "model", "mcp", "database", "http", "primitive":
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_report","message":"receipt: invalid: action.surface: must be one of: model, mcp, database, primitive"}`)
			return
		}
		f.mu.Lock()
		f.logged = body
		f.mu.Unlock()
		w.WriteHeader(f.logStatus)
		_, _ = io.WriteString(w, `{"receipt":{"id":"rcpt_migrate01","issued_at":"2026-09-07T10:00:00Z"},"evidence":"attested","verify_url":"https://x.test/verify"}`)
	})
	mux.HandleFunc("POST /v1/keys/providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer lyk_mine" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.stored = append(f.stored, body)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"stored": map[string]string{"upstream": body["upstream"]}})
	})
	return mux
}

func TestMigrateStoresRewritesAndUndoRestoresByteForByte(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()

	fake := &fakeServer{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := config{Origin: srv.URL, Key: "lyk_mine"}

	original := strings.Join([]string{
		"# project settings",
		"DATABASE_URL=postgres://u:p@localhost/app",
		`export OPENAI_API_KEY="sk-proj-openai0000ABCD"`,
		"ANTHROPIC_API_KEY=sk-ant-api03-anthropicWXYZ # prod",
		"LAWMATICS_API_KEY=lm_lawmatics1234",
		"OPENAI_BASE_URL=https://api.openai.com/v1",
		"",
	}, "\n")
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	gitignore := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(gitignore, []byte("node_modules\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := capture(t, "", func() {
		if err := runMigrate(dir, c, migrateOptions{Yes: true}); err != nil {
			t.Fatal(err)
		}
	})

	// The one rule every line of output is held to.
	for _, secret := range []string{"sk-proj-openai0000ABCD", "sk-ant-api03-anthropicWXYZ", "lm_lawmatics1234"} {
		if strings.Contains(out, secret) {
			t.Fatalf("a key value was printed:\n%s", out)
		}
	}
	for _, last := range []string{"…ABCD", "…WXYZ", "…1234"} {
		if !strings.Contains(out, last) {
			t.Errorf("the plan does not show %s:\n%s", last, out)
		}
	}

	// Every key went to the server, with the note that says where from.
	if len(fake.stored) != 3 {
		t.Fatalf("stored %d keys, want 3", len(fake.stored))
	}
	byUpstream := map[string]map[string]string{}
	for _, s := range fake.stored {
		byUpstream[s["upstream"]] = s
	}
	if byUpstream["openai"]["key"] != "sk-proj-openai0000ABCD" {
		t.Errorf("openai key sent as %q", byUpstream["openai"]["key"])
	}
	if byUpstream["anthropic"]["key"] != "sk-ant-api03-anthropicWXYZ" {
		t.Errorf("anthropic key sent as %q", byUpstream["anthropic"]["key"])
	}
	if byUpstream["lawmatics"]["key"] != "lm_lawmatics1234" {
		t.Errorf("lawmatics key sent as %q", byUpstream["lawmatics"]["key"])
	}
	if !strings.HasPrefix(byUpstream["openai"]["note"], "migrated from .env on ") {
		t.Errorf("note = %q", byUpstream["openai"]["note"])
	}

	// The file: keys replaced in place, base URLs in the block, the
	// original value nowhere in it.
	after, _ := os.ReadFile(envPath)
	text := string(after)
	for _, secret := range []string{"sk-proj-openai0000ABCD", "sk-ant-api03-anthropicWXYZ", "lm_lawmatics1234"} {
		if strings.Contains(text, secret) {
			t.Fatalf("the rewritten file still holds a key:\n%s", text)
		}
	}
	for _, want := range []string{
		`export OPENAI_API_KEY=lyk_mine`,
		"ANTHROPIC_API_KEY=\n",
		"ANTHROPIC_AUTH_TOKEN=lyk_mine",
		"ANTHROPIC_BASE_URL=" + srv.URL + "/gw/anthropic",
		"LAWMATICS_API_KEY=lyk_mine",
		"LAWMATICS_BASE_URL=" + srv.URL + "/gw/lawmatics",
		"DATABASE_URL=postgres://u:p@localhost/app",
		"OPENAI_BASE_URL=https://api.openai.com/v1",
		markerStart, markerEnd,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rewritten file lacks %q:\n%s", want, text)
		}
	}
	// The person's own OPENAI_BASE_URL was kept, and not defined twice.
	if strings.Count(text, "OPENAI_BASE_URL=") != 1 {
		t.Errorf("OPENAI_BASE_URL defined %d times:\n%s", strings.Count(text, "OPENAI_BASE_URL="), text)
	}

	backups, _ := filepath.Glob(envPath + ".lyntway-backup-*")
	if len(backups) != 1 {
		t.Fatalf("found %d backups, want 1", len(backups))
	}
	if b, _ := os.ReadFile(backups[0]); string(b) != original {
		t.Error("the backup is not the original file")
	}
	if g, _ := os.ReadFile(gitignore); !strings.Contains(string(g), gitignoreBackupLine) {
		t.Errorf(".gitignore does not ignore the backups:\n%s", g)
	}
	if !strings.Contains(out, ".gitignore now ignores") {
		t.Errorf("the .gitignore change was not said:\n%s", out)
	}

	// Undo puts the file back exactly, and takes its line out of .gitignore.
	n, err := undoRecorded()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("undo restored %d files, want 1", n)
	}
	restored, _ := os.ReadFile(envPath)
	if string(restored) != original {
		t.Errorf("undo did not restore the file byte for byte.\n got: %q\nwant: %q", restored, original)
	}
	if g, _ := os.ReadFile(gitignore); string(g) != "node_modules\n" {
		t.Errorf(".gitignore after undo: %q", g)
	}
	// A second undo has nothing left to do.
	if n, _ := undoRecorded(); n != 0 {
		t.Errorf("second undo restored %d files", n)
	}
}

func TestMigrateRunningTwiceChangesNothingTheSecondTime(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	fake := &fakeServer{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := config{Origin: srv.URL, Key: "lyk_mine"}

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	capture(t, "", func() {
		if err := runMigrate(dir, c, migrateOptions{Yes: true}); err != nil {
			t.Fatal(err)
		}
	})
	first, _ := os.ReadFile(envPath)

	out := capture(t, "", func() {
		if err := runMigrate(dir, c, migrateOptions{Yes: true}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "already routed through Lyntway") || !strings.Contains(out, "Nothing to migrate") {
		t.Errorf("second run should find nothing to do:\n%s", out)
	}
	second, _ := os.ReadFile(envPath)
	if string(first) != string(second) {
		t.Error("the second run changed the file")
	}
	if len(fake.stored) != 1 {
		t.Errorf("the key was stored %d times", len(fake.stored))
	}
	if backups, _ := filepath.Glob(envPath + ".lyntway-backup-*"); len(backups) != 1 {
		t.Errorf("%d backups after two runs, want 1", len(backups))
	}
}

func TestMigrateAsksBeforeReplacingAStoredKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	fake := &fakeServer{existing: []map[string]string{{"upstream": "openai", "last4": "OLD1"}}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := config{Origin: srv.URL, Key: "lyk_mine"}

	envPath := filepath.Join(dir, ".env")
	body := "OPENAI_API_KEY=sk-proj-openai0000ABCD\nANTHROPIC_API_KEY=sk-ant-api03-anthropicWXYZ\n"
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Yes to the plan, no to replacing the stored OpenAI key.
	out := capture(t, "y\nn\n", func() {
		if err := runMigrate(dir, c, migrateOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "already holds a key for openai ending OLD1") {
		t.Errorf("the plan did not warn about the stored key:\n%s", out)
	}
	if !strings.Contains(out, "Replace the stored openai key ending OLD1") {
		t.Errorf("no question was asked before replacing:\n%s", out)
	}
	if len(fake.stored) != 1 || fake.stored[0]["upstream"] != "anthropic" {
		t.Fatalf("stored %v, want only anthropic", fake.stored)
	}
	after, _ := os.ReadFile(envPath)
	if !strings.Contains(string(after), "OPENAI_API_KEY=sk-proj-openai0000ABCD") {
		t.Error("the OpenAI line was rewritten although replacing was declined")
	}
	if strings.Contains(string(after), "sk-ant-api03-anthropicWXYZ") {
		t.Error("the Anthropic key is still in the file")
	}
	if strings.Contains(out, "sk-proj-openai0000ABCD") || strings.Contains(out, "sk-ant-api03-anthropicWXYZ") {
		t.Fatalf("a key value was printed:\n%s", out)
	}
}

func TestMigrateWritesNothingWithoutConsent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	fake := &fakeServer{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	envPath := filepath.Join(dir, ".env.local")
	body := "OPENAI_API_KEY=sk-proj-openai0000ABCD\n"
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := capture(t, "n\n", func() {
		if err := runMigrate(dir, config{Origin: srv.URL, Key: "lyk_mine"}, migrateOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Nothing was changed") {
		t.Errorf("declining did not say so:\n%s", out)
	}
	if len(fake.stored) != 0 {
		t.Error("a key was stored without consent")
	}
	if after, _ := os.ReadFile(envPath); string(after) != body {
		t.Error("the file was changed without consent")
	}
	if backups, _ := filepath.Glob(envPath + ".lyntway-backup-*"); len(backups) != 0 {
		t.Error("a backup was written for a file that was not changed")
	}
}

func TestMigrateSkipsTheExampleFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	srv := httptest.NewServer((&fakeServer{}).handler())
	defer srv.Close()
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runMigrate(dir, config{Origin: srv.URL, Key: "lyk_mine"}, migrateOptions{Yes: true})
	if err == nil || !strings.Contains(err.Error(), "no .env file") {
		t.Errorf("an example file alone should count as no .env file; got %v", err)
	}
}

func TestMigrateRefusesADeploymentThatStoresNoKeys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/upstreams", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	mux.HandleFunc("GET /v1/keys/providers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "keys": []any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	body := "OPENAI_API_KEY=sk-proj-openai0000ABCD\n"
	envPath := filepath.Join(dir, ".env")
	_ = os.WriteFile(envPath, []byte(body), 0o600)

	err := runMigrate(dir, config{Origin: srv.URL, Key: "lyk_mine"}, migrateOptions{Yes: true})
	if err == nil || !strings.Contains(err.Error(), "does not store provider keys") {
		t.Errorf("got %v", err)
	}
	if after, _ := os.ReadFile(envPath); string(after) != body {
		t.Error("the file was changed although there was nowhere to move the key")
	}
}

// The link flow: a code, a wait, and a key that is never typed.
func TestLoginLinksAMachineFromTheBrowser(t *testing.T) {
	var polls int
	var label string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/link", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		label = body["label"]
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": "ABCD-EFGH", "url": "https://lyntway.example/link?code=ABCD-EFGH",
			"expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339), "poll_after_s": 3,
		})
	})
	mux.HandleFunc("GET /v1/link/{code}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("code") != "ABCD-EFGH" {
			w.WriteHeader(404)
			return
		}
		polls++
		if polls < 3 {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "approved", "api_key": "lyk_issued_secret", "key_id": "key_01", "origin": "https://lyntway.example", "tenant": "t_1",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var opened string
	var slept []time.Duration
	var got linkResult
	out := capture(t, "", func() {
		var err error
		got, err = linkLogin(srv.URL, "laptop", func(u string) { opened = u }, func(d time.Duration) { slept = append(slept, d) })
		if err != nil {
			t.Fatal(err)
		}
	})
	if got.APIKey != "lyk_issued_secret" || got.KeyID != "key_01" || got.Origin != "https://lyntway.example" {
		t.Errorf("got %+v", got)
	}
	if label != "laptop" {
		t.Errorf("label sent = %q", label)
	}
	if opened != "https://lyntway.example/link?code=ABCD-EFGH" {
		t.Errorf("browser opened on %q", opened)
	}
	if polls != 3 {
		t.Errorf("polled %d times, want 3", polls)
	}
	for _, d := range slept {
		if d != 3*time.Second {
			t.Errorf("slept %v between polls, want the server's 3s", d)
		}
	}
	if !strings.Contains(out, "ABCD-EFGH") || !strings.Contains(out, "/link?code=ABCD-EFGH") {
		t.Errorf("the code and URL were not shown:\n%s", out)
	}
	if strings.Contains(out, "lyk_issued_secret") {
		t.Fatalf("the issued key was printed:\n%s", out)
	}
}

func TestLoginFallsBackWhenTheServerCannotLink(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, err := linkLogin(srv.URL, "laptop", nil, func(time.Duration) {})
	if err != errLinkUnsupported {
		t.Errorf("got %v, want errLinkUnsupported", err)
	}
}

// A 410 is final whatever its reason, and the server's sentence is what
// the person reads. The fake's expires_at is a few seconds away so a
// version that keeps polling fails quickly instead of for fifteen minutes.
func TestLoginStopsWhenTheLinkIsGone(t *testing.T) {
	for _, gone := range []struct{ code, message string }{
		{"expired", "This code has expired."},
		{"consumed", "This code was already used."},
		{"denied", "This link was refused in the browser."},
	} {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /v1/link", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "ABCD-EFGH", "poll_after_s": 1,
				"expires_at": time.Now().Add(-25 * time.Second).UTC().Format(time.RFC3339)})
		})
		var polls int
		mux.HandleFunc("GET /v1/link/{code}", func(w http.ResponseWriter, r *http.Request) {
			polls++
			w.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": gone.code, "message": gone.message}})
		})
		srv := httptest.NewServer(mux)
		_ = capture(t, "", func() {
			_, err := linkLogin(srv.URL, "laptop", nil, func(time.Duration) {})
			if err == nil || !strings.Contains(err.Error(), strings.TrimSuffix(gone.message, ".")) {
				t.Errorf("%s: got %v, want the server's message", gone.code, err)
			}
		})
		srv.Close()
		if polls != 1 {
			t.Errorf("%s: polled %d times after a 410, want 1", gone.code, polls)
		}
	}
}

func TestSigningKeyIsWrittenPrivateAndReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "key_01.pem")
	priv, pub, err := generateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %o, want 0600", info.Mode().Perm())
	}
	if dirInfo, _ := os.Stat(filepath.Dir(path)); dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("key directory mode = %o, want 0700", dirInfo.Mode().Perm())
	}
	body, _ := os.ReadFile(path)
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("not a PRIVATE KEY PEM: %q", body)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	back, ok := parsed.(ed25519.PrivateKey)
	if !ok || !back.Equal(priv) {
		t.Error("the PEM does not hold the generated Ed25519 key")
	}
	if !back.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("the returned public key is not the private key's")
	}
}

func TestSignRegistersOrPrintsTheCallToMakeLater(t *testing.T) {
	for _, serverHas := range []bool{true, false} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("SHELL", "/bin/zsh")
		profile := filepath.Join(home, ".zshrc")

		var posted map[string]string
		mux := http.NewServeMux()
		if serverHas {
			mux.HandleFunc("POST /v1/keys/{id}/signing", func(w http.ResponseWriter, r *http.Request) {
				if r.PathValue("id") != "key_01" || r.Header.Get("Authorization") != "Bearer lyk_mine" {
					w.WriteHeader(403)
					return
				}
				_ = json.NewDecoder(r.Body).Decode(&posted)
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"registered":true}`)
			})
		}
		srv := httptest.NewServer(mux)
		c := config{Origin: srv.URL, Key: "lyk_mine"}
		if _, err := writeEnv(profile, c); err != nil {
			t.Fatal(err)
		}

		out := capture(t, "", func() {
			if err := runSign(c, "key_01", false, false); err != nil {
				t.Fatal(err)
			}
		})
		srv.Close()

		keyPath := filepath.Join(home, ".lyntway", "keys", "key_01.pem")
		pemBody, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(pemBody)
		parsed, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		priv := parsed.(ed25519.PrivateKey)
		pubB64 := strings.TrimSpace(strings.Split(strings.Split(out, "Public key (ed25519, base64): ")[1], "\n")[0])
		if got := priv.Public().(ed25519.PublicKey); pubB64 == "" || !strings.Contains(out, pubB64) || !equalB64(pubB64, got) {
			t.Errorf("printed public key %q is not the file's", pubB64)
		}
		// The private half is never printed, in either encoding.
		if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, strings.TrimSpace(string(pemBody))) {
			t.Fatalf("the private key was printed:\n%s", out)
		}

		if serverHas {
			if posted["public_key"] != pubB64 || posted["alg"] != "ed25519" {
				t.Errorf("registered %v", posted)
			}
			if !strings.Contains(out, "registered") || strings.Contains(out, "curl") {
				t.Errorf("a registered key should not print the curl:\n%s", out)
			}
		} else {
			if !strings.Contains(out, "does not register signing keys yet") || !strings.Contains(out, "curl -X POST "+srv.URL+"/v1/keys/key_01/signing") {
				t.Errorf("an unsupported server should print the call to make later:\n%s", out)
			}
			if !strings.Contains(out, `"public_key":"`+pubB64+`"`) {
				t.Errorf("the curl does not carry the public key:\n%s", out)
			}
		}

		saved, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if saved.KeyID != "key_01" || saved.SigningKey != keyPath {
			t.Errorf("config after sign: %+v", saved)
		}
		prof, _ := os.ReadFile(profile)
		if !strings.Contains(string(prof), `export LYNTWAY_SIGNING_KEY="`+keyPath+`"`) || !strings.Contains(string(prof), `export LYNTWAY_KEY_ID="key_01"`) {
			t.Errorf("the shell block does not export the signing key:\n%s", prof)
		}
		if strings.Count(string(prof), markerStart) != 1 {
			t.Error("the profile has more than one block")
		}

		// A second run does not silently replace the key.
		if err := runSign(c, "key_01", false, false); err == nil || !strings.Contains(err.Error(), "--force") {
			t.Errorf("a second sign should refuse without --force; got %v", err)
		}
	}
}

func equalB64(s string, pub ed25519.PublicKey) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && pub.Equal(ed25519.PublicKey(raw))
}

func TestSignRefusesAnIdItCannotNameAFileAfter(t *testing.T) {
	for _, bad := range []string{"../etc", "key/01", "", "a b"} {
		if validKeyID(bad) {
			t.Errorf("%q was accepted as a key id", bad)
		}
	}
	if !validKeyID("key_01-abc") {
		t.Error("a plain id was refused")
	}
}

func TestStatusSaysWhetherRequestsAreSigned(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key_01.pem")
	if _, _, err := generateSigningKey(keyPath); err != nil {
		t.Fatal(err)
	}
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	cases := []struct {
		name string
		c    config
		env  map[string]string
		want string
	}{
		{"not set up", config{}, nil, "not set up"},
		{"file missing", config{KeyID: "key_01", SigningKey: keyPath + ".gone"}, nil, "is missing"},
		{"not exported", config{KeyID: "key_01", SigningKey: keyPath}, nil, "not exported in this shell"},
		{"exported", config{KeyID: "key_01", SigningKey: keyPath}, map[string]string{"LYNTWAY_SIGNING_KEY": keyPath, "LYNTWAY_KEY_ID": "key_01"}, "signs from this shell"},
	}
	for _, c := range cases {
		got := signingStatusLine(c.c, env(c.env))
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want it to say %q", c.name, got, c.want)
		}
	}
}

func TestTheShellBlockCarriesSigningOnlyOnceItExists(t *testing.T) {
	profile := filepath.Join(t.TempDir(), ".zshrc")
	if _, err := writeEnv(profile, config{Origin: "https://lyntway.example", Key: "lyk_test"}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(profile)
	if strings.Contains(string(body), "LYNTWAY_SIGNING_KEY") {
		t.Error("a signing line was written for a machine with no signing key")
	}
	if _, err := writeEnv(profile, config{Origin: "https://lyntway.example", Key: "lyk_test", KeyID: "key_01", SigningKey: "/home/me/.lyntway/keys/key_01.pem"}); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(profile)
	if !strings.Contains(string(body), `export LYNTWAY_SIGNING_KEY="/home/me/.lyntway/keys/key_01.pem"`) || !strings.Contains(string(body), `export LYNTWAY_KEY_ID="key_01"`) {
		t.Errorf("signing lines missing:\n%s", body)
	}
	if strings.Count(string(body), markerStart) != 1 {
		t.Error("two blocks")
	}
}

// The flag package stops at the first positional argument, and the real
// binary showed `keys migrate <dir> --yes` asking a question anyway.
func TestMigrateFlagsMayFollowTheDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	fake := &fakeServer{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	if _, err := saveConfig(config{Origin: srv.URL, Key: "lyk_mine"}); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("OPENAI_API_KEY=sk-proj-openai0000ABCD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No input at all: a dropped --yes would read an empty answer as no.
	out := capture(t, "", func() {
		if err := keysMigrate([]string{dir, "--yes"}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "Go ahead?") || len(fake.stored) != 1 {
		t.Errorf("--yes after the directory was not honoured:\n%s", out)
	}
	if strings.Contains(out, "sk-proj-openai0000ABCD") {
		t.Fatalf("a key value was printed:\n%s", out)
	}
}

func TestMigrateEndsWithAReceiptOfItself(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY="+tOpenAI+"\nANTHROPIC_API_KEY="+tAnthropic+"\nOPENAI_BACKUP_KEY="+tOpenAI+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fake := &fakeServer{logStatus: http.StatusCreated}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := config{Origin: srv.URL, Key: "lyk_mine"}

	started := time.Now().Add(-3 * time.Second)
	out := capture(t, "", func() {
		if err := runMigrate(dir, c, migrateOptions{Yes: true, Started: started}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Receipt rcpt_migrate01") || !strings.Contains(out, "keys migrated: 2 upstreams (openai, anthropic)") {
		t.Errorf("the receipt line is missing:\n%s", out)
	}
	if !strings.Contains(out, "https://x.test/verify") || !strings.Contains(out, "attested") {
		t.Errorf("the verify URL and the honesty line are missing:\n%s", out)
	}
	if !strings.Contains(out, "Done in 3") {
		t.Errorf("elapsed time is missing or wrong:\n%s", out)
	}
	assertNoValue(t, out)

	// What the service was told: a count and the upstream names. Not the
	// keys, not the last4s, not where the file was.
	logged := string(fake.logged)
	var report struct {
		Tool      string `json:"tool"`
		Reference string `json:"reference"`
		Action    struct {
			Method string `json:"method"`
		} `json:"action"`
	}
	if err := json.Unmarshal(fake.logged, &report); err != nil {
		t.Fatalf("the report is not JSON: %s", logged)
	}
	if report.Tool != "lyntway-cli" || report.Action.Method != "keys migrate" || report.Reference != "keys migrated: 2 upstreams (openai, anthropic)" {
		t.Errorf("report: %s", logged)
	}
	assertNoValue(t, logged)
	for _, secret := range []string{"ABCD", "WXYZ", dir, ".env"} {
		if strings.Contains(logged, secret) {
			t.Errorf("%q reached the service in the report: %s", secret, logged)
		}
	}

	saved := filepath.Join(home, ".lyntway", "receipts", "rcpt_migrate01.json")
	body, err := os.ReadFile(saved)
	if err != nil || !strings.Contains(string(body), `"id": "rcpt_migrate01"`) && !strings.Contains(string(body), `"id":"rcpt_migrate01"`) {
		t.Errorf("the receipt was not saved for lyntway-verify: %v %s", err, body)
	}
	if !strings.Contains(out, saved) {
		t.Errorf("the saved path is not printed:\n%s", out)
	}
}

func TestMigrateStillSucceedsWhenTheServiceRefusesTheReceipt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	for _, status := range []int{0, http.StatusForbidden} {
		// Rewritten each time: the first run rewrites the file, and a
		// second run over it would find nothing to migrate.
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY="+tOpenAI+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		fake := &fakeServer{logStatus: status}
		srv := httptest.NewServer(fake.handler())
		c := config{Origin: srv.URL, Key: "lyk_mine"}
		var err error
		out := capture(t, "", func() { err = runMigrate(dir, c, migrateOptions{Yes: true, Replace: true}) })
		srv.Close()
		if err != nil {
			t.Fatalf("status %d: the migration itself must not fail: %v", status, err)
		}
		if !strings.Contains(out, "No receipt for this migration") || !strings.Contains(out, "Done in") {
			t.Errorf("status %d: %q", status, out)
		}
		if strings.Contains(out, "Receipt rcpt") {
			t.Errorf("status %d: a receipt was claimed that was never issued", status)
		}
		assertNoValue(t, out)
	}
}

func TestSignKeychainKeepsACopyWithoutPuttingItOnTheCommandLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/sh")

	prevOS, prevStore := goos, keychainStore
	defer func() { goos, keychainStore = prevOS, prevStore }()

	var storedID, storedSecret string
	keychainStore = func(id, secret string) error { storedID, storedSecret = id, secret; return nil }

	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := config{Origin: srv.URL, Key: "lyk_mine"}

	goos = "linux"
	if err := runSign(c, "key_01", false, true); err == nil || !strings.Contains(err.Error(), "macOS") {
		t.Fatalf("linux should refuse --keychain in one line, got %v", err)
	}
	if exists(filepath.Join(home, ".lyntway", "keys", "key_01.pem")) || storedID != "" {
		t.Fatal("the refusal must come before anything is generated")
	}

	goos = "darwin"
	out := capture(t, "", func() {
		if err := runSign(c, "key_01", false, true); err != nil {
			t.Fatal(err)
		}
	})
	if storedID != "key_01" {
		t.Fatalf("stored under account %q, want key_01", storedID)
	}
	pemBody, err := os.ReadFile(filepath.Join(home, ".lyntway", "keys", "key_01.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBody)
	if block == nil || base64.StdEncoding.EncodeToString(block.Bytes) != storedSecret {
		t.Error("the keychain copy is not the base64 of the PKCS#8 key in the file")
	}
	if !strings.Contains(out, "login keychain") || !strings.Contains(out, "The file above is what the SDKs read") {
		t.Errorf("the output must say the file is still what is read:\n%s", out)
	}
	if strings.Contains(out, storedSecret) || strings.Contains(out, "PRIVATE KEY") {
		t.Error("the private key reached the output")
	}

	// A keychain that cannot be written — a session with no login
	// keychain, as on a build machine — is reported and does not undo the
	// rest: the key is saved and set up, and the exit status says the
	// copy was not made.
	keychainStore = func(string, string) error { return fmt.Errorf("The authorization was canceled by the user") }
	var signErr error
	out = capture(t, "", func() { signErr = runSign(c, "key_02", false, true) })
	if signErr == nil || !strings.Contains(signErr.Error(), "keychain copy was not made") || !strings.Contains(signErr.Error(), "is set up and signs") {
		t.Errorf("a failed copy must be the exit status, after the rest was done: %v", signErr)
	}
	if !strings.Contains(out, "✗ keychain copy not made") {
		t.Errorf("the failure is not in the output:\n%s", out)
	}
	if saved, err := loadConfig(); err != nil || saved.KeyID != "key_02" || !exists(saved.SigningKey) {
		t.Errorf("the config must still record the key: %+v %v", saved, err)
	}

	// The item is written through security's stdin, never its argv, as
	// one line the interactive parser reads whole.
	line, err := keychainCommand("key_01", storedSecret)
	if err != nil || !strings.HasPrefix(line, "add-generic-password -a \"key_01\" -s lyntway ") || !strings.HasSuffix(line, " -U -w \""+storedSecret+"\"\n") {
		t.Errorf("command line: %q (%v)", line, err)
	}
	if _, err := keychainCommand("bad id!", storedSecret); err == nil {
		t.Error("an id that cannot be quoted safely must be refused")
	}
	for _, bad := range []string{"line1\nline2", `a"b`, `a\b`, "a b", ""} {
		if _, err := keychainCommand("key_01", bad); err == nil {
			t.Errorf("%q would end the interactive command early or start another; it must be refused", bad)
		}
	}
}

// The flags are read by the binary, not by runMigrate, so the seam is
// exercised through keysMigrate with the config on disk: a valued flag
// keeps its value in either form, and a bool after the directory still
// counts.
func TestFlagsKeepTheirValuesInEitherOrder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fake := &fakeServer{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	if _, err := saveConfig(config{Origin: srv.URL, Key: "lyk_mine"}); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{{"DIR", "--yes"}, {"--yes", "DIR"}, {"--yes", "--replace", "DIR"}} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY="+tOpenAI+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for i := range args {
			if args[i] == "DIR" {
				args[i] = dir
			}
		}
		// stdin is empty: without --yes taking effect, the question reads
		// an empty answer as no and nothing is stored.
		out := capture(t, "", func() {
			if err := keysMigrate(args); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(out, "stored for openai") {
			t.Errorf("%v: --yes was lost:\n%s", args, out)
		}
	}

	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	diff := fs.String("diff", "", "")
	format := fs.String("format", "text", "")
	yes := fs.Bool("yes", false, "")
	for _, c := range []struct {
		args []string
		rest []string
	}{
		{[]string{"--diff", "origin/main", "--format", "github"}, nil},
		{[]string{"--diff=origin/main", "--format=github"}, nil},
		{[]string{"a", "--diff", "origin/main", "b", "--format", "github", "--yes"}, []string{"a", "b"}},
		{[]string{"--yes", "--diff", "origin/main", "--", "--format", "github"}, []string{"--format", "github"}},
	} {
		*diff, *format, *yes = "", "text", false
		if err := fs.Parse(flagsFirst(fs, c.args)); err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if *diff != "origin/main" || (*format != "github" && c.rest == nil) || strings.Join(fs.Args(), " ") != strings.Join(c.rest, " ") {
			t.Errorf("%v: diff=%q format=%q rest=%v", c.args, *diff, *format, fs.Args())
		}
	}
}

// A provider key bound to another application's key id is not one this
// machine's key can use, so it is not "already held". Found on the live
// service: the only openai key on the account belonged to a different
// application, and the CLI warned about replacing it.
func TestMigrateCountsOnlyKeysThisKeyWouldUseAsAlreadyHeld(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	env := "OPENAI_API_KEY=sk-proj-openai0000ABCD\n"

	// Bound to somebody else: no warning, no question, stored as new.
	dir := t.TempDir()
	fake := &fakeServer{existing: []map[string]string{{"upstream": "openai", "last4": "0000", "key_id": "key_other"}}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	out := capture(t, "y\n", func() {
		if err := runMigrate(dir, config{Origin: srv.URL, Key: "lyk_mine", KeyID: "key_mine"}, migrateOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "already holds") || strings.Contains(out, "Replace the stored") {
		t.Errorf("a key bound to another application was treated as this machine's:\n%s", out)
	}
	if len(fake.stored) != 1 || fake.stored[0]["key_id"] != "" {
		t.Errorf("stored %v, want one account-wide key", fake.stored)
	}

	// Bound to this key, beside an account-wide one: the bound one is
	// what the gateway resolves, so it is the one named, and the
	// replacement lands on it rather than beside it.
	dir = t.TempDir()
	fake = &fakeServer{existing: []map[string]string{
		{"upstream": "openai", "last4": "WIDE", "key_id": ""},
		{"upstream": "openai", "last4": "MINE", "key_id": "key_mine"},
		{"upstream": "openai", "last4": "THEM", "key_id": "key_other"},
	}}
	srv2 := httptest.NewServer(fake.handler())
	defer srv2.Close()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	out = capture(t, "y\ny\n", func() {
		if err := runMigrate(dir, config{Origin: srv2.URL, Key: "lyk_mine", KeyID: "key_mine"}, migrateOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "already holds a key for openai ending MINE") || !strings.Contains(out, "Replace the stored openai key ending MINE") {
		t.Errorf("the key bound to this machine was not the one named:\n%s", out)
	}
	if len(fake.stored) != 1 || fake.stored[0]["key_id"] != "key_mine" {
		t.Errorf("stored %v, want the replacement bound to key_mine", fake.stored)
	}

	// Account-wide alone, for a machine whose key id is unknown: held.
	dir = t.TempDir()
	fake = &fakeServer{existing: []map[string]string{{"upstream": "openai", "last4": "WIDE"}}}
	srv3 := httptest.NewServer(fake.handler())
	defer srv3.Close()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	out = capture(t, "y\nn\n", func() {
		if err := runMigrate(dir, config{Origin: srv3.URL, Key: "lyk_mine"}, migrateOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "already holds a key for openai ending WIDE") || len(fake.stored) != 0 {
		t.Errorf("an account-wide key was not treated as held:\n%s\nstored %v", out, fake.stored)
	}
}
