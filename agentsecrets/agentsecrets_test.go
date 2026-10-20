package agentsecrets

import (
	"bytes"
	"github.com/lynt-x-global/lyntway-tools/detect"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A fixture key, assembled so this file does not itself contain a
// credential-shaped literal that every other scanner on the machine will
// report. The same trick detect/fixtures_test.go uses.
func fakeAWSKey() string    { return "AKIA" + "J3QX7F2MNB4KD9PL" }
func fakeAnthropic() string { return "sk" + "-ant-" + strings.Repeat("q", 24) }

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The claim the whole report rests on: "nothing found" is never said
// about a file that was not read.
//
// This repository's readiness check reports "found nothing" as a failure
// for the same reason — the sample was written to be found, so silence
// means the check did not work rather than that the machine is clean. A
// history scanner has the same shape: a transcript directory half of
// which could not be opened is not a clean machine.
func TestNothingFoundIsNeverSaidAboutAFileThatWasNotRead(t *testing.T) {
	home := t.TempDir()
	// A transcript that exists and holds a key.
	write(t, filepath.Join(home, ".claude", "projects", "p", "a.jsonl"),
		`{"role":"user","content":"use `+fakeAnthropic()+` please"}`+"\n")
	// A file in a source directory that cannot be read by anybody.
	unreadableFile(t, filepath.Join(home, ".claude", "shell-snapshots", "snap.sh"))

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())

	if len(res.Findings) == 0 {
		t.Fatal("the planted key was not found, so this test proves nothing about the rest")
	}
	if res.Complete() {
		t.Error("the result reports itself complete while a directory could not be read; " +
			"a report that says this is a clean machine would be claiming more than happened")
	}
	if len(res.Unread) == 0 {
		t.Fatal("the unreadable file is not named, so nobody can tell what was missed")
	}
	// The refusal must not be about permissions.
	//
	// This is the assertion that keeps the test meaningful in CI. The
	// deploy builds its image and runs this suite as root, where a mode
	// of 0000 is ignored and the premise silently stops existing — which
	// is exactly what happened, and the test failed there rather than
	// passing over nothing. A size refusal holds for every user.
	if !strings.Contains(res.Unread[0].Reason, "larger than") {
		t.Errorf("the file was refused for %q; if that is a permission error this test proves nothing "+
			"when run as root, which is how the deploy runs it", res.Unread[0].Reason)
	}
}

// A tool that is not installed is not a gap.
func TestAnAbsentToolIsNotReportedAsUnread(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude", "history.jsonl"), "{}\n")

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	if !res.Complete() {
		t.Errorf("a machine with one tool reports %d unread: %+v", len(res.Unread), res.Unread)
	}
	if res.Sources != 1 {
		t.Errorf("counted %d sources, want 1 — only one of the candidate locations exists", res.Sources)
	}
}

// No finding may carry the value, in any field.
//
// The report is printed to a terminal, which puts it in the scrollback,
// in the terminal's own buffer file, and in front of whatever agent is
// reading that terminal — which is the problem this package exists for.
// Last4 is what a person needs to revoke the right key and is not enough
// to use one.
func TestAFindingNeverCarriesTheValue(t *testing.T) {
	home := t.TempDir()
	secret := fakeAnthropic()
	write(t, filepath.Join(home, ".claude", "history.jsonl"),
		`{"display":"export ANTHROPIC_API_KEY=`+secret+`"}`+"\n")

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	for name, field := range map[string]string{
		"Label": f.Label, "Class": f.Class, "Path": f.Path,
		"Fingerprint": f.Fingerprint, "Why": f.Why, "Tool": f.Tool,
	} {
		if strings.Contains(field, secret) {
			t.Errorf("%s carries the whole secret", name)
		}
	}
	if f.Last4 != secret[len(secret)-4:] {
		t.Errorf("Last4 = %q, want the final four characters", f.Last4)
	}
	if len(f.Last4) > 4 {
		t.Errorf("Last4 is %d characters", len(f.Last4))
	}
	// And the fingerprint must actually identify it.
	if f.Fingerprint != fingerprint(secret) || len(f.Fingerprint) != 12 {
		t.Errorf("fingerprint %q does not identify the value", f.Fingerprint)
	}
}

// One key in many files is one credential to revoke, not many findings.
func TestTheSameKeyInManyFilesIsOneCredential(t *testing.T) {
	home := t.TempDir()
	secret := fakeAWSKey()
	for _, name := range []string{"a.jsonl", "b.jsonl", "c.jsonl"} {
		write(t, filepath.Join(home, ".claude", "projects", "p", name),
			`{"content":"`+secret+`"}`+"\n")
	}
	write(t, filepath.Join(home, ".claude", "history.jsonl"), `{"display":"`+secret+`"}`+"\n")

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	if len(res.Findings) != 4 {
		t.Fatalf("got %d occurrences, want 4", len(res.Findings))
	}
	creds := res.Credentials()
	if len(creds) != 1 {
		t.Fatalf("got %d distinct credentials, want 1: a report of four would tell somebody to revoke four keys", len(creds))
	}
	if len(creds[0].Seen) != 4 {
		t.Errorf("the credential records %d sightings, want 4", len(creds[0].Seen))
	}
	kinds := creds[0].Kinds()
	if len(kinds) != 2 {
		t.Errorf("kinds = %v, want both the transcript and the prompt history: how it got there differs", kinds)
	}
}

// Documented examples must not be reported, or the real finding under
// them is not read either.
func TestDocumentationExamplesAreNotReported(t *testing.T) {
	home := t.TempDir()
	for i, example := range []string{
		"ANTHROPIC_API_KEY=sk-ant-api03-YOUR-KEY-HERE",
		"OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"DATABASE_URL=postgres://user:password@localhost:5432/app",
		"DATABASE_URL=postgres://user:${DB_PASSWORD}@localhost/app",
		"DATABASE_URL=postgres://user:$PGPASSWORD@localhost/app",
		"export AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE12",
		"repo url https://oauth2:TOKEN@github.com/org/repo.git",
	} {
		write(t, filepath.Join(home, ".claude", "projects", "p", "ex"+string(rune('a'+i))+".jsonl"),
			`{"content":`+quote(example)+`}`+"\n")
	}

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	if len(res.Findings) != 0 {
		for _, f := range res.Findings {
			t.Errorf("reported %s ending %s in %s — a documented example", f.Label, f.Last4, filepath.Base(f.Path))
		}
		t.Fatal("documentation examples were reported; a scanner that cries wolf is not read twice")
	}
}

func quote(s string) string {
	out := strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(out, `"`, `\"`) + `"`
}

// A store this cannot parse is still scanned, and reported without a
// line, because a credential in it is still a credential.
func TestAnOpaqueStoreIsScannedButHasNoLine(t *testing.T) {
	home := t.TempDir()
	secret := fakeAWSKey()
	// A binary-looking file with readable text inside, which is what a
	// SQLite page holding a conversation is.
	body := "SQLite format 3\x00\x00\x01page\x00" + "the key is " + secret + "\x00\x00tail"
	write(t, filepath.Join(home, ".claude", "paste-cache", "p.bin"), body)

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings in an opaque store, want 1", len(res.Findings))
	}
	if res.Findings[0].Line != 0 {
		t.Errorf("line = %d, want 0: there is no line to point at inside a store, and a number here would be invented",
			res.Findings[0].Line)
	}
	if res.Findings[0].Format != FormatOpaque {
		t.Errorf("format = %v, want opaque so the report can say it will not be rewritten", res.Findings[0].Format)
	}
}

// Every source carries a sentence explaining what the file is, because a
// person who has never heard of ~/.claude/shell-snapshots cannot judge a
// finding in it.
func TestEverySourceExplainsWhatTheFileIs(t *testing.T) {
	for _, src := range Sources(Host{GOOS: "darwin", Home: "/Users/x"}) {
		if strings.TrimSpace(src.Why) == "" {
			t.Errorf("%s (%s) has no explanation", src.Path, src.Kind)
		}
		if src.Tool == "" || src.Kind == "" {
			t.Errorf("%s is missing its tool or kind", src.Path)
		}
	}
	for _, src := range ProjectSources("/tmp/project") {
		if strings.TrimSpace(src.Why) == "" {
			t.Errorf("project source %s has no explanation", src.Path)
		}
	}
}

// A home directory this cannot determine produces no sources, rather
// than paths rooted at the filesystem root.
func TestNoHomeMeansNoSources(t *testing.T) {
	if got := Sources(Host{GOOS: "linux", Home: ""}); got != nil {
		t.Errorf("got %d sources with no home directory", len(got))
	}
	if got := ProjectSources(""); got != nil {
		t.Errorf("got %d project sources with no directory", len(got))
	}
}

// unreadableFile makes a path that cannot be read by anybody, including
// root.
//
// chmod 0000 does not do that: the deploy builds its image and runs this
// suite as root, and root reads a directory whatever its mode says. Five
// tests asserted their own premise and failed there — correctly, and
// loudly, which is the only reason this was found rather than passing
// vacuously in CI.
//
// A file past the size cap is refused for a reason that has nothing to do
// with permissions, so it holds for every user. Written sparse — one byte
// at a high offset — so it costs no disk, and with that one byte so the
// file has blocks allocated and macOS's cloud-eviction check does not
// claim it first; the test wants one reason, not a different one per
// platform.
func unreadableFile(t *testing.T, path string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// One byte past the size cap, written sparse: instant, and 4 KB of
	// disk for a 2 GB file on every filesystem this runs on. The byte at
	// the end is deliberate — without it the file has no blocks and
	// macOS's cloud-eviction check claims it first, which would make the
	// refusal reason differ by platform when the test wants one reason.
	if _, err := f.WriteAt([]byte{'x'}, maxFileBytes+1); err != nil {
		t.Fatal(err)
	}
}

// A credential lying across a chunk boundary is found, and found once.
//
// Files are streamed in 8 MB windows with a 64 KB tail carried over, so a
// key written at the seam is split in the first window and whole in the
// second. Two things can go wrong and both are silent: the key is missed
// because neither window holds it entire, or it is reported twice because
// both windows see it and the sighting count then grows with the file
// size — and the sighting count is the number this tool is judged on.
//
// The file is built sparse so this costs no disk: a hole, the key at the
// seam, and a hole after it.
func TestACredentialAtAChunkBoundaryIsFoundExactlyOnce(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "projects", "p", "big.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := fakeAWSKey()
	// Straddling the seam: half before chunkBytes, half after. This is
	// the one that gets missed without a carried-over tail.
	at := int64(chunkBytes) - int64(len(secret)/2)
	if _, err := f.WriteAt([]byte(" "+secret+" "), at); err != nil {
		t.Fatal(err)
	}
	// And one wholly inside the overlap region, which is the case that
	// gets counted twice: both windows hold it entire, so only the limit
	// check keeps it to one sighting. Writing the first key alone made
	// this test pass with that check deleted — it was found by removing
	// it and watching nothing fail.
	inOverlap := fakeAnthropic()
	if _, err := f.WriteAt([]byte(" "+inOverlap+" "), int64(chunkBytes)+1024); err != nil {
		t.Fatal(err)
	}
	// And a second window's worth of file after it, so the stream really
	// does take more than two passes.
	if _, err := f.WriteAt([]byte{'\n'}, int64(chunkBytes)*2+1024); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	if !res.Complete() {
		t.Fatalf("the file was not read: %+v", res.Unread)
	}
	for name, want := range map[string]string{
		"across the seam":    secret,
		"inside the overlap": inOverlap,
	} {
		var seen int
		for _, fd := range res.Findings {
			if fd.Fingerprint == fingerprint(want) {
				seen++
			}
		}
		switch seen {
		case 1:
			// Right.
		case 0:
			t.Errorf("the credential %s was missed; the carried-over tail is too small or not carried", name)
		default:
			t.Errorf("the credential %s was reported %d times; both windows claimed it, so a sighting "+
				"count would grow with the file size", name, seen)
		}
	}
}

// Line numbers stay absolute across windows, or a report points somebody
// at the wrong line of a 289 MB transcript — which is worse than no line.
func TestLineNumbersSurviveStreaming(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "projects", "p", "lines.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// Enough newlines to cross a window, then the key on a known line.
	var b []byte
	for i := 0; i < 3; i++ {
		b = append(b, bytes.Repeat([]byte("x\n"), chunkBytes/2)...)
	}
	before := bytes.Count(b, []byte{'\n'})
	b = append(b, []byte(fakeAWSKey())...)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	if want := before + 1; res.Findings[0].Line != want {
		t.Errorf("line = %d, want %d — the count of newlines behind the window was lost",
			res.Findings[0].Line, want)
	}
}

// A private key has no useful last four characters.
//
// The end of a PEM block is "-----", so every private key on a machine
// reported "…----" — identical for all of them, and telling somebody
// nothing about which one to revoke while looking like it did. The first
// real run on the author's laptop found six that way. The hook's refusal
// had always left the value out for this class; the report had not.
func TestAPrivateKeyReportsNoLastFour(t *testing.T) {
	home := t.TempDir()
	// The delimiters are split across concatenations so no PEM block exists
	// in this file's text, following detect/benchmark_test.go.
	//
	// Written whole, it failed the secret scan over our own history — the
	// scanner reads the source, not the assembled value, so an unbroken
	// begin delimiter is a finding whatever the body is. Naming that
	// delimiter in this comment was a finding too, which is why it is
	// described rather than quoted.
	//
	// The zero-padded body that cmd/lyntway/scan_test.go uses is not an option
	// here either: isObviousPlaceholder drops "0000" by design, so the key
	// would never be reported and this test would pass having proved
	// nothing. Splitting the delimiter needs neither an allowlist entry nor
	// a weaker fixture.
	pem := "-----BEGIN " + "PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGx" +
		strings.Repeat("Qk", 24) + "\n-----END " + "PRIVATE KEY-----"
	write(t, filepath.Join(home, ".claude", "projects", "p", "a.jsonl"),
		`{"content":`+quote("cert: "+pem)+`}`+"\n")

	res := Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	var keys int
	for _, f := range res.Findings {
		if f.Class != "secret.private_key" {
			continue
		}
		keys++
		if f.Last4 != "" {
			t.Errorf("a private key reports last4 %q; the end of a PEM block is the same dashes for every key", f.Last4)
		}
		if f.Fingerprint == "" {
			t.Error("a private key has no fingerprint either, so nothing identifies it at all")
		}
	}
	if keys == 0 {
		t.Fatal("the planted private key was not found, so this test proves nothing")
	}

	// And a key that is not a PEM block still carries its tail, or the
	// fix has taken the identifier away from everything.
	write(t, filepath.Join(home, ".claude", "history.jsonl"),
		`{"display":"`+fakeAWSKey()+`"}`+"\n")
	res = Scan(Sources(Host{GOOS: runtime.GOOS, Home: home}), DefaultRules())
	for _, f := range res.Findings {
		if f.Class == "secret.aws_access_key" && f.Last4 != "D9PL" {
			t.Errorf("an AWS key reports last4 %q, want D9PL", f.Last4)
		}
	}
}

// A report that says "revoke" and not where is most of the way to useless.
func TestRotationAdviceNamesAPageForEachProviderAndGuessesAtNothing(t *testing.T) {
	creds := []Credential{
		{Label: "Stripe key", Class: "secret.stripe_key"},
		{Label: "Stripe key", Class: "secret.stripe_key"},
		{Label: "Anthropic key", Class: "secret.anthropic_key"},
		// Three classes where naming a page would be a guess: a PEM is a
		// key for something we cannot identify, a JWT is invalidated by
		// whoever issued it, and a database password's console is
		// whoever runs the database.
		{Label: "Private key", Class: "secret.private_key"},
		{Label: "Session token (JWT)", Class: "secret.jwt"},
		{Label: "Password in a connection URL", Class: "secret.url_password"},
	}
	got := RotationAdvice(creds)
	if len(got) != 2 {
		t.Fatalf("advice = %v, want one line each for Stripe and Anthropic and nothing else", got)
	}
	// Heaviest provider first: the reader works down by weight.
	if !strings.HasPrefix(got[0], "Stripe key — https://dashboard.stripe.com/") {
		t.Errorf("first line = %q", got[0])
	}
	if !strings.Contains(got[1], "console.anthropic.com") {
		t.Errorf("second line = %q", got[1])
	}
	for _, class := range []string{"secret.private_key", "secret.jwt", "secret.url_password"} {
		if u := rotateAt[detect.Class(class)]; u != "" {
			t.Errorf("%s names %q; a wrong rotation page sends somebody to revoke the wrong thing", class, u)
		}
	}
}

// The one way this package can come up short while Complete() stays true.
func TestEveryPlatformWeHaveNotRunOnSaysSo(t *testing.T) {
	if c := PlatformCaveat("darwin"); c != "" {
		t.Errorf("macOS has had the whole flow run on it; it should carry no caveat, got %q", c)
	}
	for _, goos := range []string{"windows", "linux"} {
		c := PlatformCaveat(goos)
		if c == "" {
			t.Fatalf("%s carries no caveat, so a wrong path there reads as a clean machine", goos)
		}
		// It has to say the thing that is actually dangerous: a low
		// count, not merely that support is new.
		if !strings.Contains(c, "clean machine") {
			t.Errorf("%s caveat does not warn about reading a low count as clean: %q", goos, c)
		}
	}
}
