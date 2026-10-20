package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture, assembled so this file holds no credential-shaped literal.
func histAWSKey() string { return "AKIA" + "J3QX7F2MNB4KD9PL" }

// historyHome builds a machine with agent history on it and points the
// command at it.
func historyHome(t *testing.T, transcripts ...string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".claude", "projects", "p")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i, body := range transcripts {
		name := filepath.Join(dir, string(rune('a'+i))+".jsonl")
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func runHistory(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	defer func() { stdout = old }()
	err := historyCommand(args)
	return buf.String(), err
}

// The report must never print the credential, because it is printed to a
// terminal — whose scrollback is a file, and which an agent is often
// reading. A tool that leaks the key while telling you the key leaked is
// not worth having.
func TestTheReportNeverPrintsTheCredential(t *testing.T) {
	secret := histAWSKey()
	historyHome(t, `{"content":"`+secret+`"}`+"\n")

	out, err := runHistory(t)
	if err == nil {
		t.Fatal("a machine with a credential in its history exited zero; this is meant to work as a check")
	}
	if strings.Contains(out, secret) {
		t.Fatal("the report printed the whole credential")
	}
	if !strings.Contains(out, "D9PL") {
		t.Error("the report does not carry the last four characters, so nobody can tell which key to revoke")
	}
	if !strings.Contains(out, "AWS access key") {
		t.Error("the report does not name what it found")
	}
	// And the caveat is above the list, not under it.
	list := strings.Index(out, "AWS access key")
	caveat := strings.Index(out, "test fixtures")
	if caveat < 0 || caveat > list {
		t.Error("the fixture caveat is missing or printed after the findings; somebody reads the number and stops")
	}
}

// "No credentials" is never said about a machine this could not finish
// reading.
func TestAnIncompleteLookIsNotReportedAsACleanMachine(t *testing.T) {
	home := historyHome(t)
	unreadableHistoryFile(t, filepath.Join(home, ".claude", "shell-snapshots", "s.sh"))

	out, err := runHistory(t)
	if err != nil {
		t.Fatalf("no credentials were planted, so this should exit zero: %v", err)
	}
	if !strings.Contains(out, "incomplete look") {
		t.Errorf("the report does not say the look was incomplete:\n%s", out)
	}
	if !strings.Contains(out, "Not read") {
		t.Error("the unreadable file is not listed")
	}
	// Refused for its size, not its permissions — see the note on
	// unreadableHistoryFile. A permission-based premise disappears when
	// the deploy runs this as root.
	if !strings.Contains(out, "larger than") {
		t.Errorf("the report does not say the file was refused for its size, so this test would prove "+
			"nothing as root:\n%s", out)
	}
	if strings.Contains(out, "No credentials in what your agents have written here") {
		t.Error("it claimed the clean-machine sentence while a directory could not be read")
	}
}

// One key in three files is one credential to revoke.
func TestTheReportCountsCredentialsNotSightings(t *testing.T) {
	body := `{"content":"` + histAWSKey() + `"}` + "\n"
	historyHome(t, body, body, body)

	out, _ := runHistory(t)
	if !strings.Contains(out, "seen 1 credential.") {
		t.Errorf("the headline does not say one credential:\n%s", out)
	}
	if !strings.Contains(out, "3 sightings") {
		t.Errorf("the report does not say how far it spread:\n%s", out)
	}
}

// --allow writes fingerprints and no values, and the next run says how
// many it is not showing.
func TestAllowRecordsFingerprintsAndTheNextRunSaysSo(t *testing.T) {
	secret := histAWSKey()
	home := historyHome(t, `{"content":"`+secret+`"}`+"\n")

	if _, err := runHistory(t, "--allow"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".lyntway", "agent-secrets-allow")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no allowlist was written: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("the allowlist carries the credential; it is meant to carry fingerprints")
	}
	if !strings.Contains(string(raw), "AWS access key") {
		t.Error("the allowlist does not say what was retired, so nobody can audit it later")
	}

	out, err := runHistory(t)
	if err != nil {
		t.Errorf("a fully judged machine still exited non-zero: %v", err)
	}
	if !strings.Contains(out, "already judged") {
		t.Errorf("the second run shows less without saying so:\n%s", out)
	}
}

// A script branches on "complete", so it has to be there.
func TestJSONCarriesWhetherTheLookWasComplete(t *testing.T) {
	historyHome(t, `{"content":"`+histAWSKey()+`"}`+"\n")

	out, err := runHistory(t, "--json")
	if err == nil {
		t.Error("findings should still exit non-zero with --json")
	}
	var doc struct {
		Credentials []struct {
			Fingerprint string `json:"fingerprint"`
			Last4       string `json:"last4"`
			Seen        []struct {
				Path string `json:"path"`
				Line int    `json:"line"`
			} `json:"seen"`
		} `json:"credentials"`
		Complete  bool   `json:"complete"`
		FilesRead int    `json:"files_read"`
		Ruleset   string `json:"ruleset"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("the output is not JSON: %v\n%s", err, out)
	}
	if !doc.Complete {
		t.Error("complete is false on a machine where everything was read")
	}
	if len(doc.Credentials) != 1 || doc.Credentials[0].Last4 != "D9PL" {
		t.Errorf("credentials = %+v", doc.Credentials)
	}
	if doc.FilesRead == 0 {
		t.Error("files_read is zero, so the report does not say what it looked at")
	}
	if !strings.Contains(doc.Ruleset, "+secrets") {
		t.Errorf("ruleset = %q; it must name the subset that actually ran", doc.Ruleset)
	}
	if strings.Contains(out, histAWSKey()) {
		t.Error("the JSON carries the credential")
	}
}

// An allowlist that cannot be read must stop the run, not look empty.
func TestAnUnreadableAllowlistStopsTheRun(t *testing.T) {
	home := historyHome(t, `{"content":"`+histAWSKey()+`"}`+"\n")
	// A directory where the allowlist should be: readable by nobody,
	// including the root the deploy's image build runs as.
	if err := os.MkdirAll(filepath.Join(home, ".lyntway", "agent-secrets-allow"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := runHistory(t)
	if err == nil {
		t.Fatal("an unreadable allowlist was treated as allowing nothing, which hands back every judged finding with no sign anything went wrong")
	}
	if !strings.Contains(err.Error(), "agent-secrets-allow") {
		t.Errorf("the error does not name the file: %v", err)
	}
}

// An MCP tool result becomes part of the next prompt, so this one must
// not carry a value — returning the key here would put it straight back
// into the model the whole command exists to keep it away from.
func TestTheMCPToolNeverReturnsAValue(t *testing.T) {
	secret := histAWSKey()
	historyHome(t, `{"content":"`+secret+`"}`+"\n")

	out, err := mcpToolHistory(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, secret) {
		t.Fatal("the tool result carries the credential, which goes straight back into the model")
	}
	for _, want := range []string{"AWS access key", "D9PL", "1 credential"} {
		if !strings.Contains(out, want) {
			t.Errorf("the result does not mention %q:\n%s", want, out)
		}
	}
	// And it tells the agent what to say about fixtures, because the
	// agent is the one writing the sentence the user reads.
	if !strings.Contains(out, "fixtures") {
		t.Error("the result does not warn that some findings may be fixtures")
	}
	if !strings.Contains(out, "never print a value") {
		t.Error("the result does not instruct the agent to withhold values")
	}
}

// An incomplete read has to be reported before the count, because an
// agent summarising this will lead with the number.
func TestTheMCPToolLeadsWithAnIncompleteRead(t *testing.T) {
	home := historyHome(t, `{"content":"`+histAWSKey()+`"}`+"\n")
	unreadableHistoryFile(t, filepath.Join(home, ".claude", "shell-snapshots", "s.sh"))

	out, err := mcpToolHistory(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("an incomplete read is not flagged:\n%s", out)
	}
	if strings.Index(out, "INCOMPLETE") > strings.Index(out, "credential") {
		t.Error("the incomplete warning comes after the count, so a summary would lead with a number over a partial read")
	}
}

// The first thing somebody sees after installing has to mention the one
// command that costs them nothing and shows them something.
//
// Not a style check. This command finds what has already happened, and
// somebody who never learns it exists keeps the credential in forty
// transcripts. The first-run report is the only place a new install is
// read end to end.
func TestFirstRunLeadsWithTheOneCommand(t *testing.T) {
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	defer func() { stdout = old }()

	printFirstRun(firstRunReport{})
	out := buf.String()

	// `lyntway secure` leads, and it is the only line needed for this.
	//
	// This asserted "history before hook install" while those were two
	// of five lines. They are one command now: secure does the look and
	// the remedy behind a single question, so the contract is that it
	// comes first — and that `history` is still offered, because a check
	// that changes nothing is a different need.
	if !strings.Contains(out, "lyntway secure") {
		t.Fatalf("the first-run report does not offer `lyntway secure`:\n%s", out)
	}
	if !strings.Contains(out, "lyntway history") {
		t.Error("the report-only form is not offered")
	}
	if strings.Index(out, "lyntway secure") > strings.Index(out, "lyntway history") {
		t.Error("history is listed before secure; the one-command form should lead")
	}
	// And it must say it sends nothing and asks first, which is why
	// somebody runs an unknown command against their own machine.
	if !strings.Contains(out, "Sends nothing") {
		t.Error("the line does not say it sends nothing")
	}
	if !strings.Contains(out, "asks before") {
		t.Error("the line does not say it asks before changing anything")
	}
}

// unreadableHistoryFile plants a file no user can read.
//
// Not chmod 0000: the deploy runs this suite as root inside its image,
// and root reads a directory whatever its mode says — which is how three
// of these tests failed there while passing on a laptop. A file past the
// size cap is refused for a reason that is not about permissions. Sparse,
// with one byte at the end so it has blocks and macOS's eviction check
// does not claim it for a different reason.
func unreadableHistoryFile(t *testing.T, path string) {
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
	if _, err := f.WriteAt([]byte{'x'}, (2<<30)+1); err != nil {
		t.Fatal(err)
	}
}

// --json has to stay a document a script can parse, so the progress
// counter must never reach stdout.
//
// The counter exists because reading a working machine takes about a
// minute and a half and silence reads as broken. Writing it to stdout
// would trade one defect for a worse one: a report that cannot be piped
// into anything.
func TestProgressNeverReachesTheJSONDocument(t *testing.T) {
	// The decision, not the plumbing. Asserting on progressTo could not
	// fail: `go test` captures stderr, so the terminal check returns
	// false and the answer is nil however --json is set.
	for _, c := range []struct {
		asJSON, terminal, want bool
	}{
		{asJSON: false, terminal: true, want: true},
		{asJSON: true, terminal: true, want: false},
		{asJSON: false, terminal: false, want: false},
		{asJSON: true, terminal: false, want: false},
	} {
		if got := wantsProgress(c.asJSON, c.terminal); got != c.want {
			t.Errorf("wantsProgress(json=%v, terminal=%v) = %v, want %v", c.asJSON, c.terminal, got, c.want)
		}
	}
	if progressTo(true) != nil {
		t.Error("--json was given a progress callback; its output has to be parseable")
	}
}

// The remedy a free user is given first must not be the one that stops
// and asks them to sign in.
//
// `keys migrate` answers "not signed in on this machine". It was the
// first thing this report recommended, so the first instruction after
// showing somebody a problem was a signup wall — spending the only
// credit the report had earned.
func TestTheFirstRemedyOfferedCostsNothing(t *testing.T) {
	historyHome(t, `{"content":"`+histAWSKey()+`"}`+"\n")

	out, _ := runHistory(t)
	hook := strings.Index(out, "lyntway hook install")
	migrate := strings.Index(out, "lyntway keys migrate")
	if hook < 0 || migrate < 0 {
		t.Fatalf("the report does not offer both remedies:\n%s", out)
	}
	if hook > migrate {
		t.Error("keys migrate is offered before hook install, so the first instruction after a finding needs an account")
	}
	if !strings.Contains(out, "needs an account") {
		t.Error("the report does not say which remedy needs an account")
	}
	if !strings.Contains(out, "Neither of these needs an account") {
		t.Error("the free remedies are not marked free, so somebody weighing this cannot tell")
	}
}

// Nothing found because nothing was looked at is not a clean machine.
func TestAMachineWithNoAgentsSaysSoRatherThanClean(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))

	out, err := runHistory(t)
	if err != nil {
		t.Fatalf("an empty machine exited non-zero: %v", err)
	}
	if !strings.Contains(out, "nothing to read") {
		t.Errorf("the report does not say there was nothing to read:\n%s", out)
	}
	if !strings.Contains(out, "not the same as a clean machine") {
		t.Error("it did not distinguish an empty machine from a clean one")
	}
	// And it has to leave somebody somewhere to go.
	for _, want := range []string{"--project", "lyntway scan", "container"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report offers no next step mentioning %q", want)
		}
	}
}

// Every command the report names must be copyable out of a terminal.
//
// A line wrap once split "lyntway keys migrate" after the first word. It
// read fine and could not be pasted, which for a report whose whole
// purpose is to tell somebody what to do next is the difference between
// advice and decoration.
func TestNoCommandTheReportOffersIsSplitAcrossLines(t *testing.T) {
	historyHome(t, `{"content":"`+histAWSKey()+`"}`+"\n")
	out, _ := runHistory(t)

	for _, cmd := range []string{
		"lyntway hook install",
		"lyntway guard -- claude",
		"lyntway keys migrate",
		"lyntway history --allow",
	} {
		if !strings.Contains(out, cmd) {
			t.Errorf("%q does not appear whole — a wrap has broken it, so it cannot be copied:\n%s", cmd, out)
		}
	}
}

// The rotation page for each provider found, and no page for a class
// where naming one would be a guess.
func TestTheReportNamesWhereToRevokeWhatItFound(t *testing.T) {
	historyHome(t, `{"content":"`+histAWSKey()+`"}`+"\n")
	out, _ := runHistory(t)

	if !strings.Contains(out, "Where to revoke") {
		t.Errorf("the report says revoke but not where:\n%s", out)
	}
	if !strings.Contains(out, "console.aws.amazon.com") {
		t.Errorf("an AWS key was found and the IAM page is not named:\n%s", out)
	}
}

// The hook reads prompts. Saying otherwise, or saying nothing, lets a
// reader take a narrow protection for a general one.
func TestTheReportSaysWhatTheHookDoesNotCover(t *testing.T) {
	historyHome(t, `{"content":"`+histAWSKey()+`"}`+"\n")
	out, _ := runHistory(t)

	for _, want := range []string{"does not cover", "own file tool"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not state the hook's limit (%q missing):\n%s", want, out)
		}
	}
}
