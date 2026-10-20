package secure

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/agentsecrets"
)

// fakeInstaller records what would have been done to the machine.
type fakeInstaller struct {
	editors []string
	fail    map[string]error
	hooked  []string
}

func (f *fakeInstaller) Editors() []string { return f.editors }

func (f *fakeInstaller) HookInto(editor string) error {
	if err, bad := f.fail[editor]; bad {
		return err
	}
	f.hooked = append(f.hooked, editor)
	return nil
}

func found(n int) agentsecrets.Result {
	var r agentsecrets.Result
	r.Sources, r.Files, r.Bytes = 3, 12, 4<<20
	for i := 0; i < n; i++ {
		r.Findings = append(r.Findings, agentsecrets.Finding{
			Fingerprint: strings.Repeat(string(rune('a'+i)), 12),
			Label:       "AWS access key",
			Last4:       "AAAA",
			Kind:        agentsecrets.KindTranscript,
			Tool:        "Claude Code",
		})
	}
	return r
}

// Nothing changes before the question, and nothing changes if the answer
// is no. The README's promise is that every change is shown and asked
// about; "one command" was never licence to drop that.
func TestNothingIsInstalledWithoutConsent(t *testing.T) {
	inst := &fakeInstaller{editors: []string{"Claude Code", "Cursor"}}
	var buf bytes.Buffer

	asked := 0
	o := Run(&buf, found(2), inst, func(string) bool { asked++; return false }, false)

	if asked != 1 {
		t.Errorf("asked %d times, want exactly one question", asked)
	}
	if len(inst.hooked) != 0 {
		t.Errorf("configured %v after the answer was no", inst.hooked)
	}
	if o.Protected() {
		t.Error("the outcome claims the machine was protected after a refusal")
	}
	if !strings.Contains(buf.String(), "Nothing was changed") {
		t.Error("the report does not say nothing changed")
	}
	// And it must still say the credentials need dealing with.
	if !strings.Contains(buf.String(), "still need revoking") {
		t.Error("declining lost the remedy")
	}
}

// One question, then every editor present.
func TestOneQuestionThenEveryEditorPresent(t *testing.T) {
	inst := &fakeInstaller{editors: []string{"Claude Code", "Cursor"}}
	var buf bytes.Buffer

	asked := 0
	o := Run(&buf, found(1), inst, func(string) bool { asked++; return true }, false)

	if asked != 1 {
		t.Errorf("asked %d times; the whole point of this command is one question", asked)
	}
	if len(inst.hooked) != 2 {
		t.Errorf("configured %v, want both editors", inst.hooked)
	}
	if !o.Protected() || !o.Agreed || !o.Asked {
		t.Errorf("outcome = %+v", o)
	}
}

// --yes is consent somebody gave in advance, and the summary has to be
// able to tell that apart from a question that was answered.
func TestAssumeYesIsRecordedAsNotAsked(t *testing.T) {
	inst := &fakeInstaller{editors: []string{"Claude Code"}}
	var buf bytes.Buffer

	o := Run(&buf, found(1), inst, func(string) bool {
		t.Error("--yes still asked")
		return false
	}, true)

	if o.Asked {
		t.Error("the outcome says somebody was asked when --yes was given")
	}
	if !o.Agreed || len(inst.hooked) != 1 {
		t.Errorf("--yes did not install: %+v", inst.hooked)
	}
}

// A clean machine is not asked anything. There is nothing to consent to,
// and asking anyway trains somebody to press y without reading.
func TestACleanMachineIsNotAsked(t *testing.T) {
	inst := &fakeInstaller{editors: []string{"Claude Code"}}
	var buf bytes.Buffer

	o := Run(&buf, found(0), inst, func(string) bool {
		t.Error("a machine with no findings was asked to change its configuration")
		return true
	}, false)

	if len(inst.hooked) != 0 {
		t.Errorf("configured %v on a clean machine", inst.hooked)
	}
	if o.Protected() {
		t.Error("claimed protection on a machine where nothing was done")
	}
	if !strings.Contains(buf.String(), "No credentials") {
		t.Errorf("the clean report does not say so:\n%s", buf.String())
	}
}

// A machine with no agent on it is not a clean machine.
func TestNoAgentFilesIsNotReportedAsClean(t *testing.T) {
	var buf bytes.Buffer
	Run(&buf, agentsecrets.Result{}, &fakeInstaller{}, func(string) bool { return true }, false)

	out := buf.String()
	if !strings.Contains(out, "nothing to read") {
		t.Errorf("an empty machine is not described:\n%s", out)
	}
	if !strings.Contains(out, "not a clean machine") {
		t.Error("an empty machine was not distinguished from a clean one")
	}
}

// A partial install is reported as partial. A machine left half
// configured that reports success is worse than one that reports nothing.
func TestAFailedInstallIsNamedNotSwallowed(t *testing.T) {
	inst := &fakeInstaller{
		editors: []string{"Claude Code", "Cursor"},
		fail:    map[string]error{"Cursor": errFake},
	}
	var buf bytes.Buffer

	o := Run(&buf, found(1), inst, func(string) bool { return true }, false)
	out := buf.String()

	if !strings.Contains(out, "Cursor") || !strings.Contains(out, errFake.Error()) {
		t.Errorf("the failure is not named:\n%s", out)
	}
	if !strings.Contains(out, "did not take") {
		t.Error("a partial configuration was reported as a success")
	}
	// The one that worked is still reported as done.
	var done int
	for _, s := range o.Steps {
		if s.Done {
			done++
		}
	}
	if done != 1 {
		t.Errorf("%d steps done, want the one that succeeded", done)
	}
}

// An incomplete look must never read as a clean result, even here where
// the headline is a count of findings.
func TestAnIncompleteLookIsSaidSo(t *testing.T) {
	res := found(1)
	res.Unread = []agentsecrets.Unread{{Tool: "Claude Code", Path: "/x", Reason: "larger than 2048 MB"}}
	var buf bytes.Buffer

	Run(&buf, res, &fakeInstaller{editors: []string{"Claude Code"}}, func(string) bool { return true }, false)
	if !strings.Contains(buf.String(), "not in\nthe count above") {
		t.Errorf("an unread file is not reflected in the report:\n%s", buf.String())
	}
}

// The fixture caveat is above the list, not under it. Somebody who takes
// the number and stops has to have been told.
func TestTheFixtureCaveatComesBeforeTheList(t *testing.T) {
	var buf bytes.Buffer
	Run(&buf, found(2), &fakeInstaller{}, func(string) bool { return false }, false)
	out := buf.String()

	caveat := strings.Index(out, "test fixtures")
	list := strings.Index(out, "AWS access key")
	if caveat < 0 || list < 0 {
		t.Fatalf("report is missing a part:\n%s", out)
	}
	if caveat > list {
		t.Error("the caveat is printed after the findings")
	}
}

var errFake = fakeErr("the file was read-only")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

// The one-command flow is the whole command for most people, so it has to
// name the console page itself rather than defer to `lyntway history`.
func TestSecureNamesWhereToRevokeAndWhatTheHookMisses(t *testing.T) {
	var out strings.Builder
	res := agentsecrets.Result{
		Findings: []agentsecrets.Finding{{
			Tool: "Claude Code", Kind: agentsecrets.KindTranscript,
			Label: "Stripe key", Class: "secret.stripe_key",
			Fingerprint: "aaaaaaaaaaaa", Last4: "TKdu", Path: "/x", Line: 1,
		}},
		Files: 1, Bytes: 10, Sources: 1,
	}
	o := Run(&out, res, &fakeInstaller{editors: []string{"Claude Code"}}, func(string) bool { return true }, true)
	got := out.String()

	if !o.Protected() {
		t.Fatal("the hook did not install, so this is testing the wrong path")
	}
	if !strings.Contains(got, "dashboard.stripe.com") {
		t.Errorf("a Stripe key was found and the console page is not named:\n%s", got)
	}
	// The limit, at the moment success is claimed.
	if !strings.Contains(got, "does not") || !strings.Contains(got, "own file tool") {
		t.Errorf("the hook's limit is not stated beside the success line:\n%s", got)
	}
	// And still no value, which no amount of helpfulness may change.
	if strings.Contains(got, "sk_live") || strings.Contains(got, "sk_test") {
		t.Errorf("a value reached the report:\n%s", got)
	}
}

// What a Windows reader is told, asked from whatever platform runs this.
func TestTheCaveatReachesTheReportOnAnUncheckedPlatform(t *testing.T) {
	saved := goos
	goos = func() string { return "windows" }
	defer func() { goos = saved }()

	var out strings.Builder
	res := agentsecrets.Result{
		Findings: []agentsecrets.Finding{{
			Tool: "Claude Code", Kind: agentsecrets.KindTranscript,
			Label: "AWS access key", Class: "secret.aws_access_key",
			Fingerprint: "bbbbbbbbbbbb", Last4: "D9PL", Path: "/x", Line: 1,
		}},
		Files: 1, Bytes: 10, Sources: 1,
	}
	Run(&out, res, &fakeInstaller{editors: []string{"Claude Code"}}, func(string) bool { return true }, true)
	if !strings.Contains(out.String(), "clean machine") {
		t.Errorf("a Windows reader is not warned that a low count is unverified:\n%s", out.String())
	}
}
