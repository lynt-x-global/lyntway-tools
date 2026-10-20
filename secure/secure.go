// Package secure is the one command.
//
// # Why this exists as its own thing
//
// The feature worked and the journey did not. A person ran `lyntway
// history`, saw a number, and was then told to revoke credentials, run
// `hook install`, run `guard`, and maybe `keys migrate` — four more
// decisions after the only moment they were paying attention. Everything
// after the first command is a funnel, and every step of a funnel loses
// most of the people on it.
//
// So: one invocation. It looks, it shows what it found, it asks once, and
// then it installs the prompt hook. Nothing is installed before that question and
// nothing is installed if the answer is no.
//
// # What it will not do, even for magic
//
// It will not change the machine without asking. The README's promise is
// that "everything that changes your machine is a separate command that
// shows you the change and asks", and a tool that silently edits an
// editor's configuration because the word on the box was "magic" has
// broken the one thing a security tool is for. The compromise that costs
// nothing is one question instead of four commands: the change is shown,
// consent is given once, and the rest happens.
//
// --yes skips the question, for a provisioning script that has already
// decided. It is never the default, because an unattended install is a
// thing somebody chose and not a thing we assume.
package secure

import (
	"fmt"
	"io"
	"strings"

	"github.com/lynt-x-global/lyntway-tools/agentsecrets"
)

// Step is one thing this command did, or refused to do.
//
// Collected rather than printed as it goes, so the summary at the end can
// say what changed in the order a person cares about and so a failure
// part-way through still reports what had already happened. A security
// tool that stops half-done and says nothing leaves a machine in a state
// nobody can describe.
type Step struct {
	What string

	// Done is false when the step was skipped or failed; Why says which.
	Done bool
	Why  string
}

// Outcome is everything the run did.
type Outcome struct {
	// Found is what the scan saw, before anything was changed.
	Found []agentsecrets.Credential

	// Scan carries the counts, so the report can say what was read and
	// whether the look was complete.
	Scan agentsecrets.Result

	// Asked is false when --yes was given: a reader of the summary
	// should be able to tell consent from assumption.
	Asked bool

	// Agreed is what the person said, or true under --yes.
	Agreed bool

	Steps []Step
}

// Protected reports whether anything on the machine actually changed.
func (o Outcome) Protected() bool {
	for _, s := range o.Steps {
		if s.Done {
			return true
		}
	}
	return false
}

// Installer is the side-effecting half, passed in so the flow can be
// tested without touching an editor's configuration on the machine
// running the tests.
type Installer interface {
	// HookInto makes the editor refuse a prompt carrying a credential.
	// Called once per editor that is present.
	HookInto(editor string) error

	// Editors lists the editors on this machine that can take a hook.
	// Empty is a normal answer and is reported, not treated as failure.
	Editors() []string
}

// Run is the whole command.
//
// ask is called at most once and only when something was found: there is
// nothing to consent to on a clean machine, and asking anyway trains
// somebody to press y without reading.
func Run(out io.Writer, res agentsecrets.Result, inst Installer,
	ask func(string) bool, assumeYes bool) Outcome {

	o := Outcome{Found: res.Credentials(), Scan: res}
	writeFound(out, o)

	if len(o.Found) == 0 {
		// Nothing to close. The hook is still worth having, and is still
		// a change to the machine, so it is offered as a sentence rather
		// than done — somebody whose machine is clean did not come here
		// to have their editor edited.
		fmt.Fprint(out, "Nothing to close here. To keep it that way:\n"+
			"  lyntway hook install      refuse a prompt carrying a key, before it is sent\n\n")
		return o
	}

	o.Asked = !assumeYes
	if assumeYes {
		o.Agreed = true
	} else {
		editors := inst.Editors()
		if len(editors) == 0 {
			fmt.Fprint(out, "No editor here that can take a prompt hook, so there is nothing to install.\n"+
				"Revoking the credentials above is the whole of the fix on this machine.\n\n")
			return o
		}
		fmt.Fprintf(out, "This can stop the next one. %s would refuse a prompt carrying a\n"+
			"credential before it is sent — read locally, nothing sent anywhere, and\n"+
			"`lyntway undo` puts the configuration back byte for byte.\n\n",
			strings.Join(editors, " and "))
		o.Agreed = ask("Set that up now? [y/N] ")
	}
	if !o.Agreed {
		fmt.Fprint(out, "\nNothing was changed. The credentials above still need revoking.\n\n")
		return o
	}

	for _, editor := range inst.Editors() {
		step := Step{What: "prompt hook in " + editor}
		if err := inst.HookInto(editor); err != nil {
			step.Why = err.Error()
		} else {
			step.Done = true
		}
		o.Steps = append(o.Steps, step)
	}
	writeDone(out, o)
	return o
}
