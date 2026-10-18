package main

import (
	"bytes"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Four documents outside this binary tell a person — or their agent — what
// to type. A command renamed here and left there is not a stale sentence;
// it is an instruction that fails in front of somebody on their first
// minute, in a file an agent will repeat without checking.
//
// This is the same contract the ruleset screens have: one place is the
// source, and a test reads both rather than trusting that whoever renames
// a command will remember four files.

var documentedCommands = []string{
	"../../console/published/skill.md",
	"../../plugin/skills/lyntway/SKILL.md",
	"../../plugin/commands/lyntway-scan.md",
	"../../README.md",
}

// Only a mention somebody could copy counts: a line in a code block, a
// `backticked` command, or one written after npx. Prose is excluded on
// purpose — "lyntway stopped this request" is a sentence about what
// happened, not an instruction, and a checker that read it as one would
// have to be silenced to pass, which is how a check stops being one.
var (
	codeCommand  = regexp.MustCompile(`^\s*(?:\$ )?(?:npx )?lyntway ([a-z][a-z-]*)`)
	proseCommand = regexp.MustCompile(`(?:` + "`" + `|npx )lyntway ([a-z][a-z-]*)`)
	fence        = regexp.MustCompile("^\\s*```")
)

// commandsNamedIn returns the subcommands a document tells somebody to run.
func commandsNamedIn(doc string) []string {
	seen := map[string]bool{}
	inFence := false
	for _, line := range strings.Split(doc, "\n") {
		if fence.MatchString(line) {
			inFence = !inFence
			continue
		}
		indented := strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t")
		if inFence || indented {
			if m := codeCommand.FindStringSubmatch(line); m != nil {
				seen[m[1]] = true
			}
			continue
		}
		for _, m := range proseCommand.FindAllStringSubmatch(line, -1) {
			seen[m[1]] = true
		}
	}
	var out []string
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func TestEveryCommandWeTellPeopleToRunIsOneThisBinaryHas(t *testing.T) {
	var usage bytes.Buffer
	usageTo(&usage)
	listed := usage.String()

	for _, path := range documentedCommands {
		raw, err := os.ReadFile(path)
		if err != nil {
			// The mirrored module carries cmd/ without the documents this
			// checks. The contract belongs to the source tree.
			t.Skipf("%s is not in this tree: %v", path, err)
		}
		for _, c := range commandsNamedIn(string(raw)) {
			if !strings.Contains(listed, "lyntway "+c) {
				t.Errorf("%s tells people to run `lyntway %s`, which this binary's usage does not list", path, c)
			}
		}
	}
}

func TestTheAgentFacingFilesNameTheCommandWeLeadWith(t *testing.T) {
	for _, path := range []string{
		"../../console/published/skill.md",
		"../../plugin/skills/lyntway/SKILL.md",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s is not in this tree: %v", path, err)
		}
		for _, want := range []string{"lyntway scan", "lyntway guard", "lyntway hook install"} {
			if !strings.Contains(string(raw), want) {
				t.Errorf("%s does not mention `%s`", path, want)
			}
		}
	}
}
