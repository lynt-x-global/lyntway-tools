package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Scanning what is still in the repository's history.
//
// `scan` read the working tree, the index or a diff, and every one of
// those answers the question "is a key about to leave?". None of them
// answers the one a person asks after a leak: is the key still in here.
//
// It is not the same question and the difference is the whole of the
// remediation. A developer who finds a key in .env deletes the line,
// commits, and believes it is gone. It is not gone: it is in the commit
// that added it, in every clone, in every fork, and in the pull request's
// diff on a service nobody controls. A scanner that reads only the tip
// agrees with them — it reports clean, which is the answer that ends the
// investigation.
//
// So this walks every reachable commit and reads the lines each one
// added. The expensive part is git's, and it is one invocation rather
// than one per commit: `git log -p` streams the whole history in a single
// pass, and the parser that already reads a diff reads each one.
//
// # One credential is one finding
//
// A key added once and carried through two hundred commits is one key.
// Reporting two hundred findings would be a number nobody can act on and
// a claim nobody can check, which is the failure `lyntway history`
// already names: the count must never be inflated. So sightings are
// grouped by what they are and what they end with, and each line says how
// many commits carry it and which one put it there.

// historyFinding is one credential, across every commit that carries it.
type historyFinding struct {
	Label string
	Class string
	Last4 string

	// Commits that carry it, oldest first, and the files it appeared in.
	Commits []string
	Files   []string

	// InWorkingTree is true when the same credential is still in the
	// files on disk. False is the dangerous case and the one this command
	// exists for: removed from the tip, still in every clone.
	InWorkingTree bool
}

// scanHistory walks every reachable commit and groups what it finds.
//
// rev is passed to git log as-is when set, so a caller can narrow to a
// branch or a range; empty means --all, which is the only answer that
// includes a key living on a branch nobody has merged.
func scanHistory(dir, rev string) ([]historyFinding, int, error) {
	args := []string{
		"log", "--no-merges", "-p", "--unified=0", "--no-color", "--no-ext-diff",
		"--diff-filter=ACMR",
		// A header this parser can find and a diff cannot accidentally
		// produce: a NUL, which git will not emit inside a path.
		"--format=%x00commit %H",
	}
	if rev == "" {
		args = append(args, "--all")
	} else {
		args = append(args, rev)
	}
	args = append(args, "--")

	out, err := gitOutput(dir, args...)
	if err != nil {
		return nil, 0, err
	}

	// In the working tree now, so a finding can say whether removing it
	// from the tip was the whole of the fix.
	inTree := map[string]bool{}
	if treeHits, _, _, err := scanPaths([]string{dir}); err == nil {
		for _, h := range treeHits {
			inTree[h.Class+"\x00"+h.Last4] = true
		}
	}

	type group struct {
		f       historyFinding
		commits map[string]bool
		files   map[string]bool
		order   []string
	}
	groups := map[string]*group{}
	commits := 0

	for _, chunk := range bytes.Split(out, []byte("\x00")) {
		if len(bytes.TrimSpace(chunk)) == 0 {
			continue
		}
		// Each chunk is "commit <sha>\n" followed by that commit's diff.
		nl := bytes.IndexByte(chunk, '\n')
		if nl < 0 {
			continue
		}
		header := string(bytes.TrimSpace(chunk[:nl]))
		sha := strings.TrimPrefix(header, "commit ")
		if sha == header || len(sha) < 7 {
			continue
		}
		commits++

		hits, _ := parseDiff(chunk[nl+1:])
		for _, h := range hits {
			// A value a secret-scanner config declares is not a finding
			// here either, for the reason splitDeclared gives: the
			// repository has already said what it is.
			if h.Declared != "" {
				continue
			}
			key := h.Class + "\x00" + h.Last4
			g := groups[key]
			if g == nil {
				g = &group{
					f:       historyFinding{Label: h.Label, Class: h.Class, Last4: h.Last4, InWorkingTree: inTree[key]},
					commits: map[string]bool{},
					files:   map[string]bool{},
				}
				groups[key] = g
			}
			if !g.commits[sha] {
				g.commits[sha] = true
				g.order = append(g.order, sha)
			}
			g.files[h.File] = true
		}
	}

	out2 := make([]historyFinding, 0, len(groups))
	for _, g := range groups {
		f := g.f
		// git log is newest first; a reader wants the commit that
		// introduced it, so the order is reversed here rather than asking
		// git for a second pass.
		for i := len(g.order) - 1; i >= 0; i-- {
			f.Commits = append(f.Commits, g.order[i])
		}
		for name := range g.files {
			f.Files = append(f.Files, name)
		}
		sort.Strings(f.Files)
		out2 = append(out2, f)
	}
	// The ones no longer in the tree first: those are the ones somebody
	// believes they have already fixed.
	sort.Slice(out2, func(i, j int) bool {
		if out2[i].InWorkingTree != out2[j].InWorkingTree {
			return !out2[i].InWorkingTree
		}
		if len(out2[i].Commits) != len(out2[j].Commits) {
			return len(out2[i].Commits) > len(out2[j].Commits)
		}
		return out2[i].Label < out2[j].Label
	})
	return out2, commits, nil
}

// printHistory writes the report a person reads.
func printHistory(found []historyFinding, commits int) {
	if len(found) == 0 {
		// "commits that added something", not "commits": a commit whose
		// only change is a deletion adds no lines and git does not list
		// it under --diff-filter=ACMR. Saying "4 commits" over a history
		// of nine would be a number that does not mean what it says.
		fmt.Fprintf(stdout, "No provider keys in %d commit%s that added content.\n", commits, pluralS(commits))
		return
	}
	for _, f := range found {
		where := "still in the working tree"
		if !f.InWorkingTree {
			where = "NOT in the working tree — only in history"
		}
		fmt.Fprintf(stdout, "%s\t…%s\t%d commit%s\t%s\n",
			f.Label, f.Last4, len(f.Commits), pluralS(len(f.Commits)), where)
		fmt.Fprintf(stdout, "\tfirst added in %s, in %s\n", short(f.Commits[0]), strings.Join(f.Files, ", "))
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, historyAdvice(found))
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// historyAdvice says the one thing that actually fixes this.
//
// Rewriting history is the obvious suggestion and it is not the fix. Every
// clone, every fork and every CI cache still holds the old objects, and a
// pull request's diff lives on a service the repository's owner does not
// control. The credential has to be revoked; rewriting is housekeeping
// done afterwards, if at all.
func historyAdvice(found []historyFinding) string {
	hidden := 0
	for _, f := range found {
		if !f.InWorkingTree {
			hidden++
		}
	}
	var b strings.Builder
	b.WriteString("Revoke each key above. A key in a commit is in every clone of this\n")
	b.WriteString("repository, in every fork, and in the diff of any pull request that\n")
	b.WriteString("carried it — rewriting history reaches none of those.\n")
	if hidden > 0 {
		b.WriteString(fmt.Sprintf("\n%d of them %s no longer in the working tree. Deleting the line was not\n",
			hidden, map[bool]string{true: "is", false: "are"}[hidden == 1]))
		b.WriteString("the fix, and a scan of the files on disk reports this repository clean.\n")
	}
	return b.String()
}
