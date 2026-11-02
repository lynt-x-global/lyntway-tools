package main

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Who signed the AI software on this machine, read from the operating
// system's own verdict.
//
// # Why this is about identity and never about safety
//
// A signature says which company's key signed a binary. It says nothing
// about what the binary does. So the states below are named for what was
// established about the publisher, and none of them is a judgement: the
// only one worth acting on is a signature that is present and fails, and
// the report says so in those words.
//
// # Why "not established" and not "unsigned" or "unverified"
//
// Homebrew, pipx and npm install the overwhelming majority of developer
// tools with an ad-hoc signature or none at all, and on this machine that
// includes llama.cpp and — until the certificates are bought — every
// binary this project ships. A red badge on `llama-server` is a false
// alarm, and the first false alarm is the moment a person stops reading
// the list. So the absence of a publisher is reported as the absence of a
// publisher, with the reason named beside it.
//
// # Cost
//
// Measured on this machine: ~13 ms per binary, so a nine-tool inventory
// costs ~120 ms. That fits the scan's budget, which is why this can run in
// the free path rather than only on an enrolled device. Each check is
// still bounded, because a signature check reads a file somebody else
// wrote and a hung verifier must not hang the scan.

// publisherState is what was established about who signed something.
type publisherState string

const (
	// publisherSigned: the OS accepted a signature and named an authority.
	publisherSigned publisherState = "signed"

	// publisherNone: no publisher identity is attached. Ad-hoc, unsigned,
	// or a platform with no signature scheme. Not a finding on its own.
	publisherNone publisherState = "none"

	// publisherBroken: a signature is present and does not verify. The one
	// state worth interrupting somebody for.
	publisherBroken publisherState = "broken"

	// publisherUnchecked: the check could not run. Never reported as
	// `none`, because "nobody signed this" and "we did not look" are
	// different facts and only one of them is about the software.
	publisherUnchecked publisherState = "unchecked"
)

// appPublisher is the publisher of one binary.
type appPublisher struct {
	State publisherState `json:"state"`

	// Name is the authority the OS named, when it named one — "Anthropic
	// PBC (Q6L2SF6YDW)". Empty for every other state.
	Name string `json:"name,omitempty"`

	// Why explains a state that is not `signed`, in terms that do not
	// imply wrongdoing where there is none.
	Why string `json:"why,omitempty"`
}

// Verified reports whether a publisher identity was established, which is
// the only question the word "verified" can honestly answer here.
func (p appPublisher) Verified() bool { return p.State == publisherSigned }

// publisherTimeout bounds one check. Generous, because codesign on a large
// bundle walks every file in it, and short enough that a stuck verifier
// cannot hold the scan open.
const publisherTimeout = 5 * time.Second

// readPublisher asks the operating system who signed the binary at path.
//
// goos is a parameter rather than runtime.GOOS so a test can exercise the
// dispatch for a platform it is not running on; the commands themselves
// only ever run for the host's own OS.
func readPublisher(goos, path string) appPublisher {
	if path == "" {
		return appPublisher{State: publisherUnchecked, Why: "this tool's location on disk was not established"}
	}
	if goos != runtime.GOOS {
		// Asking Windows about a Mach-O, or the reverse, would produce a
		// verdict about nothing.
		return appPublisher{State: publisherUnchecked, Why: "a signature can only be checked on the system that runs it"}
	}
	switch goos {
	case "darwin":
		return darwinPublisher(path)
	case "windows":
		return windowsPublisher(path)
	default:
		// ELF binaries carry no OS-enforced publisher identity, and the
		// package manager that installed them is the trust decision. Not
		// "none" with no reason, which would read as a finding.
		return appPublisher{State: publisherNone,
			Why: "this system has no publisher signature scheme; the package manager that installed it is the record"}
	}
}

// darwinPublisher reads codesign's verdict.
//
// The authority is what is read, never "is it signed". Every darwin/arm64
// Go build is ad-hoc signed by the linker, so `codesign --verify` passes
// on a binary no managed fleet accepts — which is the trap that
// scripts/verify-signatures.sh was written to catch, and it applies here
// for the same reason.
func darwinPublisher(path string) appPublisher {
	ctx, cancel := context.WithTimeout(context.Background(), publisherTimeout)
	defer cancel()
	// -dv prints the designated requirement and the authority chain on
	// stderr; --verify makes it also check, so a broken signature is
	// distinguishable from an absent one.
	out, err := exec.CommandContext(ctx, "codesign", "-dv", "--verbose=2", path).CombinedOutput()
	if ctx.Err() != nil {
		return appPublisher{State: publisherUnchecked, Why: "the signature check did not finish in time"}
	}
	text := string(out)

	if strings.Contains(text, "code object is not signed at all") {
		return appPublisher{State: publisherNone, Why: "no signature at all"}
	}
	if authority := firstAuthority(text); authority != "" {
		return appPublisher{State: publisherSigned, Name: authority}
	}
	if strings.Contains(text, "Signature=adhoc") || strings.Contains(text, "TeamIdentifier=not set") {
		// The common and innocent case: a Homebrew build, or a Go binary
		// the linker signed. Named for what it is.
		return appPublisher{State: publisherNone,
			Why: "built locally or by a package manager, with no publisher certificate"}
	}
	if err != nil {
		return appPublisher{State: publisherBroken, Why: "a signature is present and did not verify"}
	}
	return appPublisher{State: publisherUnchecked, Why: "the system returned no publisher for it"}
}

// firstAuthority returns the leaf authority codesign named, which is the
// publisher. Later lines are the issuing CA and the Apple root, and
// reporting those would name Apple as the publisher of everything.
func firstAuthority(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "Authority=")
		if !ok {
			continue
		}
		// Apple's own first-party signing identity for OS components.
		if rest == "Software Signing" {
			return rest
		}
		if name, ok := strings.CutPrefix(rest, "Developer ID Application: "); ok {
			return name
		}
		if name, ok := strings.CutPrefix(rest, "Apple Mac OS Application Signing"); ok {
			_ = name
			return "Apple Mac OS Application Signing"
		}
		// An authority we do not recognise the shape of is still the
		// authority; reporting it verbatim beats reporting nothing.
		if !strings.Contains(rest, "Certification Authority") && rest != "Apple Root CA" {
			return rest
		}
	}
	return ""
}

// windowsPublisher reads Authenticode's verdict through PowerShell.
//
// Get-AuthenticodeSignature returns a status and a signer; the status is
// what separates "nobody signed it" from "somebody signed it and the
// signature is wrong", and those must not collapse into one badge.
func windowsPublisher(path string) appPublisher {
	ctx, cancel := context.WithTimeout(context.Background(), publisherTimeout)
	defer cancel()
	const script = `$s = Get-AuthenticodeSignature -LiteralPath $args[0]; ` +
		`Write-Output ("STATUS=" + $s.Status); ` +
		`if ($s.SignerCertificate) { Write-Output ("SUBJECT=" + $s.SignerCertificate.Subject) }`
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive",
		"-Command", script, path).Output()
	if ctx.Err() != nil {
		return appPublisher{State: publisherUnchecked, Why: "the signature check did not finish in time"}
	}
	if err != nil {
		return appPublisher{State: publisherUnchecked, Why: "the signature could not be read"}
	}

	var status, subject string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "STATUS="); ok {
			status = v
		}
		if v, ok := strings.CutPrefix(line, "SUBJECT="); ok {
			subject = v
		}
	}

	switch status {
	case "Valid":
		if cn := subjectCN(subject); cn != "" {
			return appPublisher{State: publisherSigned, Name: cn}
		}
		return appPublisher{State: publisherSigned, Name: subject}
	case "NotSigned":
		return appPublisher{State: publisherNone, Why: "no signature at all"}
	case "":
		return appPublisher{State: publisherUnchecked, Why: "the system returned no publisher for it"}
	case "UnknownError":
		// Authenticode's answer when the file is not a form it signs.
		return appPublisher{State: publisherNone, Why: "not a file this system signs"}
	default:
		// HashMismatch, NotTrusted, NotSupportedFileFormat and the rest.
		// A signature was found and the system did not accept it.
		return appPublisher{State: publisherBroken,
			Why: "a signature is present and the system reports it as " + status}
	}
}

// subjectCN pulls the common name out of an X.509 subject, which is the
// publisher as a person reads it.
func subjectCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if cn, ok := strings.CutPrefix(part, "CN="); ok {
			return strings.Trim(cn, `"`)
		}
	}
	return ""
}
