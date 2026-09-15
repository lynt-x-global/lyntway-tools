package main

// Writes the readiness run to a file and has it signed, so the report can
// be handed to somebody who trusts neither the person handing it over nor
// the service that produced it.
//
// # What the signature settles, and what it does not
//
// It settles that this file is the file that was registered, byte for
// byte, at that time. It says nothing about whether the findings are
// right, whether the check was thorough, or whether the estate is secure.
// Those belong to whoever reads it and to whoever signs an assessment.
//
// That distinction is printed on the report itself rather than left for a
// reader to infer, because a signed document is exactly the kind of thing
// somebody forwards to a regulator with a covering note that claims more
// than it says.
//
// # Why the limits travel with it
//
// An assessor receiving this needs the boundaries as much as the findings:
// which methods were sent, which packages were skipped for having a range
// rather than a version, and that anything which never reached Lyntway is
// absent from the list. A finding without its boundary is how a
// pre-assessment pack becomes a false assurance.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// readinessFormat names the shape so a reader — or a later version of this
// command — can tell what it is holding.
const readinessFormat = "lyntway-readiness/1"

type readinessReport struct {
	Format  string `json:"format"`
	TakenAt string `json:"taken_at"`
	Project string `json:"project"`

	Surface *struct {
		EventsRead int             `json:"events_read"`
		Oldest     string          `json:"oldest,omitempty"`
		Newest     string          `json:"newest,omitempty"`
		Endpoints  []endpointState `json:"endpoints"`
	} `json:"surface,omitempty"`

	Dependencies []depState `json:"dependencies,omitempty"`

	Changes []struct {
		Worse bool   `json:"worse"`
		Text  string `json:"text"`
	} `json:"changes,omitempty"`

	// Limits are part of the document, not a footnote in a covering email.
	Limits []string `json:"limits"`
}

// buildReport assembles what the run found, with its boundaries attached.
func buildReport(snap readinessSnapshot, changes []change, basis surfaceDoc, surfaceRead bool) readinessReport {
	rep := readinessReport{
		Format:  readinessFormat,
		TakenAt: snap.TakenAt,
		Project: filepath.Base(mustAbs(snap.Dir)),
		Limits: []string{
			"This is a check of authentication and of published advisories. It is not a penetration test and does not replace one.",
			"The signature settles that this file has not been altered since it was registered. It says nothing about whether these findings are correct or complete.",
			"Nothing here is certified. Lyntway is not an accredited assessor.",
		},
	}
	if snap.EndpointsChecked {
		rep.Surface = &struct {
			EventsRead int             `json:"events_read"`
			Oldest     string          `json:"oldest,omitempty"`
			Newest     string          `json:"newest,omitempty"`
			Endpoints  []endpointState `json:"endpoints"`
		}{EventsRead: basis.EventsRead, Oldest: basis.Oldest, Newest: basis.Newest, Endpoints: snap.Endpoints}
		rep.Limits = append(rep.Limits,
			"Endpoints listed are those that reached Lyntway in the window above. Anything that never reached it is absent from this list, which is not the same as absent from the estate.",
			"Only GET, HEAD and OPTIONS were sent, and only to hosts named by the operator. No request that could change anything was repeated.")
	}
	if snap.DepsChecked {
		rep.Dependencies = snap.Deps
		rep.Limits = append(rep.Limits,
			"Packages given as a version range rather than an exact version were not checked, because a range describes what may be installed rather than what is.",
			"A package with no advisory has none published today. That is not the same as safe.")
	}
	for _, c := range changes {
		rep.Changes = append(rep.Changes, struct {
			Worse bool   `json:"worse"`
			Text  string `json:"text"`
		}{c.Worse, c.Text})
	}
	if !surfaceRead {
		rep.Limits = append(rep.Limits,
			"The observed surface was not read on this run, so this report covers dependencies only.")
	}
	return rep
}

func mustAbs(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	return abs
}

// signReport writes the report, registers its digest, and saves the receipt
// beside it.
//
// The file is written before anything is sent, and the digest is taken from
// the bytes on disk rather than from the value in memory — so what was
// registered is what a reader will later hash, even if writing it changed
// something we did not expect.
// writeReport puts the run on disk and returns the digest of what landed
// there — read back rather than taken from the value in memory, so what is
// registered is what a reader will later hash.
func writeReport(rep readinessReport, out string) (digest string, size int, err error) {
	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", 0, err
	}
	body = append(body, '\n')
	if err := os.WriteFile(out, body, 0o600); err != nil {
		return "", 0, err
	}
	onDisk, err := os.ReadFile(out)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(onDisk)
	return hex.EncodeToString(sum[:]), len(onDisk), nil
}

// signReport registers a report already on disk and saves the receipt
// beside it.
func signReport(c config, out, digest string, size int) error {

	req := map[string]any{
		"tool": "lyntway-readiness",
		"action": map[string]string{
			"surface": "primitive", "direction": "request", "method": "attest",
		},
		"document": map[string]string{
			"digest":     digest,
			"filename":   filepath.Base(out),
			"media_type": "application/json",
			"format":     readinessFormat,
		},
	}

	status, raw, err := api(c, http.MethodPost, "/v1/attest", req)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("registering the report: %s", apiMessage(status, raw))
	}

	var answer struct {
		Receipt json.RawMessage `json:"receipt"`
		Warning string          `json:"warning,omitempty"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return fmt.Errorf("reading the receipt: %w", err)
	}

	receiptPath := strings.TrimSuffix(out, filepath.Ext(out)) + ".receipt.json"
	pretty := receiptJSON(answer.Receipt)
	if err := os.WriteFile(receiptPath, pretty, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "  ✓ %s\n", out)
	fmt.Fprintf(stdout, "  ✓ %s\n", receiptPath)
	fmt.Fprintf(stdout, "    sha-256 %s  (%d bytes)\n", digest, size)
	if answer.Warning != "" {
		fmt.Fprintf(stdout, "    ! %s\n", answer.Warning)
	}
	fmt.Fprintln(stdout, "\n  Anyone can check the pair without an account:")
	fmt.Fprintf(stdout, "    curl -O %s/.well-known/lyntway-keys.json\n", strings.TrimRight(c.Origin, "/"))
	fmt.Fprintf(stdout, "    lyntway-verify -keys lyntway-keys.json -file %s %s\n", out, receiptPath)
	fmt.Fprintln(stdout, "\n  The signature settles that the file was not altered. It says nothing about whether")
	fmt.Fprintln(stdout, "  the findings are right, which belongs to whoever signs the assessment.")
	return nil
}

// receiptJSON re-indents the receipt for a person to read.
//
// Safe because verification canonicalises per RFC 8785 before checking the
// signature, so whitespace is not part of what was signed — confirmed by
// re-indenting one and watching it still verify. A receipt that cannot be
// re-encoded is written exactly as it arrived rather than not at all.
func receiptJSON(raw json.RawMessage) []byte {
	var any any
	if err := json.Unmarshal(raw, &any); err != nil {
		return append([]byte(raw), '\n')
	}
	pretty, err := json.MarshalIndent(any, "", "  ")
	if err != nil {
		return append([]byte(raw), '\n')
	}
	return append(pretty, '\n')
}

// uploadReport sends the report to the account, so a security team can see
// every project's last run in one place instead of asking twelve teams for
// a screenshot.
//
// The bytes go up exactly as they sit on disk. That is the whole point: the
// digest the service records is then the same digest the receipt names, so
// a reader can tie a row in the console to a document in their hand. An
// upload that re-encoded the report would break that link and nothing would
// look wrong.
func uploadReport(c config, out string) error {
	raw, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	status, body, err := apiRaw(c, http.MethodPost, "/v1/readiness", raw)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("%s", apiMessage(status, body))
	}

	var answer struct {
		Digest string `json:"digest"`
	}
	_ = json.Unmarshal(body, &answer)
	sum := sha256.Sum256(raw)
	if mine := hex.EncodeToString(sum[:]); answer.Digest != "" && answer.Digest != mine {
		// Said rather than swallowed: the console would show a digest that
		// matches nothing anybody holds, and the mismatch is the only sign.
		return fmt.Errorf("the service recorded a different digest (%s) than the file has (%s); "+
			"something altered the report in transit", answer.Digest, mine)
	}
	fmt.Fprintf(stdout, "  ✓ reported to %s\n", strings.TrimRight(c.Origin, "/"))
	return nil
}
