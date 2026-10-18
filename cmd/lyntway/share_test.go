package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A share link is the one artefact of this product that reaches somebody
// who has never heard of us. Every test here is about it not saying more
// than it can: no content in it, the limit stated before it is pasted, and
// the receipt it carries being the one the sender chose.

// shareFixture writes a receipt file and the key file beside it, the way a
// guard session leaves them.
func shareFixture(t *testing.T, receipts ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "guard-anthropic.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(receipts, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The key values are never decoded here — this exercises which key is
	// copied into a link, not a signature — so they are written to read as
	// fixtures to a person and to a scanner. A base64-shaped literal here
	// trips GitHub's push protection on the public mirror, and the only
	// honest fix for that is a fixture that is obviously not a key.
	keys := `{"keys":{"local-abc":"NOTAREALKEYonlyAShareTestFixture",` +
		`"other-key":"NOTAREALKEYeitherAndNotCopiedOut"},` +
		`"algorithms":{"local-abc":"ed25519","other-key":"ed25519"}}`
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), []byte(keys), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeReceipt(id string, count int) string {
	return `{"version":"lyntway-receipt/1","id":"` + id + `",` +
		`"issuer":{"key_id":"local-abc"},` +
		`"chain":{"id":"guard/anthropic","seq":0},` +
		`"action":{"surface":"model","direction":"request","method":"POST /v1/messages","destination":"api.anthropic.com"},` +
		`"content":{"algorithm":"sha-256","input_digest":"aa","bytes":81},` +
		`"governance":{"mode":"full","decision":"block","findings":[{"class":"secret.supabase_key","count":` +
		itoa(count) + `,"decision":"block"}]},` +
		`"evidence":{"provenance":"observed","vantage":"guard/anthropic"},` +
		`"signature":{"algorithm":"ed25519","key_id":"local-abc","canonicalization":"jcs","value":"c2ln"}}`
}

func itoa(n int) string { return string(rune('0' + n)) }

// decodeShared pulls the two halves back out of a link.
func decodeShared(t *testing.T, link string) (map[string]any, map[string]any) {
	t.Helper()
	_, frag, ok := strings.Cut(link, "#")
	if !ok {
		t.Fatalf("no fragment in %q", link)
	}
	params, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	raw, err := base64.RawURLEncoding.DecodeString(params.Get("receipt"))
	if err != nil {
		t.Fatalf("the receipt half does not decode: %v", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the receipt half is not JSON: %v", err)
	}
	keys := map[string]any{}
	if k := params.Get("key"); k != "" {
		kraw, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil {
			t.Fatalf("the key half does not decode: %v", err)
		}
		if err := json.Unmarshal(kraw, &keys); err != nil {
			t.Fatalf("the key half is not JSON: %v", err)
		}
	}
	return out, keys
}

// The receipt rides in the fragment, which browsers never send to a
// server. If it ever moved into the path or the query, following a shared
// link would tell us what somebody shared and how often — and the sentence
// this product rests on would stop being true.
func TestTheReceiptRidesInTheFragmentAndNowhereElse(t *testing.T) {
	path := shareFixture(t, fakeReceipt("rcpt_one", 1))
	var out bytes.Buffer
	if err := runShare(shareOptions{File: path, Origin: "https://lyntway.com"}, &out); err != nil {
		t.Fatal(err)
	}
	link := lastLine(t, out.String())

	before, _, _ := strings.Cut(link, "#")
	if strings.Contains(before, "rcpt_one") || strings.Contains(before, "=") {
		t.Errorf("part of the receipt is outside the fragment, where it would reach a server: %q", before)
	}
	if before != "https://lyntway.com/verify" {
		t.Errorf("link points at %q", before)
	}

	r, _ := decodeShared(t, link)
	if r["id"] != "rcpt_one" {
		t.Errorf("the link carries %v", r["id"])
	}
}

// A key file accumulates keys over time, and a link is about one receipt.
// Carrying the rest would publish which other keys the sender holds.
func TestOnlyTheKeyThatSignedThisReceiptTravels(t *testing.T) {
	path := shareFixture(t, fakeReceipt("rcpt_one", 1))
	var out bytes.Buffer
	if err := runShare(shareOptions{File: path, Origin: "https://lyntway.com"}, &out); err != nil {
		t.Fatal(err)
	}
	_, keys := decodeShared(t, lastLine(t, out.String()))

	held, _ := keys["keys"].(map[string]any)
	if len(held) != 1 {
		t.Fatalf("the link carries %d keys: %v", len(held), held)
	}
	if _, ok := held["local-abc"]; !ok {
		t.Errorf("the signing key is not the one carried: %v", held)
	}
	if _, ok := held["other-key"]; ok {
		t.Error("a key that did not sign this receipt was published in the link")
	}
}

// Said before the link, because afterwards is too late: the sender has
// already pasted it somewhere.
func TestTheLimitIsStatedBeforeTheLink(t *testing.T) {
	path := shareFixture(t, fakeReceipt("rcpt_one", 1))
	var out bytes.Buffer
	if err := runShare(shareOptions{File: path, Origin: "https://lyntway.com"}, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	limit := strings.Index(text, "not that an independent")
	link := strings.Index(text, "https://lyntway.com/verify")
	if limit < 0 {
		t.Fatalf("the output does not state what the reader cannot conclude:\n%s", text)
	}
	if limit > link {
		t.Error("the limit is printed after the link, by which time it has been pasted")
	}
	if !strings.Contains(text, "No content") {
		t.Errorf("the output does not say a receipt holds no content:\n%s", text)
	}
	// And it shows what is in it, so nothing is shared unread.
	for _, want := range []string{"rcpt_one", "secret.supabase_key", "api.anthropic.com", "block"} {
		if !strings.Contains(text, want) {
			t.Errorf("the summary does not show %q:\n%s", want, text)
		}
	}
}

func TestWhichReceiptInAChainIsShared(t *testing.T) {
	path := shareFixture(t, fakeReceipt("rcpt_one", 1), fakeReceipt("rcpt_two", 2), fakeReceipt("rcpt_three", 3))

	for _, c := range []struct {
		index int
		want  string
	}{
		{-1, "rcpt_three"}, // the default: the newest
		{0, "rcpt_one"},
		{1, "rcpt_two"},
		{-2, "rcpt_two"},
	} {
		var out bytes.Buffer
		if err := runShare(shareOptions{File: path, Index: c.index, Origin: "https://x.test"}, &out); err != nil {
			t.Fatalf("index %d: %v", c.index, err)
		}
		r, _ := decodeShared(t, lastLine(t, out.String()))
		if r["id"] != c.want {
			t.Errorf("index %d shared %v, want %s", c.index, r["id"], c.want)
		}
	}

	var out bytes.Buffer
	if err := runShare(shareOptions{File: path, Index: 9, Origin: "https://x.test"}, &out); err == nil {
		t.Error("an index past the end was accepted")
	}
}

// A receipt with no signature gives the reader nothing to check, and a
// link to one would be a screenshot pretending to be proof.
func TestAnUnsignedReceiptIsNotShareable(t *testing.T) {
	path := shareFixture(t, `{"version":"lyntway-receipt/1","id":"rcpt_bare"}`)
	var out bytes.Buffer
	err := runShare(shareOptions{File: path, Origin: "https://x.test"}, &out)
	if err == nil {
		t.Fatal("a receipt with no signature was turned into a link")
	}
	if !strings.Contains(err.Error(), "nothing for a reader to check") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// With no file named, the newest session that actually holds a receipt.
// An empty newer directory must not win: it would answer "no receipts"
// about a machine that has them.
func TestTheNewestSessionWithAReceiptIsFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	base := filepath.Join(home, ".lyntway", "receipts", guardLabel)

	older := filepath.Join(base, "20261018-100000-aaaa")
	newerEmpty := filepath.Join(base, "20261018-120000-bbbb")
	for _, d := range []string{older, newerEmpty} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(older, "guard-anthropic.jsonl"), []byte(fakeReceipt("rcpt_old", 1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The newer session started and nothing came through, so its file is
	// absent; a zero-length one from a route that saw nothing is the other
	// shape of the same thing.
	if err := os.WriteFile(filepath.Join(newerEmpty, "guard-openai.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := newestGuardReceiptFile()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(got) != older {
		t.Errorf("found %s, want the newest session that holds a receipt", got)
	}

	// And a machine with no sessions says so, naming where it looked.
	t.Setenv("HOME", t.TempDir())
	if _, err := newestGuardReceiptFile(); err == nil || !strings.Contains(err.Error(), "guard") {
		t.Errorf("a machine with no sessions: %v", err)
	}
}

func lastLine(t *testing.T, text string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
