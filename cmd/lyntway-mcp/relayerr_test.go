package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// relay ran `for scanner.Scan()` and never read scanner.Err(), so the 8 MB
// cap turned an oversized message into a relay that simply stopped. The
// goroutine returned, the process stayed alive with its other direction
// still relaying, and the agent waited forever for a reply nothing was
// going to send — the exact failure answerFor was written to prevent,
// reached by a route that skipped it.
func TestAMessageTooLargeToGovernIsReportedRatherThanEndingTheRelayQuietly(t *testing.T) {
	g := testGovernor(t)

	// One line past the cap. Valid JSON-RPC, so nothing but the size can
	// be what stops it.
	huge := `{"jsonrpc":"2.0","id":1,"result":{"content":"` +
		strings.Repeat("a", maxMessageBytes+1) + `"}}` + "\n"

	var toAgent, backToAgent bytes.Buffer
	dst := &lineWriter{w: bufio.NewWriter(&toAgent)}
	agent := &lineWriter{w: bufio.NewWriter(&backToAgent)}

	err := relay(strings.NewReader(huge), dst, agent, g, directionToAgent)
	if err == nil {
		t.Fatal("an unreadable message ended the relay with no error, which is indistinguishable from the stream ending")
	}
	for _, want := range []string{"server-to-agent", "8 MB", "not forwarded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so nobody can act on it: %v", want, err)
		}
	}

	// Fail closed: the message that could not be governed must not have
	// been passed on.
	dst.w.Flush()
	if toAgent.Len() != 0 {
		t.Errorf("a message that could not be governed was forwarded anyway (%d bytes)", toAgent.Len())
	}
}

// The ordinary end of a stream is not an error, or every clean shutdown
// would report one and the real failures would be lost in them.
func TestAStreamThatSimplyEndsIsNotReportedAsAFailure(t *testing.T) {
	g := testGovernor(t)

	var toServer, backToAgent bytes.Buffer
	dst := &lineWriter{w: bufio.NewWriter(&toServer)}
	agent := &lineWriter{w: bufio.NewWriter(&backToAgent)}

	in := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	if err := relay(strings.NewReader(in), dst, agent, g, directionToServer); err != nil {
		t.Fatalf("a stream that ended cleanly reported an error: %v", err)
	}
	dst.w.Flush()
	if toServer.Len() == 0 {
		t.Error("an ordinary message was not forwarded")
	}
}

// A read error that is not the size cap is still a read error, and still
// has to be named rather than mistaken for the end of the stream.
func TestAReadErrorIsNotMistakenForTheEndOfTheStream(t *testing.T) {
	g := testGovernor(t)

	var sink, backToAgent bytes.Buffer
	dst := &lineWriter{w: bufio.NewWriter(&sink)}
	agent := &lineWriter{w: bufio.NewWriter(&backToAgent)}

	broken := io.MultiReader(
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"),
		errReader{errors.New("the pipe went away")},
	)
	err := relay(broken, dst, agent, g, directionToServer)
	if err == nil {
		t.Fatal("a failed read was treated as the stream ending")
	}
	if !strings.Contains(err.Error(), "the pipe went away") {
		t.Errorf("the underlying cause is not reported: %v", err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
