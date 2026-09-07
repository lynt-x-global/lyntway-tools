package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Connecting a machine without pasting a key.
//
// The console can issue a key, but getting it from a browser to a terminal
// means a clipboard, and a key that has been on a clipboard has been in
// every application that reads one. So the terminal asks the server for a
// short code, the person approves that code in a browser where they are
// already signed in, and the key travels straight from the server to this
// process — once, after which the code is spent.
//
// The server side of this is optional: a self-hosted deployment with
// signup switched off has no way to issue a key on approval, and says so
// with a 404. That is reported as errLinkUnsupported so `login` can fall
// back to asking for a key from the console.

// errLinkUnsupported means the server has no /v1/link, not that linking
// failed.
var errLinkUnsupported = errors.New("this server does not offer browser linking")

// linkResult is what an approved link hands back.
type linkResult struct {
	APIKey string `json:"api_key"`
	KeyID  string `json:"key_id"`
	Origin string `json:"origin"`
	Tenant string `json:"tenant"`
}

// linkClient bounds every call. A poll that hangs forever would leave a
// terminal that looks like it is waiting for the browser when it is
// waiting for a socket.
var linkClient = &http.Client{Timeout: 30 * time.Second}

// linkLogin runs the device-link flow against origin and returns the key.
//
// open is called with the URL to approve and may fail silently: a headless
// machine has no browser, and the code is printed either way so it can be
// typed on another device. sleep may be nil, in which case the real clock
// is used; tests pass their own so a poll loop does not take three seconds
// per iteration.
func linkLogin(origin, label string, open func(string), sleep func(time.Duration)) (linkResult, error) {
	if sleep == nil {
		sleep = time.Sleep
	}

	// No key yet, so nothing signs these; they still go through the one
	// request builder so that this file cannot drift from the others.
	body, _ := json.Marshal(map[string]string{"label": label})
	req, err := newAPIRequest(config{Origin: origin}, nil, http.MethodPost, "/v1/link", body, "application/json")
	if err != nil {
		return linkResult{}, err
	}
	resp, err := linkClient.Do(req)
	if err != nil {
		return linkResult{}, fmt.Errorf("reaching %s: %w", origin, err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return linkResult{}, errLinkUnsupported
	default:
		return linkResult{}, fmt.Errorf("%s refused to start a link: %s", origin, apiMessage(resp.StatusCode, raw))
	}

	var started struct {
		Code      string `json:"code"`
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
		PollAfter int    `json:"poll_after_s"`
	}
	if err := json.Unmarshal(raw, &started); err != nil || started.Code == "" {
		return linkResult{}, fmt.Errorf("%s answered /v1/link with something this build does not understand", origin)
	}
	if started.URL == "" {
		started.URL = origin + "/link?code=" + started.Code
	}
	if started.PollAfter <= 0 {
		started.PollAfter = 3
	}

	fmt.Fprintf(stdout, "\nOpen this address in a browser where you are signed in:\n\n  %s\n\nThe code shown there should be  %s\n\nWaiting for approval…\n", started.URL, started.Code)
	if open != nil {
		open(started.URL)
	}

	// The server's expiry is the real limit; the local deadline exists so
	// a server that never answers 410 cannot keep this loop alive.
	deadline := time.Now().Add(15 * time.Minute)
	if at, err := time.Parse(time.RFC3339, started.ExpiresAt); err == nil {
		deadline = at.Add(30 * time.Second)
	}

	for time.Now().Before(deadline) {
		sleep(time.Duration(started.PollAfter) * time.Second)

		req, err := newAPIRequest(config{Origin: origin}, nil, http.MethodGet, "/v1/link/"+url.PathEscape(started.Code), nil, "")
		if err != nil {
			return linkResult{}, err
		}
		resp, err := linkClient.Do(req)
		if err != nil {
			// One failed poll is a dropped connection, not a verdict.
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusAccepted:
			continue
		case http.StatusOK:
			var got struct {
				Status string `json:"status"`
				linkResult
			}
			if err := json.Unmarshal(raw, &got); err != nil || got.APIKey == "" {
				return linkResult{}, fmt.Errorf("the approval arrived without a key; sign in from the console instead")
			}
			fmt.Fprintf(stdout, "Approved. This machine is %q in your console.\n", label)
			return got.linkResult, nil
		case http.StatusGone:
			// Final, whatever the reason: expired, already used, denied
			// in the browser, or a code the server never issued. The
			// server's own sentence says which.
			return linkResult{}, fmt.Errorf("%s. Run `lyntway login` again", apiMessage(resp.StatusCode, raw))
		default:
			return linkResult{}, fmt.Errorf("waiting on the link: %s", apiMessage(resp.StatusCode, raw))
		}
	}
	return linkResult{}, fmt.Errorf("the link was not approved in time; run `lyntway login` again")
}

// hostLabel is how this machine is named in the console.
func hostLabel() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "a machine"
	}
	return h
}

// openBrowser hands a URL to the desktop, and does not care whether the
// desktop took it. The URL is printed first regardless.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// apiMessage turns an error body into one line a person can act on,
// falling back to the status when the body is not ours.
func apiMessage(status int, raw []byte) string {
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Error.Message != "" {
		return strings.TrimRight(body.Error.Message, ".")
	}
	return fmt.Sprintf("HTTP %d", status)
}
