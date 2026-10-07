package main

import (
	"strings"
	"testing"
)

// The trust remedy must be one the person's platform can run.
func TestTrustCACommandIsForThePlatformItIsPrintedOn(t *testing.T) {
	if got := trustCACommand("windows"); !strings.Contains(got, "certutil -user -addstore Root") {
		t.Errorf("windows remedy = %q", got)
	}
	if got := trustCACommand("darwin"); !strings.Contains(got, "security add-trusted-cert") {
		t.Errorf("darwin remedy = %q", got)
	}
	if got := trustCACommand("linux"); !strings.Contains(got, "update-ca-certificates") {
		t.Errorf("linux remedy = %q", got)
	}
}
