package detect

import "testing"

func TestTruncatedPrivateKeyIsStillAKey(t *testing.T) {
	line := pemBodyLine()
	body := line + "\n" + line + "\n"

	rs := Default()
	count := func(s string) int {
		n := 0
		for _, sp := range rs.Scan([]byte(s)) {
			if sp.Class == ClassPrivateKey {
				n++
			}
		}
		return n
	}
	found := func(s string) bool { return count(s) > 0 }

	t.Run("caught", func(t *testing.T) {
		cases := map[string]string{
			"complete block":           pemHeader("RSA ") + "\n" + body + pemFooter("RSA "),
			"no END line":              pemHeader("RSA ") + "\n" + body,
			"no END, EC":               pemHeader("EC ") + "\n" + body,
			"no END, OPENSSH":          pemHeader("OPENSSH ") + "\n" + body,
			"no END, unqualified":      pemHeader("") + "\n" + body,
			"no END, PGP BLOCK":        pemBlockHeader("PGP ") + "\n" + body,
			"CRLF line endings":        pemHeader("RSA ") + "\r\n" + line + "\r\n" + line + "\r\n",
			"surrounded by other text": "here it is:\n" + pemHeader("RSA ") + "\n" + body + "\nthanks",
		}
		for name, in := range cases {
			if !found(in) {
				t.Errorf("%s: a private key went undetected", name)
			}
		}
	})

	t.Run("not a key, and must stay quiet", func(t *testing.T) {
		// The bare header is what somebody writing about keys types, including
		// this file. Flagging it fires on the people most likely to be
		// discussing key handling.
		cases := map[string]string{
			"bare header":        pemHeader("RSA "),
			"header and a blank": pemHeader("RSA ") + "\n\n",
			// With no END line. A documentation example that shows the
			// header and an ellipsis must not read as a key; one that shows
			// BEGIN...END around an ellipsis is matched by the complete-block
			// rule and always has been, which is its own choice and not this
			// rule's business.
			"header and an ellipsis, unterminated": pemHeader("RSA ") + "\n...\n",
			"header, one short line":               pemHeader("RSA ") + "\nshort\n",
			"header, one long line":                pemHeader("RSA ") + "\n" + line + "\n",
			// Short lines that are base64-shaped. Without a minimum length the
			// rule fires on any two word-like lines under a header, which is
			// what a redacted example in a runbook looks like.
			"header, short base64-ish lines": pemHeader("RSA ") + "\nabc\ndef\n",
			"header, placeholder lines":      pemHeader("RSA ") + "\nYOURKEY\nHERE\n",
			"prose about keys":               "Never commit a file containing a PRIVATE" + " KEY to the repository.",
			"a public key":                   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ user@host",
		}
		for name, in := range cases {
			if found(in) {
				t.Errorf("%s: reported a private key where there is none", name)
			}
		}
	})

	t.Run("a complete block is reported once", func(t *testing.T) {
		// Both rules match a complete block. Overlap resolution must leave one
		// finding, or a single key is counted twice in a receipt.
		in := pemHeader("RSA ") + "\n" + body + pemFooter("RSA ")
		if n := count(in); n != 1 {
			t.Errorf("a complete block produced %d private-key findings, want 1", n)
		}
	})
}
