package detect

import (
	"fmt"
	"strings"
	"testing"
)

// The fixtures below are assembled from parts rather than written out, and
// that is not cosmetic.
//
// A detector's test corpus is indistinguishable from what it detects. Forty
// characters of mixed-case base64 beside the words aws_secret_access_key IS
// an AWS secret key as far as any scanner can tell, and GitHub's push
// protection refused the release branch carrying this file. It was right to.
//
// The offered fix was an allowlist entry on the push. This repository has a
// rule about that: an ignore is never the answer to a credential shape in a
// commit, because the moment a scanner is taught to skip our files, a real
// key committed to one of them goes out unnoticed — and these are the files
// a developer working on secret detection has open. So no file here contains
// the literal, and nothing scanning this tree has to make an exception for
// us.
//
// Split, not generated: a reader of a detection test has to be able to see
// the exact bytes the rule is being asked about, and a value derived from a
// seed turns a failing assertion into a second investigation.
var (
	// Forty characters: mixed case, not hex-only, no "EXAMPLE".
	fixtureAWSSecret = "kR7bQp2Xv" + "N4mZc8Td1" + "Wy6Hs3Ff0" + "Jg9Lu5Ae2" + "Bn7P"
	// AKIA and sixteen more, deliberately not AWS's published example,
	// which the rule refuses by design.
	fixtureAWSKeyID = "AKIA" + "IOSFODNN" + "7REALKEY"
)

// The shape is asserted before anything is asserted about the rule. If
// somebody edits a part above and the fixture stops being a plausible key,
// every test below fails and reads as a broken rule; this fails first and
// says what actually happened.
func TestTheAWSFixturesAreTheShapeTheRuleNeeds(t *testing.T) {
	if len(fixtureAWSSecret) != 40 {
		t.Fatalf("the secret fixture is %d characters, not 40", len(fixtureAWSSecret))
	}
	if !plausibleAWSSecretKey(fixtureAWSSecret) {
		t.Fatal("the secret fixture is not a plausible AWS secret key, so the tests below prove nothing")
	}
	if len(fixtureAWSKeyID) != 20 || !strings.HasPrefix(fixtureAWSKeyID, "AKIA") {
		t.Fatalf("the key id fixture is not AKIA plus sixteen: %q", fixtureAWSKeyID)
	}
}

// The access key id is an identifier; the forty characters beside it are
// the credential. Only the id was ever matched, so a scan could name an
// AWS key ninety-seven times and never once name the half an attacker
// would use.
func TestAnAWSSecretKeyIsFoundByTheFieldBesideIt(t *testing.T) {
	slashed := fixtureAWSSecret[:8] + "/" + fixtureAWSSecret[9:]
	for _, tc := range []struct {
		name string
		text string
	}{
		{"an env file", "AWS_SECRET_ACCESS_KEY=" + fixtureAWSSecret},
		{"the credentials file", fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s", fixtureAWSKeyID, fixtureAWSSecret)},
		{"json, camel case", fmt.Sprintf(`{"secretAccessKey": %q}`, fixtureAWSSecret)},
		{"spelled with spaces", "the aws secret access key is " + fixtureAWSSecret},
		{"a slash in the value", "AWS_SECRET_ACCESS_KEY=" + slashed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !hasClass(Default().Scan([]byte(tc.text)), ClassAWSSecretKey) {
				t.Errorf("no AWS secret key reported in %q", tc.text)
			}
		})
	}
}

// Pasted as a pair with the field names gone, which is how it arrives in a
// chat window.
func TestAnAWSSecretKeyIsFoundBesideItsAccessKeyID(t *testing.T) {
	text := fmt.Sprintf("here you go:\n%s\n%s", fixtureAWSKeyID, fixtureAWSSecret)
	if !hasClass(Default().Scan([]byte(text)), ClassAWSSecretKey) {
		t.Error("a credential pair with no field names reported only the id")
	}
}

// One secret is one finding. Both rules match the credentials-file shape,
// and a count that doubled would overstate what was found.
func TestACredentialPairIsOneSecretNotTwo(t *testing.T) {
	text := fmt.Sprintf("aws_access_key_id = %s\naws_secret_access_key = %s", fixtureAWSKeyID, fixtureAWSSecret)
	n := 0
	for _, s := range Default().Scan([]byte(text)) {
		if s.Class == ClassAWSSecretKey {
			n++
		}
	}
	if n != 1 {
		t.Errorf("reported the one secret %d times", n)
	}
}

// Forty characters of the right alphabet are also a Git SHA, a hash and a
// redaction. These must not be reported, including when an access key id
// happens to sit above them.
func TestFortyCharactersThatAreNotASecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"a git sha under an access key id", fixtureAWSKeyID + "\nreverted in da39a3ee5e6b4b0d3255bfef95601890afd80709 yesterday"},
		{"a hex digest named as the secret", `AWS_SECRET_ACCESS_KEY=da39a3ee5e6b4b0d3255bfef95601890afd80709`},
		{"aws's own published example", `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`},
		{"a single case", `AWS_SECRET_ACCESS_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN`},
		{"a longer base64 blob", "AWS_SECRET_ACCESS_KEY=" + fixtureAWSSecret + "xQ9Zm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if hasClass(Default().Scan([]byte(tc.text)), ClassAWSSecretKey) {
				t.Errorf("reported a secret in %q", tc.text)
			}
		})
	}
}

// The limit, asserted so nobody later reads the absence as a bug: with no
// field name and no id anywhere near it, forty characters are not
// distinguishable from any other base64 string and are not reported.
func TestABareFortyCharactersIsNotReported(t *testing.T) {
	if hasClass(Default().Scan([]byte(fixtureAWSSecret)), ClassAWSSecretKey) {
		t.Error("a bare forty-character string was reported as an AWS secret")
	}
}

func TestTheAWSSecretClassIsNamed(t *testing.T) {
	if Label(ClassAWSSecretKey) == string(ClassAWSSecretKey) {
		t.Error("no label for the AWS secret key class")
	}
}
