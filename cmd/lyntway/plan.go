package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// `lyntway plan` — what you are on, what you have used, and what to do.
//
// The console already showed this to somebody signed in with a browser,
// which was the only way to find out. The ordinary path through this
// product does not involve a browser: npx, a base URL, done. Somebody who
// took that path could not see their plan, their usage against the cap, or
// a notice saying a payment had failed — the first they would learn of any
// of it is a request refused for quota, in production, on a Tuesday.
//
// Three rules this output follows:
//
//   - A notice comes first, before the plan, because it is the only part
//     that is ever urgent.
//   - The cap is drawn, not described. "1,284 of 10,000" is a number
//     somebody has to think about; a bar is a glance.
//   - Nothing here nags. There is exactly one line about upgrading and it
//     appears only when something is actually constrained.

const planUsage = `lyntway plan — what this account is on, and what it has used

  lyntway plan            show the plan, the usage and anything outstanding
  lyntway plan --json     the same, as JSON

Reads the service with the key this machine is signed in with. Shows
nothing it had to guess: a deployment with no cap prints no bar, and a
self-hosted install prints no price.
`

func planCommand(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	fs.Usage = func() { fmt.Fprint(stdout, planUsage) }
	if err := fs.Parse(flagsFirst(fs, args)); err != nil {
		return err
	}

	c, err := loadConfig()
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.Key) == "" {
		return fmt.Errorf("this machine is not signed in. Run `lyntway login` first, or `npx lyntway secure` if you only wanted the local checks, which need no account")
	}

	body, err := planFetch(c)
	if err != nil {
		return err
	}
	if *asJSON {
		fmt.Fprintln(stdout, strings.TrimSpace(string(body)))
		return nil
	}

	var report planReport
	if err := json.Unmarshal(body, &report); err != nil {
		return fmt.Errorf("the service answered something this build does not understand: %w", err)
	}
	printPlan(report, c.Origin)
	return nil
}

// planReport mirrors the server's answer.
//
// Only the fields this command prints. A field added at the other end is
// ignored rather than breaking the parse, which is the rule every verifier
// in this project follows for the same reason.
type planReport struct {
	Plan     string   `json:"plan"`
	Label    string   `json:"label"`
	Actions  int64    `json:"actions"`
	Limit    int64    `json:"limit"`
	Period   string   `json:"period"`
	Includes []string `json:"includes"`
	Excludes []string `json:"excludes"`
	Manage   string   `json:"manage"`
	Notice   struct {
		Kind    string    `json:"kind"`
		Since   time.Time `json:"since"`
		Summary string    `json:"summary"`
	} `json:"notice"`
}

func planFetch(c config) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(c.Origin, "/")+"/v1/plan", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)

	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", c.Origin, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("the service did not accept this machine's key. Run `lyntway login` again")
	case http.StatusNotFound:
		// An older deployment. Named as that rather than as a failure,
		// because self-hosted installs lag the hosted service by months
		// and "not found" reads as a bug in the command.
		return nil, fmt.Errorf("%s does not answer /v1/plan. It is running a build from before plans were reported; everything else still works", c.Origin)
	default:
		return nil, fmt.Errorf("the service answered %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
}

// printPlan writes the report the way somebody reads it.
func printPlan(r planReport, origin string) {
	// The notice first. It is the only part that is ever urgent, and
	// burying it under a feature list is how somebody misses that their
	// subscription ends in four days.
	if r.Notice.Summary != "" {
		fmt.Fprintf(stdout, "\n  ! %s\n", wrapAt(r.Notice.Summary, 72, "    "))
		if !r.Notice.Since.IsZero() {
			fmt.Fprintf(stdout, "    since %s\n", r.Notice.Since.Local().Format("2 January, 15:04"))
		}
	}

	label := r.Label
	if label == "" {
		label = r.Plan
	}
	fmt.Fprintf(stdout, "\n  plan      %s\n", label)

	switch {
	case r.Limit > 0:
		fmt.Fprintf(stdout, "  used      %s of %s governed actions%s\n",
			commas(r.Actions), commas(r.Limit), periodSuffix(r.Period))
		fmt.Fprintf(stdout, "            %s\n", bar(r.Actions, r.Limit))
	case r.Actions > 0:
		fmt.Fprintf(stdout, "  used      %s governed actions%s, with no cap\n",
			commas(r.Actions), periodSuffix(r.Period))
	default:
		fmt.Fprintf(stdout, "  used      nothing yet%s\n", periodSuffix(r.Period))
	}

	if len(r.Excludes) > 0 {
		fmt.Fprintf(stdout, "  not on it %s\n", strings.Join(r.Excludes, ", "))
	}

	// One line about money, and only when something is actually
	// constrained. A tool that asks for money every time it is run gets
	// run less.
	switch {
	case r.Notice.Summary != "" && r.Manage != "":
		fmt.Fprintf(stdout, "\n  Change it at %s\n", r.Manage)
	case r.Limit > 0 && r.Actions*10 >= r.Limit*9 && r.Manage != "":
		fmt.Fprintf(stdout, "\n  That is 90%% of the cap. More at %s\n", r.Manage)
	}
	fmt.Fprintln(stdout)
}

// bar draws usage against a cap.
//
// Twenty-four characters, because it has to sit inside the indent above it
// and still be readable in an 80-column terminal next to a timestamp.
func bar(used, limit int64) string {
	const width = 24
	if limit <= 0 {
		return ""
	}
	filled := int(int64(width) * used / limit)
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	// Over the cap still shows a full bar and says so in words beside it,
	// rather than drawing a bar wider than its own frame.
	pct := used * 100 / limit
	return "[" + strings.Repeat("#", filled) + strings.Repeat(".", width-filled) +
		fmt.Sprintf("] %d%%", pct)
}

func periodSuffix(period string) string {
	if strings.TrimSpace(period) == "" {
		return ""
	}
	return " in " + period
}

// commas groups a number the way a person reads one.
func commas(n int64) string {
	s := fmt.Sprintf("%d", n)
	if n < 0 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// wrapAt breaks a sentence to a width, indenting every line after the
// first so it sits under the one above rather than under the marker.
func wrapAt(text string, width int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n"+indent)
}
