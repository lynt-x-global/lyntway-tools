package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// What survives OCR.
//
// Every other figure in this package is measured on text we wrote. This one is
// measured on text an OCR engine produced from an image of text we wrote, which
// is the only figure that says anything about the documents people actually
// attach: a photographed statement, a scanned contract, a picture of a form.
//
// The distinction that makes it worth a separate benchmark: OCR quality and
// detection recall are not the same thing. An engine that reads a name slightly
// wrong costs nothing if the rule still fires. An engine that turns one 0 into
// an O breaks a Luhn check, and the card passes.
//
// The corpus in testdata is what RapidOCR actually returned, committed so a
// reader can see the damage rather than take a number on trust. Regenerate it
// with `python ai-sidecar/ocrbench.py`; that needs the ONNX models, which CI
// does not carry and should not have to in order to measure a ruleset.

type ocrCase struct {
	Class     string `json:"class"`
	Value     string `json:"value"`
	Condition string `json:"condition"`
	OCRText   string `json:"ocr_text"`
	Exact     bool   `json:"exact"`
}

type ocrCorpus struct {
	Engine string    `json:"engine"`
	Note   string    `json:"note"`
	Cases  []ocrCase `json:"cases"`
}

// ocrRecallFloors are the measured figures, held so a change that costs recall
// on scanned documents fails rather than passes quietly. They are not targets:
// raising one means re-running the generator and saying what improved.
var ocrRecallFloors = map[string]float64{
	"pci.card_number": 1.00,
	"pci.iban":        1.00,
	"pii.us_ssn":      1.00,
	"pii.in_aadhaar":  1.00,
	"pii.in_pan":      1.00,
	"pii.uk_nino":     1.00,
	"pii.email":       1.00,
	"pii.phone":       1.00,
}

func loadOCRCorpus(t *testing.T) ocrCorpus {
	t.Helper()
	raw, err := os.ReadFile("testdata/ocr_corpus.json")
	if err != nil {
		t.Fatalf("the OCR corpus is missing: %v\n"+
			"Regenerate it with: python ai-sidecar/ocrbench.py", err)
	}
	var c ocrCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("the OCR corpus will not parse: %v", err)
	}
	if len(c.Cases) == 0 {
		t.Fatal("the OCR corpus is empty, so this measures nothing")
	}
	return c
}

func TestOCRDetectionRecall(t *testing.T) {
	corpus := loadOCRCorpus(t)
	rs := Default()

	type tally struct{ found, total int }
	byClass := map[string]*tally{}
	byCondition := map[string]*tally{}
	var misses []ocrCase

	for _, c := range corpus.Cases {
		if byClass[c.Class] == nil {
			byClass[c.Class] = &tally{}
		}
		if byCondition[c.Condition] == nil {
			byCondition[c.Condition] = &tally{}
		}
		byClass[c.Class].total++
		byCondition[c.Condition].total++

		// Found means the real ruleset reported the labelled class somewhere
		// in what OCR returned. Not that the span matches the original
		// offsets — OCR reflows the page, so offsets are meaningless here,
		// and the question is only whether the value was caught at all.
		hit := false
		for _, sp := range ScanOCR(rs, c.OCRText) {
			if string(sp.Class) == c.Class {
				hit = true
				break
			}
		}
		if hit {
			byClass[c.Class].found++
			byCondition[c.Condition].found++
		} else {
			misses = append(misses, c)
		}
	}

	classes := make([]string, 0, len(byClass))
	for k := range byClass {
		classes = append(classes, k)
	}
	sort.Strings(classes)

	t.Logf("OCR engine: %s, %d cases", corpus.Engine, len(corpus.Cases))
	for _, cls := range classes {
		v := byClass[cls]
		recall := float64(v.found) / float64(v.total)
		t.Logf("  %-18s %2d/%2d  recall %.3f", cls, v.found, v.total, recall)

		floor, ok := ocrRecallFloors[cls]
		if !ok {
			t.Errorf("%s appears in the corpus with no recorded floor. Add one, "+
				"or a class can lose recall on scanned documents unnoticed.", cls)
			continue
		}
		if recall < floor {
			t.Errorf("%s recall %.3f is below the recorded floor %.3f: a change "+
				"has cost detection on scanned documents", cls, recall, floor)
		}
	}
	for _, cond := range []string{"clean", "scan", "poor"} {
		if v := byCondition[cond]; v != nil {
			t.Logf("  condition %-6s %2d/%2d  recall %.3f",
				cond, v.found, v.total, float64(v.found)/float64(v.total))
		}
	}

	for _, m := range misses {
		t.Logf("  MISS [%s] %s %q -> OCR gave %q",
			m.Condition, m.Class, m.Value, truncate(m.OCRText, 70))
	}
}

// The finding that made the whole benchmark worth building: RapidOCR returns
// text with the spaces inside a detected box removed, so "+44 7700 900123"
// comes back "+447700900123" and "Account holder" comes back "Accountholder".
//
// For the pattern tier that is harmless as long as the rules accept the
// unspaced form — which is the same lesson as the IBAN that was detected
// unspaced and missed in the spaced form printed on every invoice, learned
// from the other direction.
//
// For the model tier it is not harmless at all, and nothing else in this
// repository records it: NER needs word boundaries, and a name arriving as
// "PriyaRaghunathan" is a name the entity model will not find. Any claim about
// finding names in a scanned document has to reckon with this first.
func TestOCRStripsSpacesWhichThePatternRulesMustTolerate(t *testing.T) {
	corpus := loadOCRCorpus(t)

	var squashed int
	for _, c := range corpus.Cases {
		if strings.Contains(c.Value, " ") && !c.Exact &&
			strings.Contains(strings.ReplaceAll(c.OCRText, " ", ""),
				strings.ReplaceAll(c.Value, " ", "")) {
			squashed++
		}
	}
	if squashed == 0 {
		t.Skip("no spaced value in the corpus came back squashed; the engine " +
			"may have changed behaviour, which is worth knowing about")
	}
	t.Logf("%d spaced values came back with the spaces removed", squashed)

	// Each one must still be found, or a spaced value on a scanned page is
	// invisible to us while the same value in a text PDF is not.
	rs := Default()
	for _, c := range corpus.Cases {
		if !strings.Contains(c.Value, " ") || c.Exact {
			continue
		}
		found := false
		for _, sp := range ScanOCR(rs, c.OCRText) {
			if string(sp.Class) == c.Class {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s %q survived OCR as %q with its spaces removed and the "+
				"ruleset did not fire: the same value is found in a text PDF "+
				"and missed in a scan of one",
				c.Class, c.Value, truncate(c.OCRText, 60))
		}
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func TestOCRCorpusCoversEveryFlooredClass(t *testing.T) {
	corpus := loadOCRCorpus(t)
	present := map[string]bool{}
	for _, c := range corpus.Cases {
		present[c.Class] = true
	}
	for cls := range ocrRecallFloors {
		if !present[cls] {
			t.Errorf("%s has a floor but no case in the corpus, so the floor "+
				"passes without measuring anything", cls)
		}
	}
	if t.Failed() {
		var have []string
		for c := range present {
			have = append(have, c)
		}
		sort.Strings(have)
		t.Log(fmt.Sprintf("corpus covers: %s", strings.Join(have, ", ")))
	}
}
