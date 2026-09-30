package detect

import "testing"

// A script the model tier cannot read must be named, because the model's
// answer for it is an empty one and an empty answer is indistinguishable from
// a clean document.
func TestScriptsTheModelTierCannotRead(t *testing.T) {
	cases := []struct {
		name       string
		text       string
		want       Script
		unreadable bool
	}{
		{"english", "Please review the statement for Priya Raghunathan before Friday.", ScriptLatin, false},
		{"german", "Bitte prüfen Sie den Kontoauszug von Andreas Hartmann, München", ScriptLatin, false},
		{"french", "Veuillez vérifier le relevé de Marie Lefèvre à Paris", ScriptLatin, false},
		{"arabic", "يرجى مراجعة كشف الحساب الخاص بـ سارة المنصوري في دبي", ScriptArabic, false},
		// The two the model returns nothing for.
		{"hindi", "कृपया प्रिया रघुनाथन का विवरण देखें, पता अन्ना सालाई, चेन्नई", ScriptDevanagari, true},
		{"tamil", "பிரியா ரகுநாதன் அவர்களின் கணக்கு விவரம், அண்ணா சாலை", ScriptTamil, true},
		// Never measured, so they read as unreadable rather than as fine.
		{"chinese", "请查看张伟的对账单，地址在北京市朝阳区", ScriptHan, true},
		{"russian", "Пожалуйста, проверьте выписку Ивана Петрова в Москве", ScriptCyrillic, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScriptsPresent(tc.text)
			if len(got) == 0 || got[0] != tc.want {
				t.Fatalf("dominant script = %v, want %s", got, tc.want)
			}
			bad := UnreadableScripts(tc.text)
			if tc.unreadable && len(bad) == 0 {
				t.Errorf("%s is reported as readable. The entity model returns "+
					"no entities at all for it, and no findings reads exactly "+
					"like a clean document.", tc.want)
			}
			if !tc.unreadable && len(bad) > 0 {
				t.Errorf("%s reported unreadable (%v) though it was measured "+
					"as working", tc.want, bad)
			}
		})
	}
}

// One foreign name in an English paragraph must not degrade the whole
// inspection: the model reads the paragraph and finds everything else.
func TestAStraySignatureDoesNotDegradeAnEnglishDocument(t *testing.T) {
	text := "Please review the attached statement before Friday. The account " +
		"holder has queried three transactions and asked for a written reply " +
		"by the end of the month. Signed प्रिया"
	if bad := UnreadableScripts(text); len(bad) > 0 {
		t.Errorf("a mostly-English document was degraded by a short signature: %v", bad)
	}
}

// A document with a real section in an unreadable script does need saying.
func TestASectionInAnUnreadableScriptIsReported(t *testing.T) {
	text := "Summary of account. " +
		"कृपया प्रिया रघुनाथन का विवरण देखें और खाते की शेष राशि की जाँच करें। " +
		"पता अन्ना सालाई, चेन्नई।"
	bad := UnreadableScripts(text)
	if len(bad) == 0 {
		t.Fatal("a document with a Devanagari section was reported fully readable")
	}
	if bad[0] != ScriptDevanagari {
		t.Errorf("named %v, want devanagari", bad)
	}
}

// Digits carry no script. A statement is mostly figures and must not be
// classified by its handful of labels.
func TestFiguresDoNotDecideTheScript(t *testing.T) {
	if got := ScriptsPresent("4111 1111 1111 1111  2026-09-30  1,240.00"); len(got) != 0 {
		t.Errorf("a line of figures was given a script: %v", got)
	}
}

// Adding a script to the readable list must be deliberate. If this fails,
// somebody widened the claim — check that ai-sidecar/modelbench.py carries
// cases proving it.
func TestOnlyMeasuredScriptsAreClaimed(t *testing.T) {
	want := map[Script]bool{ScriptLatin: true, ScriptArabic: true}
	for s := range modelTierReads {
		if !want[s] {
			t.Errorf("%s is claimed as readable. Add the cases that prove it to "+
				"ai-sidecar/modelbench.py in the same commit, or the vocabulary "+
				"says more than we measured.", s)
		}
	}
	for s := range want {
		if !modelTierReads[s] {
			t.Errorf("%s was measured as working and is no longer claimed", s)
		}
	}
}
