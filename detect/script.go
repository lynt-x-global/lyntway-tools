package detect

import "unicode"

// Which writing systems the model tier can actually read.
//
// The entity model is a multilingual build and was treated as though that
// meant every language. Measured on 30 Sep 2026, it does not:
//
//	Arabic      سارة المنصوري          found, with the address
//	German      Andreas Hartmann       found
//	French      Marie Lefèvre          found
//	Spanish     José María Fernández   found
//	Hindi       प्रिया रघुनाथन            NOTHING
//	Tamil       பிரியா ரகுநாதன்           NOTHING
//
// Not a wrong answer for Devanagari and Tamil. An empty one — the model
// returns no entities at all. And an empty answer is indistinguishable from a
// clean document, which is the failure this whole vocabulary exists to stop:
// a scanned Indian statement would come back with no findings and be reported
// as fully inspected.
//
// The English pattern rules are unaffected. An Aadhaar number, a PAN, a card
// number and an IBAN are the same digits whatever the surrounding script, and
// those are measured at 1.000. What is lost is names, addresses and
// organisations — everything the model tier exists for.
//
// Keeping Presidio and spaCy would not help. They are English models; they
// fail the same cases for the same reason.
//
// So the answer is not to pretend, it is to say so. A body carrying a script
// the model tier has not been shown to read is reported degraded, with the
// script named, and under a blocking mode that holds rather than passes.

// Script is a writing system, named as a person would name it.
type Script string

const (
	ScriptLatin      Script = "latin"
	ScriptArabic     Script = "arabic"
	ScriptDevanagari Script = "devanagari"
	ScriptTamil      Script = "tamil"
	ScriptBengali    Script = "bengali"
	ScriptTelugu     Script = "telugu"
	ScriptHan        Script = "han"
	ScriptHiragana   Script = "kana"
	ScriptHangul     Script = "hangul"
	ScriptCyrillic   Script = "cyrillic"
	ScriptHebrew     Script = "hebrew"
	ScriptThai       Script = "thai"
	ScriptGreek      Script = "greek"
	ScriptOther      Script = "other"
)

// modelTierReads lists the scripts the entity model has been *measured* on.
//
// Measured, not assumed, and that is the whole point. A script missing here is
// not a script the model necessarily fails — it is one nobody has checked, and
// unchecked has to read the same as unsupported or the vocabulary is a lie.
// Add one only alongside the cases that prove it, in ai-sidecar/modelbench.py.
var modelTierReads = map[Script]bool{
	ScriptLatin:  true,
	ScriptArabic: true,
}

// ModelTierReads reports whether the entity model has been shown to find
// anything in this script.
func ModelTierReads(s Script) bool { return modelTierReads[s] }

// scriptShare is the fraction of letters a script must hold before it counts.
//
// One foreign name in an English paragraph should not degrade the whole
// inspection: the model reads the paragraph and finds everything else. A
// document that is a tenth Devanagari is a document with a section nobody
// read, and that does need saying.
const scriptShare = 0.10

// ScriptsPresent names the writing systems that hold a real share of the
// letters in text, most common first.
//
// Only letters are counted. Digits and punctuation carry no script and a
// statement full of figures would otherwise look like whatever its handful of
// labels were written in.
func ScriptsPresent(text string) []Script {
	counts := map[Script]int{}
	total := 0
	for _, r := range text {
		if !unicode.IsLetter(r) {
			continue
		}
		total++
		counts[scriptOf(r)]++
	}
	if total == 0 {
		return nil
	}

	var out []Script
	for s, n := range counts {
		if float64(n)/float64(total) >= scriptShare {
			out = append(out, s)
		}
	}
	// Most common first, so a caller naming one names the dominant one.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && counts[out[j]] > counts[out[j-1]]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// UnreadableScripts names the scripts in text that the model tier has not been
// measured on. An empty result means every script present is one we can claim.
func UnreadableScripts(text string) []Script {
	var out []Script
	for _, s := range ScriptsPresent(text) {
		if !ModelTierReads(s) {
			out = append(out, s)
		}
	}
	return out
}

func scriptOf(r rune) Script {
	switch {
	case unicode.Is(unicode.Latin, r):
		return ScriptLatin
	case unicode.Is(unicode.Arabic, r):
		return ScriptArabic
	case unicode.Is(unicode.Devanagari, r):
		return ScriptDevanagari
	case unicode.Is(unicode.Tamil, r):
		return ScriptTamil
	case unicode.Is(unicode.Bengali, r):
		return ScriptBengali
	case unicode.Is(unicode.Telugu, r):
		return ScriptTelugu
	case unicode.Is(unicode.Han, r):
		return ScriptHan
	case unicode.Is(unicode.Hiragana, r), unicode.Is(unicode.Katakana, r):
		return ScriptHiragana
	case unicode.Is(unicode.Hangul, r):
		return ScriptHangul
	case unicode.Is(unicode.Cyrillic, r):
		return ScriptCyrillic
	case unicode.Is(unicode.Hebrew, r):
		return ScriptHebrew
	case unicode.Is(unicode.Thai, r):
		return ScriptThai
	case unicode.Is(unicode.Greek, r):
		return ScriptGreek
	default:
		return ScriptOther
	}
}
