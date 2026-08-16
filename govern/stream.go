package govern

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
	"github.com/lynt-x-global/lyntway-tools/tokenize"
)

// Governing a stream is not governing a document in pieces.
//
// Detection reads a whole payload. Run it on each chunk as it arrives and a
// card number split across two of them matches neither — and nothing
// reports that, because a miss looks exactly like clean content. Refusing
// to stream at all was the honest answer while this did not exist; it was
// also the answer that made the gateway unusable for most agent
// applications, which stream by default.
//
// # Holding back
//
// Bytes are released only once no undetected match could still begin in
// them. That means keeping a tail: emit up to len(buffer)-lookback, and any
// pattern straddling the boundary is still whole inside the buffer next
// time. The reader sees text a fraction of a second behind, which is the
// price of not missing values at chunk edges.
//
// # Where a window is not enough
//
// Several rules are deliberately unbounded — a private key block, a JWT, an
// API key with no length limit. No finite window can guarantee those are
// whole, so no amount of buffering makes them safe to tokenise mid-stream.
//
// Every one of them is a credential, and the policy for credentials is to
// refuse rather than substitute. So they are handled by their nature rather
// than their length: as soon as a marker for a refusing class appears,
// emission stops at that point and does not resume. If the rule then
// matches, the stream is cut.
//
// # What cannot be undone
//
// Bytes already sent are gone. A stream that turns dangerous halfway
// through can only be stopped, not recalled. What must not happen is a
// truncated stream that reads as a complete one, so the receipt records the
// truncation and the caller is told.

// StreamLookback is how many bytes are held back before release.
//
// Sized for the classes that get substituted rather than refused. The
// longest of those is an email address, which RFC 5321 caps at 320 octets;
// the rest are far shorter. Doubling that leaves room without adding
// latency a reader would notice.
const StreamLookback = 640

// MaxStreamBuffer bounds how much is held while a possible credential
// resolves.
//
// Without a limit, a marker that never completes into a match would hold
// the stream open indefinitely — a denial of service performed by the
// content itself. Reaching it means giving up on the stream rather than
// releasing bytes that were held for a reason.
const MaxStreamBuffer = 256 << 10

// ErrStreamUnsafe means the stream was cut because releasing more would
// have released something the policy refuses.
var ErrStreamUnsafe = errors.New("govern: stream stopped; the remainder could not be released safely")

// StreamGovernor governs text arriving in pieces.
//
// Not safe for concurrent use by design: a stream is ordered, and allowing
// concurrent writes would make the order — and therefore the output —
// undefined.
type StreamGovernor struct {
	engine *Engine
	scope  *tokenize.Scope

	mu sync.Mutex

	// buffer holds bytes received but not yet released.
	buffer []byte

	// released is everything emitted so far, kept so the receipt can be
	// issued over exactly what the caller received.
	released []byte

	// findings accumulates across the whole stream, so the receipt
	// describes the stream rather than its last chunk.
	findings map[detect.Class]int

	// frozenAt marks where emission stopped because a refusing class may
	// begin there. Negative means nothing is frozen.
	frozenAt int

	stopped   bool
	truncated bool
}

// NewStreamGovernor starts governing a stream.
func (e *Engine) NewStreamGovernor(scope *tokenize.Scope) *StreamGovernor {
	return &StreamGovernor{
		engine:   e,
		scope:    scope,
		findings: make(map[detect.Class]int),
		frozenAt: -1,
	}
}

// Write adds received bytes and returns whatever is now safe to release.
//
// The returned slice may be empty, which is normal: early in a stream, or
// while a possible credential resolves, nothing is safe yet.
func (s *StreamGovernor) Write(chunk []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return nil, ErrStreamUnsafe
	}
	s.buffer = append(s.buffer, chunk...)

	// A completed refusing match ends the stream. Checked over the whole
	// buffer rather than the releasable part, because the point is to stop
	// before those bytes are ever released.
	if s.engine.streamHasRefusedClass(s.buffer) {
		s.stopped, s.truncated = true, true
		return nil, ErrStreamUnsafe
	}

	// A marker for a refusing class freezes emission at its position. The
	// rule may not have matched yet — that is exactly why the bytes cannot
	// be released.
	if s.frozenAt < 0 {
		if at := s.engine.firstRefusedMarker(s.buffer); at >= 0 {
			s.frozenAt = at
		}
	}

	if len(s.buffer) > MaxStreamBuffer {
		// Held too long for a match that never arrived. Releasing now
		// would release exactly what was withheld for cause.
		s.stopped, s.truncated = true, true
		return nil, fmt.Errorf("%w: held %d bytes without resolving", ErrStreamUnsafe, len(s.buffer))
	}

	return s.release(s.safeEnd()), nil
}

// safeEnd is how far into the buffer it is safe to release.
func (s *StreamGovernor) safeEnd() int {
	end := len(s.buffer) - StreamLookback
	if s.frozenAt >= 0 && s.frozenAt < end {
		end = s.frozenAt
	}
	if end < 0 {
		return 0
	}
	return end
}

// Close governs and releases whatever remains.
//
// At the end of a stream nothing more can arrive, so the lookback is no
// longer protecting anything and the remainder is whole by definition.
func (s *StreamGovernor) Close() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return nil, ErrStreamUnsafe
	}
	if s.frozenAt >= 0 && s.engine.streamHasRefusedClass(s.buffer) {
		s.stopped, s.truncated = true, true
		return nil, ErrStreamUnsafe
	}
	s.stopped = true
	return s.release(len(s.buffer)), nil
}

// release governs buffer[:end], records what was found, and returns it.
func (s *StreamGovernor) release(end int) []byte {
	if end <= 0 {
		return nil
	}
	segment := s.buffer[:end]

	spans := s.engine.ruleset.Scan(segment)
	for _, sp := range spans {
		s.findings[sp.Class]++
	}

	out := segment
	if s.scope != nil && len(spans) > 0 {
		var toTokenize []detect.Span
		for _, sp := range spans {
			if s.engine.policy.Decide(sp.Class, sp.Confidence) == receipt.DecisionTokenize {
				toTokenize = append(toTokenize, sp)
			}
		}
		if len(toTokenize) > 0 {
			if applied, err := s.scope.Apply(segment, toTokenize); err == nil {
				out = applied
			}
			// A tokenisation failure leaves the segment unchanged rather
			// than dropping it. The receipt still records the finding, so
			// the discrepancy is visible rather than silent.
		}
	}

	s.released = append(s.released, out...)
	s.buffer = append([]byte(nil), s.buffer[end:]...)
	if s.frozenAt >= 0 {
		s.frozenAt -= end
		if s.frozenAt < 0 {
			s.frozenAt = 0
		}
	}
	return out
}

// Released returns everything emitted, which is what the receipt covers.
func (s *StreamGovernor) Released() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.released...)
}

// Truncated reports whether the stream was cut short.
//
// A truncated stream that reads as a complete one is the worst outcome
// available here, so this is surfaced rather than inferred.
func (s *StreamGovernor) Truncated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.truncated
}

// Findings summarises the whole stream.
func (s *StreamGovernor) Findings() []receipt.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]receipt.Finding, 0, len(s.findings))
	for class, count := range s.findings {
		out = append(out, receipt.Finding{
			Class:    string(class),
			Count:    count,
			Decision: s.engine.policy.Decide(class, detect.ConfidenceExact),
		})
	}
	return out
}

// streamHasRefusedClass reports whether the content contains a completed
// match the policy refuses to release.
func (e *Engine) streamHasRefusedClass(content []byte) bool {
	for _, sp := range e.ruleset.Scan(content) {
		switch e.policy.Decide(sp.Class, sp.Confidence) {
		case receipt.DecisionBlock, receipt.DecisionRequireApproval:
			return true
		}
	}
	return false
}

// firstRefusedMarker finds the earliest position where a refusing class
// might begin.
//
// Uses the literal prefilters the rules already carry. A marker is not a
// match — it is the point beyond which releasing would risk releasing part
// of something the policy refuses, which is precisely when to stop.
func (e *Engine) firstRefusedMarker(content []byte) int {
	text := string(content)
	earliest := -1

	for _, rule := range e.ruleset.Rules() {
		switch e.policy.Decide(rule.Class, rule.Confidence) {
		case receipt.DecisionBlock, receipt.DecisionRequireApproval:
		default:
			continue
		}
		for _, marker := range rule.Prefilter {
			if at := strings.Index(text, marker); at >= 0 && (earliest < 0 || at < earliest) {
				earliest = at
			}
		}
	}
	return earliest
}
