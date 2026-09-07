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

	// ruleset and policy are what this stream is scanned and decided
	// with. They default to the engine's own and are replaced per stream
	// through StreamOption, for the same reason Request carries them on
	// the buffered path: one engine serves every tenant, and a tenant's
	// rules and decisions are theirs alone.
	ruleset *detect.Ruleset
	policy  *Policy

	// target is the destination the stream is bound for — the
	// receipt.Action.Target of the governed action. A policy rule scoped
	// to an upstream can only match when this is set; without it, such a
	// rule is simply absent, never assumed to apply (see PolicyRule.Upstream).
	target string

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

	// restoring reverses substitution instead of applying it, for a stream
	// travelling back to the party whose data it is.
	restoring bool

	stopped   bool
	truncated bool
}

// StreamOption adjusts how a stream is governed. The zero configuration
// is the engine's own ruleset and policy, decided for no destination.
type StreamOption func(*StreamGovernor)

// WithRuleset scans the stream with a ruleset other than the engine's own.
// Nil keeps the engine's, so a caller holding a per-tenant ruleset that may
// be absent need not branch.
func WithRuleset(r *detect.Ruleset) StreamOption {
	return func(s *StreamGovernor) {
		if r != nil {
			s.ruleset = r
		}
	}
}

// WithPolicy decides the stream's findings with a policy other than the
// engine's own. Nil keeps the engine's. Pair it with WithRuleset when the
// two come from the same configuration: a tenant's rules without the
// decisions that act on them produce findings that change nothing.
func WithPolicy(p *Policy) StreamOption {
	return func(s *StreamGovernor) {
		if p != nil {
			s.policy = p
		}
	}
}

// WithTarget names the destination the stream is bound for, which is what
// lets a rule scoped to one upstream apply. Before this existed the
// streaming path decided every finding with no target, so "allow this to
// the CRM" held on a buffered reply and was ignored on a streamed one —
// and every chat interface streams.
func WithTarget(target string) StreamOption {
	return func(s *StreamGovernor) {
		s.target = target
	}
}

// NewStreamGovernor starts governing a stream on its way out.
//
// Sensitive values found in it are substituted, because the reader is
// somebody else. This is the direction for a tool result arriving from
// elsewhere and heading for a model's context.
func (e *Engine) NewStreamGovernor(scope *tokenize.Scope, opts ...StreamOption) *StreamGovernor {
	s := &StreamGovernor{
		engine:   e,
		scope:    scope,
		ruleset:  e.ruleset,
		policy:   e.policy,
		findings: make(map[detect.Class]int),
		frozenAt: -1,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// decide is every policy decision the stream makes, so that all of them
// are made for the same destination. Three call sites once each called
// Decide directly, which is how a scoped rule came to apply on one path
// and not another.
func (s *StreamGovernor) decide(class detect.Class, conf detect.Confidence) receipt.Decision {
	return s.policy.DecideFor(s.target, class, conf)
}

// NewRestoringStreamGovernor starts governing a stream on its way back.
//
// A model's reply is written in terms of the tokens it was given, and it is
// travelling to the party those tokens stand for. So the substitution is
// reversed rather than repeated: the caller receives its own values, having
// never let the provider hold them.
//
// This is what the buffered path has always done. The streaming path
// returned before that code and shipped tokens to the application instead,
// so an identical call answered differently depending on stream=True — with
// the broken answer going to every chat interface, which all stream.
func (e *Engine) NewRestoringStreamGovernor(scope *tokenize.Scope, opts ...StreamOption) *StreamGovernor {
	g := e.NewStreamGovernor(scope, opts...)
	g.restoring = true
	return g
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
	if s.cutForRefused() {
		return nil, ErrStreamUnsafe
	}

	// A marker for a refusing class freezes emission at its position. The
	// rule may not have matched yet — that is exactly why the bytes cannot
	// be released.
	if s.frozenAt < 0 {
		if at := s.firstRefusedMarker(s.buffer); at >= 0 {
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

// withinRestored reports whether a span sits inside a value this scope just
// handed back, which is what separates the caller's own data from data the
// far end produced.
func withinRestored(sp detect.Span, marks []tokenize.Restored) bool {
	for _, m := range marks {
		if sp.Start < m.End && m.Start < sp.End {
			return true
		}
	}
	return false
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
	if s.frozenAt >= 0 && s.cutForRefused() {
		return nil, ErrStreamUnsafe
	}
	s.stopped = true
	return s.release(len(s.buffer)), nil
}

// release governs buffer[:end], records what was found, and returns it.
//
// Which way it governs depends on where the text is going. Substituting is
// for content on its way out to somebody else; restoring is for content on
// its way back to the person it belongs to. Doing the wrong one is not a
// smaller mistake than doing neither.
func (s *StreamGovernor) release(end int) []byte {
	if end <= 0 {
		return nil
	}
	segment := s.buffer[:end]

	out := segment

	// Restoring happens before the scan, and records where each value
	// landed. A token is format-preserving by design, so once restored a
	// detector cannot tell a value just handed back from one appearing for
	// the first time — the marks are how the difference survives.
	var restoredRanges []tokenize.Restored
	if s.restoring && s.scope != nil {
		if restored, marks, err := s.scope.RestoreMarking(segment); err == nil {
			out, restoredRanges = restored, marks
		}
		// A failure leaves the tokens in place. Useless to the caller, but
		// they are not somebody else's values, which is the error that
		// matters.
	}

	spans := s.ruleset.Scan(out)
	for _, sp := range spans {
		s.findings[sp.Class]++
	}

	// On the way back, two kinds of value sit in the same sentence and need
	// opposite handling. What this scope issued has just been restored and
	// belongs to the caller, so substituting it again would hand somebody
	// their own data disguised. Anything else was produced by the far end,
	// was never governed on the way out, and is substituted like any other
	// value — a model that returns a card number nobody sent it is exactly
	// the case this must not wave through.
	//
	// Both are still counted above, so the receipt describes the whole
	// reply rather than the half that was acted on.
	if s.restoring && s.scope != nil && len(spans) > 0 {
		var fresh []detect.Span
		for _, sp := range spans {
			if !withinRestored(sp, restoredRanges) {
				fresh = append(fresh, sp)
			}
		}
		if len(fresh) > 0 {
			var toTokenize []detect.Span
			for _, sp := range fresh {
				if s.decide(sp.Class, sp.Confidence) == receipt.DecisionTokenize {
					toTokenize = append(toTokenize, sp)
				}
			}
			if len(toTokenize) > 0 {
				if applied, err := s.scope.Apply(out, toTokenize); err == nil {
					out = applied
				}
			}
		}
	}

	if !s.restoring && s.scope != nil && len(spans) > 0 {
		var toTokenize []detect.Span
		for _, sp := range spans {
			if s.decide(sp.Class, sp.Confidence) == receipt.DecisionTokenize {
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
			Decision: s.decide(class, detect.ConfidenceExact),
		})
	}
	return out
}

// refusedSpans returns the completed matches the policy refuses to
// release.
func (s *StreamGovernor) refusedSpans(content []byte) []detect.Span {
	var out []detect.Span
	for _, sp := range s.ruleset.Scan(content) {
		switch s.decide(sp.Class, sp.Confidence) {
		case receipt.DecisionBlock, receipt.DecisionRequireApproval:
			out = append(out, sp)
		}
	}
	return out
}

// cutForRefused stops the stream if the buffer holds a completed match for
// a refusing class, and records that class as a finding.
//
// Findings are otherwise counted at release, and the bytes that cause a cut
// are never released — so before this the receipt for a cut stream carried
// no trace of the credential that cut it. The refused spans sit past the
// frozen point, so none of them has been counted before.
func (s *StreamGovernor) cutForRefused() bool {
	refused := s.refusedSpans(s.buffer)
	if len(refused) == 0 {
		return false
	}
	for _, sp := range refused {
		s.findings[sp.Class]++
	}
	s.stopped, s.truncated = true, true
	return true
}

// firstRefusedMarker finds the earliest position where a refusing class
// might begin.
//
// Uses the literal prefilters the rules already carry. A marker is not a
// match — it is the point beyond which releasing would risk releasing part
// of something the policy refuses, which is precisely when to stop.
func (s *StreamGovernor) firstRefusedMarker(content []byte) int {
	text := string(content)
	earliest := -1

	for _, rule := range s.ruleset.Rules() {
		switch s.decide(rule.Class, rule.Confidence) {
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
