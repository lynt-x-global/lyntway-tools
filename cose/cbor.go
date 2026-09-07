// Package cose encodes receipts as COSE_Sign1, for interoperability with
// the transparency architecture standardised as RFC 9943.
//
// # Why an envelope rather than a remapping
//
// The obvious approach is to define a CBOR representation of every receipt
// field. That means a second schema, a second canonicalisation to get
// byte-exact across four languages, and a permanent obligation to keep the
// two in step — with a divergence between them presenting as a forged
// receipt rather than as a bug.
//
// Instead the payload is the receipt's existing canonical JSON, unchanged,
// carried inside a COSE envelope with a content type that says so. The
// receipt's bytes are identical in both forms, there is one schema, and
// anything that speaks COSE can read what we issue.
//
// # A receipt cannot be converted after the fact
//
// The two forms sign different things: the JSON form signs its canonical
// bytes, and COSE signs a structure that includes its own protected
// headers. So producing a COSE form means signing again, which only the
// issuer can do. Nobody can take a JSON receipt they were handed and
// present it as COSE — and a design that appeared to allow it would be
// inviting people to forge the conversion.
package cose

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

// Deterministic CBOR, as RFC 8949 section 4.2.1 defines it.
//
// Determinism is not a nicety here. Two implementations that encode the
// same receipt differently produce different signing inputs, and every
// signature then fails in a way indistinguishable from tampering. The rules
// are few: shortest-form integers, definite lengths everywhere, and map
// keys ordered by their encoded bytes.
//
// Only the subset a COSE_Sign1 needs is implemented. A general CBOR library
// would carry indefinite lengths, floats, and tags this never emits — all
// of them decisions to get wrong in a package that sits in the chain of
// trust.

// Major types, in the high three bits of an initial byte.
const (
	majorUint   byte = 0
	majorNegInt byte = 1
	majorBytes  byte = 2
	majorText   byte = 3
	majorArray  byte = 4
	majorMap    byte = 5
	majorTag    byte = 6
)

// Value is anything this encoder accepts.
//
// A closed set rather than `any`, so an unsupported value is a compile-time
// mistake instead of a runtime one in the middle of signing.
type Value interface{ encode(*[]byte) }

// Uint is a non-negative integer.
type Uint uint64

// Int is a signed integer, used for COSE algorithm identifiers, which are
// negative by convention.
type Int int64

// Bytes is a byte string.
type Bytes []byte

// Text is a UTF-8 string.
type Text string

// Array is an ordered sequence.
type Array []Value

// MapEntry is one key and value. A slice of these rather than a Go map,
// because deterministic encoding depends on order and a map has none.
type MapEntry struct {
	Key   Value
	Value Value
}

// Map is a CBOR map. Entries are sorted by encoded key at encoding time.
type Map []MapEntry

// Tag wraps a value with a semantic tag.
type Tag struct {
	Number uint64
	Value  Value
}

func (v Uint) encode(out *[]byte) { encodeHead(out, majorUint, uint64(v)) }
func (v Bytes) encode(out *[]byte) {
	encodeHead(out, majorBytes, uint64(len(v)))
	*out = append(*out, v...)
}
func (v Text) encode(out *[]byte) {
	encodeHead(out, majorText, uint64(len(v)))
	*out = append(*out, v...)
}

func (v Int) encode(out *[]byte) {
	if v >= 0 {
		encodeHead(out, majorUint, uint64(v))
		return
	}
	// A negative integer is encoded as -1 minus the value, so -1 is 0.
	encodeHead(out, majorNegInt, uint64(-1-int64(v)))
}

func (v Array) encode(out *[]byte) {
	encodeHead(out, majorArray, uint64(len(v)))
	for _, item := range v {
		item.encode(out)
	}
}

func (v Map) encode(out *[]byte) {
	// Sorted by the bytes of the encoded key, which is what makes two
	// encoders agree. Sorting by the Go value would order -7 before 1 by
	// arithmetic and after it by encoding, and the two would disagree.
	type encoded struct {
		key   []byte
		value Value
	}
	entries := make([]encoded, 0, len(v))
	for _, e := range v {
		var key []byte
		e.Key.encode(&key)
		entries = append(entries, encoded{key: key, value: e.Value})
	}
	sort.Slice(entries, func(i, j int) bool {
		return string(entries[i].key) < string(entries[j].key)
	})

	encodeHead(out, majorMap, uint64(len(entries)))
	for _, e := range entries {
		*out = append(*out, e.key...)
		e.value.encode(out)
	}
}

func (v Tag) encode(out *[]byte) {
	encodeHead(out, majorTag, v.Number)
	v.Value.encode(out)
}

// encodeHead writes a major type and argument in the shortest form.
//
// Shortest form is required: an encoder that wrote every length in eight
// bytes would produce valid CBOR that no deterministic decoder accepts, and
// the signature over it would verify nowhere else.
func encodeHead(out *[]byte, major byte, argument uint64) {
	high := major << 5
	switch {
	case argument < 24:
		*out = append(*out, high|byte(argument))
	case argument <= math.MaxUint8:
		*out = append(*out, high|24, byte(argument))
	case argument <= math.MaxUint16:
		*out = append(*out, high|25)
		*out = binary.BigEndian.AppendUint16(*out, uint16(argument))
	case argument <= math.MaxUint32:
		*out = append(*out, high|26)
		*out = binary.BigEndian.AppendUint32(*out, uint32(argument))
	default:
		*out = append(*out, high|27)
		*out = binary.BigEndian.AppendUint64(*out, argument)
	}
}

// Encode returns the deterministic CBOR encoding of a value.
func Encode(v Value) []byte {
	var out []byte
	v.encode(&out)
	return out
}

// Errors from decoding.
var (
	// ErrMalformed means the input is not the CBOR this package expects.
	ErrMalformed = errors.New("cose: malformed CBOR")

	// ErrNotDeterministic means the input is valid CBOR encoded in a form
	// this package will not accept.
	//
	// Refused rather than tolerated. Accepting a non-shortest encoding
	// would mean two byte sequences with one meaning, and a signature is a
	// statement about bytes.
	ErrNotDeterministic = errors.New("cose: CBOR is not in deterministic form")
)

// decodeHead reads a major type and argument, rejecting non-shortest forms.
func decodeHead(in []byte) (major byte, argument uint64, rest []byte, err error) {
	if len(in) == 0 {
		return 0, 0, nil, ErrMalformed
	}
	initial := in[0]
	major = initial >> 5
	low := initial & 0x1f
	in = in[1:]

	switch {
	case low < 24:
		return major, uint64(low), in, nil
	case low == 24:
		if len(in) < 1 {
			return 0, 0, nil, ErrMalformed
		}
		if in[0] < 24 {
			return 0, 0, nil, ErrNotDeterministic
		}
		return major, uint64(in[0]), in[1:], nil
	case low == 25:
		if len(in) < 2 {
			return 0, 0, nil, ErrMalformed
		}
		v := uint64(binary.BigEndian.Uint16(in))
		if v <= math.MaxUint8 {
			return 0, 0, nil, ErrNotDeterministic
		}
		return major, v, in[2:], nil
	case low == 26:
		if len(in) < 4 {
			return 0, 0, nil, ErrMalformed
		}
		v := uint64(binary.BigEndian.Uint32(in))
		if v <= math.MaxUint16 {
			return 0, 0, nil, ErrNotDeterministic
		}
		return major, v, in[4:], nil
	case low == 27:
		if len(in) < 8 {
			return 0, 0, nil, ErrMalformed
		}
		v := binary.BigEndian.Uint64(in)
		if v <= math.MaxUint32 {
			return 0, 0, nil, ErrNotDeterministic
		}
		return major, v, in[8:], nil
	}
	// Indefinite lengths and the reserved values are never emitted here
	// and never accepted.
	return 0, 0, nil, fmt.Errorf("%w: unsupported initial byte %#x", ErrMalformed, initial)
}

// Null is the CBOR simple value null, which a COSE_Sign1 carries in place
// of a payload that travels separately (RFC 9052 section 4.2). COSE
// Receipts detach their payload on purpose — RFC 9942 section 4.4 — so a
// verifier is forced to recompute the root rather than trust the one in
// the envelope.
type Null struct{}

// simpleNull is the argument of major type 7 that means null.
const simpleNull = 22

func (Null) encode(out *[]byte) { encodeHead(out, majorSimple, simpleNull) }

// majorSimple is major type 7: simple values and floats. Only null is
// accepted from it.
const majorSimple byte = 7

// decodeValue reads one value of any kind this package encodes.
//
// The signed structures are read field by field, because a verifier must
// not depend on a generic decoder's idea of what it saw. This exists for
// the headers, where a map has to be walked to find the labels that matter
// and carried intact past the ones that do not.
func decodeValue(in []byte) (Value, []byte, error) {
	major, argument, rest, err := decodeHead(in)
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case majorUint:
		return Uint(argument), rest, nil
	case majorNegInt:
		if argument > math.MaxInt64 {
			// -1 - argument would not fit an int64. Nothing here needs a
			// number that large, and pretending otherwise would wrap.
			return nil, nil, fmt.Errorf("%w: negative integer out of range", ErrMalformed)
		}
		return Int(-1 - int64(argument)), rest, nil
	case majorBytes, majorText:
		if uint64(len(rest)) < argument {
			return nil, nil, ErrMalformed
		}
		body, rest := rest[:argument], rest[argument:]
		if major == majorBytes {
			return Bytes(body), rest, nil
		}
		return Text(body), rest, nil
	case majorArray:
		out := make(Array, 0, min(argument, uint64(len(rest))))
		for i := uint64(0); i < argument; i++ {
			var item Value
			item, rest, err = decodeValue(rest)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, item)
		}
		return out, rest, nil
	case majorMap:
		out := make(Map, 0, min(argument, uint64(len(rest))))
		seen := make(map[string]bool, len(out))
		for i := uint64(0); i < argument; i++ {
			var key, value Value
			key, rest, err = decodeValue(rest)
			if err != nil {
				return nil, nil, err
			}
			// A duplicate key is two values for one label, and a
			// verifier and a signer could pick different ones.
			encoded := string(Encode(key))
			if seen[encoded] {
				return nil, nil, fmt.Errorf("%w: duplicate map key", ErrMalformed)
			}
			seen[encoded] = true
			value, rest, err = decodeValue(rest)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, MapEntry{Key: key, Value: value})
		}
		return out, rest, nil
	case majorTag:
		inner, rest, err := decodeValue(rest)
		if err != nil {
			return nil, nil, err
		}
		return Tag{Number: argument, Value: inner}, rest, nil
	case majorSimple:
		if argument == simpleNull {
			return Null{}, rest, nil
		}
	}
	return nil, nil, fmt.Errorf("%w: unsupported major type %d", ErrMalformed, major)
}

// get returns the value under a label, matching on encoded bytes so that
// Uint(1) and Int(1) name the same entry.
func (v Map) get(key Value) (Value, bool) {
	want := string(Encode(key))
	for _, e := range v {
		if string(Encode(e.Key)) == want {
			return e.Value, true
		}
	}
	return nil, false
}

// set replaces the value under a label, or adds it.
func (v Map) set(key Value, value Value) Map {
	want := string(Encode(key))
	for i, e := range v {
		if string(Encode(e.Key)) == want {
			out := append(Map(nil), v...)
			out[i].Value = value
			return out
		}
	}
	return append(append(Map(nil), v...), MapEntry{Key: key, Value: value})
}
