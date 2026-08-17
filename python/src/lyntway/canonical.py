"""RFC 8785 JSON Canonicalization Scheme.

This must produce byte-identical output to the Go implementation in
``receipt/canonical.go`` and the TypeScript one in ``@lyntway/govern``. A
single byte of divergence means every signature fails to verify, and the
failure looks exactly like tampering — the worst way for an interoperability
bug to present.

The rules that actually bite:

* Object keys sort by UTF-16 code unit, not by code point and not by UTF-8
  byte order. The three agree for ASCII and diverge above U+FFFF, where a
  supplementary character encodes as a surrogate pair starting at 0xD800 and
  therefore sorts *before* characters in U+E000..U+FFFF.
* Only seven characters take short escapes. Everything else below U+0020
  takes a lowercase ``\\u00xx`` escape, and nothing else is escaped at all —
  in particular not ``<``, ``>`` or ``&``, which many JSON encoders escape by
  default for HTML safety.
* No insignificant whitespace anywhere.

Numbers are deliberately restricted. RFC 8785 requires ECMAScript
``Number::toString`` formatting, which is the largest single source of
cross-language canonicalisation bugs. The receipt schema contains no
floating-point fields, so this implementation rejects non-integral numbers
rather than reimplementing shortest-round-trip formatting and hoping it
matches.
"""

from __future__ import annotations

from typing import Any

__all__ = ["canonicalize", "canonical_bytes", "CanonicalizationError"]


class CanonicalizationError(ValueError):
    """A value has no reproducible canonical form."""

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"cannot canonicalize at {path}: {reason}")
        self.path = path
        self.reason = reason


def canonicalize(value: Any) -> str:
    """Serialise ``value`` as canonical JSON per RFC 8785."""
    out: list[str] = []
    _write(value, "$", out)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    """Serialise ``value`` and return its UTF-8 bytes.

    This is what a signature actually covers.
    """
    return canonicalize(value).encode("utf-8")


def _write(value: Any, path: str, out: list[str]) -> None:
    if value is None:
        out.append("null")
        return

    # bool must be checked before int: in Python, bool is a subclass of int,
    # so True would otherwise serialise as 1 and silently change the signed
    # bytes.
    if isinstance(value, bool):
        out.append("true" if value else "false")
        return

    if isinstance(value, str):
        out.append(_write_string(value))
        return

    if isinstance(value, int):
        out.append(str(value))
        return

    if isinstance(value, float):
        if value != int(value) or value != value or value in (float("inf"), float("-inf")):
            raise CanonicalizationError(
                path,
                f"non-integral number {value}: the receipt schema forbids "
                "floating-point values because RFC 8785 number formatting is "
                "not reproducible across implementations; use an integer in a "
                "fixed unit, or a string",
            )
        out.append(str(int(value)))
        return

    if isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, f"{path}[{i}]", out)
        out.append("]")
        return

    if isinstance(value, dict):
        _write_object(value, path, out)
        return

    raise CanonicalizationError(path, f"unsupported type {type(value).__name__}")


def _utf16_sort_key(s: str) -> bytes:
    """Return a sort key ordering strings by UTF-16 code unit.

    Encoding to big-endian UTF-16 and comparing the resulting bytes
    lexicographically is exactly a comparison of code units, including the
    surrogate behaviour above U+FFFF that a naive code-point sort gets wrong.

    Receipt keys are ASCII today, so this can never bite in practice — which
    is precisely why it would go unnoticed until an extension field carried
    an emoji and interoperability silently broke.
    """
    return s.encode("utf-16-be", errors="surrogatepass")


def _write_object(obj: dict[Any, Any], path: str, out: list[str]) -> None:
    keys = []
    for k in obj:
        if not isinstance(k, str):
            raise CanonicalizationError(path, f"object key {k!r} is not a string")
        # A None value has no JSON representation distinct from an absent
        # member here; the Go and TypeScript sides omit empty optionals, so
        # dropping None keeps the three in agreement.
        if obj[k] is None:
            continue
        keys.append(k)
    keys.sort(key=_utf16_sort_key)

    out.append("{")
    for i, k in enumerate(keys):
        if i:
            out.append(",")
        out.append(_write_string(k))
        out.append(":")
        _write(obj[k], f"{path}.{k}", out)
    out.append("}")


_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _write_string(s: str) -> str:
    out = ['"']
    for ch in s:
        escape = _SHORT_ESCAPES.get(ch)
        if escape is not None:
            out.append(escape)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            # Everything else is emitted literally, including <, > and & —
            # json.dumps would not escape those, but many encoders do, and
            # doing so would break interoperability.
            out.append(ch)
    out.append('"')
    return "".join(out)
