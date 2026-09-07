"""Regenerate signing_vectors.json.

    cd packages/lyntway-py && PYTHONPATH=src python3 tests/testdata/make_signing_vectors.py

The vectors are the cross-language contract for request signing: the
Python and TypeScript SDKs both assert them, and the Go verifier
(webbotauth.Verify) checks that every one of them verifies. That last step
is the one that matters. Regenerating with a broken signer produces vectors
the two SDKs agree on and the gateway rejects, so nothing here is right
until the Go test has run against it.

Everything is fixed — seed, key id, created, nonce — so the output is
byte-identical from one run to the next.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from lyntway.signing import DEFAULT_TTL, sign_request  # noqa: E402

SEED = hashlib.sha256(b"lyntway signing vectors").digest()
KEY_ID = "key_5f3a9c1e7b2d4680a1b2c3d4e5f60718"
CREATED = 1757203200  # 2026-09-07T00:00:00Z
NONCE = "c2lnbmluZy12ZWN0b3Jz"  # base64url of 16 fixed bytes

BODY = json.dumps(
    {
        "chain_id": "ws_acme",
        "content": "Customer priya@acme.com paid with 4111111111111111.",
        "actor": {"type": "agent", "id": "agent_support", "source": "lyntway_key"},
    },
    separators=(", ", ": "),
)

CASES = [
    # name, method, url, body, expected @authority, expected @path, note.
    # authority and path are written by hand, not derived, so the test that
    # reads them checks the signer's derivation against a person's reading of
    # the URL rather than against itself.
    ("post_with_body", "POST", "https://govern.lyntway.com/v1/govern", BODY,
     "govern.lyntway.com", "/v1/govern",
     "the common case: JSON body, content-digest covered"),
    ("get_without_body", "GET", "https://govern.lyntway.com/v1/keys", None,
     "govern.lyntway.com", "/v1/keys",
     "no body, so content-digest is neither sent nor covered"),
    ("default_port_and_case_folded", "POST", "https://GOVERN.Lyntway.com:443/v1/govern", BODY,
     "govern.lyntway.com", "/v1/govern",
     "@authority is lowercased and :443 dropped on https"),
    ("nondefault_port_kept", "POST", "http://localhost:8899/gw/openai/v1/chat/completions",
     '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}',
     "localhost:8899", "/gw/openai/v1/chat/completions",
     "a non-default port stays in @authority"),
    ("query_not_in_path", "GET", "https://govern.lyntway.com/v1/receipts?limit=5&after=rcpt_01",
     None, "govern.lyntway.com", "/v1/receipts",
     "@path is the path alone; the query is not covered"),
    ("empty_path_is_slash", "GET", "https://govern.lyntway.com", None,
     "govern.lyntway.com", "/",
     "a URL with no path signs @path as /"),
    ("utf8_body", "POST", "https://govern.lyntway.com/v1/govern",
     '{"content": "Priya a payé 1 200 € — carte 4111 1111 1111 1111"}',
     "govern.lyntway.com", "/v1/govern",
     "the digest is over the UTF-8 bytes, not the code points"),
    ("empty_body_no_digest", "POST", "https://govern.lyntway.com/v1/govern", "",
     "govern.lyntway.com", "/v1/govern",
     "an empty body counts as no body: nothing to digest"),
]


def main() -> None:
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    vectors = []
    for name, method, url, body, authority, path, note in CASES:
        raw = None if body is None else body.encode("utf-8")
        headers = sign_request(
            method, url, raw, private_key=key, key_id=KEY_ID, created=CREATED, nonce=NONCE
        )
        vectors.append(
            {
                "name": name,
                "note": note,
                "request": {"method": method, "url": url, "body": body},
                "created": CREATED,
                "expires": CREATED + DEFAULT_TTL,
                "nonce": NONCE,
                "verify_at": CREATED + 10,
                "expected": {
                    "authority": authority,
                    "path": path,
                    "content_digest": headers.get("Content-Digest"),
                    "signature_input": headers["Signature-Input"],
                    "signature": headers["Signature"],
                },
            }
        )

    out = {
        "description": (
            "Web Bot Auth (RFC 9421) request signatures produced by the Lyntway SDKs. "
            "Each vector's expected headers must be reproduced exactly by the Python and "
            "TypeScript signers, and must verify with webbotauth.Verify in Go when the "
            "clock is set to verify_at and the key id resolves to public_key."
        ),
        "profile": {
            "label": "sig1",
            "covered": ["@method", "@authority", "@path", "content-digest"],
            "content_digest_when": "the body is non-empty; then Content-Digest: sha-256=:base64:",
            "params": "created, expires=created+300, nonce (16 random bytes, base64url, unpadded), keyid, alg=ed25519, tag=web-bot-auth",
            "authority": "host lowercased; :443 dropped on https and :80 on http; any other port kept",
            "path": "the URL path without the query; / when empty",
            "signature_base": 'RFC 9421 section 2.5: one "name": value line per covered component, then "@signature-params": <inner list and params exactly as in Signature-Input>, newline-separated, no trailing newline',
        },
        "key_id": KEY_ID,
        "private_key_pem": pem,
        "private_key_seed_b64": base64.b64encode(SEED).decode("ascii"),
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "vectors": vectors,
    }
    dest = Path(__file__).with_name("signing_vectors.json")
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors)} vectors to {dest}")


if __name__ == "__main__":
    main()
