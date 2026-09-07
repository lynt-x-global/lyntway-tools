"""Request signing: the vectors, the client, and the environment.

The vectors in ``testdata/signing_vectors.json`` are the contract shared
with the TypeScript SDK and checked against the Go verifier. The check here
does not stop at "the headers match": ``_verify_independently`` rebuilds the
signature base from the vector's hand-written authority and path and checks
the Ed25519 signature against the public key, so a signer that derived the
wrong host would fail even if its own output were internally consistent.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import sys
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyntway import Lyntway, RequestSigner, sign_request  # noqa: E402
from lyntway.signing import content_digest, load_private_key  # noqa: E402

VECTORS = json.loads(
    (Path(__file__).parent / "testdata" / "signing_vectors.json").read_text(encoding="utf-8")
)
PUBLIC = Ed25519PublicKey.from_public_bytes(base64.b64decode(VECTORS["public_key_b64"]))
KEY_ID = VECTORS["key_id"]
PEM = VECTORS["private_key_pem"]


def _verify_independently(
    headers: dict, method: str, authority: str, path: str, body: bytes | None
) -> None:
    """Check a signature the way the gateway does, without the signer's help.

    Parses Signature-Input, rebuilds the base from values supplied by the
    caller, and verifies with the public key. Raises on any mismatch.
    """
    label, inner = headers["Signature-Input"].split("=", 1)
    assert label == "sig1"
    covered = inner[1 : inner.index(")")].split(" ")
    values = {
        '"@method"': method.upper(),
        '"@authority"': authority,
        '"@path"': path,
    }
    if body:
        assert headers["Content-Digest"] == (
            "sha-256=:" + base64.b64encode(__import__("hashlib").sha256(body).digest()).decode() + ":"
        )
        values['"content-digest"'] = headers["Content-Digest"]
        assert covered == ['"@method"', '"@authority"', '"@path"', '"content-digest"']
    else:
        assert "Content-Digest" not in headers
        assert covered == ['"@method"', '"@authority"', '"@path"']

    lines = [f"{c}: {values[c]}" for c in covered]
    lines.append(f'"@signature-params": {inner}')
    base = "\n".join(lines).encode("utf-8")

    sig_label, sig_value = headers["Signature"].split("=", 1)
    assert sig_label == "sig1"
    assert sig_value.startswith(":") and sig_value.endswith(":")
    signature = base64.b64decode(sig_value[1:-1])
    PUBLIC.verify(signature, base)  # raises InvalidSignature on mismatch


# -- The cross-language vectors ----------------------------------------------


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_vector_is_reproduced_exactly(vector: dict) -> None:
    req = vector["request"]
    body = None if req["body"] is None else req["body"].encode("utf-8")
    headers = sign_request(
        req["method"],
        req["url"],
        body,
        private_key=PEM,
        key_id=KEY_ID,
        created=vector["created"],
        nonce=vector["nonce"],
    )
    expected = vector["expected"]
    assert headers.get("Content-Digest") == expected["content_digest"]
    assert headers["Signature-Input"] == expected["signature_input"]
    assert headers["Signature"] == expected["signature"]


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_vector_verifies_against_hand_written_authority_and_path(vector: dict) -> None:
    req = vector["request"]
    body = None if req["body"] is None else req["body"].encode("utf-8")
    expected = vector["expected"]
    headers = {"Signature-Input": expected["signature_input"], "Signature": expected["signature"]}
    if expected["content_digest"] is not None:
        headers["Content-Digest"] = expected["content_digest"]
    _verify_independently(
        headers,
        req["method"],
        vector["expected"]["authority"],
        vector["expected"]["path"],
        body,
    )


def test_vector_params_are_what_the_profile_requires() -> None:
    for vector in VECTORS["vectors"]:
        inp = vector["expected"]["signature_input"]
        assert f";created={vector['created']};expires={vector['created'] + 300};" in inp
        assert f';keyid="{KEY_ID}";alg="ed25519";tag="web-bot-auth"' in inp
        assert "signature-agent" not in inp


# -- The signer on its own --------------------------------------------------


def test_fresh_signature_verifies_and_nonces_differ() -> None:
    body = b'{"content": "hello"}'
    a = sign_request("POST", "https://govern.lyntway.com/v1/govern", body, private_key=PEM, key_id=KEY_ID)
    b = sign_request("POST", "https://govern.lyntway.com/v1/govern", body, private_key=PEM, key_id=KEY_ID)
    _verify_independently(a, "POST", "govern.lyntway.com", "/v1/govern", body)
    _verify_independently(b, "POST", "govern.lyntway.com", "/v1/govern", body)
    assert a["Signature-Input"] != b["Signature-Input"], "two signatures reused a nonce"


def test_changed_body_no_longer_verifies() -> None:
    body = b'{"content": "hello"}'
    headers = sign_request("POST", "https://govern.lyntway.com/v1/govern", body, private_key=PEM, key_id=KEY_ID)
    with pytest.raises(Exception):
        _verify_independently(headers, "POST", "govern.lyntway.com", "/v1/govern", b'{"content": "hellp"}')


def test_content_digest_is_rfc_9530_sha256() -> None:
    # SHA-256 of the empty string, a value anybody can check against a table.
    assert content_digest(b"") == "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"


def test_non_ed25519_key_is_refused() -> None:
    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="not Ed25519"):
        load_private_key(pem)


def test_key_id_that_cannot_be_quoted_is_refused() -> None:
    with pytest.raises(ValueError):
        sign_request("GET", "https://govern.lyntway.com/", private_key=PEM, key_id='key_"x')


def test_url_without_host_is_refused() -> None:
    with pytest.raises(ValueError):
        sign_request("GET", "/v1/govern", private_key=PEM, key_id=KEY_ID)


def test_public_key_matches_the_vectors() -> None:
    signer = RequestSigner(PEM, KEY_ID)
    assert base64.b64encode(signer.public_key).decode() == VECTORS["public_key_b64"]


# -- The client ---------------------------------------------------------------


class _Captured:
    """Records the urllib Request the client built and answers it."""

    def __init__(self) -> None:
        self.request: urllib.request.Request | None = None

    def __call__(self, request, timeout=None):  # noqa: D102
        self.request = request
        return io.BytesIO(json.dumps({"decision": "allow", "mode": "full", "receipt": {}}).encode())


def _headers_of(request: urllib.request.Request) -> dict:
    # urllib title-cases header names on the way in; put them back.
    canon = {"signature-input": "Signature-Input", "signature": "Signature",
             "content-digest": "Content-Digest", "authorization": "Authorization"}
    return {canon.get(k.lower(), k): v for k, v in request.header_items()}


def _govern(client: Lyntway, monkeypatch) -> dict:
    captured = _Captured()
    monkeypatch.setattr("lyntway.client.urllib.request.urlopen", captured)
    client.govern(chain_id="c", content="hello", actor_id="agent_1")
    assert captured.request is not None
    return _headers_of(captured.request) | {"__data__": captured.request.data,
                                            "__url__": captured.request.full_url}


def test_client_signs_the_bytes_it_sends(monkeypatch) -> None:
    client = Lyntway("https://govern.lyntway.com/", "sk-test", signer=RequestSigner(PEM, KEY_ID))
    sent = _govern(client, monkeypatch)
    assert sent["Authorization"] == "Bearer sk-test", "the bearer must stay; the signature upgrades identity"
    _verify_independently(sent, "POST", "govern.lyntway.com", "/v1/govern", sent["__data__"])


def test_client_with_no_signer_sends_no_signature(monkeypatch) -> None:
    monkeypatch.delenv("LYNTWAY_SIGNING_KEY", raising=False)
    monkeypatch.delenv("LYNTWAY_KEY_ID", raising=False)
    sent = _govern(Lyntway("https://govern.lyntway.com", "sk-test"), monkeypatch)
    assert "Signature" not in sent and "Signature-Input" not in sent and "Content-Digest" not in sent


def test_client_reads_signing_configuration_from_the_environment(monkeypatch, tmp_path) -> None:
    pem_path = tmp_path / "key.pem"
    pem_path.write_text(PEM)
    monkeypatch.setenv("LYNTWAY_SIGNING_KEY", str(pem_path))
    monkeypatch.setenv("LYNTWAY_KEY_ID", KEY_ID)

    sent = _govern(Lyntway("http://localhost:8899", "sk-test"), monkeypatch)
    assert f'keyid="{KEY_ID}"' in sent["Signature-Input"]
    _verify_independently(sent, "POST", "localhost:8899", "/v1/govern", sent["__data__"])


def test_signer_false_overrides_the_environment(monkeypatch, tmp_path) -> None:
    pem_path = tmp_path / "key.pem"
    pem_path.write_text(PEM)
    monkeypatch.setenv("LYNTWAY_SIGNING_KEY", str(pem_path))
    monkeypatch.setenv("LYNTWAY_KEY_ID", KEY_ID)
    sent = _govern(Lyntway("https://govern.lyntway.com", "sk-test", signer=False), monkeypatch)
    assert "Signature" not in sent


def test_half_a_signing_configuration_raises(monkeypatch) -> None:
    """Silently sending unsigned would leave receipts reading asserted for weeks."""
    monkeypatch.setenv("LYNTWAY_SIGNING_KEY", "/nonexistent/key.pem")
    monkeypatch.delenv("LYNTWAY_KEY_ID", raising=False)
    with pytest.raises(ValueError, match="LYNTWAY_KEY_ID"):
        Lyntway("https://govern.lyntway.com", "sk-test")

    monkeypatch.delenv("LYNTWAY_SIGNING_KEY", raising=False)
    monkeypatch.setenv("LYNTWAY_KEY_ID", KEY_ID)
    with pytest.raises(ValueError, match="LYNTWAY_SIGNING_KEY"):
        Lyntway("https://govern.lyntway.com", "sk-test")


def test_litellm_handler_survives_a_bad_signing_configuration(monkeypatch, caplog) -> None:
    """The constructor raises on purpose; inside LiteLLM that must become a log line."""
    from lyntway.litellm import LyntwayLogger

    monkeypatch.setenv("LYNTWAY_SIGNING_KEY", "/nonexistent/key.pem")
    monkeypatch.setenv("LYNTWAY_KEY_ID", KEY_ID)
    lg = LyntwayLogger(base_url="https://example.invalid", api_key="k")
    with caplog.at_level(logging.WARNING, logger="lyntway.litellm"):
        lg.log_success_event({"messages": [{"role": "user", "content": "hi"}]}, None, 0, 0)
    assert lg._client is None
    assert any("could not be configured" in r.getMessage() for r in caplog.records)
