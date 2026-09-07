"""Sign requests so the gateway can record who sent them as verified.

The profile is RFC 9421 HTTP Message Signatures, Web Bot Auth flavour, as
verified by the gateway's ``webbotauth`` package. A bearer key proves the
caller *holds a secret we issued*; a signature proves the request came from
*the holder of a private key we never saw*. The receipt records the second
as ``verified`` and the first as ``asserted``, and that difference is the
whole point of doing this.

What is signed
--------------

Four components, always in this order: ``@method``, ``@authority``,
``@path`` and — only when the request has a body — ``content-digest``. The
authority binds the signature to the host it was sent to, so a signature
captured by one origin cannot be replayed against another; the digest
binds it to the exact bytes, so a proxy cannot swap the payload under a
valid signature.

The signature parameters carry ``created``, ``expires`` (five minutes
later), a random ``nonce``, the Lyntway ``keyid``, ``alg="ed25519"`` and
``tag="web-bot-auth"``. The tag is domain separation: RFC 9421 signatures
are used for many things and a signature made for one of them must not be
mistakable for agent identity.

There is no Signature-Agent header. Web Bot Auth agents publish a key
directory and name it there; a Lyntway key registers its public key against
its own key id instead, so the verifier already knows where to look.

What the verifier will rebuild
------------------------------

Everything here has to reproduce, byte for byte, what ``webbotauth``
constructs on the other side. ``@authority`` is the host, lowercased, with a
default port removed; ``@path`` is the path alone, never the query; the
``@signature-params`` line is the inner list and parameters exactly as they
appear in ``Signature-Input``. The cross-language vectors in
``tests/testdata/signing_vectors.json`` are the contract, and the Go
verifier is what they are checked against.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from pathlib import Path
from typing import Mapping, Optional, Union
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

__all__ = [
    "DEFAULT_TTL",
    "ENV_KEY_ID",
    "ENV_SIGNING_KEY",
    "RequestSigner",
    "content_digest",
    "load_private_key",
    "sign_request",
]

#: Path to a PKCS#8 PEM Ed25519 private key. Set alongside :data:`ENV_KEY_ID`
#: and every request the client sends to the gateway is signed.
ENV_SIGNING_KEY = "LYNTWAY_SIGNING_KEY"

#: The Lyntway key id (``key_…``) the public half was registered against.
ENV_KEY_ID = "LYNTWAY_KEY_ID"

#: Seconds from ``created`` to ``expires``. Short on purpose: a signature is
#: proof that this request was made now, and the longer it stays valid the
#: longer a captured one is worth replaying.
DEFAULT_TTL = 300

_LABEL = "sig1"
_TAG = "web-bot-auth"
_ALG = "ed25519"

KeySource = Union[Ed25519PrivateKey, bytes, str, "os.PathLike[str]"]


def load_private_key(source: KeySource) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM text, PEM bytes, or a file path.

    Only unencrypted PKCS#8 is accepted, which is what ``lyntway keys sign``
    writes. A key of another type is refused rather than signed with: the
    verifier only speaks Ed25519, and a signature it cannot check is worse
    than none because the request looks tampered with instead of unsigned.
    """
    if isinstance(source, Ed25519PrivateKey):
        return source

    if isinstance(source, (bytes, bytearray)):
        pem = bytes(source)
    elif isinstance(source, str) and "-----BEGIN" in source:
        pem = source.encode("utf-8")
    else:
        pem = Path(os.fspath(source)).read_bytes()

    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(
            f"signing key is {type(key).__name__}, not Ed25519; the gateway "
            "verifies Ed25519 only"
        )
    return key


def content_digest(body: bytes) -> str:
    """The RFC 9530 ``Content-Digest`` value for a body: ``sha-256=:…:``."""
    digest = hashlib.sha256(body).digest()
    return "sha-256=:" + base64.b64encode(digest).decode("ascii") + ":"


def _authority(parts) -> str:  # type: ignore[no-untyped-def]
    """The ``@authority`` component: host lowercased, default port dropped.

    The verifier reads the Host header the request arrived with and strips
    ``:443`` or ``:80`` according to the scheme. Both ``urllib`` and
    ``fetch`` omit a default port from Host themselves, so the two sides
    agree only if we drop it here too.
    """
    host = parts.hostname or ""
    if not host:
        raise ValueError("url has no host to bind the signature to")
    if ":" in host:
        # An IPv6 literal. hostname strips the brackets; Host carries them.
        host = "[" + host + "]"
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"url has an invalid port: {exc}") from exc
    if port is None:
        return host
    if (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80):
        return host
    return f"{host}:{port}"


def _quoted(value: str, name: str) -> str:
    """Serialise a structured-field string parameter.

    Escaping is refused rather than implemented. A key id or nonce with a
    quote or backslash in it does not occur — key ids are ``key_`` and hex,
    nonces are base64url — and an escape sequence is exactly the kind of
    detail two parsers disagree on, in a way that reads as a bad signature.
    """
    if not value or any(ch in value for ch in '"\\') or not value.isprintable():
        raise ValueError(f"{name} contains characters that cannot appear in a signature parameter")
    return '"' + value + '"'


def _new_nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")


def sign_request(
    method: str,
    url: str,
    body: Optional[bytes] = None,
    *,
    private_key: KeySource,
    key_id: str,
    created: Optional[int] = None,
    nonce: Optional[str] = None,
    ttl: int = DEFAULT_TTL,
) -> dict:
    """Return the headers that sign one request.

    For people using their own HTTP client: call this with the method, the
    full URL and the exact body bytes about to be sent, and add every
    returned header to the request. The result carries ``Signature-Input``
    and ``Signature``, and ``Content-Digest`` whenever ``body`` is
    non-empty. The body must then be sent unchanged — any re-serialisation
    changes the digest and the signature fails as if tampered with.

    ``created`` and ``nonce`` exist so the test vectors are reproducible.
    Leave them unset in real use.
    """
    if not method:
        raise ValueError("method is required")
    if not key_id:
        raise ValueError("key_id is required")
    if ttl <= 0:
        raise ValueError("ttl must be positive")

    key = load_private_key(private_key)
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"url must be http or https, got {parts.scheme!r}")

    authority = _authority(parts).lower()
    path = parts.path or "/"
    if created is None:
        created = int(time.time())
    if nonce is None:
        nonce = _new_nonce()
    expires = created + ttl

    headers: dict = {}
    components = [
        ("@method", method.upper()),
        ("@authority", authority),
        ("@path", path),
    ]
    if body:
        headers["Content-Digest"] = content_digest(body)
        components.append(("content-digest", headers["Content-Digest"]))

    params = (
        f";created={created};expires={expires}"
        f";nonce={_quoted(nonce, 'nonce')};keyid={_quoted(key_id, 'key_id')}"
        f';alg="{_ALG}";tag="{_TAG}"'
    )
    inner = "(" + " ".join(f'"{name}"' for name, _ in components) + ")" + params

    # RFC 9421 §2.5: one line per covered component, then the parameters
    # line, newline-separated with nothing after the last.
    lines = [f'"{name}": {value}' for name, value in components]
    lines.append(f'"@signature-params": {inner}')
    base = "\n".join(lines).encode("utf-8")

    signature = key.sign(base)
    headers["Signature-Input"] = f"{_LABEL}={inner}"
    headers["Signature"] = f"{_LABEL}=:{base64.b64encode(signature).decode('ascii')}:"
    return headers


class RequestSigner:
    """A private key and the key id it was registered against.

    :param private_key: An Ed25519 private key, PKCS#8 PEM, or a path to one.
    :param key_id: The Lyntway key id whose registered public key matches.
    :param ttl: Seconds a signature stays valid. Defaults to five minutes.
    """

    def __init__(self, private_key: KeySource, key_id: str, *, ttl: int = DEFAULT_TTL) -> None:
        if not key_id:
            raise ValueError("key_id is required")
        self._key = load_private_key(private_key)
        self._key_id = key_id
        self._ttl = ttl

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> bytes:
        """The raw 32-byte public key, for registering against the key id."""
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> Optional["RequestSigner"]:
        """Build a signer from the environment, or ``None`` when it is unset.

        Half a configuration raises. Somebody who exported the key path and
        forgot the key id believes their requests are signed, and a client
        that quietly sent them unsigned would have their receipts read
        ``asserted`` for weeks before anyone noticed.
        """
        env = os.environ if environ is None else environ
        path = (env.get(ENV_SIGNING_KEY) or "").strip()
        key_id = (env.get(ENV_KEY_ID) or "").strip()
        if not path and not key_id:
            return None
        if not path:
            raise ValueError(f"{ENV_KEY_ID} is set but {ENV_SIGNING_KEY} is not; both are needed to sign")
        if not key_id:
            raise ValueError(f"{ENV_SIGNING_KEY} is set but {ENV_KEY_ID} is not; both are needed to sign")
        return cls(path, key_id)

    def sign(
        self,
        method: str,
        url: str,
        body: Optional[bytes] = None,
        *,
        created: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> dict:
        """The headers that sign one request. See :func:`sign_request`."""
        return sign_request(
            method,
            url,
            body,
            private_key=self._key,
            key_id=self._key_id,
            created=created,
            nonce=nonce,
            ttl=self._ttl,
        )
