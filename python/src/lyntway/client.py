"""Client for the govern primitive.

HTTP uses ``urllib`` from the standard library rather than ``requests``, so
the package's only runtime dependency is ``cryptography`` — required because
Python has no Ed25519 in its standard library and hand-rolled curve
arithmetic has no place in an SDK whose job is deciding whether evidence is
genuine.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

__all__ = ["Lyntway", "LyntwayError", "GovernResponse"]


class LyntwayError(Exception):
    """The service returned an error."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.status = status
        self.code = code


@dataclass
class GovernResponse:
    """The outcome of governing content."""

    #: The governed payload. ``None`` when the action was blocked.
    content: str | None
    decision: str
    mode: str
    receipt: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    #: Conditions the caller should see, such as a failed anchoring attempt.
    warnings: list[str] = field(default_factory=list)


class Lyntway:
    """Client for a Lyntway govern deployment."""

    def __init__(self, base_url: str, api_key: str, *, timeout: float = 30.0) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        if not api_key:
            raise ValueError("api_key is required")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def govern(
        self,
        *,
        chain_id: str,
        content: str,
        actor_id: str,
        actor_type: str = "agent",
        actor_source: str = "lyntway_key",
        actor_verified: bool = False,
        delegation: Sequence[Mapping[str, str]] | None = None,
        surface: str = "primitive",
        direction: str = "request",
        method: str = "POST /v1/govern",
        target: str | None = None,
        destination: str | None = None,
        receipt_id: str | None = None,
        anchor: bool = False,
    ) -> GovernResponse:
        """Govern content and return it with a signed receipt.

        :param chain_id: Scopes the receipt chain and the token namespace.
            Tokens are stable within a chain, which is what lets an agent
            correlate the same value across separate calls.
        :param destination: Where governed content was permitted to travel.
            Worth populating: it is the field an auditor asks about first.
        :param anchor: Request a synchronous external timestamp proof. Off by
            default — a timestamp authority round trip takes hundreds of
            milliseconds against a governance pass measured in microseconds.
        """
        if not chain_id:
            raise ValueError("chain_id is required")
        if not isinstance(content, str):
            raise TypeError("content must be a string")
        if not actor_id:
            raise ValueError("actor_id is required")

        body: dict[str, Any] = {
            "chain_id": chain_id,
            "content": content,
            "anchor": anchor,
            "action": {
                "surface": surface,
                "direction": direction,
                "method": method,
                "target": target,
                "destination": destination,
            },
            "actor": {
                "type": actor_type,
                "id": actor_id,
                "source": actor_source,
                "verified": actor_verified,
                "delegation": list(delegation) if delegation else None,
            },
        }
        if receipt_id:
            body["receipt_id"] = receipt_id

        payload = self._request("POST", "/v1/govern", body, auth=True)
        return GovernResponse(
            content=payload.get("content"),
            decision=payload.get("decision", ""),
            mode=payload.get("mode", ""),
            receipt=payload.get("receipt") or {},
            findings=payload.get("findings") or [],
            warnings=payload.get("warnings") or [],
        )

    def public_keys(self) -> dict[str, str]:
        """Fetch the deployment's published signing keys.

        Public and unauthenticated. Cache the result and verify offline
        rather than calling this per receipt: a verifier that must reach the
        issuer to check a receipt is a lookup service, and it fails exactly
        when the issuer is the party in dispute.
        """
        payload = self._request("GET", "/.well-known/lyntway-keys.json", None, auth=False)
        return payload.get("keys") or {}

    def ready(self) -> bool:
        """Report whether the service can issue receipts."""
        try:
            self._request("GET", "/readyz", None, auth=False)
            return True
        except Exception:
            return False

    def _request(
        self, method: str, path: str, body: Any, *, auth: bool
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = f"Bearer {self._api_key}"

        request = urllib.request.Request(
            f"{self._base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            code, message = "http_error", f"request failed with status {exc.code}"
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("error") or {}
                code = detail.get("code", code)
                message = detail.get("message", message)
            except Exception:
                # A non-JSON error body is not itself worth surfacing; the
                # status code already carries the useful information.
                pass
            raise LyntwayError(exc.code, code, message) from exc
