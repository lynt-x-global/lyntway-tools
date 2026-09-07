"""LiteLLM callback: record what LiteLLM sent, without standing in its way.

Why this exists at all
----------------------

Two model providers cannot be put behind a proxy. AWS Bedrock signs every
request with SigV4 and Google Vertex signs with its own scheme, and both
signatures cover the host — so a gateway in the path breaks them. That is a
property of their authentication, not something we can engineer around.

LiteLLM already signs those requests itself. So when LiteLLM is in the
path, a callback is not the weaker option, it is the *only* option: a
handler running inside LiteLLM is the only place where a Bedrock call is
visible to us at all. The alternative is no record, and a coverage report
that says "we cannot see this" forever.

What the receipt is allowed to claim
------------------------------------

We read the prompt ourselves, so the findings are first-hand: our rules and
our models ran over the actual bytes. But we did not watch the call happen
— LiteLLM made it and told us afterwards — so the *action* is the caller's
description of its own work, and the receipt says exactly that.

The distinction matters when somebody disputes the record. "We detected a
card number in this text" is something we can stand behind. "This text was
sent to Bedrock at 14:02" is something LiteLLM told us, and a reader
deserves to know which half is which.

We also cannot change anything here. LiteLLM's success callback runs after
the response is back; there is nothing left to redact. So this records and
never blocks, and the console says so rather than letting somebody assume a
protection they are not getting.

Failure policy
--------------

A logging callback that breaks a customer's traffic is a callback they
remove. Everything here is wrapped: if we are unreachable, slow, or
mistaken, LiteLLM carries on and the call succeeds. The cost of that choice
is an occasional missing receipt, which is visible in the coverage report —
the honest failure, rather than an outage nobody attributes to us.

Usage
-----

In ``config.yaml``::

    litellm_settings:
      callbacks: [lyntway.litellm.handler]

    environment_variables:
      LYNTWAY_URL: https://your-lyntway
      LYNTWAY_KEY: sk-...

Or in Python::

    import litellm
    from lyntway.litellm import LyntwayLogger

    litellm.callbacks = [LyntwayLogger()]
"""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping, Sequence

from .client import Lyntway

__all__ = ["LyntwayLogger", "handler"]

_log = logging.getLogger("lyntway.litellm")

# Imported lazily and tolerantly. This module has to be importable in an
# environment without LiteLLM — the test suite is one — and LiteLLM has
# moved this class between releases more than once.
try:  # pragma: no cover - depends on the host environment
    from litellm.integrations.custom_logger import CustomLogger as _Base
except Exception:  # pragma: no cover

    class _Base:  # type: ignore[no-redef]
        """Stand-in so the module imports without LiteLLM installed."""


def _text_of(messages: Any) -> str:
    """Flatten whatever LiteLLM passed into text we can inspect.

    Deliberately forgiving. A message list may hold plain strings, or the
    content-part lists the vision APIs use, and a shape we do not recognise
    must not raise inside somebody's request path.
    """
    if isinstance(messages, str):
        return messages
    if not isinstance(messages, Sequence):
        return ""

    parts: list[str] = []
    for m in messages:
        if isinstance(m, str):
            parts.append(m)
            continue
        if not isinstance(m, Mapping):
            continue
        content = m.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, Sequence):
            for piece in content:
                if isinstance(piece, Mapping) and isinstance(piece.get("text"), str):
                    parts.append(piece["text"])
    return "\n".join(p for p in parts if p)


def _response_text(response: Any) -> str:
    """Pull the assistant's reply out of a LiteLLM response object."""
    try:
        choices = getattr(response, "choices", None)
        if choices is None and isinstance(response, Mapping):
            choices = response.get("choices")
        if not choices:
            return ""
        out: list[str] = []
        for c in choices:
            msg = getattr(c, "message", None)
            if msg is None and isinstance(c, Mapping):
                msg = c.get("message")
            content = getattr(msg, "content", None)
            if content is None and isinstance(msg, Mapping):
                content = msg.get("content")
            if isinstance(content, str):
                out.append(content)
        return "\n".join(out)
    except Exception:
        return ""


def _destination(kwargs: Mapping[str, Any]) -> str:
    """Name where the call actually went.

    The model string is the useful answer: an auditor asking "where did our
    data go" wants "bedrock/anthropic.claude-3-sonnet", not "litellm".
    """
    model = kwargs.get("model")
    if isinstance(model, str) and model:
        return model
    params = kwargs.get("litellm_params")
    if isinstance(params, Mapping):
        custom = params.get("custom_llm_provider")
        if isinstance(custom, str) and custom:
            return custom
    return "unknown"


def _actor(kwargs: Mapping[str, Any]) -> str:
    """Attribute the call to whoever LiteLLM says made it.

    LiteLLM knows the virtual key's user or team. Passing it through is what
    turns "somebody sent a customer record" into "this person did", which is
    the whole reason a development team buys this.
    """
    params = kwargs.get("litellm_params")
    meta: Mapping[str, Any] = {}
    if isinstance(params, Mapping) and isinstance(params.get("metadata"), Mapping):
        meta = params["metadata"]
    for key in ("user_api_key_user_id", "user_api_key_alias", "user_api_key_team_id"):
        v = meta.get(key)
        if isinstance(v, str) and v:
            return v
    v = kwargs.get("user")
    if isinstance(v, str) and v:
        return v
    return "litellm"


def _chain_id(kwargs: Mapping[str, Any]) -> str:
    """Group a request and its response under one identifier.

    LiteLLM's call id is stable across the pair, so the two receipts join up
    rather than appearing as two unrelated events.
    """
    params = kwargs.get("litellm_params")
    if isinstance(params, Mapping):
        for key in ("litellm_call_id", "call_id"):
            v = params.get(key)
            if isinstance(v, str) and v:
                return "litellm/" + v
    v = kwargs.get("litellm_call_id")
    if isinstance(v, str) and v:
        return "litellm/" + v
    return "litellm"


class LyntwayLogger(_Base):
    """Reports each LiteLLM call to Lyntway and records what was in it.

    :param base_url: Where Lyntway is. Defaults to ``$LYNTWAY_URL``.
    :param api_key: An API key from the console. Defaults to ``$LYNTWAY_KEY``.
    :param log_responses: Also inspect what came back. On by default — a
        model reply carrying a customer's details is the direction most
        people forget to look at.
    :param timeout: Seconds to wait. Kept short: this runs beside somebody's
        traffic, and a slow recorder is worse than a missing record.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        log_responses: bool = True,
        timeout: float = 5.0,
    ) -> None:
        try:
            super().__init__()
        except Exception:  # pragma: no cover - base may take arguments
            pass

        self.log_responses = log_responses
        self._base_url = base_url
        self._api_key = api_key
        self._timeout = timeout
        self._client: Lyntway | None = None
        self._resolved = False

    def _resolve(self) -> Lyntway | None:
        """Build the client on first use, not at import.

        ``handler`` at the bottom of this module is constructed when the
        module is imported, and LiteLLM applies the ``environment_variables``
        block of its config around the same time. Reading the environment in
        ``__init__`` therefore loses a race that depends on LiteLLM's
        internal ordering — and loses it silently, which is the worst kind:
        traffic flows, nothing is recorded, and the coverage report is the
        only place it shows.

        Missing configuration disables recording rather than raising.
        Raising would take down a LiteLLM deployment on startup over an
        unset variable of ours, which is not a trade anybody agreed to.
        """
        if self._resolved:
            return self._client
        self._resolved = True

        url = self._base_url or os.environ.get("LYNTWAY_URL", "")
        key = self._api_key or os.environ.get("LYNTWAY_KEY", "")
        if url and key:
            try:
                self._client = Lyntway(url, key, timeout=self._timeout)
            except Exception as exc:  # noqa: BLE001
                # Half a signing configuration, or an unreadable key file,
                # raises from the constructor by design — but not here,
                # where the exception would land in LiteLLM's request path.
                _log.warning(
                    "lyntway: client could not be configured, so nothing "
                    "will be recorded. Traffic is unaffected. %s", exc,
                )
        else:
            _log.warning(
                "lyntway: LYNTWAY_URL or LYNTWAY_KEY is not set, so nothing "
                "will be recorded. Traffic is unaffected."
            )
        return self._client

    # -- LiteLLM's callback surface -------------------------------------
    #
    # Both the sync and async names are implemented because which one
    # LiteLLM calls depends on how the caller invoked it, and a handler
    # that only covers one silently records half the traffic.

    def log_success_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D102
        self._record(kwargs, response_obj)

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D102
        self._record(kwargs, response_obj)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D102
        # A failed call still sent the prompt. The data left the building
        # whether or not a reply came back, so it is still worth a receipt.
        self._record(kwargs, None)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D102
        self._record(kwargs, None)

    # -- The work --------------------------------------------------------

    def _record(self, kwargs: Any, response_obj: Any) -> None:
        client = self._resolve()
        if client is None:
            return
        try:
            self._govern_pair(client, kwargs if isinstance(kwargs, Mapping) else {}, response_obj)
        except Exception as exc:  # noqa: BLE001
            # Never propagate. LiteLLM is in somebody's request path and a
            # recorder must not be able to fail their traffic.
            _log.warning("lyntway: this call was not recorded: %s", exc)

    def _govern_pair(self, client: Lyntway, kwargs: Mapping[str, Any], response_obj: Any) -> None:
        chain = _chain_id(kwargs)
        actor = _actor(kwargs)
        destination = _destination(kwargs)

        prompt = _text_of(kwargs.get("messages") or kwargs.get("input") or kwargs.get("prompt"))
        if prompt.strip():
            client.govern(
                chain_id=chain,
                content=prompt,
                actor_id=actor,
                actor_type="human" if actor != "litellm" else "agent",
                surface="model",
                direction="request",
                method="litellm",
                destination=destination,
            )

        if not self.log_responses or response_obj is None:
            return
        reply = _response_text(response_obj)
        if reply.strip():
            client.govern(
                chain_id=chain,
                content=reply,
                actor_id=actor,
                actor_type="human" if actor != "litellm" else "agent",
                surface="model",
                direction="response",
                method="litellm",
                destination=destination,
            )


#: A ready-made instance, so ``callbacks: [lyntway.litellm.handler]`` in a
#: LiteLLM YAML config works without any Python being written.
handler = LyntwayLogger()
