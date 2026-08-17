"""Tests for the LiteLLM callback.

The happy path is the least interesting part. This handler runs inside
somebody else's request loop, so what actually matters is that it cannot
take their traffic down: a broken payload, an unreachable Lyntway, or a
response shape nobody anticipated all have to end in a shrug and a log
line, never an exception escaping into LiteLLM.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyntway.litellm import (  # noqa: E402
    LyntwayLogger,
    _actor,
    _chain_id,
    _destination,
    _response_text,
    _text_of,
)


class FakeClient:
    """Stands in for Lyntway and remembers what it was asked to govern."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def govern(self, **kwargs):
        self.calls.append(kwargs)
        return None


class ExplodingClient:
    def govern(self, **kwargs):
        raise RuntimeError("lyntway is down")


def logger_with(client) -> LyntwayLogger:
    lg = LyntwayLogger(base_url="https://example.invalid", api_key="k")
    lg._client = client
    lg._resolved = True
    return lg


# -- Flattening whatever LiteLLM hands over ----------------------------------


def test_plain_message_list():
    msgs = [{"role": "user", "content": "card 4111 1111 1111 1111"}]
    assert "4111" in _text_of(msgs)


def test_vision_content_parts():
    """The multi-part shape must not be skipped: text hides in there too."""
    msgs = [{"role": "user", "content": [
        {"type": "text", "text": "email priya@acme.co"},
        {"type": "image_url", "image_url": {"url": "https://x.invalid/a.png"}},
    ]}]
    assert "priya@acme.co" in _text_of(msgs)


def test_unrecognised_shapes_do_not_raise():
    for bad in (None, 42, object(), [None, 7], [{"content": {"nested": "dict"}}]):
        assert isinstance(_text_of(bad), str)


# -- Attribution and destination ---------------------------------------------


def test_destination_is_the_model_not_litellm():
    """An auditor asking where data went wants the model, not the proxy."""
    assert _destination({"model": "bedrock/anthropic.claude-3-sonnet"}) == (
        "bedrock/anthropic.claude-3-sonnet"
    )


def test_destination_falls_back_to_provider():
    kwargs = {"litellm_params": {"custom_llm_provider": "vertex_ai"}}
    assert _destination(kwargs) == "vertex_ai"


def test_unknown_destination_is_named_not_guessed():
    assert _destination({}) == "unknown"


def test_actor_comes_from_the_virtual_key():
    kwargs = {"litellm_params": {"metadata": {"user_api_key_user_id": "priya"}}}
    assert _actor(kwargs) == "priya"


def test_actor_falls_back_to_the_tool_itself():
    assert _actor({}) == "litellm"


def test_request_and_response_share_a_chain():
    kwargs = {"litellm_params": {"litellm_call_id": "abc123"}}
    assert _chain_id(kwargs) == "litellm/abc123"


# -- Reading the reply --------------------------------------------------------


def test_response_text_from_a_mapping():
    resp = {"choices": [{"message": {"content": "here is the record"}}]}
    assert _response_text(resp) == "here is the record"


def test_response_text_from_an_object():
    class Msg:
        content = "objectish reply"

    class Choice:
        message = Msg()

    class Resp:
        choices = [Choice()]

    assert _response_text(Resp()) == "objectish reply"


def test_response_text_of_nonsense_is_empty_not_an_error():
    assert _response_text(object()) == ""


# -- What actually gets recorded ---------------------------------------------


def test_both_directions_are_recorded():
    client = FakeClient()
    lg = logger_with(client)
    lg.log_success_event(
        {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello priya@acme.co"}],
         "litellm_params": {"litellm_call_id": "c1"}},
        {"choices": [{"message": {"content": "reply with 4111 1111 1111 1111"}}]},
        None, None,
    )
    directions = [c["direction"] for c in client.calls]
    assert directions == ["request", "response"]
    # Both halves belong to one conversation, or they read as unrelated events.
    assert {c["chain_id"] for c in client.calls} == {"litellm/c1"}
    assert all(c["destination"] == "gpt-4o" for c in client.calls)


def test_a_failed_call_still_records_the_prompt():
    """The data left the building whether or not a reply came back."""
    client = FakeClient()
    lg = logger_with(client)
    lg.log_failure_event(
        {"model": "gpt-4o", "messages": [{"role": "user", "content": "secret"}]},
        None, None, None,
    )
    assert [c["direction"] for c in client.calls] == ["request"]


def test_responses_can_be_left_alone():
    client = FakeClient()
    lg = LyntwayLogger(base_url="https://example.invalid", api_key="k", log_responses=False)
    lg._client, lg._resolved = client, True
    lg.log_success_event(
        {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
        {"choices": [{"message": {"content": "there"}}]},
        None, None,
    )
    assert [c["direction"] for c in client.calls] == ["request"]


def test_empty_prompt_records_nothing():
    client = FakeClient()
    lg = logger_with(client)
    lg.log_success_event({"model": "m", "messages": []}, None, None, None)
    assert client.calls == []


# -- The part that matters: it must not break the caller ---------------------


def test_a_broken_lyntway_does_not_break_litellm(caplog):
    lg = logger_with(ExplodingClient())
    with caplog.at_level(logging.WARNING):
        lg.log_success_event(
            {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
            None, None, None,
        )
    assert "not recorded" in caplog.text


def test_garbage_kwargs_do_not_break_litellm():
    lg = logger_with(FakeClient())
    for bad in (None, 7, "string", []):
        lg.log_success_event(bad, None, None, None)


def test_missing_configuration_disables_rather_than_raises(monkeypatch, caplog):
    """An unset variable of ours must not stop a LiteLLM deployment."""
    monkeypatch.delenv("LYNTWAY_URL", raising=False)
    monkeypatch.delenv("LYNTWAY_KEY", raising=False)
    lg = LyntwayLogger()
    with caplog.at_level(logging.WARNING):
        lg.log_success_event(
            {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
            None, None, None,
        )
    assert "will be recorded" in caplog.text


def test_configuration_is_read_when_used_not_when_imported(monkeypatch):
    """LiteLLM applies its environment_variables block around the time it
    imports callbacks. Reading the environment in __init__ loses that race
    silently — traffic flows and nothing is recorded."""
    monkeypatch.delenv("LYNTWAY_URL", raising=False)
    monkeypatch.delenv("LYNTWAY_KEY", raising=False)
    lg = LyntwayLogger()          # constructed before the variables exist
    monkeypatch.setenv("LYNTWAY_URL", "https://example.invalid")
    monkeypatch.setenv("LYNTWAY_KEY", "sk-test")
    assert lg._resolve() is not None


def test_async_names_exist():
    """LiteLLM picks sync or async depending on how it was called. A handler
    that implements only one silently records half the traffic."""
    for name in ("async_log_success_event", "async_log_failure_event",
                 "log_success_event", "log_failure_event"):
        assert callable(getattr(LyntwayLogger, name))
