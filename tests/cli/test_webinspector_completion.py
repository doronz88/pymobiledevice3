from types import SimpleNamespace
from typing import Any, cast

import pytest
from prompt_toolkit.completion import CompleteEvent, Completion
from prompt_toolkit.document import Document

from pymobiledevice3.cli.webinspector import JsShellCompleter

pytestmark = [pytest.mark.cli]


def _completer(names: dict[str, str]) -> "tuple[JsShellCompleter, dict[str, Any]]":
    captured: dict[str, Any] = {}

    async def evaluate_expression(exp: str, return_by_value: bool = False) -> dict[str, str]:
        captured["exp"] = exp
        return names

    shell = SimpleNamespace(evaluate_expression=evaluate_expression)
    return JsShellCompleter(cast(Any, shell)), captured


async def _collect(completer: JsShellCompleter, text: str) -> list[Completion]:
    document = Document(text, cursor_position=len(text))
    return [completion async for completion in completer.get_completions_async(document, CompleteEvent())]


async def test_completions_sorted_prefix_filtered_with_function_marker() -> None:
    completer, _ = _completer({
        "normalize": "function",
        "name": "string",
        "navigator": "object",
        "location": "object",
    })
    completions = await _collect(completer, "window.n")
    assert [completion.display_text for completion in completions] == ["name", "navigator", "normalize"]
    assert [completion.display_meta_text for completion in completions] == ["", "", "ƒ"]
    # the prefix is stripped from the inserted text
    assert [completion.text for completion in completions] == ["ame", "avigator", "ormalize"]


async def test_dollar_identifiers_are_completed() -> None:
    completer, captured = _completer({"$refresh": "function"})
    completions = await _collect(completer, "$x.")
    assert "globalThis.$x" in captured["exp"]
    assert [completion.display_text for completion in completions] == ["$refresh"]


async def test_reserved_words_are_not_evaluated() -> None:
    completer, captured = _completer({"anything": "object"})
    completions = await _collect(completer, "x = await.")
    assert completions == []
    assert "exp" not in captured


def test_get_access_logs_are_debug_only() -> None:
    """The landing page polls GET /api/targets every second; those access lines are relabelled
    DEBUG and dropped unless debug logging is on, while POSTs and the rest stay at their level."""
    import logging

    from pymobiledevice3.cli.webinspector import _GetAccessToDebug

    access_filter = _GetAccessToDebug()

    def record(method: str) -> logging.LogRecord:
        return logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            0,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:1", method, "/api/targets", "1.1", 200),
            None,
        )

    root = logging.getLogger()
    previous = root.level
    try:
        root.setLevel(logging.INFO)
        get_record = record("GET")
        assert access_filter.filter(get_record) is False, "a GET access log is dropped at INFO"
        assert get_record.levelno == logging.DEBUG and get_record.levelname == "DEBUG"

        post_record = record("POST")
        assert access_filter.filter(post_record) is True, "a POST access log is kept"
        assert post_record.levelno == logging.INFO

        root.setLevel(logging.DEBUG)
        assert access_filter.filter(record("GET")) is True, "a GET access log is kept when debugging"
    finally:
        root.setLevel(previous)
