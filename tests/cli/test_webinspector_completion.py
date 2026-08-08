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
