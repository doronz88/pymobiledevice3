import inspect
import os
from pathlib import Path

import pytest

from pymobiledevice3.utils import hexdump, path_to_str, str_to_path


def test_hexdump_formats_full_and_partial_lines() -> None:
    data = bytes(range(0x41, 0x41 + 16)) + b"\x00\xff hi"
    assert hexdump(data) == (
        "00000000: 41 42 43 44 45 46 47 48  49 4A 4B 4C 4D 4E 4F 50  ABCDEFGHIJKLMNOP\n"
        "00000010: 00 FF 20 68 69                                    .. hi"
    )


def test_hexdump_pads_a_line_that_ends_in_the_second_half() -> None:
    assert hexdump(b"0123456789") == "00000000: 30 31 32 33 34 35 36 37  38 39                    0123456789"


def test_hexdump_of_nothing_is_empty() -> None:
    assert hexdump(b"") == ""


def test_path_to_str_converts_paths_given_for_str_parameters() -> None:
    @path_to_str()
    def f(name: str, size: int, other: str = "x", *, flag: bool = False) -> tuple[object, ...]:
        return name, size, other, flag

    # str(), so the separators are the platform's
    assert f(Path("/a/b"), 1, other=Path("c")) == (str(Path("/a/b")), 1, "c", False)  # pyright: ignore[reportArgumentType]
    assert f("/a/b", 1) == ("/a/b", 1, "x", False)
    # Only str parameters are converted
    assert f("a", Path("1")) == ("a", Path("1"), "x", False)  # pyright: ignore[reportArgumentType]
    assert [p.annotation for p in inspect.signature(f).parameters.values()] == [os.PathLike, int, os.PathLike, bool]


def test_str_to_path_converts_the_named_parameters() -> None:
    @str_to_path("package")
    def f(package: Path, other: Path) -> tuple[object, ...]:
        return package, other

    assert f("a/b", "c") == (Path("a/b"), "c")  # pyright: ignore[reportArgumentType]
    assert f(other=Path("c"), package="a") == (Path("a"), Path("c"))  # pyright: ignore[reportArgumentType]
    assert [p.annotation for p in inspect.signature(f).parameters.values()] == [str, Path]


def test_converting_decorator_leaves_a_bad_call_to_the_function() -> None:
    @path_to_str()
    def f(name: str) -> str:
        return name

    with pytest.raises(TypeError, match="missing 1 required positional argument"):
        f()  # pyright: ignore[reportCallIssue]


@pytest.mark.asyncio
async def test_path_to_str_wraps_coroutine_functions() -> None:
    @path_to_str()
    async def f(name: str) -> str:
        return name

    assert await f(Path("a")) == "a"  # pyright: ignore[reportArgumentType]
