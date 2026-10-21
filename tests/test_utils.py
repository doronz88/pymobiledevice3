import asyncio
import inspect
import os
import signal
from pathlib import Path

import pytest
from bytestruct import BinaryParseError

from pymobiledevice3.utils import (
    bytes_to_uint,
    cancel_on_sigint,
    hexdump,
    path_to_str,
    sigint_handler,
    str_to_path,
)


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


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x01", 1),
        (b"\x01\x02", 0x0201),
        (b"\x01\x02\x03", 0x0201),
        (b"\x01\x02\x03\x04", 0x04030201),
        (b"\x01\x02\x03\x04\x05\x06\x07", 0x04030201),
        (b"\x01\x02\x03\x04\x05\x06\x07\x08", 0x0807060504030201),
        (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09", 0x0807060504030201),
    ],
)
def test_bytes_to_uint_reads_the_widest_integer_that_fits(data: bytes, expected: int) -> None:
    assert bytes_to_uint(data) == expected


def test_bytes_to_uint_of_nothing() -> None:
    with pytest.raises(BinaryParseError):
        bytes_to_uint(b"")


async def test_cancel_on_sigint_cancels_the_task_then_raises() -> None:
    previous = signal.getsignal(signal.SIGINT)
    task = asyncio.ensure_future(asyncio.sleep(10))
    with cancel_on_sigint(task) as interrupted:
        assert not interrupted()
        signal.raise_signal(signal.SIGINT)
        with pytest.raises(asyncio.CancelledError):
            await task
        assert interrupted()
        # Once the task is done, Ctrl-C is a KeyboardInterrupt again.
        with pytest.raises(KeyboardInterrupt):
            signal.raise_signal(signal.SIGINT)
    assert signal.getsignal(signal.SIGINT) is previous


async def test_cancel_on_sigint_leaves_an_ignored_sigint_alone() -> None:
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        task = asyncio.ensure_future(asyncio.sleep(0))
        with cancel_on_sigint(task):
            assert signal.getsignal(signal.SIGINT) is signal.SIG_IGN
        await task
    finally:
        signal.signal(signal.SIGINT, previous)


async def test_sigint_handler_takes_over_inside_cancel_on_sigint() -> None:
    task = asyncio.ensure_future(asyncio.sleep(10))
    with cancel_on_sigint(task) as interrupted:
        handler = signal.getsignal(signal.SIGINT)
        with sigint_handler(signal.default_int_handler), pytest.raises(KeyboardInterrupt):
            signal.raise_signal(signal.SIGINT)
        assert signal.getsignal(signal.SIGINT) is handler
        assert not interrupted()
    task.cancel()
