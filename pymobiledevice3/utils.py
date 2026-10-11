import asyncio
import inspect
import os
import sys
import traceback
from collections.abc import Coroutine
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Union, cast, overload

import questionary
import requests
from construct import Int8ul, Int16ul, Int32ul, Int64ul, Select
from tqdm import tqdm

_F = TypeVar("_F", bound=Callable[..., Any])


def plist_access_path(d: Any, path: tuple[Any, ...], type_: Optional[type] = None, required: bool = False):
    for component in path:
        d = d.get(component)
        if d is None:
            break

    if type_ is bool and isinstance(d, str):
        if d.lower() not in ("true", "false"):
            raise ValueError()
        d = d.lower() == "true"
    elif type_ is not None and not isinstance(d, type_):
        # wrong type
        d = None

    if d is None and required:
        raise KeyError(f"path: {path} doesn't exist in given plist object")

    return d


def bytes_to_uint(b: bytes):
    return Select(u64=Int64ul, u32=Int32ul, u16=Int16ul, u8=Int8ul).parse(b)


def current_task_name(default: str = "?") -> str:
    """Name of the running asyncio task, for log messages. ``asyncio.current_task()`` is typed
    Optional (it is ``None`` outside a running task), so this returns ``default`` in that case."""
    task = asyncio.current_task()
    return task.get_name() if task is not None else default


@overload
def try_decode(s: bytes) -> Union[str, bytes]: ...


@overload
def try_decode(s: bytes, *, errors: str) -> str: ...


def try_decode(s: bytes, *, errors: Optional[str] = None) -> Union[str, bytes]:
    """Decode UTF-8 bytes to str, falling back to the raw bytes on failure.

    :param errors: when given (e.g. ``"replace"``), the caller asserts the input is text: decode with
        that error policy and always return ``str`` (no bytes fallback). Omit it for the default
        best-effort behaviour that returns the raw bytes when decoding fails.
    """
    if errors is not None:
        return s.decode("utf8", errors=errors)
    try:
        return s.decode("utf8")
    except UnicodeDecodeError:
        return s


def hexdump(data: bytes) -> str:
    """Format ``data`` as a hex dump, 16 bytes a line:

    ``00000000: 48 65 6C 6C 6F 20 77 6F  72 6C 64 21              Hello world!``
    """
    lines: list[str] = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        halves = [" ".join(f"{byte:02X}" for byte in chunk[i : i + 8]) for i in (0, 8)]
        text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in chunk)
        lines.append(f"{offset:08X}: {halves[0]:<23}  {halves[1]:<23}  {text}")
    return "\n".join(lines)


def _convert_annotated_params(
    annotation: Any, accepted: type, convert: Callable[[Any], Any], advertised: Any, names: tuple[str, ...]
) -> Callable[[_F], _F]:
    """Decorator converting the ``accepted`` arguments passed for parameters annotated ``annotation``.

    ``names`` selects the parameters by name instead, converting whatever they are passed. The
    decorated function's signature shows ``advertised`` for the converted parameters."""

    def decorate(f: _F) -> _F:
        signature = inspect.signature(f)
        converted = [
            name
            for name, param in signature.parameters.items()
            if (name in names if names else param.annotation == annotation)
        ]

        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                bound = signature.bind(*args, **kwargs)
            except TypeError:
                # Let the function itself report the bad call
                return f(*args, **kwargs)
            for name in converted:
                if name in bound.arguments and (names or isinstance(bound.arguments[name], accepted)):
                    bound.arguments[name] = convert(bound.arguments[name])
            return f(*bound.args, **bound.kwargs)

        cast(Any, wrapper).__signature__ = signature.replace(
            parameters=[
                param.replace(annotation=advertised) if name in converted else param
                for name, param in signature.parameters.items()
            ]
        )
        return cast(_F, wrapper)

    return decorate


def path_to_str(*names: str) -> Callable[[_F], _F]:
    """Decorator letting the ``str`` parameters of a function (or just ``names``) take a ``Path`` too."""
    return _convert_annotated_params(str, Path, str, os.PathLike, names)


def str_to_path(*names: str) -> Callable[[_F], _F]:
    """Decorator letting the ``Path`` parameters of a function (or just ``names``) take a ``str`` too."""
    return _convert_annotated_params(Path, str, Path, str, names)


def asyncio_print_traceback(f: Callable[..., Any]):
    @wraps(f)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await f(*args, **kwargs)
        except (Exception, RuntimeError) as e:
            if not isinstance(e, asyncio.CancelledError):
                traceback.print_exc()
            raise

    return wrapper


_ASYNCIO_LOOP: Optional[asyncio.AbstractEventLoop] = None


def get_asyncio_loop() -> asyncio.AbstractEventLoop:
    global _ASYNCIO_LOOP
    if _ASYNCIO_LOOP is None or _ASYNCIO_LOOP.is_closed():
        if sys.platform == "win32":
            # The proactor loop breaks blocking-socket operations performed while the socket
            # is attached to a stream transport (its pre-posted overlapped recv consumes the
            # bytes), e.g. the strip-ssl handshake in DTX services. The selector policy set in
            # __main__ cannot cover this loop since it is created at import time, before that
            # policy is applied. See https://github.com/doronz88/pymobiledevice3/issues/1217.
            _ASYNCIO_LOOP = asyncio.SelectorEventLoop()
        else:
            _ASYNCIO_LOOP = asyncio.new_event_loop()
    return _ASYNCIO_LOOP


def run_in_loop(coro: Coroutine[Any, Any, Any]):
    return get_asyncio_loop().run_until_complete(coro)


def ask_prompt(question: questionary.Question) -> Any:
    """Ask a questionary prompt from either a sync or an async calling context.

    prompt_toolkit refuses ``Application.run()`` while an asyncio loop is already running in
    the current thread, and prompts are regularly reached from ``@async_command`` handlers.
    In that case run the prompt on a worker thread, blocking the loop for the prompt's
    duration — the same terminal-owning behavior a plain blocking read would have.

    Raises ``KeyboardInterrupt`` on Ctrl-C (questionary's ``unsafe_ask`` contract).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return question.unsafe_ask()
    return question.application.run(in_thread=True)


def start_ipython_shell(*, user_ns: Optional[dict[str, Any]] = None, header: Optional[str] = None) -> None:
    # Imported here rather than at module scope. This is IPython's only use
    # in the package, but `pymobiledevice3.lockdown` imports this module, so
    # every library consumer that opens a lockdown connection was paying to
    # import a REPL it never starts.
    import IPython
    from traitlets.config import Config  # IPython's own configuration system

    # Keep IPython autoawait on the same loop used by CLI async wrappers.
    config = Config()
    config.InteractiveShell.loop_runner = run_in_loop
    if header is not None:
        print(header)
    # IPython exposes start_ipython lazily via module-level __getattr__, which pyright cannot see.
    cast(Any, IPython).start_ipython(argv=[], config=config, user_ns=user_ns or {})


def file_download(url: str, outfile: Path, chunk_size: int = 1024) -> None:
    resp = requests.get(url, stream=True, timeout=30)
    total = int(resp.headers.get("content-length", 0))
    with (
        outfile.open("wb") as file,
        tqdm(
            desc=outfile.name,
            total=total,
            unit="iB",
            unit_scale=True,
            unit_divisor=1024,
        ) as bar,
    ):
        for data in resp.iter_content(chunk_size=chunk_size):
            size = file.write(data)
            bar.update(size)
