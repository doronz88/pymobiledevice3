import asyncio
import traceback
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

import IPython
import requests
from construct import Int8ul, Int16ul, Int32ul, Int64ul, Select
from tqdm import tqdm
from traitlets.config import Config


def plist_access_path(d, path: tuple, type_=None, required=False):
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


def try_decode(s: bytes):
    try:
        return s.decode("utf8")
    except UnicodeDecodeError:
        return s


def asyncio_print_traceback(f: Callable):
    @wraps(f)
    async def wrapper(*args, **kwargs):
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
        _ASYNCIO_LOOP = asyncio.new_event_loop()
    return _ASYNCIO_LOOP


def run_in_loop(coro):
    return get_asyncio_loop().run_until_complete(coro)


def start_ipython_shell(*, user_ns: Optional[dict[str, Any]] = None, header: Optional[str] = None) -> None:
    # Keep IPython autoawait on the same loop used by CLI async wrappers.
    config = Config()
    config.InteractiveShell.loop_runner = run_in_loop
    if header is not None:
        print(header)
    IPython.start_ipython(argv=[], config=config, user_ns=user_ns or {})


def file_download(url: str, outfile: Path, chunk_size=1024) -> None:
    resp = requests.get(url, stream=True)
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
