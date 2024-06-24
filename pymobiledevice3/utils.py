import asyncio
import traceback
from functools import wraps
from pathlib import Path
from typing import Callable

import requests
from construct import Int8ul, Int16ul, Int32ul, Int64ul, Select
from tqdm import tqdm


def plist_access_path(d, path: tuple, type_=None, required=False):
    for component in path:
        d = d.get(component)
        if d is None:
            break

    if type_ == bool and isinstance(d, str):
        if d.lower() not in ('true', 'false'):
            raise ValueError()
        d = 'true' == d.lower()
    elif type_ is not None and not isinstance(d, type_):
        # wrong type
        d = None

    if d is None and required:
        raise KeyError(f'path: {path} doesn\'t exist in given plist object')

    return d


def bytes_to_uint(b: bytes):
    return Select(u64=Int64ul, u32=Int32ul, u16=Int16ul, u8=Int8ul).parse(b)


def try_decode(s: bytes):
    try:
        return s.decode('utf8')
    except UnicodeDecodeError:
        return s


def asyncio_print_traceback(f: Callable):
    @wraps(f)
    async def wrapper(*args, **kwargs):
        try:
            return await f(*args, **kwargs)
        except Exception as e:  # noqa: E72
            if not isinstance(e, asyncio.CancelledError):
                traceback.print_exc()
            raise

    return wrapper


def get_asyncio_loop() -> asyncio.AbstractEventLoop:
    try:
        loop = asyncio.get_running_loop()
        if loop.is_closed():
            raise RuntimeError('The existing loop is closed.')
    except RuntimeError:
        # This happens when there is no current event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop


def file_download(url: str, outfile: Path, chunk_size=1024) -> None:
    resp = requests.get(url, stream=True)
    total = int(resp.headers.get('content-length', 0))
    with outfile.open('wb') as file, tqdm(
            desc=outfile.name,
            total=total,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
    ) as bar:
        for data in resp.iter_content(chunk_size=chunk_size):
            size = file.write(data)
            bar.update(size)
