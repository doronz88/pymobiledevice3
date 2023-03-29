import re
from typing import Any, Mapping, Union

from construct import Int8ul, Int16ul, Int32ul, Int64ul, Select

from pymobiledevice3.exceptions import DeviceVersionFormatError


def plist_access_path(d: Mapping, path: tuple, type_=None, required=False) -> Any:
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


def bytes_to_uint(b: bytes) -> int:
    return Select(u64=Int64ul, u32=Int32ul, u16=Int16ul, u8=Int8ul).parse(b)


def sanitize_ios_version(version: str) -> str:
    try:
        return re.match(r'\d*\.\d*', version)[0]
    except TypeError as e:
        raise DeviceVersionFormatError from e


def try_decode(s: bytes) -> Union[str, bytes]:
    try:
        return s.decode('utf8')
    except UnicodeDecodeError:
        return s
