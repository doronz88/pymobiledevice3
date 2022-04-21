import re

from construct import Select, Int32ul, Int64ul, Int8ul, Int16ul

from pymobiledevice3.exceptions import DeviceVersionFormatError


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


def sanitize_ios_version(version: str):
    try:
        return re.match(r'\d*\.\d*', version)[0]
    except TypeError as e:
        raise DeviceVersionFormatError from e


def try_decode(s: bytes):
    try:
        return s.decode('utf8')
    except UnicodeDecodeError:
        return s
