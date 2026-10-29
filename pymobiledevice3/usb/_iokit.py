"""
The IOKit calls needed to reach a driver's user-space plug-in (a COM-style interface) from ctypes, plus a few
IORegistry walks. macOS only.
"""

import ctypes
import plistlib
from collections.abc import Generator
from contextlib import contextmanager
from ctypes import POINTER, byref, c_char_p, c_int32, c_uint8, c_uint32, c_void_p
from typing import Any, cast

_iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
_cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")

KERN_SUCCESS = 0
_CF_STRING_ENCODING_UTF8 = 0x08000100
_CF_PROPERTY_LIST_BINARY_FORMAT = 200
IO_SERVICE_PLANE = b"IOService"


class CFUUIDBytes(ctypes.Structure):
    _fields_ = [("bytes", c_uint8 * 16)]


_cf.CFUUIDGetConstantUUIDWithBytes.restype = c_void_p
_cf.CFUUIDGetConstantUUIDWithBytes.argtypes = [c_void_p] + [c_uint8] * 16
_cf.CFUUIDGetUUIDBytes.restype = CFUUIDBytes
_cf.CFUUIDGetUUIDBytes.argtypes = [c_void_p]
_cf.CFRelease.argtypes = [c_void_p]
_cf.CFStringCreateWithCString.restype = c_void_p
_cf.CFStringCreateWithCString.argtypes = [c_void_p, c_char_p, c_uint32]
_cf.CFPropertyListCreateData.restype = c_void_p
_cf.CFPropertyListCreateData.argtypes = [c_void_p, c_void_p, c_int32, c_uint32, c_void_p]
_cf.CFDataGetLength.restype = ctypes.c_long
_cf.CFDataGetLength.argtypes = [c_void_p]
_cf.CFDataGetBytePtr.restype = c_void_p
_cf.CFDataGetBytePtr.argtypes = [c_void_p]
_iokit.IOServiceMatching.restype = c_void_p
_iokit.IOServiceMatching.argtypes = [c_char_p]
_iokit.IOServiceGetMatchingServices.restype = c_int32
_iokit.IOServiceGetMatchingServices.argtypes = [c_uint32, c_void_p, POINTER(c_uint32)]
_iokit.IOIteratorNext.restype = c_uint32
_iokit.IOIteratorNext.argtypes = [c_uint32]
_iokit.IOObjectRelease.argtypes = [c_uint32]
_iokit.IOObjectRetain.argtypes = [c_uint32]
_iokit.IORegistryEntryGetRegistryEntryID.restype = c_int32
_iokit.IORegistryEntryGetRegistryEntryID.argtypes = [c_uint32, POINTER(ctypes.c_uint64)]
_iokit.IORegistryEntryIDMatching.restype = c_void_p
_iokit.IORegistryEntryIDMatching.argtypes = [ctypes.c_uint64]
_iokit.IOServiceGetMatchingService.restype = c_uint32
_iokit.IOServiceGetMatchingService.argtypes = [c_uint32, c_void_p]
_iokit.IOObjectConformsTo.restype = c_uint32
_iokit.IOObjectConformsTo.argtypes = [c_uint32, c_char_p]
_iokit.IORegistryEntryGetParentEntry.restype = c_int32
_iokit.IORegistryEntryGetParentEntry.argtypes = [c_uint32, c_char_p, POINTER(c_uint32)]
_iokit.IORegistryEntryGetName.restype = c_int32
_iokit.IORegistryEntryGetName.argtypes = [c_uint32, c_char_p]
_iokit.IORegistryEntryCreateCFProperty.restype = c_void_p
_iokit.IORegistryEntryCreateCFProperty.argtypes = [c_uint32, c_void_p, c_void_p, c_uint32]
_iokit.IOCreatePlugInInterfaceForService.restype = c_int32
_iokit.IOCreatePlugInInterfaceForService.argtypes = [
    c_uint32,
    c_void_p,
    c_void_p,
    POINTER(c_void_p),
    POINTER(c_int32),
]


def uuid(*uuid_bytes: int) -> int:
    """A CFUUIDRef constant (never released, like the SDK's ``CFUUIDGetConstantUUIDWithBytes`` macros)."""
    return cast(int, _cf.CFUUIDGetConstantUUIDWithBytes(None, *uuid_bytes))


# kIOCFPlugInInterfaceID
_PLUGIN_INTERFACE_ID = uuid(
    0xC2, 0x44, 0xE8, 0x58, 0x10, 0x9C, 0x11, 0xD4, 0x91, 0xD4, 0x00, 0x50, 0xE4, 0xC6, 0x42, 0x6F
)  # fmt: skip

# IUnknown's vtable: _reserved, QueryInterface, AddRef, Release
_QUERY_INTERFACE = 1
_RELEASE = 3


class IOKitError(OSError):
    def __init__(self, operation: str, kern_return: int) -> None:
        self.kern_return = kern_return & 0xFFFFFFFF
        super().__init__(f"{operation} failed: {self.kern_return:#x}")


def com_call(interface: c_void_p, slot: int, restype: Any, argtypes: list[Any], *args: Any) -> Any:
    """Call entry ``slot`` of a COM interface's vtable (slot numbers come from the SDK's struct layout)."""
    vtable = ctypes.cast(ctypes.cast(interface, POINTER(c_void_p))[0], POINTER(c_void_p))
    function = ctypes.CFUNCTYPE(restype, c_void_p, *argtypes)(vtable[slot])
    return function(interface, *args)


def create_interface(service: int, plugin_type: int, interface_id: int) -> c_void_p:
    """Load ``service``'s user-space plug-in of ``plugin_type`` and return its ``interface_id`` interface.

    The caller owns the returned interface and must ``release`` it.
    """
    plugin, score = c_void_p(), c_int32()
    kr = _iokit.IOCreatePlugInInterfaceForService(
        service, plugin_type, _PLUGIN_INTERFACE_ID, byref(plugin), byref(score)
    )
    if kr != KERN_SUCCESS:
        raise IOKitError("IOCreatePlugInInterfaceForService", kr)
    interface = c_void_p()
    try:
        hr = com_call(
            plugin,
            _QUERY_INTERFACE,
            c_int32,
            [CFUUIDBytes, POINTER(c_void_p)],
            _cf.CFUUIDGetUUIDBytes(interface_id),
            byref(interface),
        )
    finally:
        com_call(plugin, _RELEASE, c_uint32, [])
    if hr != 0 or not interface.value:
        raise IOKitError("QueryInterface", hr)
    return interface


def release(interface: c_void_p) -> None:
    com_call(interface, _RELEASE, c_uint32, [])


@contextmanager
def matching_services(class_name: str) -> Generator[list[int], None, None]:
    """Every registered service of ``class_name`` (or a subclass); released on exit."""
    iterator = c_uint32()
    kr = _iokit.IOServiceGetMatchingServices(0, _iokit.IOServiceMatching(class_name.encode()), byref(iterator))
    if kr != KERN_SUCCESS:
        raise IOKitError("IOServiceGetMatchingServices", kr)
    services: list[int] = []
    while service := _iokit.IOIteratorNext(iterator.value):
        services.append(service)
    _iokit.IOObjectRelease(iterator.value)
    try:
        yield services
    finally:
        for service in services:
            _iokit.IOObjectRelease(service)


def iterator_objects(iterator: int) -> list[int]:
    """Drain and release ``iterator``; the caller releases the returned objects."""
    objects: list[int] = []
    while obj := _iokit.IOIteratorNext(iterator):
        objects.append(obj)
    _iokit.IOObjectRelease(iterator)
    return objects


def ancestor(entry: int, class_name: str) -> int:
    """The closest IOService-plane ancestor of ``entry`` that is a ``class_name``; the caller releases it."""
    current = entry
    while True:
        parent = c_uint32()
        kr = _iokit.IORegistryEntryGetParentEntry(current, IO_SERVICE_PLANE, byref(parent))
        if current != entry:
            _iokit.IOObjectRelease(current)
        if kr != KERN_SUCCESS:
            raise IOKitError(f"finding the {class_name} above an entry", kr)
        if _iokit.IOObjectConformsTo(parent.value, class_name.encode()):
            return parent.value
        current = parent.value


def release_object(entry: int) -> None:
    _iokit.IOObjectRelease(entry)


def retain_object(entry: int) -> None:
    _iokit.IOObjectRetain(entry)


def registry_entry_id(entry: int) -> int:
    entry_id = ctypes.c_uint64()
    kr = _iokit.IORegistryEntryGetRegistryEntryID(entry, byref(entry_id))
    if kr != KERN_SUCCESS:
        raise IOKitError("IORegistryEntryGetRegistryEntryID", kr)
    return entry_id.value


def is_registered(entry_id: int) -> bool:
    """Whether the service with registry entry ID ``entry_id`` is still matchable (not terminated)."""
    service = _iokit.IOServiceGetMatchingService(0, _iokit.IORegistryEntryIDMatching(entry_id))
    if not service:
        return False
    _iokit.IOObjectRelease(service)
    return True


def name(entry: int) -> str:
    buffer = ctypes.create_string_buffer(128)
    kr = _iokit.IORegistryEntryGetName(entry, buffer)
    if kr != KERN_SUCCESS:
        raise IOKitError("IORegistryEntryGetName", kr)
    return buffer.value.decode()


def get_property(entry: int, key: str) -> Any:
    """``entry``'s property ``key`` as a Python value, or None when it is missing or not a property-list type."""
    cf_key = _cf.CFStringCreateWithCString(None, key.encode(), _CF_STRING_ENCODING_UTF8)
    try:
        value = _iokit.IORegistryEntryCreateCFProperty(entry, cf_key, None, 0)
    finally:
        _cf.CFRelease(cf_key)
    if not value:
        return None
    try:
        return cf_to_python(value)
    finally:
        _cf.CFRelease(value)


def cf_to_python(value: int) -> Any:
    """A CoreFoundation property-list object as a Python value, or None when it is not one; ``value`` is kept."""
    data = _cf.CFPropertyListCreateData(None, value, _CF_PROPERTY_LIST_BINARY_FORMAT, 0, None)
    if not data:
        return None
    try:
        return plistlib.loads(ctypes.string_at(_cf.CFDataGetBytePtr(data), _cf.CFDataGetLength(data)))
    finally:
        _cf.CFRelease(data)


def cf_release(value: int) -> None:
    _cf.CFRelease(value)
