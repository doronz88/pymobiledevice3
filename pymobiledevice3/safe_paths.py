"""Keep device-supplied names and paths beneath the host directory they belong in.

A paired device is not trusted with the host filesystem: a backup file name, an archive member, a
provisioning profile UUID or a device identifier all come off the wire and are used to build host
paths. These helpers are the single place that turns such a string into a path.
"""

from pathlib import Path, PureWindowsPath

from pymobiledevice3.exceptions import DevicePathError

_FORBIDDEN_IN_FILENAME = ("/", "\\", "\0")
# Opening "NUL", "nul.txt" or "COM1 " on Windows opens the device, not a file in the directory
_WINDOWS_DEVICE_NAMES = frozenset({
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in "123456789¹²³"),
    *(f"LPT{i}" for i in "123456789¹²³"),
})


def _is_windows_device_name(part: str) -> bool:
    return part.partition(".")[0].rstrip(" ").upper() in _WINDOWS_DEVICE_NAMES


def validate_device_filename(name: str) -> str:
    """Require a single path component, suitable for a filename or a device identifier.

    Colons are allowed on purpose: a TCP lockdown client uses the device's hostname as its
    identifier, and that is an IPv6 address for a device found over Wi-Fi.
    """
    if not name or name in (".", "..") or any(c in name for c in _FORBIDDEN_IN_FILENAME):
        raise DevicePathError(f"Invalid device filename: {name!r}")
    if PureWindowsPath(name).drive or _is_windows_device_name(name):
        # "C:" joined onto a directory is drive-relative on Windows and discards the directory
        raise DevicePathError(f"Invalid device filename: {name!r}")
    return name


def device_file_path(root: Path, name: str, suffix: str = "") -> Path:
    """`root / (name + suffix)` where `name` must be a single device-supplied component."""
    return root / (validate_device_filename(name) + suffix)


def resolve_device_path(root: Path, device_path: str) -> Path:
    """Join a device-supplied relative path onto `root`, refusing anything that leaves it.

    Absolute paths (both `/x` and `C:\\x` / `\\\\host\\share` on Windows), `..` components and
    embedded NULs are refused outright. The joined path is then resolved and checked to still lie
    beneath `root`, so a link inside `root` that points elsewhere cannot be used to get out either.
    The returned path is the plain join, so callers operate on the entry they named rather than on
    a link's target.
    """
    if "\0" in device_path:
        raise DevicePathError(f"Invalid device path: {device_path!r}")
    # Windows path rules are a superset of POSIX ones (both separators, drives, UNC), so one view
    # of the string classifies it the same way on every host.
    windows_path = PureWindowsPath(device_path)
    if windows_path.drive or windows_path.root:
        raise DevicePathError(f"Absolute device path: {device_path!r}")
    if ".." in windows_path.parts:
        raise DevicePathError(f"Device path traverses upwards: {device_path!r}")
    if any(_is_windows_device_name(part) for part in windows_path.parts):
        raise DevicePathError(f"Device path names a Windows device: {device_path!r}")
    path = root / device_path
    if not path.resolve().is_relative_to(root.resolve()):
        raise DevicePathError(f"Device path escapes {root}: {device_path!r}")
    return path
