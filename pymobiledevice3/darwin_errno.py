"""Darwin (device-side) ``errno`` values.

Several device services report failures as a raw ``errno`` produced by the *device*, which runs
Darwin. Those numbers must not be rendered with `os.strerror` or the stdlib `errno` module: both
resolve against the C runtime of the **host** running pymobiledevice3, so a Windows or Linux host
prints the wrong name for the same number. ``ENOTCAPABLE`` (107) does not exist on Linux at all,
and the numbering above ~34 diverges between all three platforms.

The table below is generated from Darwin's ``sys/errno.h`` and is therefore correct regardless of
what the host is.
"""

#: Darwin errno number -> symbolic name, from the discrete (``__DARWIN_UNIX03``/kernel) numbering
#: the device actually reports. ``EWOULDBLOCK`` is a pure alias of ``EAGAIN`` (35) and so is not
#: listed. ``EOPNOTSUPP`` is *not* an alias here: it is discrete at 102, and only collapses onto
#: ``ENOTSUP`` (45) in legacy non-UNIX03 builds.
DARWIN_ERRNO_NAMES: dict[int, str] = {
    1: "EPERM",
    2: "ENOENT",
    3: "ESRCH",
    4: "EINTR",
    5: "EIO",
    6: "ENXIO",
    7: "E2BIG",
    8: "ENOEXEC",
    9: "EBADF",
    10: "ECHILD",
    11: "EDEADLK",
    12: "ENOMEM",
    13: "EACCES",
    14: "EFAULT",
    15: "ENOTBLK",
    16: "EBUSY",
    17: "EEXIST",
    18: "EXDEV",
    19: "ENODEV",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    23: "ENFILE",
    24: "EMFILE",
    25: "ENOTTY",
    26: "ETXTBSY",
    27: "EFBIG",
    28: "ENOSPC",
    29: "ESPIPE",
    30: "EROFS",
    31: "EMLINK",
    32: "EPIPE",
    33: "EDOM",
    34: "ERANGE",
    35: "EAGAIN",
    36: "EINPROGRESS",
    37: "EALREADY",
    38: "ENOTSOCK",
    39: "EDESTADDRREQ",
    40: "EMSGSIZE",
    41: "EPROTOTYPE",
    42: "ENOPROTOOPT",
    43: "EPROTONOSUPPORT",
    44: "ESOCKTNOSUPPORT",
    45: "ENOTSUP",
    46: "EPFNOSUPPORT",
    47: "EAFNOSUPPORT",
    48: "EADDRINUSE",
    49: "EADDRNOTAVAIL",
    50: "ENETDOWN",
    51: "ENETUNREACH",
    52: "ENETRESET",
    53: "ECONNABORTED",
    54: "ECONNRESET",
    55: "ENOBUFS",
    56: "EISCONN",
    57: "ENOTCONN",
    58: "ESHUTDOWN",
    59: "ETOOMANYREFS",
    60: "ETIMEDOUT",
    61: "ECONNREFUSED",
    62: "ELOOP",
    63: "ENAMETOOLONG",
    64: "EHOSTDOWN",
    65: "EHOSTUNREACH",
    66: "ENOTEMPTY",
    67: "EPROCLIM",
    68: "EUSERS",
    69: "EDQUOT",
    70: "ESTALE",
    71: "EREMOTE",
    72: "EBADRPC",
    73: "ERPCMISMATCH",
    74: "EPROGUNAVAIL",
    75: "EPROGMISMATCH",
    76: "EPROCUNAVAIL",
    77: "ENOLCK",
    78: "ENOSYS",
    79: "EFTYPE",
    80: "EAUTH",
    81: "ENEEDAUTH",
    82: "EPWROFF",
    83: "EDEVERR",
    84: "EOVERFLOW",
    85: "EBADEXEC",
    86: "EBADARCH",
    87: "ESHLIBVERS",
    88: "EBADMACHO",
    89: "ECANCELED",
    90: "EIDRM",
    91: "ENOMSG",
    92: "EILSEQ",
    93: "ENOATTR",
    94: "EBADMSG",
    95: "EMULTIHOP",
    96: "ENODATA",
    97: "ENOLINK",
    98: "ENOSR",
    99: "ENOSTR",
    100: "EPROTO",
    101: "ETIME",
    102: "EOPNOTSUPP",
    103: "ENOPOLICY",
    104: "ENOTRECOVERABLE",
    105: "EOWNERDEAD",
    106: "EQFULL",
    107: "ENOTCAPABLE",
}

#: Frequently checked values, for callers that want to branch on a specific failure.
ENOENT = 2
EINVAL = 22
ENOTSUP = 45


def describe_errno(error: int) -> str:
    """Render a device-side Darwin errno as ``NAME (n)``, or ``errno n`` when unrecognized.

    :param error: errno reported by the device.
    """
    name = DARWIN_ERRNO_NAMES.get(error)
    return f"{name} ({error})" if name is not None else f"errno {error}"
