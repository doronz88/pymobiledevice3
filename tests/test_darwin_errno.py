import errno as host_errno
import platform

from pymobiledevice3.darwin_errno import DARWIN_ERRNO_NAMES, EINVAL, ENOENT, ENOTSUP, describe_errno


def test_describe_known_errno() -> None:
    assert describe_errno(ENOENT) == "ENOENT (2)"
    assert describe_errno(EINVAL) == "EINVAL (22)"
    assert describe_errno(ENOTSUP) == "ENOTSUP (45)"


def test_describe_unknown_errno_falls_back_to_the_number() -> None:
    assert describe_errno(9999) == "errno 9999"


def test_table_covers_the_darwin_range() -> None:
    # sys/errno.h runs 1..107 (ELAST is 106, ENOTCAPABLE 107) with no gaps.
    assert set(DARWIN_ERRNO_NAMES) == set(range(1, 108))


def test_names_do_not_come_from_the_host_runtime() -> None:
    """The whole point of this module: these are device-side numbers.

    On a non-Darwin host `os.strerror`/`errno` resolve the same integers to different meanings, so
    the table must be independent of them. Asserted on values where the platforms actually diverge.
    """
    assert DARWIN_ERRNO_NAMES[45] == "ENOTSUP"
    assert DARWIN_ERRNO_NAMES[60] == "ETIMEDOUT"
    assert DARWIN_ERRNO_NAMES[107] == "ENOTCAPABLE"
    # Linux ENOTSUP is 95 and has no errno 107 at all; if we had used the host tables these would
    # disagree on any non-Darwin CI runner.
    if platform.system() != "Darwin":  # pragma: no cover - only meaningful off Darwin
        assert host_errno.errorcode.get(45) != "ENOTSUP"


def test_pure_aliases_are_not_in_the_table() -> None:
    # EWOULDBLOCK is an unconditional alias of EAGAIN, so only the canonical name is kept.
    assert DARWIN_ERRNO_NAMES[35] == "EAGAIN"
    assert "EWOULDBLOCK" not in DARWIN_ERRNO_NAMES.values()


def test_enotsup_and_eopnotsupp_are_distinct() -> None:
    # sys/errno.h aliases EOPNOTSUPP to ENOTSUP only in legacy non-UNIX03 builds; under
    # __DARWIN_UNIX03 (and in the kernel) it is discrete at 102, which is what the device reports.
    assert DARWIN_ERRNO_NAMES[45] == "ENOTSUP"
    assert DARWIN_ERRNO_NAMES[102] == "EOPNOTSUPP"
