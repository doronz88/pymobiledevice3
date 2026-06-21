"""PyTCP compatibility layer for the userspace tunnel.

PyTCP is Linux-first, so this module quarantines the cross-platform shims the tunnel needs
(an ``os.eventfd`` emulation, socket-backed interface I/O for Windows, a Windows ``fcntl``
stub, a daemon-thread wrapper for clean teardown, and an MLD-attribute bug workaround). The
tunnel itself (``remote/userspace_tunnel.py``) uses only PyTCP's public API plus the helpers
here.

Throughput tuning is NOT done here: it rides PyTCP's public ``tcp.rcv_wnd_max`` /
``tcp.snd_mss_max`` sysctls (see :func:`throughput_sysctls`), passed through
``stack.init(sysctls=...)``. Older PyTCP releases that predate those knobs simply run
untuned (slower) — :func:`throughput_sysctls` omits any the installed PyTCP doesn't register.

This module imports PyTCP at module level, so importing it REQUIRES PyTCP (Python >= 3.14).
That is intentional: only :mod:`pymobiledevice3.remote.userspace_tunnel` imports it, and only
``cli_common`` imports that — inside a try/except that falls back to the kernel tunnel when
PyTCP is absent. The Windows ``fcntl`` stub below must run before the PyTCP imports.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import types
from collections.abc import Iterator
from contextlib import contextmanager, suppress

# Windows: PyTCP does a top-level ``import fcntl`` (Unix-only) in pytcp.stack, so this stub
# MUST be installed before ``import pytcp`` below. We never hit fcntl's ioctl path (we inject
# our own interface fd rather than create a kernel TAP).
if os.name == "nt":
    try:
        import fcntl  # noqa: F401
    except ImportError:
        _fcntl_stub = types.ModuleType("fcntl")
        _fcntl_stub.ioctl = lambda *a, **k: 0  # type: ignore[attr-defined]
        sys.modules["fcntl"] = _fcntl_stub

# This module is the single point that imports PyTCP — after the Windows fcntl stub above.
# The PyTCP API surface the tunnel uses is re-exported here so userspace_tunnel imports it
# from a first-party module and never has to reproduce the stub-before-import ordering.
from net_addr import Ip6Address, Ip6IfAddr, MacAddress  # noqa: F401  (re-exported)
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer  # noqa: F401  (re-exported)
from pytcp.runtime.packet_handler import PacketHandlerL3
from pytcp.socket import AF_INET6, SOCK_STREAM  # noqa: F401  (re-exported)
from pytcp.socket import socket as pytcp_socket  # noqa: F401  (re-exported)
from pytcp.stack import sysctl

logger = logging.getLogger(__name__)

#: Receive-window ceiling (PyTCP 'tcp.rcv_wnd_max'; default 65535). A download is bounded by
#: window / RTT, so 64 KB throttles it; 4 MiB keeps a full bandwidth-delay-product in flight
#: and stays within PyTCP's negotiated window-scale-7 reach (~8 MiB). Measured on an iOS 17+
#: DSC fetch: 64 KB window -> 8 MB/s, 4 MiB window -> 40 MB/s (kernel-tunnel parity).
MAX_RECV_WINDOW = 4 * 1024 * 1024

#: Cap on the host->device send MSS (PyTCP 'tcp.snd_mss_max'; 0 = uncapped). A large interface
#: MTU makes downloads fast (big device->host segments), but ~16 KB host->device segments stall
#: in RTO backoff over the forwarding path; 1340 (= 1400-byte IPv6 packet minus 40+20 headers)
#: is the proven-safe send size. The advertised receive MSS is untouched, so downloads stay fast.
MAX_SEND_MSS = 1340


def needs_socket_io() -> bool:
    """Whether PyTCP's interface I/O must go through sockets rather than os.read/os.writev.

    True on Windows (os.writev is absent and os.read can't touch a socket handle). Set
    ``PYMOBILEDEVICE3_FORCE_SOCK_IO=1`` to exercise this path on Unix without a Windows box.
    """
    return os.name == "nt" or os.environ.get("PYMOBILEDEVICE3_FORCE_SOCK_IO") == "1"


# Interface fds the os.read/os.writev shim must treat as sockets (recv/sendall). Keyed by
# fileno; the tunnel registers its socketpair end here on the socket-I/O path.
_interface_fds: dict[int, socket.socket] = {}


def register_interface_fd(sock: socket.socket) -> None:
    """Route the os.read/os.writev shim's I/O for ``sock``'s fd through the socket itself.
    No-op unless on the socket-I/O path."""
    if needs_socket_io():
        _interface_fds[sock.fileno()] = sock


def unregister_interface_fd(sock: socket.socket) -> None:
    """Drop ``sock`` from the shim (call before closing it, while the fileno is still valid,
    so a recycled fd can't divert another caller's os.read)."""
    _interface_fds.pop(sock.fileno(), None)


@contextmanager
def daemonize_new_threads() -> Iterator[None]:
    """Force threads created within the block to be daemons.

    PyTCP starts non-daemon worker threads (RX/TX rings, timer, packet handler) during
    stack bring-up that its stop() does not fully join, which would hang interpreter exit.
    Daemon threads are killed at exit instead. Wrap stack.init()/start() with this.
    """
    orig_thread = threading.Thread

    class _DaemonThread(orig_thread):  # type: ignore[misc, valid-type]
        def __init__(self, *a, **k):
            k["daemon"] = True
            super().__init__(*a, **k)

    threading.Thread = _DaemonThread  # type: ignore[misc]
    try:
        yield
    finally:
        threading.Thread = orig_thread  # type: ignore[misc]


_applied = False


def apply() -> None:
    """Install the PyTCP/OS portability shims. Idempotent.

    Call once before bringing up the stack. PyTCP must be importable (Python >= 3.14); the
    caller guarantees that by only reaching the userspace path when PyTCP is present.
    """
    global _applied
    if _applied:
        return
    _silence_pytcp_stderr_logging()
    _install_eventfd_shim()
    if needs_socket_io():
        _install_interface_io_shim()
    _patch_missing_mld_attribute()
    _applied = True


def throughput_sysctls() -> dict[str, int]:
    """The ``stack.init(sysctls=...)`` entries that tune the tunnel for bulk transfer.

    Uses PyTCP's public sysctls (``tcp.rcv_wnd_max`` raises the advertised receive window for
    fast downloads; ``tcp.snd_mss_max`` caps host->device segments so a large interface MTU
    does not stall uploads). Any knob the installed PyTCP does not register is omitted (with a
    warning) so an older release runs untuned rather than failing — the keys land once a PyTCP
    that carries them is installed.
    """
    wanted = {"tcp.rcv_wnd_max": MAX_RECV_WINDOW, "tcp.default.snd_mss_max": MAX_SEND_MSS}
    # The registry lists base keys, so an interface-scope knob is checked by its base name.
    base_key = {"tcp.rcv_wnd_max": "tcp.rcv_wnd_max", "tcp.default.snd_mss_max": "tcp.snd_mss_max"}
    registered = sysctl.list_keys()
    out: dict[str, int] = {}
    for key, value in wanted.items():
        if base_key[key] in registered:
            out[key] = value
        else:
            logger.warning(
                "userspace tunnel: installed PyTCP lacks the %r sysctl; running untuned "
                "(upgrade PyTCP for full throughput)",
                base_key[key],
            )
    return out


def _silence_pytcp_stderr_logging() -> None:
    # PyTCP prints every log channel per-packet straight to stderr, bypassing pmd3's
    # logging. Mute it unless pmd3 is at debug verbosity (e.g. `-v`).
    if logging.getLogger().getEffectiveLevel() > logging.DEBUG:
        stack.LOG__CHANNEL = set()


def _patch_missing_mld_attribute() -> None:
    # PyTCP's L3 packet handler references an MLD attribute that doesn't exist, crashing the
    # address-setup thread. Provide a default (referenced during IPv6 multicast join even on
    # our L2 path).
    if not hasattr(PacketHandlerL3, "_mld__v1_querier_present_until_ms"):
        PacketHandlerL3._mld__v1_querier_present_until_ms = None  # type: ignore[attr-defined]


def _install_eventfd_shim() -> None:
    # os.eventfd is Linux-only; PyTCP uses it as a selectable wakeup. Real eventfd is fine on
    # Linux unless we're forcing the socket-I/O path. Otherwise emulate it: a socketpair on
    # the socket-I/O path (Windows select() accepts only sockets), else a non-blocking pipe.
    if hasattr(os, "eventfd") and not needs_socket_io():
        return

    os.EFD_NONBLOCK = getattr(os, "EFD_NONBLOCK", 0o4000)
    os.EFD_CLOEXEC = getattr(os, "EFD_CLOEXEC", 0o2000000)

    if needs_socket_io():
        pairs: dict[int, tuple[socket.socket, socket.socket]] = {}

        def _eventfd(initval: int = 0, flags: int = 0) -> int:
            r, w = socket.socketpair()
            r.setblocking(False)
            pairs[r.fileno()] = (r, w)
            for _ in range(initval):
                try:
                    w.send(b"\x01")
                except OSError:
                    break
            return r.fileno()

        def _eventfd_write(fd: int, value: int) -> None:
            with suppress(OSError):  # already signaled / closed
                pairs[fd][1].send(b"\x01")

        def _eventfd_read(fd: int) -> int:
            reader = pairs[fd][0]
            total = 0
            try:
                while True:
                    chunk = reader.recv(4096)
                    if not chunk:
                        break
                    total += len(chunk)
            except (BlockingIOError, OSError):
                pass
            return total or 1

    else:
        write_ends: dict[int, int] = {}

        def _eventfd(initval: int = 0, flags: int = 0) -> int:
            r, w = os.pipe()
            os.set_blocking(r, False)
            os.set_blocking(w, False)
            write_ends[r] = w
            for _ in range(initval):
                try:
                    os.write(w, b"\x01")
                except BlockingIOError:
                    break
            return r

        def _eventfd_write(fd: int, value: int) -> None:
            with suppress(BlockingIOError):  # already signaled
                os.write(write_ends[fd], b"\x01")

        def _eventfd_read(fd: int) -> int:
            total = 0
            try:
                while True:
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        break
                    total += len(chunk)
            except BlockingIOError:
                pass
            return total or 1

    os.eventfd = _eventfd  # type: ignore[attr-defined]
    os.eventfd_write = _eventfd_write  # type: ignore[attr-defined]
    os.eventfd_read = _eventfd_read  # type: ignore[attr-defined]


def _install_interface_io_shim() -> None:
    # PyTCP reads/writes the interface fd with os.read / os.writev. On Windows os.writev is
    # absent and os.read can't touch a socket handle, so divert ONLY our registered interface
    # fds (see register_interface_fd) to blocking socket recv/sendall; every other fd
    # delegates to the real implementation.
    real_read = os.read

    def _read(fd: int, n: int):  # type: ignore[misc]
        sock = _interface_fds.get(fd)
        return sock.recv(n) if sock is not None else real_read(fd, n)

    real_writev = getattr(os, "writev", None)

    def _writev(fd: int, buffers):  # type: ignore[misc]
        sock = _interface_fds.get(fd)
        if sock is not None:
            data = b"".join(buffers)
            sock.sendall(data)
            return len(data)
        return real_writev(fd, buffers)  # type: ignore[misc]

    os.read = _read  # type: ignore[assignment]
    os.writev = _writev  # type: ignore[attr-defined]
