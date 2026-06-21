"""Tests for the PyTCP compatibility layer behind the userspace tunnel.

The throughput tuning rides PyTCP's public ``tcp.rcv_wnd_max`` / ``tcp.snd_mss_max``
sysctls; these tests pin that :func:`throughput_sysctls` emits values the installed PyTCP
actually accepts (and silently omits any a too-old PyTCP lacks), plus that the portability
shims install idempotently.
"""

import pytest

# PyTCP ships only on Python >= 3.14; skip the whole module when it's absent.
pytest.importorskip("pytcp")

from pytcp.stack import sysctl

from pymobiledevice3.remote import pytcp_compat


def test_throughput_sysctls_only_emits_registered_knobs():
    # Every emitted key must be accepted by stack.init's sysctl bag — i.e. its (base) knob is
    # registered in the installed PyTCP. This is what keeps an older PyTCP from crashing.
    registered = sysctl.list_keys()
    for key in pytcp_compat.throughput_sysctls():
        base = key.replace(".default.", ".") if ".default." in key else key
        assert base in registered, f"{key!r} emitted but {base!r} is not a registered sysctl"


def test_throughput_sysctls_values_when_supported():
    knobs = pytcp_compat.throughput_sysctls()
    if "tcp.rcv_wnd_max" not in sysctl.list_keys():
        pytest.skip("installed PyTCP predates the throughput sysctls")
    assert knobs["tcp.rcv_wnd_max"] == pytcp_compat.MAX_RECV_WINDOW
    assert knobs["tcp.default.snd_mss_max"] == pytcp_compat.MAX_SEND_MSS


def test_throughput_sysctls_round_trip_through_sysctl_set():
    # The emitted entries must apply cleanly the way stack.init(sysctls=...) applies them.
    for key, value in pytcp_compat.throughput_sysctls().items():
        sysctl.set(key, value)
    sysctl.reset_to_defaults()


def test_apply_installs_eventfd_shim_and_is_idempotent():
    pytcp_compat.apply()
    pytcp_compat.apply()  # must not raise or double-install
    # apply() guarantees PyTCP's selectable wakeup primitive exists on every platform.
    assert hasattr(__import__("os"), "eventfd")
