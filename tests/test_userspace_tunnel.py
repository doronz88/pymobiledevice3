"""Tests for the userspace tunnel's throughput tuning.

The tuning rides pmd-pytcp's public ``tcp.rcv_wnd_max`` / ``tcp.snd_mss_max`` sysctls; these
tests pin that :func:`throughput_sysctls` emits values the installed pmd-pytcp actually accepts
(and silently omits any a too-old pmd-pytcp lacks). The cross-platform/portability concerns that
used to live in a host-side compatibility layer are now handled inside pmd-pytcp itself.
"""

import pytest

# pmd-pytcp ships only on Python >= 3.14; skip the whole module when it's absent.
pytest.importorskip("pmd_pytcp")

from pmd_pytcp.stack import sysctl

from pymobiledevice3.remote import userspace_tunnel


def test_throughput_sysctls_only_emits_registered_knobs():
    # Every emitted key must be accepted by stack.init's sysctl bag — i.e. its (base) knob is
    # registered in the installed pmd-pytcp. This is what keeps an older fork from crashing.
    registered = sysctl.list_keys()
    for key in userspace_tunnel.throughput_sysctls():
        base = key.replace(".default.", ".") if ".default." in key else key
        assert base in registered, f"{key!r} emitted but {base!r} is not a registered sysctl"


def test_throughput_sysctls_values_when_supported():
    knobs = userspace_tunnel.throughput_sysctls()
    if "tcp.rcv_wnd_max" not in sysctl.list_keys():
        pytest.skip("installed pmd-pytcp predates the throughput sysctls")
    assert knobs["tcp.rcv_wnd_max"] == userspace_tunnel.MAX_RECV_WINDOW
    assert knobs["tcp.default.snd_mss_max"] == userspace_tunnel.MAX_SEND_MSS


def test_throughput_sysctls_round_trip_through_sysctl_set():
    # The emitted entries must apply cleanly the way stack.init(sysctls=...) applies them.
    for key, value in userspace_tunnel.throughput_sysctls().items():
        sysctl.set(key, value)
    sysctl.reset_to_defaults()
