import asyncio
import logging
from contextlib import asynccontextmanager, nullcontext
from unittest.mock import AsyncMock, Mock

import pytest
from bytestruct import TruncatedDataError, UnexpectedConstantError

from pymobiledevice3.exceptions import ConnectionTerminatedError, MuxException
from pymobiledevice3.tunneld import server as tunneld_server


class _FakeMux:
    """Minimal stand-in for a usbmux connection used by monitor_usbmux_task."""

    def __init__(self, on_receive) -> None:
        self._on_receive = on_receive
        self.devices = []
        self.closed = False

    async def listen(self) -> None:
        return None

    async def receive_device_state_update(self) -> None:
        await self._on_receive()

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_monitor_usbmux_task_reconnects_after_socket_broken(monkeypatch):
    """Regression for issue #1742: a dropped usbmuxd listen socket raises
    MuxException("socket connection broken"). The monitor task must catch it and
    reconnect instead of dying, otherwise the tunnel never auto-recovers after a
    device replug/reboot (notably on Linux)."""
    # make the reconnect backoff instant
    monkeypatch.setattr(tunneld_server, "USBMUX_INTERVAL", 0)

    create_calls = 0

    async def fake_receive() -> None:
        # first connection: usbmuxd drops the socket
        raise MuxException("socket connection broken")

    async def fake_create_mux(usbmux_address=None):
        nonlocal create_calls
        create_calls += 1
        if create_calls >= 2:
            # the task successfully reconnected; stop the loop cleanly.
            # CancelledError is caught by the task's own handler, which breaks the loop.
            raise asyncio.CancelledError()
        return _FakeMux(fake_receive)

    monkeypatch.setattr(tunneld_server.usbmux, "create_mux", fake_create_mux)

    core = tunneld_server.TunneldCore(wifi_monitor=False, usb_monitor=False, usbmux_monitor=True, mobdev2_monitor=False)

    # The task should swallow the MuxException, sleep, attempt create_mux again, and
    # then return cleanly once cancelled (rather than dying on the MuxException).
    await core.monitor_usbmux_task()

    assert create_calls >= 2, "monitor task did not reconnect after socket connection broken"


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [TruncatedDataError("short reply"), UnexpectedConstantError("bad magic")])
async def test_monitor_usbmux_task_reconnects_after_a_malformed_usbmux_reply(monkeypatch, error):
    monkeypatch.setattr(tunneld_server, "USBMUX_INTERVAL", 0)
    create_calls = 0

    async def fake_receive() -> None:
        raise error

    async def fake_create_mux(usbmux_address=None):
        nonlocal create_calls
        create_calls += 1
        if create_calls >= 2:
            raise asyncio.CancelledError()
        return _FakeMux(fake_receive)

    monkeypatch.setattr(tunneld_server.usbmux, "create_mux", fake_create_mux)
    core = tunneld_server.TunneldCore(wifi_monitor=False, usb_monitor=False, usbmux_monitor=True, mobdev2_monitor=False)
    await core.monitor_usbmux_task()
    assert create_calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [TruncatedDataError("short reply"), UnexpectedConstantError("bad magic")])
async def test_monitor_usbmux_task_skips_a_device_whose_lockdown_reply_is_malformed(monkeypatch, error):
    receives = 0

    async def fake_receive() -> None:
        nonlocal receives
        receives += 1
        if receives >= 2:
            raise asyncio.CancelledError()

    mux = _FakeMux(fake_receive)
    mux.devices = [Mock(serial="device", connection_type="USB")]

    async def fake_create_mux(usbmux_address=None):
        return mux

    async def fake_create_using_usbmux(serial, usbmux_address=None):
        raise error

    monkeypatch.setattr(tunneld_server.usbmux, "create_mux", fake_create_mux)
    monkeypatch.setattr(tunneld_server, "create_using_usbmux", fake_create_using_usbmux)
    core = tunneld_server.TunneldCore(wifi_monitor=False, usb_monitor=False, usbmux_monitor=True, mobdev2_monitor=False)
    await core.monitor_usbmux_task()
    assert receives == 2
    assert core.tunnel_tasks == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [ConnectionTerminatedError(), TruncatedDataError("short reply")])
async def test_start_tunnel_task_reports_dropped_device_quietly(monkeypatch, caplog, error):
    """A device that drops the link while the tunnel is being established is routine for a
    long-running tunneld; it must not be logged as an unexpected exception with a traceback."""

    @asynccontextmanager
    async def fake_start_tunnel(protocol_handler, protocol=None):
        raise error
        yield

    monkeypatch.setattr(tunneld_server, "start_tunnel", fake_start_tunnel)
    core = tunneld_server.TunneldCore(
        wifi_monitor=False, usb_monitor=False, usbmux_monitor=False, mobdev2_monitor=False
    )
    protocol_handler = Mock(remote_identifier="device", close=AsyncMock())

    with caplog.at_level(logging.DEBUG, logger=tunneld_server.logger.name):
        await core.start_tunnel_task("usbmux-device-USB", protocol_handler)

    assert [record for record in caplog.records if record.levelno >= logging.ERROR] == []
    protocol_handler.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_usb_ncm_task_reports_device_dropping_rsd_handshake_quietly(monkeypatch, caplog):
    """A reset during the RSD handshake on a new NCM interface is routine (remoted racing us for the
    link, an unplug) and must not be logged as an unexpected exception with a traceback."""

    class DroppingRsd:
        def __init__(self, address, handshake_uuid=None) -> None:
            pass

        async def connect(self) -> None:
            raise ConnectionTerminatedError()

        async def close(self) -> None:
            pass

    monkeypatch.setattr(tunneld_server, "RemoteServiceDiscoveryService", DroppingRsd)
    monkeypatch.setattr(tunneld_server, "remoted_handshake_uuid", lambda: None)
    monkeypatch.setattr(tunneld_server, "stop_remoted", nullcontext)
    core = tunneld_server.TunneldCore(
        wifi_monitor=False, usb_monitor=False, usbmux_monitor=False, mobdev2_monitor=False
    )

    with caplog.at_level(logging.DEBUG, logger=tunneld_server.logger.name):
        await core.handle_new_potential_usb_cdc_ncm_interface_task("fe80::1")

    assert [record for record in caplog.records if record.levelno >= logging.ERROR] == []


@pytest.mark.asyncio
async def test_monitor_usb_task_follows_the_rsd_addresses_the_os_reports(monkeypatch):
    # The OS reports each USB device's RSD address: the monitor starts a tunnel task for new ones,
    # leaves a device that already has a tunnel alone, and drops the tunnel of an address that went away.
    snapshots = iter([
        {"TUNNELED": "fe80::1%anri0", "NEW": "fe80::2%anri1"},
        {"NEW": "fe80::2%anri1"},
    ])
    started = []
    sleeps = 0

    async def fake_sleep(_):
        # one full iteration per snapshot, then stop the loop
        nonlocal sleeps
        sleeps += 1
        if sleeps >= 2:
            raise asyncio.CancelledError()

    async def fake_handle(address):
        started.append(address)
        await asyncio.Event().wait()

    async def tunnel() -> None:
        await asyncio.Event().wait()

    core = tunneld_server.TunneldCore(
        wifi_monitor=False, usb_monitor=False, usbmux_monitor=False, mobdev2_monitor=False
    )
    existing = asyncio.ensure_future(tunnel())
    core.tunnel_tasks["fe80::1%anri0"] = tunneld_server.TunnelTask(task=existing, udid="TUNNELED", tunnel=Mock())
    monkeypatch.setattr(core, "tunnel_exists_for_udid", lambda udid: udid == "TUNNELED" and not existing.done())
    monkeypatch.setattr(core, "handle_new_potential_usb_cdc_ncm_interface_task", fake_handle)
    monkeypatch.setattr(tunneld_server.OSUTILS, "usb_rsd_addresses", lambda: next(snapshots))
    monkeypatch.setattr(tunneld_server.asyncio, "sleep", fake_sleep)

    def fallback(*args, **kwargs):
        raise AssertionError("the host-address/bonjour fallback should not be used")

    monkeypatch.setattr(tunneld_server, "browse_remoted", fallback)
    monkeypatch.setattr(tunneld_server.OSUTILS, "get_ipv6_ips", fallback)

    await core.monitor_usb_task()

    # TUNNELED's address disappeared in the second snapshot (a real tunnel task then removes its own entry)
    assert existing.cancelled()
    assert sorted(key for key, t in core.tunnel_tasks.items() if not t.task.done()) == ["fe80::2%anri1"]
    for tunnel_task in core.tunnel_tasks.values():
        tunnel_task.task.cancel()
    await asyncio.gather(*(t.task for t in core.tunnel_tasks.values()), return_exceptions=True)
    assert started == ["fe80::2%anri1"]


@pytest.mark.asyncio
async def test_monitor_usb_task_retries_a_failing_rsd_address_with_backoff(monkeypatch):
    # Right after boot a device's RSD link is up before RSD answers: retry the address soon, but back
    # off so a device that never gets a tunnel doesn't have remoted suspended every few seconds.
    clock = 0.0
    attempts = []
    real_sleep = asyncio.sleep

    async def fake_sleep(_):
        nonlocal clock
        await real_sleep(0)  # let the attempt started this iteration run
        clock += 1
        if clock >= 16:
            raise asyncio.CancelledError()

    core = tunneld_server.TunneldCore(
        wifi_monitor=False, usb_monitor=False, usbmux_monitor=False, mobdev2_monitor=False
    )

    async def failing_handle(address):
        attempts.append(clock)
        core.tunnel_tasks.pop(address, None)

    monkeypatch.setattr(core, "handle_new_potential_usb_cdc_ncm_interface_task", failing_handle)
    monkeypatch.setattr(tunneld_server.OSUTILS, "usb_rsd_addresses", lambda: {"BOOTING": "fe80::1%anri0"})
    monkeypatch.setattr(tunneld_server.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(asyncio.get_running_loop(), "time", lambda: clock)

    await core.monitor_usb_task()
    # let the last attempt's task run
    await asyncio.gather(*(t.task for t in core.tunnel_tasks.values()), return_exceptions=True)

    assert attempts == [0, 2, 6, 14]


@pytest.mark.asyncio
async def test_monitor_usb_task_keeps_tunnels_when_the_os_briefly_cannot_tell(monkeypatch):
    # e.g. a new device whose public NCM function shows up before its private one: the fallback
    # iteration must not treat the IORegistry addresses as gone and cancel their tunnels.
    snapshots = iter([{"DEVICE": "fe80::1%anri0"}, None, {"DEVICE": "fe80::1%anri0"}])
    sleeps = 0

    async def fake_sleep(_):
        nonlocal sleeps
        sleeps += 1
        if sleeps >= 3:
            raise asyncio.CancelledError()

    async def tunnel() -> None:
        await asyncio.Event().wait()

    async def browse_remoted(**kwargs):
        return []

    core = tunneld_server.TunneldCore(
        wifi_monitor=False, usb_monitor=False, usbmux_monitor=False, mobdev2_monitor=False
    )
    existing = asyncio.ensure_future(tunnel())
    core.tunnel_tasks["fe80::1%anri0"] = tunneld_server.TunnelTask(task=existing, udid="DEVICE", tunnel=Mock())
    monkeypatch.setattr(core, "tunnel_exists_for_udid", lambda udid: udid == "DEVICE" and not existing.done())
    monkeypatch.setattr(tunneld_server.OSUTILS, "usb_rsd_addresses", lambda: next(snapshots))
    monkeypatch.setattr(tunneld_server.OSUTILS, "get_ipv6_ips", lambda: ["fe80::99%en0"])
    monkeypatch.setattr(tunneld_server, "browse_remoted", browse_remoted)
    monkeypatch.setattr(tunneld_server.asyncio, "sleep", fake_sleep)

    await core.monitor_usb_task()

    assert not existing.done()
    existing.cancel()
