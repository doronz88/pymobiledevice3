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


class _ListeningMux:
    """A usbmux listen connection that reports one attached device, then no further events.

    It records how the monitor reads it: the read is not cancel-safe, so it must never be cancelled
    while the connection is in use, nor run concurrently with another read."""

    def __init__(self, device) -> None:
        self._device = device
        self.devices = []
        self.reads = 0
        self.in_flight = 0
        self.max_in_flight = 0
        self.cancelled_reads = 0

    async def listen(self) -> None:
        return None

    async def receive_device_state_update(self) -> None:
        self.reads += 1
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.reads == 1:
                self.devices.append(self._device)
                return
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled_reads += 1
            raise
        finally:
            self.in_flight -= 1

    async def close(self) -> None:
        pass


class _Lockdown:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info) -> None:
        pass


async def _until(condition, timeout: float = 5) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        assert loop.time() < deadline, "condition not reached"
        await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_monitor_usbmux_task_tunnels_a_usb_device_once_its_other_tunnel_ends(monkeypatch):
    """Issue #2052: a device attached over USB while it has a Wi-Fi tunnel is skipped; when that
    tunnel ends no usbmux event follows, so the monitor must re-evaluate the devices it knows of."""
    closed: dict[str, asyncio.Event] = {}

    @asynccontextmanager
    async def fake_start_tunnel(protocol_handler, protocol=None):
        closed[protocol_handler.name] = asyncio.Event()
        client = Mock(wait_closed=closed[protocol_handler.name].wait, stop_tunnel=AsyncMock())
        yield Mock(client=client, address="fd00::1", port=1)

    usb_handler = Mock(remote_identifier="DEVICE", close=AsyncMock())
    usb_handler.name = "usb"

    async def fake_create_using_usbmux(serial, usbmux_address=None):
        return _Lockdown()

    mux = _ListeningMux(Mock(serial="DEVICE", connection_type="USB"))

    async def fake_create_mux(usbmux_address=None):
        return mux

    monkeypatch.setattr(tunneld_server, "start_tunnel", fake_start_tunnel)
    monkeypatch.setattr(tunneld_server, "create_using_usbmux", fake_create_using_usbmux)
    monkeypatch.setattr(tunneld_server.CoreDeviceTunnelProxy, "create", AsyncMock(return_value=usb_handler))
    monkeypatch.setattr(tunneld_server.usbmux, "create_mux", fake_create_mux)
    monkeypatch.setattr(tunneld_server, "USBMUX_INTERVAL", 0.05)
    core = tunneld_server.TunneldCore(wifi_monitor=False, usb_monitor=False, usbmux_monitor=True, mobdev2_monitor=False)

    monitor = asyncio.create_task(core.monitor_usbmux_task())
    wifi_handler = Mock(remote_identifier="DEVICE", close=AsyncMock())
    wifi_handler.name = "wifi"
    core.tunnel_tasks["fd00::2"] = tunneld_server.TunnelTask(
        task=asyncio.create_task(core.start_tunnel_task("fd00::2", wifi_handler)), udid="DEVICE"
    )
    try:
        await _until(lambda: core.tunnel_exists_for_udid("DEVICE"))
        # the attach event was evaluated and the monitor is back waiting for the next one
        await _until(lambda: mux.reads == 2)
        assert list(core.tunnel_tasks) == ["fd00::2"]

        closed["wifi"].set()

        await _until(lambda: "usbmux-DEVICE-USB" in core.tunnel_tasks)
        await _until(lambda: core.tunnel_exists_for_udid("DEVICE"))
        assert list(core.tunnel_tasks) == ["usbmux-DEVICE-USB"]
        assert (mux.reads, mux.max_in_flight, mux.cancelled_reads) == (2, 1, 0)
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        await core.close()


@pytest.mark.asyncio
async def test_start_tunnel_task_signals_a_usbmux_rescan_when_any_attempt_ends(monkeypatch):
    # A failed attempt also signals: a device skipped while it was pending may now need a tunnel.
    @asynccontextmanager
    async def failing_start_tunnel(protocol_handler, protocol=None):
        raise ConnectionTerminatedError()
        yield

    monkeypatch.setattr(tunneld_server, "start_tunnel", failing_start_tunnel)
    core = tunneld_server.TunneldCore(
        wifi_monitor=False, usb_monitor=False, usbmux_monitor=False, mobdev2_monitor=False
    )
    core._usbmux_rescan = asyncio.Event()

    await core.start_tunnel_task("usbmux-DEVICE-USB", Mock(remote_identifier="DEVICE", close=AsyncMock()))

    assert core._usbmux_rescan.is_set()


@pytest.mark.asyncio
async def test_monitor_usbmux_task_rescans_after_a_usb_attempt_that_gave_way_finishes(monkeypatch):
    """#2052, a later ordering: the USB attempt starts while a Wi-Fi tunnel exists, gives way to it,
    and is still closing when the Wi-Fi tunnel ends. The rescan that Wi-Fi signals sees the USB entry
    still registered and skips the device, so the USB attempt must signal again once it is gone."""
    creating_usb = asyncio.Event()
    finish_usb_create = asyncio.Event()
    usb_closing = asyncio.Event()
    finish_usb_close = asyncio.Event()
    closed: dict[str, asyncio.Event] = {}

    @asynccontextmanager
    async def fake_start_tunnel(protocol_handler, protocol=None):
        closed[protocol_handler.name] = asyncio.Event()
        client = Mock(wait_closed=closed[protocol_handler.name].wait, stop_tunnel=AsyncMock())
        yield Mock(client=client, address="fd00::1", port=1)

    async def close_usb() -> None:
        usb_closing.set()
        await finish_usb_close.wait()

    usb_handler = Mock(remote_identifier="DEVICE", close=close_usb)
    usb_handler.name = "usb"

    async def fake_create_using_usbmux(serial, usbmux_address=None):
        creating_usb.set()
        await finish_usb_create.wait()
        return _Lockdown()

    mux = _ListeningMux(Mock(serial="DEVICE", connection_type="USB"))

    async def fake_create_mux(usbmux_address=None):
        return mux

    monkeypatch.setattr(tunneld_server, "start_tunnel", fake_start_tunnel)
    monkeypatch.setattr(tunneld_server, "create_using_usbmux", fake_create_using_usbmux)
    monkeypatch.setattr(tunneld_server.CoreDeviceTunnelProxy, "create", AsyncMock(return_value=usb_handler))
    monkeypatch.setattr(tunneld_server.usbmux, "create_mux", fake_create_mux)
    monkeypatch.setattr(tunneld_server, "USBMUX_INTERVAL", 0.05)
    core = tunneld_server.TunneldCore(wifi_monitor=False, usb_monitor=False, usbmux_monitor=True, mobdev2_monitor=False)

    monitor = asyncio.create_task(core.monitor_usbmux_task())
    wifi_handler = Mock(remote_identifier="DEVICE", close=AsyncMock())
    wifi_handler.name = "wifi"
    try:
        await creating_usb.wait()
        # a Wi-Fi tunnel comes up while the monitor is still preparing its USB attempt
        core.tunnel_tasks["fd00::2"] = tunneld_server.TunnelTask(
            task=asyncio.create_task(core.start_tunnel_task("fd00::2", wifi_handler)), udid="DEVICE"
        )
        await _until(lambda: core.tunnel_exists_for_udid("DEVICE"))
        finish_usb_create.set()
        await usb_closing.wait()  # the USB attempt gave way and is closing, still registered
        await _until(lambda: mux.reads == 2)

        closed["wifi"].set()
        await _until(lambda: "fd00::2" not in core.tunnel_tasks)
        rescan = core._usbmux_rescan
        assert rescan is not None
        await _until(lambda: not rescan.is_set())  # consumed while USB is registered
        finish_usb_close.set()

        await _until(lambda: "usb" in closed)  # a second USB attempt established a tunnel
        await _until(lambda: core.tunnel_exists_for_udid("DEVICE"))
        assert list(core.tunnel_tasks) == ["usbmux-DEVICE-USB"]
        assert (mux.reads, mux.max_in_flight, mux.cancelled_reads) == (2, 1, 0)
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        await core.close()


@pytest.mark.asyncio
async def test_monitor_usbmux_task_throttles_rescans_for_a_tunnel_that_keeps_ending(monkeypatch):
    # A USB tunnel that ends as soon as it is up signals a rescan each time; every retry, the first
    # included, must come at least USBMUX_INTERVAL after the previous evaluation, not in a busy loop.
    attempts: list[float] = []
    loop = asyncio.get_running_loop()

    @asynccontextmanager
    async def short_lived_tunnel(protocol_handler, protocol=None):
        attempts.append(loop.time())
        yield Mock(client=Mock(wait_closed=AsyncMock(), stop_tunnel=AsyncMock()), address="fd00::1", port=1)

    async def fake_create_using_usbmux(serial, usbmux_address=None):
        return _Lockdown()

    mux = _ListeningMux(Mock(serial="DEVICE", connection_type="USB"))

    async def fake_create_mux(usbmux_address=None):
        return mux

    monkeypatch.setattr(tunneld_server, "start_tunnel", short_lived_tunnel)
    monkeypatch.setattr(tunneld_server, "create_using_usbmux", fake_create_using_usbmux)
    monkeypatch.setattr(
        tunneld_server.CoreDeviceTunnelProxy,
        "create",
        AsyncMock(side_effect=lambda *args, **kwargs: Mock(remote_identifier="DEVICE", close=AsyncMock())),
    )
    monkeypatch.setattr(tunneld_server.usbmux, "create_mux", fake_create_mux)
    monkeypatch.setattr(tunneld_server, "USBMUX_INTERVAL", 0.2)
    core = tunneld_server.TunneldCore(wifi_monitor=False, usb_monitor=False, usbmux_monitor=True, mobdev2_monitor=False)

    monitor = asyncio.create_task(core.monitor_usbmux_task())
    try:
        await _until(lambda: len(attempts) >= 3)
        gaps = [later - earlier for earlier, later in zip(attempts, attempts[1:])]
        assert all(gap >= 0.15 for gap in gaps), gaps
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        await core.close()


@pytest.mark.asyncio
async def test_monitor_usbmux_task_rescans_after_a_pending_usb_attempt_fails(monkeypatch):
    """#2052: the USB attempt is still in its handshake while a Wi-Fi tunnel comes and goes. The
    rescan Wi-Fi signals skips the device (its USB attempt is registered); when that attempt then
    fails, its end must signal again, or the device is left without a tunnel."""
    handshake = asyncio.Event()
    fail_usb = asyncio.Event()
    wifi_ends = asyncio.Event()
    usb_attempts = 0

    @asynccontextmanager
    async def fake_start_tunnel(protocol_handler, protocol=None):
        nonlocal usb_attempts
        if protocol_handler.name == "usb":
            usb_attempts += 1
            if usb_attempts == 1:
                handshake.set()
                await fail_usb.wait()
                raise ConnectionTerminatedError()
        ends = wifi_ends if protocol_handler.name == "wifi" else asyncio.Event()
        yield Mock(client=Mock(wait_closed=ends.wait, stop_tunnel=AsyncMock()), address="fd00::1", port=1)

    def handler(name: str) -> Mock:
        result = Mock(remote_identifier="DEVICE", close=AsyncMock())
        result.name = name
        return result

    async def fake_create_using_usbmux(serial, usbmux_address=None):
        return _Lockdown()

    mux = _ListeningMux(Mock(serial="DEVICE", connection_type="USB"))

    async def fake_create_mux(usbmux_address=None):
        return mux

    monkeypatch.setattr(tunneld_server, "start_tunnel", fake_start_tunnel)
    monkeypatch.setattr(tunneld_server, "create_using_usbmux", fake_create_using_usbmux)
    monkeypatch.setattr(
        tunneld_server.CoreDeviceTunnelProxy, "create", AsyncMock(side_effect=lambda *args, **kwargs: handler("usb"))
    )
    monkeypatch.setattr(tunneld_server.usbmux, "create_mux", fake_create_mux)
    monkeypatch.setattr(tunneld_server, "USBMUX_INTERVAL", 0.05)
    core = tunneld_server.TunneldCore(wifi_monitor=False, usb_monitor=False, usbmux_monitor=True, mobdev2_monitor=False)

    monitor = asyncio.create_task(core.monitor_usbmux_task())
    try:
        await handshake.wait()
        core.tunnel_tasks["fd00::2"] = tunneld_server.TunnelTask(
            task=asyncio.create_task(core.start_tunnel_task("fd00::2", handler("wifi"))), udid="DEVICE"
        )
        await _until(lambda: core.tunnel_exists_for_udid("DEVICE"))
        wifi_ends.set()
        await _until(lambda: "fd00::2" not in core.tunnel_tasks)
        rescan = core._usbmux_rescan
        assert rescan is not None
        await _until(lambda: not rescan.is_set())  # consumed while the USB attempt is registered
        fail_usb.set()

        await _until(lambda: usb_attempts == 2)
        await _until(lambda: core.tunnel_exists_for_udid("DEVICE"))
        assert list(core.tunnel_tasks) == ["usbmux-DEVICE-USB"]
        assert (mux.reads, mux.max_in_flight, mux.cancelled_reads) == (2, 1, 0)
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        await core.close()


@pytest.mark.asyncio
async def test_cancelled_tunnels_do_not_signal_a_usbmux_rescan(monkeypatch):
    # A tunnel ended through the API (cancel or clear) must stay gone, not be rebuilt by the monitor.
    @asynccontextmanager
    async def fake_start_tunnel(protocol_handler, protocol=None):
        yield Mock(client=Mock(wait_closed=asyncio.Event().wait, stop_tunnel=AsyncMock()), address="fd00::1", port=1)

    monkeypatch.setattr(tunneld_server, "start_tunnel", fake_start_tunnel)
    core = tunneld_server.TunneldCore(
        wifi_monitor=False, usb_monitor=False, usbmux_monitor=False, mobdev2_monitor=False
    )
    rescan = core._usbmux_rescan = asyncio.Event()

    for end in (lambda: core.cancel("DEVICE"), core.clear):
        task = asyncio.create_task(
            core.start_tunnel_task("usbmux-DEVICE-USB", Mock(remote_identifier="DEVICE", close=AsyncMock()))
        )
        core.tunnel_tasks["usbmux-DEVICE-USB"] = tunneld_server.TunnelTask(task=task, udid="DEVICE")
        await _until(lambda: core.tunnel_exists_for_udid("DEVICE"))
        end()
        await task
        assert not rescan.is_set()
        assert not core._cancel_requested
