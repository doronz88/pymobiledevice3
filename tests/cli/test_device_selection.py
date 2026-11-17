from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
import typer

from pymobiledevice3.bonjour import Address, ServiceInstance
from pymobiledevice3.cli import cli_common
from pymobiledevice3.cli import lockdown as lockdown_cli
from pymobiledevice3.cli.cli_common import prompt_device_list

pytestmark = [pytest.mark.cli]


def test_prompt_without_tty_fails_fast_with_candidates(capsys: pytest.CaptureFixture[str]) -> None:
    # pytest runs without a TTY on stdin/stdout, which is exactly the guarded scenario
    devices = [SimpleNamespace(udid="udid-a"), SimpleNamespace(udid="udid-b")]
    with pytest.raises(typer.Exit) as exc_info:
        prompt_device_list(devices)
    assert exc_info.value.exit_code == 1
    err = capsys.readouterr().err
    assert "interactive selection requires a terminal" in err
    assert "udid-a" in err
    assert "udid-b" in err
    assert "PYMOBILEDEVICE3_UDID" in err


def test_prompt_device_closes_the_devices_not_chosen(monkeypatch: pytest.MonkeyPatch) -> None:
    lockdowns = [Mock(close=AsyncMock()) for _ in range(3)]
    monkeypatch.setattr(cli_common, "prompt_device_list", lambda devices: devices[1])
    assert cli_common._prompt_device(lockdowns) is lockdowns[1]
    assert [lockdown.close.await_count for lockdown in lockdowns] == [1, 0, 1]


def test_prompt_device_closes_every_device_when_the_prompt_is_aborted(monkeypatch: pytest.MonkeyPatch) -> None:
    lockdowns = [Mock(close=AsyncMock()) for _ in range(2)]

    def abort(devices: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_common, "prompt_device_list", abort)
    with pytest.raises(KeyboardInterrupt):
        cli_common._prompt_device(lockdowns)
    assert [lockdown.close.await_count for lockdown in lockdowns] == [1, 1]


@pytest.mark.parametrize(
    "dependency,autopair",
    [
        (lambda: cli_common.any_service_provider_dependency(rsd_service_provider=None, mobdev2=False), True),
        (lambda: cli_common.no_autopair_service_provider_dependency(rsd_service_provider=None), False),
    ],
)
def test_multiple_usb_devices_prompt(monkeypatch: pytest.MonkeyPatch, dependency: Any, autopair: bool) -> None:
    devices = [SimpleNamespace(serial="udid-a"), SimpleNamespace(serial="udid-b")]
    created: list[dict[str, Any]] = []

    async def select_devices_by_connection_type(**kwargs: Any) -> list[SimpleNamespace]:
        return devices

    async def create_using_usbmux(**kwargs: Any) -> Mock:
        created.append(kwargs)
        return Mock(udid=kwargs["serial"], close=AsyncMock())

    monkeypatch.setattr(cli_common.usbmuxd, "select_devices_by_connection_type", select_devices_by_connection_type)
    monkeypatch.setattr(cli_common, "create_using_usbmux", create_using_usbmux)
    monkeypatch.setattr(cli_common, "prompt_device_list", lambda lockdowns: lockdowns[1])

    assert dependency().udid == "udid-b"
    assert [kwargs["autopair"] for kwargs in created] == [autopair, autopair]


def _pairable_devices(monkeypatch: pytest.MonkeyPatch, names: dict[str, Any]) -> dict[str, Mock]:
    """Advertise one device in pairing mode per address, named as ``names`` says (an exception: unreachable)."""
    lockdowns = {
        ip: Mock(identifier=ip, all_values={} if name is None else {"DeviceName": name}, close=AsyncMock())
        for ip, name in names.items()
        if not isinstance(name, Exception)
    }

    async def browse_pairable() -> list[ServiceInstance]:
        return [
            ServiceInstance(instance=f"tv-{i}", host=f"tv-{i}.local", port=0, addresses=[Address(ip=ip, iface="en0")])
            for i, ip in enumerate(names)
        ]

    async def create_using_tcp(hostname: str, autopair: bool) -> Mock:
        assert not autopair
        if hostname not in lockdowns:
            raise names[hostname]
        return lockdowns[hostname]

    monkeypatch.setattr(lockdown_cli, "browse_pairable", browse_pairable)
    monkeypatch.setattr(lockdown_cli, "create_using_tcp", create_using_tcp)
    return lockdowns


@pytest.mark.asyncio
async def test_pairable_devices_are_offered_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    lockdowns = _pairable_devices(
        monkeypatch, {"10.0.0.1": "Living Room", "10.0.0.2": OSError(), "10.0.0.3": None, "10.0.0.4": "Bedroom"}
    )
    offered: list[str] = []

    def prompt_selection(choices: list[str], message: str, idx: bool, hint: str) -> int:
        offered.extend(choices)
        return 2

    monkeypatch.setattr(lockdown_cli, "prompt_selection", prompt_selection)

    assert await lockdown_cli._connect_pairable_device() is lockdowns["10.0.0.4"]
    # a device that cannot be reached is not offered, and one that keeps its name to itself still is
    assert offered == [
        "Living Room - tv-0.local (10.0.0.1)",
        "tv-2.local (10.0.0.3)",
        "Bedroom - tv-3.local (10.0.0.4)",
    ]
    assert [lockdown.close.await_count for lockdown in lockdowns.values()] == [1, 1, 0]


@pytest.mark.asyncio
async def test_a_single_pairable_device_is_not_asked_about(monkeypatch: pytest.MonkeyPatch) -> None:
    lockdowns = _pairable_devices(monkeypatch, {"10.0.0.1": "Living Room", "10.0.0.2": OSError()})
    monkeypatch.setattr(lockdown_cli, "prompt_selection", Mock(side_effect=AssertionError))

    assert await lockdown_cli._connect_pairable_device() is lockdowns["10.0.0.1"]
    assert lockdowns["10.0.0.1"].close.await_count == 0


@pytest.mark.asyncio
async def test_pairable_devices_are_closed_when_the_prompt_is_aborted(monkeypatch: pytest.MonkeyPatch) -> None:
    lockdowns = _pairable_devices(monkeypatch, {"10.0.0.1": "Living Room", "10.0.0.2": "Bedroom"})
    monkeypatch.setattr(lockdown_cli, "prompt_selection", Mock(side_effect=typer.Exit(code=1)))

    with pytest.raises(typer.Exit):
        await lockdown_cli._connect_pairable_device()
    assert [lockdown.close.await_count for lockdown in lockdowns.values()] == [1, 1]
