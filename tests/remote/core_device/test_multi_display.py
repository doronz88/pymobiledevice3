import asyncio
import base64
import json
from typing import Any

import pytest

from pymobiledevice3.remote.core_device import hid_service
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService, display_rotation, select_display
from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer, _SubState
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

# Trimmed from an unfolded foldable's get_display_info: the cover panel (1) is off, the inner one (2) is lit.
UNFOLDED: dict[str, Any] = {
    "displays": [
        {
            "displayId": 1,
            "uniqueId": "987-654-321",
            "name": "LCD",
            "primary": True,
            "external": False,
            "active": False,
            "currentMode": {"size": [1398.0, 2034.0]},
        },
        {
            "displayId": 2,
            "uniqueId": "123-456-789",
            "name": "LCD-1",
            "primary": False,
            "external": False,
            "active": True,
            "currentOrientation": "rot90",
            "currentMode": {"size": [2007.0, 2853.0]},
        },
        {"displayId": 3, "name": "TVOut", "primary": False, "external": True, "active": False},
    ]
}

# The matching list_connected_services reply: one touchscreen per panel, tagged with its display.
CONNECTED_SERVICES: dict[str, Any] = {
    "connectedServices": [
        {"_ServiceID": 257, "displayUUID": "987-654-321", "DeviceTypeHint": "Digitizer"},
        {"_ServiceID": 258, "displayUUID": "123-456-789", "DeviceTypeHint": "Digitizer"},
        {"_ServiceID": 512, "DeviceTypeHint": "Keyboard"},
        {"_ServiceID": 1281, "Product": "CoreDevice touchscreenGesture"},
    ]
}


def _rsd() -> RemoteServiceDiscoveryService:
    return RemoteServiceDiscoveryService(("127.0.0.1", 0))


def test_select_display_picks_the_lit_panel():
    assert select_display(UNFOLDED)["displayId"] == 2


def test_select_display_follows_a_fold():
    folded = json.loads(json.dumps(UNFOLDED))
    folded["displays"][0]["active"] = True
    folded["displays"][1]["active"] = False
    assert select_display(folded)["displayId"] == 1


def test_select_display_ignores_active_external_displays():
    info = {"displays": [{"displayId": 1, "primary": True}, {"displayId": 4, "external": True, "active": True}]}
    assert select_display(info)["displayId"] == 1


def test_select_display_honours_a_pinned_id():
    assert select_display(UNFOLDED, 1)["uniqueId"] == "987-654-321"
    assert select_display(UNFOLDED, 9) == {"displayId": 9}


@pytest.mark.parametrize(
    ("orientation", "degrees"), [("rot0", 0), ("rot90", 90), ("rot180", 180), ("rot270", -90), (None, 0)]
)
def test_display_rotation(orientation, degrees):
    display = {} if orientation is None else {"currentOrientation": orientation}
    assert display_rotation(display) == degrees


@pytest.mark.asyncio
async def test_screen_stream_broadcasts_a_rotation():
    server = ScreenStreamServer(_rsd())
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    server._subscribers[queue] = _SubState()
    server._apply_display(select_display(UNFOLDED))
    server._broadcast_rotation()
    message = queue.get_nowait()
    assert message[4] == 4
    assert json.loads(message[5:]) == {"rotation": 90}


def test_select_display_without_displays_is_the_main_one():
    assert select_display({}) == {"displayId": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("unique_id", "service_id"),
    [
        ("987-654-321", 257),
        ("123-456-789", 258),
        ("not-a-display", hid_service.DIGITIZER_SURFACE_MAIN_TOUCHSCREEN),
        (None, hid_service.DIGITIZER_SURFACE_MAIN_TOUCHSCREEN),
    ],
)
async def test_touchscreen_service_id_matches_the_display(monkeypatch, unique_id, service_id):
    service = hid_service.UniversalHIDServiceService(_rsd())

    async def list_connected_services() -> dict[str, Any]:
        return CONNECTED_SERVICES

    monkeypatch.setattr(service, "list_connected_services", list_connected_services)
    assert await service.touchscreen_service_id(unique_id) == service_id


def test_screen_stream_switches_display_and_touchscreen():
    server = ScreenStreamServer(_rsd())
    assert server._follow_active_display
    assert server._apply_display(select_display(UNFOLDED))
    assert (server._display_id, server._display_unique_id, server._display_size) == (2, "123-456-789", (2007, 2853))
    server._touch_service_id = 258
    assert not server._apply_display(select_display(UNFOLDED))
    assert server._touch_service_id == 258
    assert server._apply_display(select_display(UNFOLDED, 1))
    assert (server._display_id, server._display_size) == (1, (1398, 2034))
    # the next touch re-resolves the touchscreen of the new display
    assert server._touch_service_id is None


def test_screen_stream_pinned_display():
    server = ScreenStreamServer(_rsd(), display_id=2)
    assert not server._follow_active_display
    assert server._display_id == 2


def test_decoder_config_message_carries_the_display_size():
    server = ScreenStreamServer(_rsd())
    assert server._build_decoder_config_message() is None
    server._apply_display(select_display(UNFOLDED))
    server._codec_string = "hev1.1.6.L150.B0"
    # parameter sets lifted from a real stream of the inner panel
    server._vps_nal = bytes.fromhex("40011c01ffff016000000300b000000300000300960cc090")
    server._sps_nal = bytes.fromhex(
        "420111016000000300b000000300000300964800b02007e1620339245218b9fc4fc2fe86fd43fea823f550"
        "4feaa82bf55505feaaa833f555529b8101010040"
    )
    server._pps_nal = bytes.fromhex("4401480724c16c90")
    message = server._build_decoder_config_message()
    assert message is not None
    assert int.from_bytes(message[:4], "big") == len(message) - 4
    assert message[4] == 3
    config = json.loads(message[5:])
    assert config["codec"] == "hev1.1.6.L150.B0"
    assert base64.b64decode(config["description"])[0] == 1  # hvcC configurationVersion
    assert config["display"] == {"width": 2007, "height": 2853, "rotation": 90}


@pytest.mark.asyncio
async def test_every_built_in_display_has_its_touchscreen(service_provider):
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("requires an RSD tunnel")
    async with DeviceInfoService(service_provider) as info:
        display_info = await info.get_display_info()
    built_in = [d for d in display_info["displays"] if not d.get("external")]
    active = select_display(display_info)
    assert active in built_in
    async with hid_service.UniversalHIDServiceService(service_provider) as hid:
        service_ids = [await hid.touchscreen_service_id(d.get("uniqueId")) for d in built_in]
    # one touchscreen per panel: a foldable's panels must not share one
    assert len(set(service_ids)) == len(built_in)
