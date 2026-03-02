import asyncio
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import Depends, InjectingTyper

try:
    from defusedxml import ElementTree as DefusedET
except Exception as exc:  # pragma: no cover - optional dependency gate
    raise ImportError("WDA CLI requires pymobiledevice3[wda] or pymobiledevice3[full]") from exc

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.exceptions import ConnectionFailedError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.testmanaged.xcuitest import XCUITestPlanConsumer, start_xcuitest_runner
from pymobiledevice3.services.wda import DEFAULT_WDA_PORT, WdaServiceClient
from pymobiledevice3.utils import get_asyncio_loop

cli = InjectingTyper(
    name="wda",
    help="Interact with WebDriverAgent (launch apps and tap elements).",
    no_args_is_help=True,
)


def wda_client_dep(
    service_provider: ServiceProviderDep,
    port: Annotated[
        int,
        typer.Option(
            "--port",
            help="WDA device port to connect to.",
        ),
    ] = DEFAULT_WDA_PORT,
    timeout: Annotated[
        float,
        typer.Option(help="HTTP timeout in seconds."),
    ] = 10.0,
) -> WdaServiceClient:
    return WdaServiceClient(service_provider=service_provider, port=port, timeout=timeout)


WdaClientDep = Annotated[
    WdaServiceClient,
    Depends(wda_client_dep),
]


async def wait_for_xctest_app(
    service_provider: LockdownServiceProvider, xctrunner: str
) -> tuple[XCUITestPlanConsumer, asyncio.Task]:
    consumer, task = await start_xcuitest_runner(service_provider, xctrunner)
    while True:
        device = await usbmux.select_device(service_provider.udid)
        try:
            await device.connect(DEFAULT_WDA_PORT)
        except ConnectionFailedError:
            await asyncio.sleep(0.1)
        else:
            break
    return consumer, task


def wda_xctest_dep(
    service_provider: ServiceProviderDep,
    xctrunner: Annotated[
        Optional[str],
        typer.Option(
            "--xctrunner",
            "-xc",
            help="Bundle id of an XCUITest runner to start (e.g. com.facebook.WebDriverAgentRunner.xctrunner).",
        ),
    ] = None,
) -> Optional[tuple[XCUITestPlanConsumer, asyncio.Task]]:
    if xctrunner is None:
        return None
    return get_asyncio_loop().run_until_complete(wait_for_xctest_app(service_provider, xctrunner))


WdaXcRunnerDep = Annotated[
    Optional[tuple[XCUITestPlanConsumer, asyncio.Task]],
    Depends(wda_xctest_dep),
]


async def _cleanup_xctrunner(xctrunner: WdaXcRunnerDep) -> None:
    if xctrunner is None:
        return
    consumer, task = xctrunner
    await consumer.stop()
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


@cli.command("launch")
@async_command
async def wda_launch(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
    bundle_id: str,
) -> None:
    """Launch an app by starting a WDA session and print the session id."""
    session_id = await client.start_session(bundle_id=bundle_id)
    print(session_id)
    await _cleanup_xctrunner(_xctrunner)


@cli.command("tap")
@async_command
async def wda_tap(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
    selector: str,
    using: Annotated[
        str,
        typer.Option(
            "--using",
            "-u",
            help="Element lookup strategy (e.g. 'accessibility id', 'name', 'label', 'xpath').",
        ),
    ] = "accessibility id",
    session_id: Annotated[
        Optional[str],
        typer.Option(
            "--session-id",
            "-s",
            help="Existing WDA session id (omit to create a new session).",
        ),
    ] = None,
    bundle_id: Annotated[
        Optional[str],
        typer.Option(
            "--bundle-id",
            help="Bundle id to launch if a new session is created.",
        ),
    ] = None,
) -> None:
    """Tap an element (typically a button) using a WDA selector."""
    if session_id is None:
        session_id = await client.start_session(bundle_id=bundle_id)
    else:
        client.session_id = session_id
    element_id = await client.find_element(using=using, value=selector, session_id=session_id)
    await client.click(element_id=element_id, session_id=session_id)
    await _cleanup_xctrunner(_xctrunner)


@cli.command("press")
@async_command
async def wda_press(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
    name: str,
    session_id: Annotated[
        Optional[str],
        typer.Option(
            "--session-id",
            "-s",
            help="Existing WDA session id (optional; some servers require it).",
        ),
    ] = None,
) -> None:
    """Press a device button (e.g. home, volumeup, volumedown, lock)."""
    if session_id is None:
        session_id = await client.start_session()
    await client.press_button(name=name, session_id=session_id)
    await _cleanup_xctrunner(_xctrunner)


@cli.command("list-items")
@async_command
async def wda_list_items(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
    session_id: Annotated[
        Optional[str],
        typer.Option(
            "--session-id",
            "-s",
            help="Existing WDA session id (optional).",
        ),
    ] = None,
    hittable_only: Annotated[
        bool,
        typer.Option(
            "--hittable-only",
            help="Show only elements marked hittable by WDA.",
        ),
    ] = False,
    with_rect: Annotated[
        bool,
        typer.Option(
            "--with-rect",
            help="Include element bounds (x,y,width,height) if present.",
        ),
    ] = False,
) -> None:
    """Show tappable WDA elements (use with 'tap' selectors)."""
    source = await client.get_source(session_id=session_id)
    root = DefusedET.fromstring(source)

    items = []
    for elem in root.iter():
        attrs = elem.attrib
        elem_type = elem.tag
        enabled = attrs.get("enabled")
        visible = attrs.get("visible")
        hittable = attrs.get("hittable")
        if hittable_only and hittable != "true":
            continue
        name = attrs.get("name")
        label = attrs.get("label")
        value = attrs.get("value")
        rect = None
        if with_rect:
            rect = {
                "x": attrs.get("x"),
                "y": attrs.get("y"),
                "width": attrs.get("width"),
                "height": attrs.get("height"),
            }
            if all(v is None for v in rect.values()):
                rect = None
        if not (name or label or value or rect):
            continue
        item = {
            "type": elem_type,
            "name": name,
            "label": label,
            "value": value,
            "enabled": enabled,
            "visible": visible,
            "hittable": hittable,
        }
        if with_rect:
            item["rect"] = rect
        items.append(item)

    print_json(items)
    await _cleanup_xctrunner(_xctrunner)


@cli.command("screenshot")
@async_command
async def wda_screenshot(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
    out: Path,
    session_id: Annotated[
        Optional[str],
        typer.Option(
            "--session-id",
            "-s",
            help="Existing WDA session id (optional).",
        ),
    ] = None,
) -> None:
    """Save a screenshot via WDA."""
    data = await client.get_screenshot(session_id=session_id)
    out.write_bytes(data)
    await _cleanup_xctrunner(_xctrunner)


@cli.command("status")
@async_command
async def wda_status(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
) -> None:
    """Show WDA status."""
    print_json(await client.get_status())
    await _cleanup_xctrunner(_xctrunner)


@cli.command("type")
@async_command
async def wda_type(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
    text: str,
    session_id: Annotated[
        Optional[str],
        typer.Option(
            "--session-id",
            "-s",
            help="Existing WDA session id (omit to create a new session).",
        ),
    ] = None,
    bundle_id: Annotated[
        Optional[str],
        typer.Option(
            "--bundle-id",
            help="Bundle id to launch if a new session is created.",
        ),
    ] = None,
) -> None:
    """Type text into the focused element."""
    if session_id is None:
        session_id = await client.start_session(bundle_id=bundle_id)
    else:
        client.session_id = session_id
    await client.send_keys(text, session_id=session_id)
    await _cleanup_xctrunner(_xctrunner)


@cli.command("swipe")
@async_command
async def wda_swipe(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    duration: Annotated[
        float,
        typer.Option(
            "--duration",
            "-d",
            help="Swipe duration in seconds.",
        ),
    ] = 0.2,
    session_id: Annotated[
        Optional[str],
        typer.Option(
            "--session-id",
            "-s",
            help="Existing WDA session id (omit to create a new session).",
        ),
    ] = None,
    bundle_id: Annotated[
        Optional[str],
        typer.Option(
            "--bundle-id",
            help="Bundle id to launch if a new session is created.",
        ),
    ] = None,
) -> None:
    """Swipe from one coordinate to another."""
    if session_id is None:
        session_id = await client.start_session(bundle_id=bundle_id)
    else:
        client.session_id = session_id
    await client.swipe(start_x, start_y, end_x, end_y, duration=duration, session_id=session_id)
    await _cleanup_xctrunner(_xctrunner)


@cli.command("window-size")
@async_command
async def wda_window_size(
    client: WdaClientDep,
    _xctrunner: WdaXcRunnerDep,
    session_id: Annotated[
        Optional[str],
        typer.Option(
            "--session-id",
            "-s",
            help="Existing WDA session id (omit to create a new session).",
        ),
    ] = None,
    bundle_id: Annotated[
        Optional[str],
        typer.Option(
            "--bundle-id",
            help="Bundle id to launch if a new session is created.",
        ),
    ] = None,
) -> None:
    """Show window size (screen dimensions)."""
    if session_id is None:
        session_id = await client.start_session(bundle_id=bundle_id)
    else:
        client.session_id = session_id
    print_json(await client.get_window_size(session_id=session_id))
    await _cleanup_xctrunner(_xctrunner)
