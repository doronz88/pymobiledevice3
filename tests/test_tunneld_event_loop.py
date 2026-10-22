import http.client
import json
import socket
import subprocess
import sys
import time

# A tunneld with all monitors disabled, started the way the CLI starts it: on Windows,
# pymobiledevice3/__main__.py installs the selector policy before tunneld runs (#1217). An extra
# route reports the event loop uvicorn ended up serving on.
TUNNELD_SCRIPT = (
    "import asyncio, sys, warnings\n"
    "if sys.platform == 'win32':\n"
    "    with warnings.catch_warnings():\n"
    "        warnings.simplefilter('ignore', category=DeprecationWarning)\n"
    "        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())\n"
    "from pymobiledevice3.tunneld.server import TunneldRunner\n"
    "runner = TunneldRunner('127.0.0.1', int(sys.argv[1]), usb_monitor=False, wifi_monitor=False, "
    "usbmux_monitor=False, mobdev2_monitor=False)\n"
    "@runner._app.get('/event-loop')\n"
    "async def event_loop():\n"
    "    loop = asyncio.get_running_loop()\n"
    "    return {'type': type(loop).__name__, 'selector': isinstance(loop, asyncio.SelectorEventLoop)}\n"
    "runner._run_app()\n"
)


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_tunneld_serves_on_a_selector_loop() -> None:
    """On Windows uvicorn's "asyncio" loop factory forces a ProactorEventLoop, on which the Wi-Fi
    monitor's bonjour browse gets no answers (#2051); tunneld must run on the selector loop."""
    port = _unused_port()
    proc = subprocess.Popen(
        [sys.executable, "-c", TUNNELD_SCRIPT, str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                assert proc.poll() is None, "tunneld server exited prematurely"
                assert time.monotonic() < deadline, "tunneld server did not come up"
                time.sleep(0.1)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            connection.request("GET", "/event-loop")
            response = connection.getresponse()
            assert response.status == 200
            event_loop = json.loads(response.read())
        finally:
            connection.close()
        assert event_loop["selector"], event_loop
    finally:
        proc.kill()
        proc.wait(timeout=10)
