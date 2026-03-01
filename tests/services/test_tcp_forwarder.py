import asyncio

import pytest

from pymobiledevice3.lockdown import SERVICE_PORT, LockdownClient
from pymobiledevice3.tcp_forwarder import UsbmuxTcpForwarder

FREE_PORT = 3582


async def attempt_local_connection(port: int) -> None:
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.close()
    await writer.wait_closed()


@pytest.mark.parametrize("dst_port", [FREE_PORT, SERVICE_PORT])
@pytest.mark.asyncio
async def test_tcp_forwarder_bad_port(lockdown: LockdownClient, dst_port: int) -> None:
    # start forwarder
    forwarder = UsbmuxTcpForwarder(lockdown.udid, dst_port, FREE_PORT)
    task = asyncio.create_task(forwarder.start())

    try:
        # wait for it to actually start listening
        for _ in range(100):
            if forwarder.server is not None:
                break
            await asyncio.sleep(0.01)
        assert forwarder.server is not None
        await attempt_local_connection(FREE_PORT)

    finally:
        # tell it to stop
        forwarder.stop()
        # make sure it stops
        await asyncio.wait_for(task, timeout=5)
