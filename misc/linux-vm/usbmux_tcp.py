"""Expose the host's usbmuxd on a loopback TCP port, so a local VM can reach the USB-attached devices.

Every process that can connect to the port gets full usbmuxd access (including pair records), so it
only listens on 127.0.0.1 and is meant to run just for the duration of a test run.
"""

import asyncio
import sys

USBMUXD_PATH = "/var/run/usbmuxd"


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        mux_reader, mux_writer = await asyncio.open_unix_connection(USBMUXD_PATH)
    except OSError:
        writer.close()
        return
    await asyncio.gather(_pump(reader, mux_writer), _pump(mux_reader, writer), return_exceptions=True)


async def main(port: int) -> None:
    server = await asyncio.start_server(_handle, "127.0.0.1", port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1])))
