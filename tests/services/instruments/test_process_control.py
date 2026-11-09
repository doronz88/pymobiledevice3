import asyncio
import signal
from typing import cast

import pytest

from pymobiledevice3.dtx.channel import DTXChannel
from pymobiledevice3.dtx.connection import DTXConnection
from pymobiledevice3.dtx.message import DTXMessage, DTXMessageType
from pymobiledevice3.dtx.message_aux import MessageAux
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl, ProcessControlService


class _Writer:
    def __init__(self) -> None:
        self.writes: list[bytes] = []

    def get_extra_info(self, name: str, default: object = None) -> object:
        return default

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        pass


class _Connection(DTXConnection):
    def __init__(self) -> None:
        self.writer = _Writer()
        self.sent_messages: list[DTXMessage] = []
        super().__init__(asyncio.StreamReader(), cast(asyncio.StreamWriter, self.writer))

    async def _send_message(self, message: DTXMessage) -> None:
        await super()._send_message(message)
        self.sent_messages.append(message)

    async def _wait_for_reply(self, msg_id: int) -> DTXMessage:
        self._pending_replies.pop(msg_id).cancel()
        return DTXMessage(type=DTXMessageType.OK)


@pytest.mark.asyncio
@pytest.mark.parametrize("sig", [signal.SIGTERM, int(signal.SIGTERM)], ids=["signal-enum", "int"])
async def test_signal_normalizes_integer_values_before_dtx_serialization(sig: int) -> None:
    connection = _Connection()
    identifier = ProcessControlService.IDENTIFIER
    assert identifier is not None
    channel = DTXChannel(1, identifier, connection)
    service = ProcessControlService(connection.ctx.child(channel=channel))
    process_control = ProcessControl(cast(DtxServiceProvider, object()), service=service)

    await process_control.signal(173, sig)

    assert connection.writer.writes
    assert len(connection.sent_messages) == 1
    message = connection.sent_messages[0]
    assert message.payload == "sendSignal:toPid:"
    args = MessageAux.parse(message.aux_data)
    assert args[0] == int(sig)
    assert type(args[0]) is int
    assert args[1] == 173
    assert message.aux_data == MessageAux.build([int(sig), 173])
