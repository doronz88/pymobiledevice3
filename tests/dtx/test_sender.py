from __future__ import annotations

import pytest

from pymobiledevice3.dtx._sender import _DTXSenderMixin
from pymobiledevice3.dtx.message import DTXMessage, DTXMessageType
from pymobiledevice3.dtx.ns_types import NSError


class _DummySender(_DTXSenderMixin):
    def __init__(self) -> None:
        self.sent: list[DTXMessage] = []

    async def _send_message(self, message: DTXMessage) -> None:
        self.sent.append(message)


@pytest.mark.asyncio
async def test_send_reply_ack_has_no_payload_or_aux() -> None:
    sender = _DummySender()

    await sender.send_reply_ack(channel_code=7, msg_id=11, conv_idx=2)

    assert len(sender.sent) == 1
    msg = sender.sent[0]
    assert msg.type == DTXMessageType.OK
    assert msg.payload is None
    assert list(msg.aux) == []
    assert len(msg.payload_data) == 0
    assert len(msg.aux_data) == 0


@pytest.mark.asyncio
async def test_send_reply_defaults_none_aux_to_empty_aux() -> None:
    sender = _DummySender()

    await sender.send_reply(channel_code=3, msg_id=12, conv_idx=2, payload={"key": "value"})

    assert len(sender.sent) == 1
    msg = sender.sent[0]
    assert msg.type == DTXMessageType.OBJECT
    assert msg.payload == {"key": "value"}
    assert list(msg.aux) == []
    assert len(msg.aux_data) == 0


@pytest.mark.asyncio
async def test_send_reply_error_rejects_non_empty_aux() -> None:
    sender = _DummySender()
    error = NSError(1, "DTXMessage", {"NSLocalizedDescription": "failure"})

    with pytest.raises(AssertionError, match="ERROR replies must not have aux arguments"):
        await sender._send_reply(5, 10, 2, DTXMessageType.ERROR, payload=error, aux_args=[1])
