import plistlib
from typing import Any, Union

import pytest
import requests

from pymobiledevice3.exceptions import TSSError, TSSUnavailableError
from pymobiledevice3.restore import tss
from pymobiledevice3.restore.tss import TSS_REQUEST_ATTEMPTS, TSSRequest

TICKET = {"ApImg4Ticket": b"ticket"}
SUCCESS = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=" + plistlib.dumps(TICKET)


class _Response:
    def __init__(self, status_code: int, content: bytes) -> None:
        self.status_code = status_code
        self.content = content


class _Replies(list[Union[_Response, Exception]]):
    """What each POST to TSS returns (a `_Response`) or raises (an exception), in order."""

    def __init__(self) -> None:
        super().__init__()
        self.posts: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs) -> _Response:
        self.posts.append(kwargs)
        reply = self.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


@pytest.fixture
def replies(monkeypatch) -> _Replies:
    queue = _Replies()
    monkeypatch.setattr(tss.requests, "post", queue.post)
    monkeypatch.setattr(tss, "TSS_RETRY_DELAY", 0)
    return queue


@pytest.mark.asyncio
async def test_a_successful_reply_is_the_ticket(replies) -> None:
    replies.append(_Response(200, SUCCESS))
    assert await TSSRequest().send_receive() == TICKET
    assert replies.posts[0]["timeout"] == tss.TSS_REQUEST_TIMEOUT


@pytest.mark.asyncio
async def test_an_empty_502_is_retried_and_then_reported_as_unavailable(replies) -> None:
    # A proxy on the way to gs.apple.com answering an empty 502 used to surface as an IndexError
    replies.extend(_Response(502, b"") for _ in range(TSS_REQUEST_ATTEMPTS))
    with pytest.raises(TSSUnavailableError, match="HTTP 502 with an empty body"):
        await TSSRequest().send_receive()
    assert len(replies.posts) == TSS_REQUEST_ATTEMPTS


@pytest.mark.asyncio
async def test_a_transient_failure_is_retried(replies) -> None:
    replies.extend([requests.ConnectionError("reset"), requests.Timeout("slow"), _Response(200, SUCCESS)])
    assert await TSSRequest().send_receive() == TICKET


@pytest.mark.asyncio
async def test_a_refusal_is_final(replies) -> None:
    replies.append(_Response(200, b"STATUS=94&MESSAGE=This device isn't eligible for the requested build."))
    with pytest.raises(TSSError, match="eligible"):
        await TSSRequest().send_receive()
    assert len(replies.posts) == 1


@pytest.mark.parametrize(
    "content",
    [
        b"<html><body>Proxy authentication required</body></html>",
        b"STATUS=0&MESSAGE=SUCCESS",
        b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=<?xml version='1.0'?><plist><dict>",
    ],
    ids=["not-a-tss-reply", "no-ticket", "truncated-ticket"],
)
def test_a_reply_that_is_not_a_ticket_is_unavailable_not_refused(content: bytes) -> None:
    with pytest.raises(TSSUnavailableError):
        tss.parse_tss_reply(200, content)
