import asyncio
from typing import Any, cast

import pytest

from pymobiledevice3.dtx.connection import DTXConnection
from pymobiledevice3.dtx.service import DTXProxyService, DTXService
from pymobiledevice3.exceptions import ConnectionTerminatedError

pytestmark = pytest.mark.asyncio


class _Wanted(DTXService):
    pass


def _connection(services: dict[int, DTXService]) -> DTXConnection:
    connection = object.__new__(DTXConnection)
    connection._services = cast(Any, dict(services))
    connection._service_condition = asyncio.Condition()
    connection._closed = False
    return connection


def _proxy(local: DTXService, remote: DTXService) -> DTXProxyService:
    proxy = object.__new__(DTXProxyService)
    proxy._local_service = local
    proxy._remote_service = remote
    return proxy


async def test_wait_for_service_returns_a_service_which_is_already_there() -> None:
    other, wanted = object.__new__(DTXService), object.__new__(_Wanted)
    connection = _connection({1: other, 2: wanted})

    assert await connection.wait_for_service(_Wanted, timeout=1) is wanted
    assert await connection.wait_for_service(lambda svc: svc is other, timeout=1) is other


async def test_wait_for_service_waits_for_the_service_to_be_opened() -> None:
    connection = _connection({})
    waiter = asyncio.create_task(connection.wait_for_service(_Wanted, timeout=1))
    await asyncio.sleep(0)
    assert not waiter.done()

    wanted = object.__new__(_Wanted)
    connection._services[1] = wanted
    async with connection._service_condition:
        connection._service_condition.notify_all()

    assert await waiter is wanted


@pytest.mark.parametrize("remote", [True, False])
async def test_wait_for_proxied_service_returns_the_side_asked_for(remote: bool) -> None:
    local, far = object.__new__(_Wanted), object.__new__(_Wanted)
    # a proxy with nothing assigned after the match is never read
    connection = _connection({
        1: object.__new__(DTXService),
        2: _proxy(local, far),
        3: _proxy(cast(Any, None), cast(Any, None)),
    })

    found = await connection.wait_for_proxied_service(_Wanted, remote=remote, timeout=1)

    assert found is (far if remote else local)


async def test_waiting_ends_when_the_connection_closes() -> None:
    connection = _connection({})
    connection._closed = True

    with pytest.raises(ConnectionTerminatedError, match="expected service"):
        await connection.wait_for_service(_Wanted, timeout=1)
    with pytest.raises(ConnectionTerminatedError, match="expected proxied service"):
        await connection.wait_for_proxied_service(_Wanted, remote=True, timeout=1)


async def test_waiting_times_out() -> None:
    with pytest.raises(asyncio.TimeoutError):
        await _connection({}).wait_for_service(_Wanted, timeout=0.01)
