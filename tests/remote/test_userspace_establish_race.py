import asyncio
import contextlib
from types import SimpleNamespace
from typing import Any

import pytest
from bytestruct import TruncatedDataError

import pymobiledevice3.remote.userspace_tunnel as ut
from pymobiledevice3.exceptions import PyMobileDevice3Exception


def _setup(monkeypatch: pytest.MonkeyPatch, error: Exception) -> Any:
    winner_rsd = SimpleNamespace(udid="UDID")
    winner = SimpleNamespace(serial="UDID", rsd=winner_rsd)

    async def aopen(self: ut.UserspaceRsdTunnel) -> Any:
        raise error

    monkeypatch.setattr(ut.UserspaceRsdTunnel, "aopen", aopen)
    monkeypatch.setattr(ut, "_cli_tunnel", None)
    monkeypatch.setattr(ut, "_active_tunnel", winner)
    return winner_rsd


@pytest.mark.asyncio
async def test_losing_the_establishment_race_shares_the_winner(monkeypatch: pytest.MonkeyPatch) -> None:
    winner_rsd = _setup(monkeypatch, PyMobileDevice3Exception("a userspace tunnel is already active"))
    assert await ut.establish_userspace_rsd("UDID") is winner_rsd


@pytest.mark.asyncio
async def test_a_malformed_reply_is_not_mistaken_for_a_lost_race(monkeypatch: pytest.MonkeyPatch) -> None:
    _setup(monkeypatch, TruncatedDataError("short reply"))
    with pytest.raises(TruncatedDataError):
        await ut.establish_userspace_rsd("UDID")


def test_ctrl_c_during_exit_teardown_abandons_it_quietly(monkeypatch: pytest.MonkeyPatch) -> None:
    # The CLI's tunnel is closed by an atexit hook; Ctrl-C pressed while that teardown runs
    # (the first Ctrl-C already ended the command) must abandon it instead of printing an
    # "Exception ignored in atexit callback" KeyboardInterrupt traceback.
    class InterruptedTunnel:
        rsd = object()

        async def aclose(self) -> None:
            raise KeyboardInterrupt

    # On a private loop: on Python <= 3.11 the interrupted wait_for stays pending on the loop it ran
    # on, and would re-raise the KeyboardInterrupt in whatever runs on the shared CLI loop next.
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(ut, "get_asyncio_loop", lambda: loop)
    monkeypatch.setattr(ut, "_cli_tunnel", InterruptedTunnel())
    try:
        ut._close_cli_tunnel_at_exit()  # must not raise
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        with contextlib.suppress(BaseException):
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()
