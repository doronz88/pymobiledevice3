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
