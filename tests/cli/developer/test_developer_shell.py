from typing import Any, Optional, cast

import pytest
import typer.main

from pymobiledevice3.cli import developer
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


@pytest.mark.parametrize(
    ("args", "expected"),
    [([], None), (["-r"], True), (["--remove-ssl-context"], True), (["--keep-ssl-context"], False)],
)
def test_shell_remove_ssl_context_is_tri_state(args: list[str], expected: Optional[bool]) -> None:
    command = cast(Any, typer.main.get_command(developer.cli)).commands["shell"]
    ctx = command.make_context("shell", ["com.apple.instruments.dtservicehub", *args])
    assert ctx.params["remove_ssl_context"] is expected


def test_shell_leaves_strip_ssl_to_the_provider_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # None lets DtxServiceProvider._default_strip_ssl() pick per device; False would override it
    received: list[Optional[bool]] = []

    class _Stop(Exception):
        pass

    class _FakeDtxServiceProvider:
        def __init__(self, _service_provider: object, strip_ssl: Optional[bool] = None) -> None:
            received.append(strip_ssl)
            raise _Stop

    monkeypatch.setattr(developer, "DtxServiceProvider", _FakeDtxServiceProvider)

    with pytest.raises(_Stop):
        developer.developer_shell(cast(LockdownServiceProvider, object()), "com.apple.instruments.dtservicehub")

    assert received == [None]
