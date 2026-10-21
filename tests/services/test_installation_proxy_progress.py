import logging
from typing import Any
from unittest.mock import AsyncMock

import pytest

from pymobiledevice3.services.installation_proxy import InstallationProxyService


def _service(replies: list[dict[str, Any]]) -> InstallationProxyService:
    service = InstallationProxyService.__new__(InstallationProxyService)
    service.logger = logging.getLogger(__name__)
    connection = AsyncMock()
    connection.recv_plist.side_effect = replies
    service._service = connection
    return service


_PROGRESS = [{"PercentComplete": 50}, {"Status": "Complete"}]


@pytest.mark.parametrize(
    "operation",
    [
        lambda service, handler: service.restore("com.example", None, handler, "a", "b"),
        lambda service, handler: service.uninstall("com.example", None, handler, "a", "b"),
        lambda service, handler: service.send_package("Install", {}, handler, "/x.ipa", "a", "b"),
    ],
)
async def test_progress_handler_gets_the_extra_args_unpacked(operation: Any) -> None:
    calls: list[tuple[Any, ...]] = []
    await operation(_service(list(_PROGRESS)), lambda *args: calls.append(args))
    assert calls == [(50, "a", "b")]
