"""Integration tests for all :meth:`DTXConnection.open_channel` call signatures.

Tests are split by service provider:

- **DVT / Instruments** (``DvtProvider``) — used for plain channels.
- **testmanagerd** (``_TestManagerProvider``) — used for ``dtxproxy:`` channels.

Covered combinations
--------------------

Plain channels (DVT):
  1. ``open_channel(identifier: str)``                 → ``DTXDynamicService``
  2. ``open_channel(cls: type[DTXService])``            → custom ``DTXService``
  3. ``open_channel(identifier: str, cls)``             → custom ``DTXService`` by explicit id
  4. ``open_channel(identifier: str)`` after
     ``register_service(cls)``                         → custom ``DTXService`` via registry

Proxy channels (testmanagerd):
  5. ``open_channel(identifier: str)`` for a dtxproxy  → ``DTXProxyService``
     with ``DTXDynamicService`` sub-services
  6. ``open_channel(identifier: str, cls)`` for a
     dtxproxy where ``cls`` is a ``DTXProxyService``
     subclass                                          → ``DTXProxyService``
     with typed sub-services

Run with::

    pytest tests/services/instruments/test_dtx_open_channel.py -s --tunnel '' -v
"""

from __future__ import annotations

import pytest

from pymobiledevice3.dtx import (
    DTXDynamicService,
    DTXService,
    dtx_method,
)
from pymobiledevice3.dtx.service import DTXProxyService as _DTXProxyService
from pymobiledevice3.exceptions import InvalidServiceError
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.testmanaged.dtx_services import (
    XCTestManager_DaemonConnectionInterface,
    XCTestManager_IDEInterface,
)
from pymobiledevice3.services.dvt.testmanaged.xcuitest import _TestManagerProvider

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEVICEINFO_ID = "com.apple.instruments.server.services.deviceinfo"
_PROXY_ID = "dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface"

# ---------------------------------------------------------------------------
# Local minimal DTXService subclass for DVT tests
# ---------------------------------------------------------------------------


class _MinimalDeviceInfoService(DTXService):
    """Minimal typed stub for the deviceinfo service — just runningProcesses."""

    IDENTIFIER = _DEVICEINFO_ID

    @dtx_method("runningProcesses")
    async def running_processes(self) -> list: ...


# ---------------------------------------------------------------------------
# Proxy DTXService subclass used for proxy tests
# ---------------------------------------------------------------------------


class _TestManagerProxyService(_DTXProxyService):
    """Typed DTXProxyService stub pre-wired with the IDE/Daemon sub-services."""

    IDENTIFIER = _PROXY_ID

    # Sub-services are assigned by DTXProxyService at open_channel time.
    local_service: XCTestManager_IDEInterface
    remote_service: XCTestManager_DaemonConnectionInterface


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def skip_if_no_dvt(service_provider):
    """Skip the test if the DVT service is not accessible on this device."""
    # Accessing the DVT provider inside the test handles the skip;
    # this fixture is just documentation of the dependency.


@pytest.fixture
def skip_if_no_testmanagerd(service_provider):
    """Skip the test if testmanagerd is not accessible on this device."""


# ---------------------------------------------------------------------------
# DVT / Instruments — plain channels
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_open_channel_by_string_returns_dynamic_service(service_provider) -> None:
    """open_channel(identifier: str) → DTXDynamicService (fallback)."""
    try:
        async with DvtProvider(service_provider) as provider:
            svc = await provider.dtx.open_channel(_DEVICEINFO_ID)
    except InvalidServiceError:
        pytest.skip("DVT service not accessible")

    assert isinstance(svc, DTXDynamicService), f"Expected DTXDynamicService, got {type(svc).__name__}"


@pytest.mark.asyncio
async def test_open_channel_by_string_after_register_returns_typed_service(service_provider) -> None:
    """open_channel(identifier: str) after register_service(cls) → custom DTXService."""
    try:
        async with DvtProvider(service_provider) as provider:
            provider.dtx.register_service(_MinimalDeviceInfoService)
            svc = await provider.dtx.open_channel(_DEVICEINFO_ID)
    except InvalidServiceError:
        pytest.skip("DVT service not accessible")

    assert isinstance(svc, _MinimalDeviceInfoService), f"Expected _MinimalDeviceInfoService, got {type(svc).__name__}"


@pytest.mark.asyncio
async def test_open_channel_by_class_returns_typed_service(service_provider) -> None:
    """open_channel(cls: type[DTXService]) → custom DTXService, identifier from cls.IDENTIFIER."""
    try:
        async with DvtProvider(service_provider) as provider:
            svc = await provider.dtx.open_channel(_MinimalDeviceInfoService)

            assert isinstance(svc, _MinimalDeviceInfoService), (
                f"Expected _MinimalDeviceInfoService, got {type(svc).__name__}"
            )
            # Sanity: the service must be callable and return a list.
            procs = await svc.running_processes()
            assert isinstance(procs, list) and len(procs) > 0, "runningProcesses should return a non-empty list"
    except InvalidServiceError:
        pytest.skip("DVT service not accessible")


@pytest.mark.asyncio
async def test_open_channel_by_string_and_class_returns_typed_service(service_provider) -> None:
    """open_channel(identifier: str, cls) → custom DTXService with explicit identifier."""

    class IgnoredService(DTXService):
        IDENTIFIER = _DEVICEINFO_ID

    try:
        async with DvtProvider(service_provider) as provider:
            provider.dtx.register_service(IgnoredService)  # Should be ignored since cls is passed explicitly.
            svc = await provider.dtx.open_channel(_DEVICEINFO_ID, _MinimalDeviceInfoService)

            assert isinstance(svc, _MinimalDeviceInfoService), (
                f"Expected _MinimalDeviceInfoService, got {type(svc).__name__}"
            )
            procs = await svc.running_processes()
            assert isinstance(procs, list) and len(procs) > 0, "runningProcesses should return a non-empty list"
    except InvalidServiceError:
        pytest.skip("DVT service not accessible")


@pytest.mark.asyncio
async def test_open_channel_two_classes_raises(service_provider) -> None:
    """open_channel(cls, cls) → ValueError (two types not allowed)."""
    try:
        async with DvtProvider(service_provider) as provider:
            with pytest.raises(ValueError, match="Cannot specify two types"):
                await provider.dtx.open_channel(_MinimalDeviceInfoService, _MinimalDeviceInfoService)
    except InvalidServiceError:
        pytest.skip("DVT service not accessible")


# ---------------------------------------------------------------------------
# testmanagerd — dtxproxy: channels
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_open_proxy_channel_by_string_returns_proxy_service(service_provider) -> None:
    """open_channel(proxy_identifier: str) → DTXProxyService with DTXDynamicService sub-services."""
    try:
        async with _TestManagerProvider(service_provider) as provider:
            svc = await provider.dtx.open_channel(_PROXY_ID)
    except InvalidServiceError:
        pytest.skip("testmanagerd not accessible")

    assert isinstance(svc, _DTXProxyService), f"Expected DTXProxyService, got {type(svc).__name__}"
    # Without registered sub-services the proxy falls back to DTXDynamicService sub-services.
    assert isinstance(svc.local_service, DTXDynamicService), (
        f"Expected local_service to be a DTXDynamicService, got {type(svc.local_service).__name__}"
    )
    assert isinstance(svc.remote_service, DTXDynamicService), (
        f"Expected remote_service to be a DTXDynamicService, got {type(svc.remote_service).__name__}"
    )


@pytest.mark.asyncio
async def test_open_proxy_channel_after_register_returns_typed_sub_services(service_provider) -> None:
    """open_channel(proxy_identifier: str) after register_service for both sides → typed sub-services."""
    try:
        async with _TestManagerProvider(service_provider) as provider:
            provider.dtx.register_service(XCTestManager_IDEInterface)
            provider.dtx.register_service(XCTestManager_DaemonConnectionInterface)
            svc = await provider.dtx.open_channel(_PROXY_ID)
    except InvalidServiceError:
        pytest.skip("testmanagerd not accessible")

    assert isinstance(svc, _DTXProxyService)
    assert isinstance(svc.local_service, XCTestManager_IDEInterface), (
        f"Expected XCTestManager_IDEInterface, got {type(svc.local_service).__name__}"
    )
    assert isinstance(svc.remote_service, XCTestManager_DaemonConnectionInterface), (
        f"Expected XCTestManager_DaemonConnectionInterface, got {type(svc.remote_service).__name__}"
    )


@pytest.mark.asyncio
async def test_open_proxy_channel_by_typed_class_returns_proxy_service(service_provider) -> None:
    """open_channel(identifier: str, cls) where cls is a DTXProxyService subclass → typed proxy.

    Note: passing an explicit class to open_channel bypasses the sub-service
    assembly that happens via the registry (``_instantiate_service``).  The
    returned instance is of the correct type but ``local_service`` /
    ``remote_service`` are not wired — use ``register_service`` + plain
    ``open_channel(identifier)`` when you need typed sub-services (covered by
    ``test_open_proxy_channel_after_register_returns_typed_sub_services``).
    """

    class IgnoredProxyService(_DTXProxyService):
        IDENTIFIER = _PROXY_ID

    try:
        async with _TestManagerProvider(service_provider) as provider:
            provider.dtx.register_service(IgnoredProxyService)  # Should be ignored since cls is passed explicitly.
            svc = await provider.dtx.open_channel(_PROXY_ID, _TestManagerProxyService)

            assert isinstance(svc, _TestManagerProxyService), (
                f"Expected _TestManagerProxyService, got {type(svc).__name__}"
            )
    except InvalidServiceError:
        pytest.skip("testmanagerd not accessible")
