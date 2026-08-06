from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import CryptexdError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.cryptexd import (
    NONCE_DOMAIN_CRYPTEX,
    CryptexdService,
    InstalledCryptex,
    unwrap_nonce,
)


class FakeConnection:
    """Records requests and replays a canned response; tracks its own open/close lifecycle."""

    def __init__(self, response: dict[str, Any], sent: list[dict[str, Any]]) -> None:
        self._response = response
        self._sent = sent
        self.connected = False
        self.closed = False

    async def connect(self) -> None:
        self.connected = True

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        assert self.connected and not self.closed, "request sent outside an open connection"
        self._sent.append(request)
        return self._response

    async def close(self) -> None:
        self.closed = True


class FakeRsd:
    def __init__(self, response: dict[str, Any], sent: list[dict[str, Any]]) -> None:
        self._response = response
        self._sent = sent
        self.connections: list[FakeConnection] = []

    def start_remote_service(self, name: str) -> Any:
        assert name == CryptexdService.SERVICE_NAME
        connection = FakeConnection(self._response, self._sent)
        self.connections.append(connection)
        return connection


def _service(response: dict[str, Any]) -> tuple[CryptexdService, list[dict[str, Any]]]:
    sent: list[dict[str, Any]] = []
    service = CryptexdService(cast(RemoteServiceDiscoveryService, FakeRsd(response, sent)))
    return service, sent


def test_service_name() -> None:
    assert CryptexdService.SERVICE_NAME == "com.apple.security.cryptexd.remote"


@pytest.mark.asyncio
async def test_invoke_wraps_routine_and_argv() -> None:
    service, sent = _service({"error": 0, "argv": {"ok": True}})

    result = await service.invoke("some-routine", {"a": 1})

    assert sent == [{"routine": "some-routine", "argv": {"a": 1}}]
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_invoke_raises_on_cferr() -> None:
    service, _ = _service({
        "cferr": {
            "cferr_code": 10,
            "cferr_domain": "com.apple.security.cryptex",
            "cferr_userinfo": {"NSLocalizedDescription": "nonce domain doesn't exist for index: 0"},
        }
    })

    with pytest.raises(CryptexdError, match="nonce domain doesn't exist"):
        await service.invoke("get-nonce", {})


@pytest.mark.asyncio
async def test_invoke_raises_on_nonzero_error() -> None:
    service, _ = _service({"error": 2})

    with pytest.raises(CryptexdError, match=r"ENOENT \(2\)"):
        await service.invoke("copy-installed", {})


@pytest.mark.asyncio
async def test_get_nonce_accepts_a_domain_handle() -> None:
    service, sent = _service({"error": 0, "argv": {"nonce": b"\x01"}})

    await service.get_nonce(nonce_domain_handle=7)

    assert sent[0]["argv"] == {"nonce-domain-handle": 7}
    assert "nonce-domain" not in sent[0]["argv"]


@pytest.mark.asyncio
async def test_nonce_selectors_are_mutually_exclusive() -> None:
    service, _ = _service({"error": 0, "argv": {"nonce": b""}})

    with pytest.raises(ValueError):
        await service.get_nonce(nonce_domain=2, nonce_domain_handle=7)
    with pytest.raises(ValueError):
        await service.roll_nonce(nonce_domain=2, nonce_domain_handle=7)


@pytest.mark.asyncio
async def test_roll_nonce_sends_roll_routine() -> None:
    service, sent = _service({"error": 0, "argv": {}})

    await service.roll_nonce()

    assert sent[0]["routine"] == "roll-nonce"
    assert int(sent[0]["argv"]["nonce-domain"]) == NONCE_DOMAIN_CRYPTEX


@pytest.mark.asyncio
async def test_uninstall_sends_identifier_only_by_default() -> None:
    service, sent = _service({"error": 0, "argv": {}})

    await service.uninstall("com.apple.MobileAsset.DDI")

    assert sent[0]["routine"] == "uninstall"
    assert sent[0]["argv"] == {"remote-cryptex-identifier": "com.apple.MobileAsset.DDI"}


@pytest.mark.asyncio
async def test_uninstall_includes_version_when_given() -> None:
    service, sent = _service({"error": 0, "argv": {}})

    await service.uninstall("com.apple.MobileAsset.DDI", "27.1.5228.8")

    assert sent[0]["argv"]["remote-cryptex-version"] == "27.1.5228.8"


@pytest.mark.asyncio
async def test_uninstall_of_unknown_cryptex_raises_enoent() -> None:
    # Verified against the device: a bogus identifier passes validation and fails with ENOENT.
    service, _ = _service({"error": 2})

    with pytest.raises(CryptexdError, match=r"ENOENT \(2\)"):
        await service.uninstall("com.example.not-installed")


@pytest.mark.asyncio
async def test_read_personalization_identifiers_tolerates_missing_error_key() -> None:
    # read-personalization-id replies omit "error" entirely on success.
    chip = {"img4_chip_chip": 32816, "img4_chip_bord": 4}
    service, sent = _service({"argv": chip})

    assert await service.read_personalization_identifiers() == chip
    assert sent[0]["routine"] == "read-personalization-id"


@pytest.mark.asyncio
async def test_copy_installed_parses_entries() -> None:
    service, _ = _service({
        "error": 0,
        "argv": {
            "remote-cryptex-array": [
                {"remote-cryptex-identifier": "com.apple.MobileAsset.DDI", "remote-cryptex-version": "27.1.5228.8"}
            ]
        },
    })

    assert await service.copy_installed() == [
        InstalledCryptex(identifier="com.apple.MobileAsset.DDI", version="27.1.5228.8")
    ]


@pytest.mark.asyncio
async def test_copy_installed_handles_empty() -> None:
    service, _ = _service({"error": 0, "argv": {}})

    assert await service.copy_installed() == []


@pytest.mark.asyncio
async def test_get_nonce_sends_domain_and_returns_nonce() -> None:
    service, sent = _service({"error": 0, "argv": {"nonce": b"\x01\x02"}})

    assert await service.get_nonce() == b"\x01\x02"
    assert sent[0]["routine"] == "get-nonce"
    assert int(sent[0]["argv"]["nonce-domain"]) == NONCE_DOMAIN_CRYPTEX


@pytest.mark.asyncio
async def test_each_invoke_uses_a_fresh_closed_connection() -> None:
    # cryptexd serves one routine per connection; reusing one fails with an incomplete read.
    service, sent = _service({"error": 0, "argv": {}})
    rsd = cast(FakeRsd, service.rsd)

    await service.invoke("copy-installed", {})
    await service.invoke("copy-installed", {})

    assert len(sent) == 2
    assert len(rsd.connections) == 2
    assert all(connection.closed for connection in rsd.connections)


@pytest.mark.asyncio
async def test_connection_is_closed_even_when_the_routine_fails() -> None:
    service, _ = _service({"cferr": {"cferr_code": 10, "cferr_domain": "d", "cferr_userinfo": {}}})
    rsd = cast(FakeRsd, service.rsd)

    with pytest.raises(CryptexdError):
        await service.invoke("get-nonce", {})

    assert rsd.connections[0].closed


@pytest.mark.asyncio
async def test_cryptexd_from_device(service_provider) -> None:
    """Exercise the read-only routines against a connected device."""
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("cryptexd requires an RSD tunnel")

    cryptexd = CryptexdService(service_provider)
    identifiers = await cryptexd.read_personalization_identifiers()
    # A second routine on the same instance must work, each on its own connection.
    installed = await cryptexd.copy_installed()

    assert "img4_chip_chip" in identifiers
    assert "img4_chip_ecid" in identifiers
    assert all(isinstance(cryptex, InstalledCryptex) for cryptex in installed)


class RecordingConnection:
    """Captures the install request plus every file transfer pushed on the same connection."""

    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.request: dict[str, Any] = {}
        self.transfers: list[tuple[int, bytes]] = []
        self.closed = False

    async def connect(self) -> None: ...

    async def send_request(self, request: dict[str, Any], wanting_reply: bool = False) -> None:
        self.request = request

    async def send_file_transfer(self, transfer_id: int, data: bytes) -> None:
        self.transfers.append((transfer_id, data))

    async def receive_response(self) -> dict[str, Any]:
        return self._response

    async def close(self) -> None:
        self.closed = True


def _install_service(response: dict[str, Any]) -> tuple[CryptexdService, RecordingConnection]:
    connection = RecordingConnection(response)

    class Rsd:
        def start_remote_service(self, name: str) -> Any:
            return connection

    return CryptexdService(cast(RemoteServiceDiscoveryService, Rsd())), connection


@pytest.mark.asyncio
async def test_install_announces_transfers_and_pushes_them() -> None:
    service, connection = _install_service({"error": 0})

    await service.install(b"image-bytes", b"tc", b"im4m", b"info", b"vol", {})

    argv = connection.request["argv"]
    assert connection.request["routine"] == "install"
    # Each payload is announced by size and id, then pushed under the same id.
    assert argv["image"].transfer_size == len(b"image-bytes")
    assert [argv[k].transfer_id for k in ("image", "trustcache", "im4m", "info", "volumehash")] == [1, 2, 3, 4, 5]
    assert connection.transfers == [(1, b"image-bytes"), (2, b"tc"), (3, b"im4m"), (4, b"info"), (5, b"vol")]
    assert connection.closed


@pytest.mark.asyncio
async def test_install_sends_the_scalar_keys_the_daemon_requires() -> None:
    # Verified against the device: omitting any of these fails validation with EINVAL, and
    # image-type-index must be int64 while the rest are uint64.
    service, connection = _install_service({"error": 0})

    await service.install(b"i", b"t", b"m", b"info", b"vol", {"Cryptex1,SubType": 2})

    argv = connection.request["argv"]
    assert type(argv["image-type-index"]).__name__ == "XpcInt64Type"
    for key in ("persistence", "nonce-persistence", "auth", "client-version"):
        assert type(argv[key]).__name__ == "XpcUInt64Type"
    # Captured from Xcode: the cryptex is named by the info plist, not by argv keys.
    assert "remote-cryptex-identifier" not in argv
    assert "remote-cryptex-version" not in argv
    assert argv["cryptex1-properties"] == {"Cryptex1,SubType": 2}
    assert int(argv["client-version"]) == 3
    assert int(argv["image-type-index"]) == 10
    assert (int(argv["persistence"]), int(argv["nonce-persistence"])) == (2, 1)


@pytest.mark.asyncio
async def test_install_raises_on_a_cferr_reply() -> None:
    service, _ = _install_service({
        "cferr": {
            "cferr_code": 13,
            "cferr_domain": "com.apple.security.cryptex.posix",
            "cferr_userinfo": {"NSLocalizedDescription": "initialization failed [13: Permission denied]"},
        }
    })

    with pytest.raises(CryptexdError, match="Permission denied"):
        await service.install(b"i", b"t", b"m", b"info", b"vol", {})


def test_unwrap_nonce_extracts_the_nonce_from_the_daemon_structure() -> None:
    # get-nonce returns 2-byte lead + nonce + LE uint32 length; verified against the mounter's
    # query_nonce and the cnch tag of Xcode's ticket.
    nonce = bytes(range(48))
    blob = b"\x00\x00" + nonce + b"\x00\x00" + (48).to_bytes(4, "little")
    assert unwrap_nonce(blob) == nonce
