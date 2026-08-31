import pytest
import typer

from pymobiledevice3.cli.cli_common import _parse_tunnel_spec
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, TunneldAddress

UDID = "00008120-0000000000000000"


@pytest.mark.parametrize(
    "spec,expected_udid,expected_address",
    [
        (UDID, UDID, TUNNELD_DEFAULT_ADDRESS),
        ("", "", TUNNELD_DEFAULT_ADDRESS),
        (f"{UDID}:50000", UDID, ("127.0.0.1", 50000)),
        (":50000", "", ("127.0.0.1", 50000)),
    ],
)
def test_parse_tunnel_spec(spec: str, expected_udid: str, expected_address: TunneldAddress) -> None:
    assert _parse_tunnel_spec(spec) == (expected_udid, expected_address)


@pytest.mark.parametrize("spec", [f"{UDID}:/var/run/tunneld.sock", ":/tmp/tunneld.sock"])
def test_parse_tunnel_spec_rejects_uds_path(spec: str) -> None:
    with pytest.raises(typer.BadParameter, match="unix-socket tunneld support was removed"):
        _parse_tunnel_spec(spec)
