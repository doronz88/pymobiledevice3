import datetime
import json
import logging
import uuid

import ansilogs
import pytest

from pymobiledevice3.cli import cli_common
from pymobiledevice3.cli.cli_common import default_json_encoder, print_json, set_color_flag

pytestmark = [pytest.mark.cli]


def _roundtrip(obj) -> object:
    return json.loads(json.dumps(obj, default=default_json_encoder))


def test_json_encoder_bytes_as_tagged_hex():
    assert _roundtrip(b"\xa1\xb2\xc3") == {"$hex": "a1b2c3"}


def test_json_encoder_empty_bytes():
    assert _roundtrip(b"") == {"$hex": ""}


def test_json_encoder_nested_bytes():
    assert _roundtrip({"nonce": b"\x00\xff", "name": "ok"}) == {"nonce": {"$hex": "00ff"}, "name": "ok"}


def test_json_encoder_datetime_iso8601():
    aware = datetime.datetime(2024, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    assert _roundtrip(aware) == "2024-01-02T03:04:05+00:00"
    naive = datetime.datetime(2024, 1, 2, 3, 4, 5, 123456)
    assert _roundtrip(naive) == "2024-01-02T03:04:05.123456"


def test_json_encoder_uuid():
    value = uuid.UUID("12345678-1234-5678-1234-567812345678")
    assert _roundtrip(value) == "12345678-1234-5678-1234-567812345678"


@pytest.fixture
def colored_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(cli_common, "COLORED_OUTPUT", True)
    monkeypatch.setattr(cli_common, "isatty", lambda: True)


@pytest.mark.parametrize("colored", [False, True])
def test_print_json_keeps_non_ascii_text(colored_tty, capsys: pytest.CaptureFixture[str], colored: bool):
    print_json({"DeviceName": "John\u2019s iPhone"}, colored=colored)
    out = capsys.readouterr().out
    assert "\u2019" in out
    assert "\\u2019" not in out


@pytest.mark.parametrize("colored", [False, True])
def test_print_json_ends_with_a_single_newline(colored_tty, capsys: pytest.CaptureFixture[str], colored: bool):
    print_json({"a": 1}, colored=colored)
    out = capsys.readouterr().out
    assert out.endswith("\n")
    assert not out.endswith("\n\n")
    assert ("\x1b[" in out) == colored


def test_no_color_env_disables_colored_output(colored_tty, monkeypatch: pytest.MonkeyPatch):
    assert cli_common.user_requested_colored_output()
    monkeypatch.setenv("NO_COLOR", "1")
    assert not cli_common.user_requested_colored_output()


def test_no_color_flag_turns_off_log_colors(monkeypatch: pytest.MonkeyPatch):
    handler = ansilogs.StderrHandler()
    handler.setFormatter(ansilogs.ColoredFormatter(colors=True))
    monkeypatch.setattr(logging.getLogger(), "handlers", [handler])
    monkeypatch.setattr(cli_common, "COLORED_OUTPUT", True)
    set_color_flag(False)
    formatter = handler.formatter
    assert isinstance(formatter, ansilogs.ColoredFormatter)
    assert not formatter.colors
