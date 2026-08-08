import datetime
import json
import uuid

import pytest

from pymobiledevice3.cli.cli_common import default_json_encoder

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
