import os
import struct
from pathlib import Path
from typing import Any

import pytest
from bytestruct import TruncatedDataError
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from pymobiledevice3.services import mobilebackup2
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service


def _decrypt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, manifest_key: bytes, class_keys: dict[int, bytes]
) -> bytes:
    (tmp_path / "Manifest.plist").write_bytes(b"plist")
    (tmp_path / "Manifest.db").write_bytes(b"encrypted db")

    class Manifest:
        pass

    class FakeKeybag:
        def decrypt(self, data: bytes, key: bytes) -> bytes:
            return b"decrypted db"

        def get_key(self, protection_class: int) -> bytes:
            return class_keys[protection_class]

    manifest: Any = Manifest()
    manifest.manifest_key = manifest_key
    monkeypatch.setattr(mobilebackup2.ManifestPlist, "from_path", lambda path: manifest)
    monkeypatch.setattr(mobilebackup2.Keybag, "from_manifest", lambda manifest, password: FakeKeybag())
    return Mobilebackup2Service._decrypt_backup_manifest_db(tmp_path, "password", tmp_path / "out.db")


def test_manifest_key_is_a_protection_class_and_a_wrapped_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class_key = os.urandom(32)
    key = os.urandom(32)
    manifest_key = struct.pack("<I", 4) + aes_key_wrap(class_key, key)
    assert _decrypt(tmp_path, monkeypatch, manifest_key, {4: class_key}) == key
    assert (tmp_path / "out.db").read_bytes() == b"decrypted db"


def test_short_manifest_key_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(TruncatedDataError):
        _decrypt(tmp_path, monkeypatch, b"\x04\x00", {})
