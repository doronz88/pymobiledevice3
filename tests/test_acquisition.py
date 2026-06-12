import hashlib

from pymobiledevice3.acquisition import (
    DIRECTORY_DIGEST_ALGORITHM,
    build_acquisition_manifest,
    build_device_context,
    classify_artifact,
)


def test_build_acquisition_manifest_summarizes_files_and_directories(tmp_path) -> None:
    file_path = tmp_path / "note.txt"
    file_path.write_bytes(b"hello")
    directory = tmp_path / "collection"
    directory.mkdir()
    nested = directory / "nested"
    nested.mkdir()
    (nested / "data.bin").write_bytes(b"abc")

    manifest = build_acquisition_manifest([file_path, directory])

    assert manifest["schema_version"] == 1
    assert "generated_at" in manifest
    assert manifest["artifacts"][0] == {
        "kind": "file",
        "modified_at": manifest["artifacts"][0]["modified_at"],
        "name": "note.txt",
        "path": str(file_path),
        "sha256": hashlib.sha256(b"hello").hexdigest(),
        "size": 5,
        "type": "file",
    }
    assert manifest["artifacts"][1] == {
        "digest_algorithm": DIRECTORY_DIGEST_ALGORITHM,
        "directory_count": 1,
        "file_count": 1,
        "kind": "directory",
        "modified_at": manifest["artifacts"][1]["modified_at"],
        "name": "collection",
        "path": str(directory),
        "sha256": manifest["artifacts"][1]["sha256"],
        "total_size": 3,
        "type": "directory",
    }


def test_build_acquisition_manifest_can_skip_hashes(tmp_path) -> None:
    file_path = tmp_path / "note.txt"
    file_path.write_bytes(b"hello")
    directory = tmp_path / "collection"
    directory.mkdir()
    (directory / "data.bin").write_bytes(b"abc")

    manifest = build_acquisition_manifest([file_path, directory], hash_files=False)

    assert "sha256" not in manifest["artifacts"][0]
    assert "sha256" not in manifest["artifacts"][1]
    assert "digest_algorithm" not in manifest["artifacts"][1]


def test_classify_artifact_detects_common_acquisition_artifacts(tmp_path) -> None:
    backup = tmp_path / "backup"
    backup.mkdir()
    for marker in ("Info.plist", "Manifest.plist", "Status.plist"):
        (backup / marker).write_bytes(b"")
    backup_root = tmp_path / "backup-root"
    backup_root.mkdir()
    nested_backup = backup_root / "device-udid"
    nested_backup.mkdir()
    for marker in ("Info.plist", "Manifest.plist", "Status.plist"):
        (nested_backup / marker).write_bytes(b"")
    crash = tmp_path / "panic-full.ips"
    crash.write_text("{}")
    sysdiagnose = tmp_path / "sysdiagnose_2026.tar.gz"
    sysdiagnose.write_bytes(b"archive")

    assert classify_artifact(backup) == "itunes_backup"
    assert classify_artifact(backup_root) == "itunes_backup_root"
    assert classify_artifact(crash) == "crash_report"
    assert classify_artifact(sysdiagnose) == "sysdiagnose_archive"


def test_build_device_context_redacts_identifiers_by_default() -> None:
    values = {
        "BuildVersion": "23A000",
        "DeviceClass": "iPhone",
        "DeviceName": "Example iPhone",
        "ProductType": "iPhone99,9",
        "ProductVersion": "26.0",
        "SerialNumber": "SERIAL",
        "UniqueChipID": 123,
        "UniqueDeviceID": "UDID",
    }

    assert build_device_context(values) == {
        "build_version": "23A000",
        "device_class": "iPhone",
        "product_type": "iPhone99,9",
        "product_version": "26.0",
    }
    assert build_device_context(values, include_identifiers=True) == {
        "build_version": "23A000",
        "device_class": "iPhone",
        "device_name": "Example iPhone",
        "product_type": "iPhone99,9",
        "product_version": "26.0",
        "serial_number": "SERIAL",
        "unique_chip_id": 123,
        "unique_device_id": "UDID",
    }
