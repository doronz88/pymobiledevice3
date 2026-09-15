from pymobiledevice3.restore.restore import GLOBAL_MANIFEST_DEFAULT_PREFIX, global_manifest_path


def test_default_global_manifest_path():
    assert GLOBAL_MANIFEST_DEFAULT_PREFIX == "apticket"
    assert (
        global_manifest_path("macOS Customer", "j413ap")
        == "Firmware/Manifests/restore/macOS Customer/apticket.j413ap.im4m"
    )


def test_global_manifest_path_honours_restored_prefix_and_suffix():
    """macOS 27 restored asks for e.g. GlobalManifestPrefix/Suffix instead of the hardcoded apticket name."""
    assert (
        global_manifest_path("macOS Customer", "j413ap", prefix="localpolicy", suffix=".recovery")
        == "Firmware/Manifests/restore/macOS Customer/localpolicy.j413ap.recovery.im4m"
    )
