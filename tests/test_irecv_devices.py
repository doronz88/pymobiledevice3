from collections import Counter

from pymobiledevice3.irecv_devices import IRECV_DEVICES


def _by_product_type(product_type: str):
    return [d for d in IRECV_DEVICES if d.product_type == product_type]


def test_product_type_and_hardware_model_pairs_are_unique():
    """A product type may map to several boards (n71ap/n71map), but never to the same board twice."""
    pairs = Counter((d.product_type, d.hardware_model) for d in IRECV_DEVICES)
    assert [pair for pair, count in pairs.items() if count > 1] == []


def test_hardware_models_are_unique():
    models = Counter(d.hardware_model for d in IRECV_DEVICES)
    assert [model for model, count in models.items() if count > 1] == []


def test_watch_series_8_and_ultra_rows_match_libirecovery():
    """Regression: the Ultra row was filed under Watch6,17 (the Series 8 45mm Cellular product type)."""
    (series_8,) = _by_product_type("Watch6,17")
    (ultra,) = _by_product_type("Watch6,18")
    assert (series_8.hardware_model, series_8.board_id) == ("n198bap", 0x36)
    assert (ultra.hardware_model, ultra.board_id) == ("n199ap", 0x26)


def test_watch_se_2_board_id_matches_libirecovery():
    (se2_40mm,) = _by_product_type("Watch6,10")
    assert (se2_40mm.hardware_model, se2_40mm.board_id, se2_40mm.chip_id) == ("n143sap", 0x28, 0x8301)


def test_recent_models_are_present():
    expected = {
        "Mac17,2": ("j704ap", 0x22, 0x8142),
        "Mac17,5": ("j700ap", 0x64, 0x8140),
        "iPad13,18": ("j271ap", 0x14, 0x8101),
        "AppleTV14,1": ("j255ap", 0x02, 0x8110),
        "iAccy1,1": ("b137ap", 0x00, 0x8747),
    }
    for product_type, (hardware_model, board_id, chip_id) in expected.items():
        (device,) = _by_product_type(product_type)
        assert (device.hardware_model, device.board_id, device.chip_id) == (hardware_model, board_id, chip_id)
