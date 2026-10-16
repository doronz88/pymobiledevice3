from typing import cast

import pytest

from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap


@pytest.mark.parametrize("interval_ms", [Sysmontap.DEFAULT_INTERVAL_MS, 1000, 50])
def test_output_rate_follows_sampling_interval(interval_ms: int) -> None:
    tap = Sysmontap(cast(DtxServiceProvider, None), ["pid"], ["vmFreeCount"], interval_ms=interval_ms)

    assert tap._config["ur"] == interval_ms
    assert tap._config["sampleInterval"] == interval_ms * 1_000_000


def test_output_rate_defaults_to_default_interval() -> None:
    tap = Sysmontap(cast(DtxServiceProvider, None), ["pid"], ["vmFreeCount"])

    assert tap._config["ur"] == Sysmontap.DEFAULT_INTERVAL_MS
