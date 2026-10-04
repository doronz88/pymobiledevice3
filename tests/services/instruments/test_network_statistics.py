import datetime
from types import SimpleNamespace
from typing import Any, cast

from pymobiledevice3.dtx.ns_types import NSDate
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.network_statistics import NetworkStatistics


class _FakeProvider:
    dtx = SimpleNamespace(register_service=lambda service_class: None)

    async def connect(self) -> None:
        pass


class _FakeNetworkStatisticsService:
    def __init__(self, replies: list[Any]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, list[int]]] = []

    async def start_sampling_for_pids_(self, pid_list: list[int]) -> list[int]:
        self.calls.append(("start", pid_list))
        return pid_list

    async def stop_sampling_for_pids_(self, pid_list: list[int]) -> list[int]:
        self.calls.append(("stop", pid_list))
        return pid_list

    async def sample_attributes_for_pids_(self, attributes: dict[str, Any], pid_list: list[int]) -> Any:
        self.calls.append(("sample", pid_list))
        return self.replies.pop(0)


def _network_statistics(replies: list[Any]) -> tuple[NetworkStatistics, _FakeNetworkStatisticsService]:
    service = _FakeNetworkStatisticsService(replies)
    network_statistics = NetworkStatistics(cast(DtxServiceProvider, _FakeProvider()), [42], interval_ms=0)
    network_statistics._service = cast(Any, service)
    return network_statistics, service


async def _first_sample(network_statistics: NetworkStatistics) -> dict[int, dict[str, Any]]:
    async for sample in network_statistics:
        return sample
    raise AssertionError("the sampler stopped without yielding")


async def test_network_statistics_discards_stale_and_empty_samples() -> None:
    stale = {7: {"pid": 7, "net.bytes": 1}}
    fresh = {42: {"pid": 42, "net.bytes": 2, "time": NSDate(0.0)}}
    network_statistics, service = _network_statistics([stale, None, fresh])

    async with network_statistics:
        sample = await _first_sample(network_statistics)

    assert sample == {
        42: {"pid": 42, "net.bytes": 2, "time": datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)}
    }
    assert service.calls == [("start", [42]), ("sample", [42]), ("sample", [42]), ("sample", [42]), ("stop", [42])]


async def test_network_statistics(dvt) -> None:
    async with DeviceInfo(dvt) as device_info:
        pid = next(process["pid"] for process in await device_info.proclist() if process["name"] == "SpringBoard")

    async with NetworkStatistics(dvt, [pid], interval_ms=100) as network_statistics:
        sample = await _first_sample(network_statistics)

    record = sample[pid]
    assert record["pid"] == pid
    assert isinstance(record["time"], datetime.datetime)
    for key in ("net.bytes", "net.packets", "net.rx.bytes", "net.tx.bytes", "net.bytes.delta"):
        assert isinstance(record[key], int)
