import dataclasses

from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.tap import Tap


class Sysmontap(Tap):
    CHANNEL_IDENTIFIER = "com.apple.instruments.server.services.sysmontap"
    DEFAULT_INTERVAL_MS = 500
    MINIMUM_INTERVAL_MS = 1

    def __init__(
        self,
        dvt: DvtProvider,
        process_attributes: list[str],
        system_attributes: list[str],
        interval_ms: int = DEFAULT_INTERVAL_MS,
    ) -> None:
        super().__init__(dvt)

        self.process_attributes_cls = dataclasses.make_dataclass("SysmonProcessAttributes", process_attributes)
        self.system_attributes_cls = dataclasses.make_dataclass("SysmonSystemAttributes", system_attributes)

        self.__config__ = {
            "ur": Sysmontap.MINIMUM_INTERVAL_MS,  # Output frequency ms
            "bm": 0,
            "procAttrs": process_attributes,
            "sysAttrs": system_attributes,
            "cpuUsage": True,
            "physFootprint": True,  # memory value
            "sampleInterval": interval_ms * 1_000_000,
        }

    @classmethod
    async def create(cls, dvt: DvtProvider, interval: int = DEFAULT_INTERVAL_MS) -> "Sysmontap":
        async with DeviceInfo(dvt) as device_info:
            process_attributes = list(await device_info.sysmon_process_attributes())
            system_attributes = list(await device_info.sysmon_system_attributes())
        return cls(dvt, process_attributes, system_attributes, interval_ms=interval)

    async def config(self) -> dict:
        return self.__config__

    async def iter_processes(self):
        async for row in self:
            if isinstance(row, dict):
                row = [row]
            for event in row:
                if not isinstance(event, dict) or "Processes" not in event:
                    continue
                yield [
                    dataclasses.asdict(self.process_attributes_cls(*process_info))
                    for process_info in event["Processes"].values()
                ]
