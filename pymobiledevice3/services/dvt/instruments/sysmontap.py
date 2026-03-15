import dataclasses

from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.tap import Tap


class Sysmontap(Tap):
    IDENTIFIER = "com.apple.instruments.server.services.sysmontap"
    DEFAULT_INTERVAL = 500

    def __init__(
        self, dvt, process_attributes: list[str], system_attributes: list[str], interval: int = DEFAULT_INTERVAL
    ) -> None:
        self.process_attributes_cls = dataclasses.make_dataclass("SysmonProcessAttributes", process_attributes)
        self.system_attributes_cls = dataclasses.make_dataclass("SysmonSystemAttributes", system_attributes)

        config = {
            "ur": interval,  # Output frequency ms
            "bm": 0,
            "procAttrs": process_attributes,
            "sysAttrs": system_attributes,
            "cpuUsage": True,
            "physFootprint": True,  # memory value
            "sampleInterval": interval * 1000000,
        }

        super().__init__(dvt, self.IDENTIFIER, config)

    @classmethod
    async def create(cls, dvt, interval: int = DEFAULT_INTERVAL) -> "Sysmontap":
        async with DeviceInfo(dvt) as device_info:
            process_attributes = list(await device_info.sysmon_process_attributes())
            system_attributes = list(await device_info.sysmon_system_attributes())
        return cls(dvt, process_attributes, system_attributes, interval=interval)

    async def iter_processes(self):
        async for row in self:
            if "Processes" not in row:
                continue

            entries = []

            processes = row["Processes"].items()
            for _pid, process_info in processes:
                entry = dataclasses.asdict(self.process_attributes_cls(*process_info))
                entries.append(entry)

            yield entries
