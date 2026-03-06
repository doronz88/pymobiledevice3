import dataclasses

from pymobiledevice3.services.remote_server import Tap


class Sysmontap(Tap):
    IDENTIFIER = "com.apple.instruments.server.services.sysmontap"

    def __init__(self, dvt, process_attributes: list[str], system_attributes: list[str]):
        self.process_attributes_cls = dataclasses.make_dataclass("SysmonProcessAttributes", process_attributes)
        self.system_attributes_cls = dataclasses.make_dataclass("SysmonSystemAttributes", system_attributes)

        config = {
            "ur": 500,  # Output frequency ms
            "bm": 0,
            "procAttrs": process_attributes,
            "sysAttrs": system_attributes,
            "cpuUsage": True,
            "physFootprint": True,  # memory value
            "sampleInterval": 500000000,
        }

        super().__init__(dvt, self.IDENTIFIER, config)

    @classmethod
    async def create(cls, dvt) -> "Sysmontap":
        device_info_channel = await dvt.make_channel("com.apple.instruments.server.services.deviceinfo")
        await device_info_channel.sysmonProcessAttributes()
        process_attributes = list(await device_info_channel.receive_plist())
        await device_info_channel.sysmonSystemAttributes()
        system_attributes = list(await device_info_channel.receive_plist())
        return cls(dvt, process_attributes, system_attributes)

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
