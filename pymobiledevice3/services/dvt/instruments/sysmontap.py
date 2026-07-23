import dataclasses

from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.tap import Tap


class Sysmontap(Tap):
    """
    Sample per-process and system-wide telemetry (CPU, memory, etc.) over the
    `com.apple.instruments.server.services.sysmontap` DTX channel.

    Constructed with a `DvtProvider` (passed as ``dvt``) plus the attribute lists
    to sample; prefer the `create` factory, which discovers the supported
    attributes automatically. Used as an async context manager, and is async-iterable:
    iterating yields the raw sample rows pushed by the device.
    """

    IDENTIFIER = "com.apple.instruments.server.services.sysmontap"
    DEFAULT_INTERVAL_MS = 500
    MINIMUM_INTERVAL_MS = 1

    def __init__(
        self,
        dvt: DtxServiceProvider,
        process_attributes: list[str],
        system_attributes: list[str],
        interval_ms: int = DEFAULT_INTERVAL_MS,
    ) -> None:
        """
        :param dvt: The `DvtProvider` owning the underlying DTX connection.
        :param process_attributes: Per-process attribute names to sample (request as ``procAttrs``).
        :param system_attributes: System-wide attribute names to sample (request as ``sysAttrs``).
        :param interval_ms: Sampling interval in milliseconds.
        """
        self.process_attributes_cls = dataclasses.make_dataclass("SysmonProcessAttributes", process_attributes)
        self.system_attributes_cls = dataclasses.make_dataclass("SysmonSystemAttributes", system_attributes)

        config = {
            "ur": Sysmontap.MINIMUM_INTERVAL_MS,  # Output frequency ms
            "bm": 0,
            "procAttrs": process_attributes,
            "sysAttrs": system_attributes,
            "cpuUsage": True,
            "physFootprint": True,  # memory value
            "sampleInterval": interval_ms * 1_000_000,
        }

        super().__init__(dvt, self.IDENTIFIER, config)

    @classmethod
    async def create(cls, dvt: DtxServiceProvider, interval: int = DEFAULT_INTERVAL_MS) -> "Sysmontap":
        """
        Build a `Sysmontap` with the device's full set of supported attributes.

        Queries `DeviceInfo` for the supported sysmon process and system attribute
        names and uses them to construct the instance.

        :param dvt: The `DvtProvider` owning the underlying DTX connection.
        :param interval: Sampling interval in milliseconds.
        :returns: A configured `Sysmontap` instance, not yet connected.
        """
        async with DeviceInfo(dvt) as device_info:
            process_attributes = list(await device_info.sysmon_process_attributes())
            system_attributes = list(await device_info.sysmon_system_attributes())
        return cls(dvt, process_attributes, system_attributes, interval_ms=interval)

    async def iter_processes(self):
        """
        Iterate per-process samples, decoded into attribute dicts.

        Consumes the raw sample rows, keeps only those carrying a ``Processes``
        entry, and maps each process's values onto the requested process
        attribute names.

        :yields: For each sample, the list of per-process attribute dicts.
        """
        async for row in self:
            if "Processes" not in row:
                continue

            entries = []

            processes = row["Processes"].items()
            for _pid, process_info in processes:
                entry = dataclasses.asdict(self.process_attributes_cls(*process_info))
                entries.append(entry)

            yield entries
