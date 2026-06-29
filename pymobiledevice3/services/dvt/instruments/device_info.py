import plistlib
import typing
from datetime import datetime

from pymobiledevice3.dtx import DTXNsError, DTXService, dtx_method
from pymobiledevice3.dtx.ns_types import NSDate
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import DvtDirListError


class DeviceInfoService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.deviceinfo"

    @dtx_method("directoryListingForPath:")
    async def directory_listing_for_path_(self, path: str) -> list[str]: ...

    @dtx_method("execnameForPid:")
    async def execname_for_pid_(self, pid: int) -> str: ...

    @dtx_method("runningProcesses")
    async def running_processes(self) -> list[dict]: ...

    @dtx_method("isRunningPid:")
    async def is_running_pid_(self, pid: int) -> bool: ...

    @dtx_method("nameForUID:")
    async def name_for_uid_(self, uid: int) -> str: ...

    @dtx_method("nameForGID:")
    async def name_for_gid_(self, gid: int) -> str: ...

    @dtx_method("systemInformation")
    async def system_information(self) -> dict: ...

    @dtx_method("hardwareInformation")
    async def hardware_information(self) -> dict: ...

    @dtx_method("networkInformation")
    async def network_information(self) -> dict: ...

    @dtx_method("machTimeInfo")
    async def mach_time_info(self) -> dict: ...

    @dtx_method("machKernelName")
    async def mach_kernel_name(self) -> str: ...

    @dtx_method("kpepDatabase")
    async def kpep_database(self) -> typing.Optional[bytes]: ...

    @dtx_method("traceCodesFile")
    async def trace_codes_file(self) -> str: ...

    @dtx_method("sysmonProcessAttributes")
    async def sysmon_process_attributes(self) -> list[str]: ...

    @dtx_method("sysmonSystemAttributes")
    async def sysmon_system_attributes(self) -> list[str]: ...

    # TODO: parsing: https://github.com/frida/frida-core/blob/1bdf9a2fd3171f83bb3dad0d7293b883bb171557/src/fruity/cs-signature.vala#L233

    @dtx_method("symbolicatorSignatureForPid:trackingSelector:")
    async def symbolicator_signature_for_pid_tracking_selector_(self, pid: int, selector: str) -> typing.Any: ...


class DeviceInfo(DtxService[DeviceInfoService]):
    """
    Query device, process, filesystem and kernel information over the
    `com.apple.instruments.server.services.deviceinfo` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``DeviceInfo(DvtProvider(service_provider))``,
    and used as an async context manager to open the channel.
    """

    async def ls(self, path: str) -> list:
        """
        List the contents of a directory on the device.

        Invokes the `directoryListingForPath:` selector.

        :param path: Absolute path of the directory to list.
        :returns: The directory entries.
        :raises DvtDirListError: If the listing fails or the device returns no result.
        """
        try:
            result = await self.service.directory_listing_for_path_(path)
        except DTXNsError as e:
            raise DvtDirListError() from e
        if result is None:
            raise DvtDirListError()
        return result

    async def execname_for_pid(self, pid: int) -> str:
        """
        Get the executable path of a running process.

        Invokes the `execnameForPid:` selector.

        :param pid: Process identifier.
        :returns: Full executable path of the process.
        """
        return await self.service.execname_for_pid_(pid)

    async def proclist(self) -> list[dict]:
        """
        Get the list of running processes from the device.

        Invokes the `runningProcesses` selector. Any per-process ``startDate``
        field is normalized to a `datetime`.

        :returns: One dict of attributes per running process.
        """
        result = await self.service.running_processes()
        assert isinstance(result, list)
        for process in result:
            if "startDate" in process:
                d = process["startDate"]
                process["startDate"] = d.utc if isinstance(d, NSDate) else datetime.fromtimestamp(d)
        return result

    async def is_running_pid(self, pid: int) -> bool:
        """
        Check whether a process is currently running.

        Invokes the `isRunningPid:` selector.

        :param pid: Process identifier.
        :returns: ``True`` if the process is running, ``False`` otherwise.
        """
        return await self.service.is_running_pid_(pid)

    async def system_information(self):
        """
        Get general system information.

        Invokes the `systemInformation` selector.

        :returns: Mapping of system attributes (OS build, device name, etc.).
        """
        return await self.service.system_information()

    async def hardware_information(self):
        """
        Get hardware information.

        Invokes the `hardwareInformation` selector.

        :returns: Mapping of hardware attributes (CPU count, model, etc.).
        """
        return await self.service.hardware_information()

    async def network_information(self):
        """
        Get network interface information.

        Invokes the `networkInformation` selector.

        :returns: Mapping describing the device's network interfaces.
        """
        return await self.service.network_information()

    async def mach_time_info(self):
        """
        Get the Mach absolute-time clock parameters.

        Invokes the `machTimeInfo` selector.

        :returns: Mapping with the Mach timebase and current time values.
        """
        return await self.service.mach_time_info()

    async def mach_kernel_name(self) -> str:
        """
        Get the running Mach kernel name.

        Invokes the `machKernelName` selector.

        :returns: The kernel name string.
        """
        return await self.service.mach_kernel_name()

    async def kpep_database(self) -> typing.Optional[dict]:
        """
        Get the KPEP (kernel performance event) database.

        Invokes the `kpepDatabase` selector and parses the returned plist bytes.

        :returns: The parsed KPEP database, or ``None`` if the device returns no data.
        """
        kpep_database = await self.service.kpep_database()
        if kpep_database is not None:
            return plistlib.loads(kpep_database)

    async def trace_codes(self):
        """
        Get the kernel trace-code table.

        Invokes the `traceCodesFile` selector and parses the whitespace-separated
        ``<hex-code> <name>`` lines.

        :returns: Mapping of integer trace code to its symbolic name.
        """
        codes_file = await self.service.trace_codes_file()
        return {int(k, 16): v for k, v in (line.split() for line in codes_file.splitlines())}

    async def sysmon_process_attributes(self) -> list[str]:
        """
        Get the per-process attribute names supported by sysmontap.

        Invokes the `sysmonProcessAttributes` selector.

        :returns: The supported process attribute names.
        """
        return await self.service.sysmon_process_attributes()

    async def sysmon_system_attributes(self) -> list[str]:
        """
        Get the system-wide attribute names supported by sysmontap.

        Invokes the `sysmonSystemAttributes` selector.

        :returns: The supported system attribute names.
        """
        return await self.service.sysmon_system_attributes()

    async def name_for_uid(self, uid: int) -> str:
        """
        Resolve a user id to its user name.

        Invokes the `nameForUID:` selector.

        :param uid: Numeric user id.
        :returns: The corresponding user name.
        """
        return await self.service.name_for_uid_(uid)

    async def name_for_gid(self, gid: int) -> str:
        """
        Resolve a group id to its group name.

        Invokes the `nameForGID:` selector.

        :param gid: Numeric group id.
        :returns: The corresponding group name.
        """
        return await self.service.name_for_gid_(gid)
