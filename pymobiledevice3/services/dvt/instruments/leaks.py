import dataclasses
from typing import Any, Optional, cast

from pymobiledevice3.dtx import DTXService, PInt64, dtx_method
from pymobiledevice3.dtx.exceptions import DTXNsError
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import ProcessInspectionError


@dataclasses.dataclass(frozen=True)
class MemoryGraph:
    """A memory graph of a process, with the leaks the device found while building it."""

    #: The graph in the ``.memgraph`` file format, as read by macOS's ``leaks``, ``heap`` and ``vmmap``.
    #: ``None`` for a leaked-only graph of a process that has no leaks: the device then sends none.
    data: Optional[bytes]
    #: Number of leaked allocations.
    leaked_count: int
    #: Addresses of the leaked allocations; the device leaves them out of a leaked-only graph.
    leaked_addresses: list[int]


class LeaksService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.remoteleaks"

    @dtx_method("requestGraph:options:")
    async def request_graph_options_(self, pid: PInt64, options: dict[str, Any]) -> Optional[dict[str, Any]]: ...


class Leaks(DtxService[LeaksService]):
    """
    Capture memory graphs through Instruments' Leaks channel.

    The device scans the target's heap through its task port, so on a production device this only
    works for apps that are debuggable (development-signed, with ``get-task-allow``) and that are
    already running: a process that is still suspended at launch has no heap to scan.

    Constructed with a `DvtProvider` and used as an async context manager.
    """

    async def memory_graph(self, pid: int, leaked_only: bool = False) -> MemoryGraph:
        """
        Capture the memory graph of a process and find its leaks.

        :param pid: the process to inspect.
        :param leaked_only: keep only the leaked allocations in the graph, which makes it smaller.
        :raises ProcessInspectionError: if the device could not inspect the process.
        """
        options = {"LeakedCount": True, "LeakedAddresses": True, "LeakedGraphOnly": leaked_only}
        try:
            # The pid has to be a 64-bit primitive: the device reads anything above 32 bits as the
            # token of a graph it kept from an earlier request.
            response = await self.service.request_graph_options_(PInt64(pid), options)
        except DTXNsError as e:
            reason = (e.error.user_info or {}).get("NSLocalizedDescription", e)
            raise ProcessInspectionError(pid, "capture a memory graph of", str(reason)) from e
        graph = cast(Optional[bytes], (response or {}).get("SerializedGraph"))
        if not response or (not graph and response.get("LeakedCount") is None):
            raise ProcessInspectionError(pid, "capture a memory graph of", "it returned no graph")
        return MemoryGraph(
            data=bytes(graph) if graph else None,
            leaked_count=cast(int, response.get("LeakedCount", 0)),
            leaked_addresses=list(cast(list[int], response.get("LeakedAddresses") or [])),
        )
