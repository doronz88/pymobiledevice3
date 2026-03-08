import logging

from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.exceptions import PyMobileDevice3Exception


class ConditionInducerService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.ConditionInducer"

    @dtx_method("availableConditionInducers")
    async def available_condition_inducers(self) -> list: ...

    @dtx_method("enableConditionWithIdentifier:profileIdentifier:")
    async def enable_condition_with_identifier_profile_identifier_(
        self, condition_identifier: str, profile_identifier: str
    ) -> None: ...

    @dtx_method("disableActiveCondition", expects_reply=False)
    async def disable_active_condition(self) -> None: ...


class ConditionInducerChannel(DtxService[ConditionInducerService]):
    pass


class ConditionInducer:
    IDENTIFIER = ConditionInducerService.IDENTIFIER

    def __init__(self, dvt: DtxServiceProvider):
        self.logger = logging.getLogger(__name__)
        self._provider = dvt
        self._channel: ConditionInducerChannel | None = None

    async def _service_ref(self) -> ConditionInducerService:
        if self._channel is None:
            self._channel = ConditionInducerChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def list(self) -> list[dict]:
        return await (await self._service_ref()).available_condition_inducers()

    async def set(self, profile_identifier):
        for group in await self.list():
            for profile in group.get("profiles"):
                if profile_identifier == profile.get("identifier"):
                    self.logger.info(profile.get("description"))
                    await (await self._service_ref()).enable_condition_with_identifier_profile_identifier_(
                        group.get("identifier"), profile.get("identifier")
                    )
                    return
        raise PyMobileDevice3Exception("Invalid profile identifier")

    async def clear(self):
        await (await self._service_ref()).disable_active_condition()
