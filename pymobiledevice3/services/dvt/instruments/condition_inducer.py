import logging

from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService
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


class ConditionInducer(DtxService[ConditionInducerService]):
    def __init__(self, dvt):
        super().__init__(dvt)
        self.logger = logging.getLogger(__name__)

    async def list(self) -> list[dict]:
        return await self.service.available_condition_inducers()

    async def set(self, profile_identifier):
        for group in await self.list():
            for profile in group.get("profiles"):
                if profile_identifier == profile.get("identifier"):
                    self.logger.info(profile.get("description"))
                    await self.service.enable_condition_with_identifier_profile_identifier_(
                        group.get("identifier"), profile.get("identifier")
                    )
                    return
        raise PyMobileDevice3Exception("Invalid profile identifier")

    async def clear(self):
        await self.service.disable_active_condition()
