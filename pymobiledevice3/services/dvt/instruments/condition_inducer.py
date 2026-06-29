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
    """
    Induce simulated device conditions (such as degraded network or thermal states) via the
    Instruments ConditionInducer channel.

    Constructed with a `DvtProvider`. A single condition can be active at a time; enabling one
    replaces any previously active condition.
    """

    def __init__(self, dvt):
        super().__init__(dvt)
        self.logger = logging.getLogger(__name__)

    async def list(self) -> list[dict]:
        """
        List the condition groups available on the device.

        :returns: The available condition inducers, each a group dict containing an `identifier`
            and a list of selectable `profiles`.
        """
        return await self.service.available_condition_inducers()

    async def set(self, profile_identifier):
        """
        Activate the condition profile with the given identifier.

        Searches every available group for a profile whose identifier matches, then enables it.

        :param profile_identifier: Identifier of the profile to activate.
        :raises PyMobileDevice3Exception: If no available profile matches `profile_identifier`.
        """
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
        """Disable the currently active condition, returning the device to normal behavior."""
        await self.service.disable_active_condition()
