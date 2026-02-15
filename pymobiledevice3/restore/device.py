from contextlib import suppress
from typing import Optional, overload

from pymobiledevice3.exceptions import MissingValueError
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient


class Device:
    @overload
    def __init__(self, lockdown: LockdownClient, irecv: None = None) -> None: ...

    @overload
    def __init__(self, lockdown: None = None, *, irecv: IRecv) -> None: ...

    def __init__(self, lockdown: Optional[LockdownClient] = None, irecv: Optional[IRecv] = None) -> None:
        self.lockdown: Optional[LockdownClient] = lockdown
        self.irecv: Optional[IRecv] = irecv
        self._ecid: Optional[int] = None
        self._hardware_model: Optional[str] = None
        self._is_image4_supported: Optional[bool] = None
        self._ap_parameters: Optional[dict] = None
        self._ap_nonce = None
        self._ap_nonce_loaded = False
        self._sep_nonce = None
        self._sep_nonce_loaded = False
        self._preflight_info: Optional[dict] = None
        self._preflight_info_loaded = False
        self._firmware_preflight_info: Optional[dict] = None
        self._firmware_preflight_info_loaded = False
        self._product_type: Optional[str] = None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ecid: async hardware_model: async image4-support: async>"

    def set_lockdown(self, value: Optional[LockdownClient]) -> None:
        self.lockdown = value

    def set_irecv(self, value: Optional[IRecv]) -> None:
        self.irecv = value

    async def get_is_lockdown(self) -> bool:
        return self.lockdown is not None

    async def get_is_irecv(self) -> bool:
        return self.irecv is not None

    async def get_ecid(self):
        return self.get_ecid_value()

    def get_ecid_value(self) -> int:
        if self._ecid is not None:
            return self._ecid
        if self.lockdown is not None:
            self._ecid = self.lockdown.ecid
        else:
            self._ecid = self.irecv.ecid
        return self._ecid

    async def get_hardware_model(self):
        return self.get_hardware_model_value()

    def get_hardware_model_value(self) -> str:
        if self._hardware_model is not None:
            return self._hardware_model
        if self.lockdown is not None:
            self._hardware_model = self.lockdown.all_values["HardwareModel"].lower()
        else:
            self._hardware_model = self.irecv.hardware_model
        return self._hardware_model

    async def get_is_image4_supported(self) -> bool:
        if self._is_image4_supported is not None:
            return self._is_image4_supported
        if self.lockdown is not None:
            self._is_image4_supported = bool(await self.lockdown.get_value("", "Image4Supported"))
        else:
            self._is_image4_supported = bool(self.irecv.is_image4_supported)

        return self._is_image4_supported

    async def get_ap_parameters(self) -> dict:
        if self._ap_parameters is not None:
            return self._ap_parameters

        if self.lockdown is not None:
            try:
                self._ap_parameters = await self.lockdown.get_value("", "ApParameters") or {}
            except MissingValueError:
                pass
            else:
                return self._ap_parameters
        self._ap_parameters = {}
        return self._ap_parameters

    async def get_ap_nonce(self):
        if self._ap_nonce_loaded:
            return self._ap_nonce

        if self.lockdown is not None:
            ap_nonce_from_ap_parameters = (await self.get_ap_parameters()).get("ApNonce")
            if ap_nonce_from_ap_parameters:
                self._ap_nonce = ap_nonce_from_ap_parameters
                return self._ap_nonce
            self._ap_nonce = await self.lockdown.get_value("", "ApNonce")
        else:
            self._ap_nonce = self.irecv.ap_nonce
        self._ap_nonce_loaded = True
        return self._ap_nonce

    async def get_sep_nonce(self):
        if self._sep_nonce_loaded:
            return self._sep_nonce

        if self.lockdown is not None:
            sep_nonce_from_ap_parameters = (await self.get_ap_parameters()).get("SepNonce")
            if sep_nonce_from_ap_parameters:
                self._sep_nonce = sep_nonce_from_ap_parameters
                return self._sep_nonce
            self._sep_nonce = await self.lockdown.get_value("", "SEPNonce")
        else:
            self._sep_nonce = self.irecv.sep_nonce
        self._sep_nonce_loaded = True
        return self._sep_nonce

    async def get_preflight_info(self) -> Optional[dict]:
        if self._preflight_info_loaded:
            return self._preflight_info

        if self.lockdown is not None:
            with suppress(MissingValueError):
                self._preflight_info = self.lockdown.preflight_info
                self._preflight_info_loaded = True
                return self._preflight_info
        self._preflight_info = None
        self._preflight_info_loaded = True
        return self._preflight_info

    async def get_firmware_preflight_info(self) -> Optional[dict]:
        if self._firmware_preflight_info_loaded:
            return self._firmware_preflight_info

        if self.lockdown is not None:
            with suppress(MissingValueError):
                self._firmware_preflight_info = self.lockdown.firmware_preflight_info
                self._firmware_preflight_info_loaded = True
                return self._firmware_preflight_info
        self._firmware_preflight_info = None
        self._firmware_preflight_info_loaded = True
        return self._firmware_preflight_info

    async def get_product_type(self) -> str:
        if self._product_type is not None:
            return self._product_type

        if self.lockdown is not None:
            self._product_type = self.lockdown.product_type
        else:
            self._product_type = self.irecv.product_type
        return self._product_type
