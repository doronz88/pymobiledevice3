from contextlib import suppress
from functools import cached_property

from pymobiledevice3.exceptions import MissingValueError
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient


class Device:
    def __init__(self, lockdown: LockdownClient = None, irecv: IRecv = None):
        self.lockdown = lockdown
        self.irecv = irecv

    def __repr__(self) -> str:
        return (
            f'<{self.__class__.__name__} '
            f'ecid: {self.ecid} '
            f'hardware_model: {self.hardware_model} '
            f'image4-support: {self.is_image4_supported}>'
        )

    @cached_property
    def ecid(self):
        if self.lockdown:
            return self.lockdown.ecid
        return self.irecv.ecid

    @cached_property
    def hardware_model(self):
        if self.lockdown:
            return self.lockdown.all_values['HardwareModel'].lower()
        return self.irecv.hardware_model

    @cached_property
    def is_image4_supported(self):
        if self.lockdown:
            return self.lockdown.get_value(key='Image4Supported')
        return self.irecv.is_image4_supported

    @cached_property
    def ap_parameters(self) -> dict:
        if self.lockdown:
            try:
                return self.lockdown.get_value(key='ApParameters')
            except MissingValueError:
                pass
        return {}

    @cached_property
    def ap_nonce(self):
        if self.lockdown:
            ap_nonce_from_ap_parameters = self.ap_parameters.get('ApNonce')
            if ap_nonce_from_ap_parameters:
                return ap_nonce_from_ap_parameters
            return self.lockdown.get_value(key='ApNonce')
        return self.irecv.ap_nonce

    @cached_property
    def sep_nonce(self):
        if self.lockdown:
            sep_nonce_from_ap_parameters = self.ap_parameters.get('SepNonce')
            if sep_nonce_from_ap_parameters:
                return sep_nonce_from_ap_parameters
            return self.lockdown.get_value(key='SEPNonce')
        return self.irecv.sep_nonce

    @cached_property
    def preflight_info(self):
        if self.lockdown:
            with suppress(MissingValueError):
                return self.lockdown.preflight_info
        return None

    @cached_property
    def product_type(self) -> str:
        if self.lockdown:
            return self.lockdown.product_type
        return self.irecv.product_type
