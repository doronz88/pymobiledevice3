import logging

from cached_property import cached_property
from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.restore.img4 import stitch_component
from pymobiledevice3.restore.tss import TSSResponse


class Component:
    def __init__(self, build_identity, name: str, tss: TSSResponse = None, data: bytes = None, path: str = None):
        self.logger = logging.getLogger(__name__)
        self._tss = tss
        self.build_identity = build_identity
        self.name = name
        self._data = data
        self._path = path

    @cached_property
    def path(self):
        if self._path:
            return self._path

        path = None
        if self._tss:
            path = self._tss.get_path_by_entry(self.name)

            if path is None:
                self.logger.debug(f'NOTE: No path for component {self.name} in TSS, will fetch from build_identity')

        if path is None:
            path = self.build_identity.get_component_path(self.name)

        if path is None:
            raise PyMobileDevice3Exception(f'Failed to find component path for: {self.name}')

        return path

    @cached_property
    def data(self):
        if self._data is None:
            return self.build_identity.build_manifest.ipsw.read(self.path)
        return self._data

    @cached_property
    def personalized_data(self):
        if self._tss is None:
            raise PyMobileDevice3Exception(f'TSS ticket must be supplied for personalizing component: {self.name}')

        # stitch ApImg4Ticket into IMG4 file
        return stitch_component(self.name, self.data, self._tss.ap_img4_ticket)
