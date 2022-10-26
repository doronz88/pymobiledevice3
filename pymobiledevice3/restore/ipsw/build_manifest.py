import plistlib

from cached_property import cached_property

from pymobiledevice3.exceptions import NoSuchBuildIdentityError
from pymobiledevice3.restore.ipsw.build_identity import BuildIdentity


class BuildManifest:
    def __init__(self, ipsw, manifest: bytes):
        self.ipsw = ipsw
        self._manifest = plistlib.loads(manifest)
        self._parse_build_identities()

    @cached_property
    def build_major(self):
        build_major = str()
        for i in self._manifest['ProductBuildVersion']:
            if i.isdigit():
                build_major += i
            else:
                break

        return int(build_major)

    @cached_property
    def supported_product_types(self):
        return self._manifest['SupportedProductTypes']

    @cached_property
    def supported_product_types_family(self):
        product = self.supported_product_types[0]
        if product.startswith('iBridge'):
            return 'iBridge'
        elif product.startswith('iPhone'):
            return 'iPhone'
        else:
            raise ValueError()

    def get_build_identity(self, device_class: str, restore_behavior: str = None, variant: str = None):
        for build_identity in self.build_identities:
            if variant is not None:
                if variant not in build_identity.variant:
                    continue

            if build_identity.device_class != device_class:
                continue

            if restore_behavior is not None:
                if build_identity.restore_behavior != restore_behavior:
                    continue

            return build_identity
        raise NoSuchBuildIdentityError('failed to find the correct BuildIdentity from the BuildManifest')

    def _parse_build_identities(self):
        self.build_identities = []
        for build_identity in self._manifest['BuildIdentities']:
            self.build_identities.append(BuildIdentity(self, build_identity))
