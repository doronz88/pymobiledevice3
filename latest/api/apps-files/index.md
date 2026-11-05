# Apps, files & profiles

App-container file access, configuration profiles, and provisioning profiles. (`InstallationProxyService` and `AfcService` live under [Lockdown services](https://doronz88.github.io/pymobiledevice3/latest/api/services/index.md).)

## pymobiledevice3.services.house_arrest.HouseArrestService

Bases: `AfcService`

AFC access to an installed application's container.

house_arrest vends an application sandbox over the AFC protocol, allowing the container's files to be browsed and transferred. The container is selected by calling `send_command` (or via the `create` factory) with the target app's bundle id; `documents_only` controls whether the whole container or only its `Documents` subtree is exposed.

Being an `AfcService`, instances may be used as an async context manager::

```
async with await HouseArrestService.create(lockdown, bundle_id) as house_arrest:
    ...
```

Source code in `pymobiledevice3/services/house_arrest.py`

```
class HouseArrestService(AfcService):
    """
    AFC access to an installed application's container.

    house_arrest vends an application sandbox over the AFC protocol, allowing the
    container's files to be browsed and transferred. The container is selected by
    calling `send_command` (or via the `create` factory) with the target app's
    bundle id; ``documents_only`` controls whether the whole container or only its
    ``Documents`` subtree is exposed.

    Being an `AfcService`, instances may be used as an async context manager::

        async with await HouseArrestService.create(lockdown, bundle_id) as house_arrest:
            ...
    """

    SERVICE_NAME = "com.apple.mobile.house_arrest"
    RSD_SERVICE_NAME = "com.apple.mobile.house_arrest.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider, documents_only: bool = False):
        super().__init__(lockdown)
        self.documents_only = documents_only

    @classmethod
    async def create(
        cls, lockdown: LockdownServiceProvider, bundle_id: str, documents_only: bool = False
    ) -> "HouseArrestService":
        """
        Create a service already vending the container of the given application.

        Instantiates the service and immediately issues the vend command, leaving the AFC
        session rooted at the application's container. On failure the service is closed
        before the error propagates.

        :param lockdown: service provider used to start the service and reach the device.
        :param bundle_id: bundle identifier of the application whose container to vend.
        :param documents_only: when True, vend only the container's ``Documents`` subtree
            (``VendDocuments``); otherwise vend the whole container (``VendContainer``).
        :returns: a connected `HouseArrestService` rooted at the application's container.
        :raises AppNotInstalledError: if no application with ``bundle_id`` is installed.
        :raises PyMobileDevice3Exception: if the device reports any other vend error.
        """
        service = cls(lockdown, documents_only=documents_only)
        cmd = VEND_DOCUMENTS if documents_only else VEND_CONTAINER
        try:
            await service.send_command(bundle_id, cmd)
        except (PyMobileDevice3Exception, BinaryDataError):  # an error status, or a malformed reply
            await service.close()
            raise
        return service

    async def send_command(self, bundle_id: str, cmd: str = "VendContainer") -> None:
        """
        Vend an application's container so subsequent AFC operations act on it.

        :param bundle_id: bundle identifier of the application to vend.
        :param cmd: vend command, either ``VendContainer`` (whole container) or
            ``VendDocuments`` (only the ``Documents`` subtree).
        :raises AppNotInstalledError: if no application with ``bundle_id`` is installed.
        :raises PyMobileDevice3Exception: if the device reports any other error.
        """
        response = await self.service.send_recv_plist({"Command": cmd, "Identifier": bundle_id})
        error = response.get("Error")
        if error:
            if error == "ApplicationLookupFailed":
                raise AppNotInstalledError(f"No app with bundle ID {bundle_id} is installed.")
            else:
                raise PyMobileDevice3Exception(f"The device refused to open the container of {bundle_id}: {error}")

    def shell(self, host_tools: Iterable[str] = ()) -> None:
        """
        Launch an interactive AFC shell over the vended container.

        The shell starts in the container's ``Documents`` directory when the service was
        created with ``documents_only``, otherwise at the container root.

        :param host_tools: Names of more host executables to offer as commands in the shell
        """
        shell = AfcShell(self, cwd=DOCUMENTS_ROOT if self.documents_only else "/", host_tools=host_tools)
        get_asyncio_loop().run_until_complete(shell.interact())
```

### create

```
create(lockdown: LockdownServiceProvider, bundle_id: str, documents_only: bool = False) -> HouseArrestService
```

Create a service already vending the container of the given application.

Instantiates the service and immediately issues the vend command, leaving the AFC session rooted at the application's container. On failure the service is closed before the error propagates.

Parameters:

| Name             | Type                      | Description                                                                                                                 | Default    |
| ---------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `lockdown`       | `LockdownServiceProvider` | service provider used to start the service and reach the device.                                                            | *required* |
| `bundle_id`      | `str`                     | bundle identifier of the application whose container to vend.                                                               | *required* |
| `documents_only` | `bool`                    | when True, vend only the container's Documents subtree (VendDocuments); otherwise vend the whole container (VendContainer). | `False`    |

Returns:

| Type                 | Description                                                           |
| -------------------- | --------------------------------------------------------------------- |
| `HouseArrestService` | a connected HouseArrestService rooted at the application's container. |

Raises:

| Type                       | Description                                    |
| -------------------------- | ---------------------------------------------- |
| `AppNotInstalledError`     | if no application with bundle_id is installed. |
| `PyMobileDevice3Exception` | if the device reports any other vend error.    |

Source code in `pymobiledevice3/services/house_arrest.py`

```
@classmethod
async def create(
    cls, lockdown: LockdownServiceProvider, bundle_id: str, documents_only: bool = False
) -> "HouseArrestService":
    """
    Create a service already vending the container of the given application.

    Instantiates the service and immediately issues the vend command, leaving the AFC
    session rooted at the application's container. On failure the service is closed
    before the error propagates.

    :param lockdown: service provider used to start the service and reach the device.
    :param bundle_id: bundle identifier of the application whose container to vend.
    :param documents_only: when True, vend only the container's ``Documents`` subtree
        (``VendDocuments``); otherwise vend the whole container (``VendContainer``).
    :returns: a connected `HouseArrestService` rooted at the application's container.
    :raises AppNotInstalledError: if no application with ``bundle_id`` is installed.
    :raises PyMobileDevice3Exception: if the device reports any other vend error.
    """
    service = cls(lockdown, documents_only=documents_only)
    cmd = VEND_DOCUMENTS if documents_only else VEND_CONTAINER
    try:
        await service.send_command(bundle_id, cmd)
    except (PyMobileDevice3Exception, BinaryDataError):  # an error status, or a malformed reply
        await service.close()
        raise
    return service
```

### send_command

```
send_command(bundle_id: str, cmd: str = 'VendContainer') -> None
```

Vend an application's container so subsequent AFC operations act on it.

Parameters:

| Name        | Type  | Description                                                                                         | Default           |
| ----------- | ----- | --------------------------------------------------------------------------------------------------- | ----------------- |
| `bundle_id` | `str` | bundle identifier of the application to vend.                                                       | *required*        |
| `cmd`       | `str` | vend command, either VendContainer (whole container) or VendDocuments (only the Documents subtree). | `'VendContainer'` |

Raises:

| Type                       | Description                                    |
| -------------------------- | ---------------------------------------------- |
| `AppNotInstalledError`     | if no application with bundle_id is installed. |
| `PyMobileDevice3Exception` | if the device reports any other error.         |

Source code in `pymobiledevice3/services/house_arrest.py`

```
async def send_command(self, bundle_id: str, cmd: str = "VendContainer") -> None:
    """
    Vend an application's container so subsequent AFC operations act on it.

    :param bundle_id: bundle identifier of the application to vend.
    :param cmd: vend command, either ``VendContainer`` (whole container) or
        ``VendDocuments`` (only the ``Documents`` subtree).
    :raises AppNotInstalledError: if no application with ``bundle_id`` is installed.
    :raises PyMobileDevice3Exception: if the device reports any other error.
    """
    response = await self.service.send_recv_plist({"Command": cmd, "Identifier": bundle_id})
    error = response.get("Error")
    if error:
        if error == "ApplicationLookupFailed":
            raise AppNotInstalledError(f"No app with bundle ID {bundle_id} is installed.")
        else:
            raise PyMobileDevice3Exception(f"The device refused to open the container of {bundle_id}: {error}")
```

### shell

```
shell(host_tools: Iterable[str] = ()) -> None
```

Launch an interactive AFC shell over the vended container.

The shell starts in the container's `Documents` directory when the service was created with `documents_only`, otherwise at the container root.

Parameters:

| Name         | Type            | Description                                                      | Default |
| ------------ | --------------- | ---------------------------------------------------------------- | ------- |
| `host_tools` | `Iterable[str]` | Names of more host executables to offer as commands in the shell | `()`    |

Source code in `pymobiledevice3/services/house_arrest.py`

```
def shell(self, host_tools: Iterable[str] = ()) -> None:
    """
    Launch an interactive AFC shell over the vended container.

    The shell starts in the container's ``Documents`` directory when the service was
    created with ``documents_only``, otherwise at the container root.

    :param host_tools: Names of more host executables to offer as commands in the shell
    """
    shell = AfcShell(self, cwd=DOCUMENTS_ROOT if self.documents_only else "/", host_tools=host_tools)
    get_asyncio_loop().run_until_complete(shell.interact())
```

## pymobiledevice3.services.mobile_config.MobileConfigService

Bases: `LockdownService`

Manage configuration profiles and cloud (supervision) configuration.

Wraps the `com.apple.mobile.MCInstall` lockdown service used by MDM/Apple Configurator. It can list, install and remove configuration profiles, drive supervision and cloud-configuration state, and erase the device. Some operations require supervised/silent installation, which is unlocked by `escalate` using a supervision identity (a PEM keybag holding both certificate and private key).

Being a `LockdownService`, instances may be used as an async context manager::

```
async with MobileConfigService(lockdown) as mc:
    profiles = await mc.get_profile_list()
```

Source code in `pymobiledevice3/services/mobile_config.py`

```
class MobileConfigService(LockdownService):
    """
    Manage configuration profiles and cloud (supervision) configuration.

    Wraps the ``com.apple.mobile.MCInstall`` lockdown service used by MDM/Apple
    Configurator. It can list, install and remove configuration profiles, drive
    supervision and cloud-configuration state, and erase the device. Some operations
    require supervised/silent installation, which is unlocked by `escalate` using a
    supervision identity (a PEM keybag holding both certificate and private key).

    Being a `LockdownService`, instances may be used as an async context manager::

        async with MobileConfigService(lockdown) as mc:
            profiles = await mc.get_profile_list()
    """

    SERVICE_NAME = "com.apple.mobile.MCInstall"
    RSD_SERVICE_NAME = "com.apple.mobile.MCInstall.shim.remote"

    async def hello(self) -> None:
        """Perform the ``HelloHostIdentifier`` handshake with the service."""
        await self._send_recv({"RequestType": "HelloHostIdentifier"})

    async def flush(self) -> None:
        """Issue a ``Flush`` request to the service."""
        await self._send_recv({"RequestType": "Flush"})

    async def escalate(self, keybag_file: Path) -> None:
        """
        Authenticate as a supervisor to unlock silent/supervised operations.

        Runs the ``Escalate`` challenge-response handshake using the supervision identity,
        then requests keybag migration. Must be called before silent profile installation.

        :param keybag_file: path to a PEM file containing both the supervisor certificate
            and its (unencrypted) private key.
        """
        with open(keybag_file, "rb") as f:
            keybag_data = f.read()
        private_key = serialization.load_pem_private_key(keybag_data, password=None)
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise ProfileError(
                f"The supervision keybag must hold an RSA or EC private key, not {type(private_key).__name__}"
            )
        cer = x509.load_pem_x509_certificate(keybag_data)
        public_key = cer.public_bytes(Encoding.DER)
        escalate_response = await self._send_recv({"RequestType": "Escalate", "SupervisorCertificate": public_key})
        signed_challenge = (
            PKCS7SignatureBuilder()
            .set_data(escalate_response["Challenge"])
            .add_signer(cer, private_key, hashes.SHA256())
            .sign(Encoding.DER, [PKCS7Options.Binary])
        )
        await self._send_recv({"RequestType": "EscalateResponse", "SignedRequest": signed_challenge})
        await self._send_recv({"RequestType": "ProceedWithKeybagMigration"})

    async def get_stored_profile(self, purpose: Purpose = Purpose.PostSetupInstallation) -> dict[str, Any]:
        """
        Retrieve a profile stored on the device for a given purpose.

        :param purpose: purpose the profile was stored under.
        :returns: the device's response plist.
        """
        return await self._send_recv({"RequestType": "GetStoredProfile", "Purpose": purpose.value})

    async def store_profile(self, profile_data: bytes, purpose: Purpose = Purpose.PostSetupInstallation) -> None:
        """
        Store a profile on the device for later use under a given purpose.

        :param profile_data: raw profile bytes to store.
        :param purpose: purpose to store the profile under.
        """
        await self._send_recv({"RequestType": "StoreProfile", "ProfileData": profile_data, "Purpose": purpose.value})

    async def get_cloud_configuration(self) -> Optional[dict[str, Any]]:
        """
        Retrieve the device's cloud (supervision) configuration.

        :returns: the ``CloudConfiguration`` dictionary, or None if not set.
        """
        return (await self._send_recv({"RequestType": "GetCloudConfiguration"})).get("CloudConfiguration")

    async def set_cloud_configuration(self, cloud_configuration: dict[str, Any]) -> None:
        """
        Set the device's cloud (supervision) configuration.

        :param cloud_configuration: cloud configuration dictionary to apply.
        """
        await self._send_recv({"RequestType": "SetCloudConfiguration", "CloudConfiguration": cloud_configuration})

    async def download_and_apply_cloud_configuration(
        self, username: Optional[str] = None, password: Optional[str] = None
    ) -> None:
        """
        Ask the device to download and apply its DEP cloud configuration.

        :param username: optional MDM enrollment username.
        :param password: optional MDM enrollment password.
        """
        await self._send_recv({
            "RequestType": "DownloadAndApplyCloudConfiguration",
            "MDMUsername": username or "",
            "MDMPassword": password or "",
        })

    async def establish_provisional_enrollment(self, nonce: bytes) -> None:
        """
        Establish a provisional MDM enrollment.

        :param nonce: enrollment nonce.
        """
        await self._send_recv({"RequestType": "EstablishProvisionalEnrollment", "Nonce": nonce})

    async def set_wifi_power_state(self, state: bool) -> None:
        """
        Turn the device's Wi-Fi radio on or off.

        :param state: True to power Wi-Fi on, False to power it off.
        """
        await self._send_recv({"RequestType": "SetWiFiPowerState", "PowerState": state})

    async def erase_device(self, preserve_data_plan: bool, disallow_proximity_setup: bool) -> None:
        """
        Erase all content and settings from the device.

        The connection is normally terminated by the device as it begins erasing; that
        termination is suppressed so the call returns cleanly.

        :param preserve_data_plan: whether to preserve the cellular data plan across the erase.
        :param disallow_proximity_setup: whether to disallow proximity setup after the erase.
        """
        with contextlib.suppress(ConnectionTerminatedError):
            await self._send_recv({
                "RequestType": "EraseDevice",
                "PreserveDataPlan": preserve_data_plan,
                "DisallowProximitySetup": disallow_proximity_setup,
            })

    async def get_profile_list(self) -> dict[str, Any]:
        """
        List the configuration profiles installed on the device.

        :returns: the device's response plist (including ``ProfileMetadata`` keyed by
            profile identifier).
        """
        return await self._send_recv({"RequestType": "GetProfileList"})

    async def install_profile(self, payload: bytes) -> None:
        """
        Install a configuration profile, prompting the user for confirmation.

        :param payload: raw configuration profile bytes to install.
        """
        await self._send_recv({"RequestType": "InstallProfile", "Payload": payload})

    async def install_profile_silent(self, keybag_file: Path, profile: bytes) -> None:
        """
        Install a configuration profile silently, without user interaction.

        Escalates to supervisor privileges with the supervision identity, then installs
        the profile.

        :param keybag_file: path to a PEM file containing the supervisor certificate and
            its private key, used to escalate.
        :param profile: raw configuration profile bytes to install.
        """
        await self.escalate(keybag_file)
        await self._send_recv({"RequestType": "InstallProfileSilent", "Payload": profile})

    async def remove_profile(self, identifier: str) -> None:
        """
        Remove an installed configuration profile by its identifier.

        Looks up the profile's metadata in the installed profile list and, if present,
        sends a signed-free removal request. Does nothing if no profiles are installed or
        the identifier is not currently installed.

        :param identifier: payload identifier of the profile to remove.
        """
        profiles = await self.get_profile_list()
        if not profiles:
            return
        if identifier not in profiles["ProfileMetadata"]:
            self.logger.info(f"Trying to remove not installed profile: {identifier}")
            return
        meta = profiles["ProfileMetadata"][identifier]
        data = plistlib.dumps({
            "PayloadType": "Configuration",
            "PayloadIdentifier": identifier,
            "PayloadUUID": meta["PayloadUUID"],
            "PayloadVersion": meta["PayloadVersion"],
        })
        await self._send_recv({"RequestType": "RemoveProfile", "ProfileIdentifier": data})

    async def request_unlock_token(self) -> bytes:
        """
        Fetch the passcode unlock token, which `clear_passcode` can later use to remove a passcode.

        Requires a connection escalated with `escalate`. The device must have no passcode set:
        while one is active the keybag refuses to mint a token.

        :returns: the raw unlock token.
        :raises PasscodeSetError: the device has a passcode set.
        """
        response = await self._send_recv({"RequestType": "RequestUnlockToken"}, redact=True)
        token = response.get("UnlockToken")
        if not isinstance(token, bytes):
            raise ProfileError("The RequestUnlockToken response carries no UnlockToken")
        return token

    async def clear_passcode(self, unlock_token: bytes) -> None:
        """
        Remove the device passcode without knowing it.

        Requires a connection escalated with `escalate`. The device drops this host's pairing
        afterwards, as it does whenever the passcode changes; re-pair with `pair_supervised`.

        :param unlock_token: a token previously fetched by `request_unlock_token`, before the
            passcode was set.
        """
        await self._send_recv({"RequestType": "ClearPasscode", "UnlockToken": unlock_token}, redact=True)

    async def clear_restrictions_password(self) -> None:
        """
        Clear the Screen Time (restrictions) passcode. No unlock token is needed.

        Requires a connection escalated with `escalate`. iOS 27.2 always fails it with a
        ``ScreenTimeSettingsServiceClientError``: the device's own sandbox denies mc_mobile_tunnel
        the lookup of ``com.apple.ScreenTimeSettingsAgent.private``.
        """
        await self._send_recv({"RequestType": "ClearRestrictionsPassword"})

    async def get_security_info(self) -> dict[str, Any]:
        """
        Query the device's security status. Read-only; performs no keybag operation.

        Requires a connection escalated with `escalate` (unescalated, the device answers
        ``CommandFormatError``). The reply includes ``PasscodePresent``, which reliably tells
        whether a passcode is set, unlike lockdown's ``PasswordProtected`` (which reflects whether
        the device is currently locked), along with passcode compliance, lock grace periods,
        hardware encryption capabilities and management status.

        :returns: the ``SecurityInfo`` dictionary.
        """
        info = (await self._send_recv({"RequestType": "SecurityInfo"})).get("SecurityInfo")
        if not isinstance(info, dict):
            raise ProfileError("The SecurityInfo response carries no SecurityInfo dictionary")
        return cast(dict[str, Any], info)

    async def set_wallpaper(self, image: bytes, screen: WallpaperScreen = WallpaperScreen.HOME) -> None:
        """
        Set the device wallpaper via the ``Settings`` request's ``Wallpaper`` item.

        Requires a connection escalated with `escalate`. Since iOS 16 the lock and home screen
        wallpapers form a pair, so the device may apply the image to both regardless of `screen`.

        :param image: JPEG or PNG image bytes.
        :param screen: which screen(s) to apply the wallpaper to.
        """
        response = await self._send_recv({
            "RequestType": "Settings",
            "Settings": [{"Item": "Wallpaper", "Where": screen.value, "Image": image}],
        })
        settings = response.get("Settings")
        if not isinstance(settings, list) or not settings or not isinstance(settings[0], dict):
            raise ProfileError(f"The wallpaper Settings response carries no item status: {response}")
        item = cast(dict[str, Any], settings[0])
        if item.get("Status") != "Acknowledged":
            raise ProfileError(f"The device rejected the wallpaper: {item}")

    async def _send_recv(self, request: dict[str, Any], redact: bool = False) -> dict[str, Any]:
        response = await self.service.send_recv_plist(request)
        if response.get("Status", None) != "Acknowledged":
            error_chain = cast(list[dict[str, Any]], response.get("ErrorChain") or [])
            if error_chain:
                error_code = error_chain[0].get("ErrorCode")
                if error_code == ERROR_CLOUD_CONFIGURATION_ALREADY_PRESENT:
                    raise CloudConfigurationAlreadyPresentError()
            if any(
                error.get("ErrorDomain") == KEYBAG_ERROR_DOMAIN and error.get("ErrorCode") == ERROR_KEYBAG_PASSCODE_SET
                for error in error_chain
            ):
                raise PasscodeSetError()
            if redact:
                # The response may echo or carry an unlock token, so only describe the failure.
                errors = "; ".join(
                    f"{error.get('ErrorDomain')}({error.get('ErrorCode')}): {error.get('LocalizedDescription')}"
                    for error in error_chain
                )
                raise ProfileError(
                    f"The device rejected the {request['RequestType']} request: Status={response.get('Status')}"
                    + (f"; {errors}" if errors else "")
                )
            raise ProfileError(f"The device rejected the profile request: {response}")
        return response

    async def install_wifi_profile(
        self,
        encryption_type: str,
        ssid: str,
        password: str,
        auto_join: bool = True,
        captive_bypass: bool = False,
        disable_association_mac_randomization: bool = False,
        hidden_network: bool = False,
        is_hotspot: bool = False,
        keybag_file: Optional[Path] = None,
    ) -> None:
        """
        Build and install a ``com.apple.wifi.managed`` profile for a Wi-Fi network.

        :param encryption_type: Wi-Fi encryption type (e.g. ``WPA``, ``WEP``, ``None``).
        :param ssid: network SSID.
        :param password: network password.
        :param auto_join: whether the device should automatically join the network.
        :param captive_bypass: whether to bypass the captive portal check.
        :param disable_association_mac_randomization: whether to disable MAC-address
            randomization when associating.
        :param hidden_network: whether the network is hidden (does not broadcast its SSID).
        :param is_hotspot: whether the network is treated as a personal hotspot.
        :param keybag_file: when provided, install silently using this supervision identity;
            otherwise install with a user prompt.
        """
        payload_uuid = str(uuid4())
        await self.install_managed_profile(
            f"WiFi Profile For {ssid}",
            {
                "AutoJoin": auto_join,
                "CaptiveBypass": captive_bypass,
                "DisableAssociationMACRandomization": disable_association_mac_randomization,
                "EncryptionType": encryption_type,
                "HIDDEN_NETWORK": hidden_network,
                "IsHotspot": is_hotspot,
                "Password": password,
                "PayloadDescription": "Configures Wi-Fi settings",
                "PayloadDisplayName": "Wi-Fi",
                "PayloadIdentifier": f"com.apple.wifi.managed.{payload_uuid}",
                "PayloadType": "com.apple.wifi.managed",
                "PayloadUUID": payload_uuid,
                "PayloadVersion": 1,
                "ProxyType": "None",
                "SSID_STR": ssid,
            },
            keybag_file=keybag_file,
        )

    async def install_http_proxy(self, server: str, server_port: int, keybag_file: Optional[Path] = None) -> None:
        """
        Build and install a global manual HTTP-proxy profile.

        The profile uses the fixed `GLOBAL_HTTP_PROXY_UUID` so it can later be removed by
        `remove_http_proxy`.

        :param server: proxy server host.
        :param server_port: proxy server port.
        :param keybag_file: when provided, install silently using this supervision identity;
            otherwise install with a user prompt.
        """
        payload_uuid = str(uuid4())
        await self.install_managed_profile(
            f"HTTP Proxy for {server}:{server_port}",
            {
                "PayloadDescription": "Global HTTP Proxy",
                "PayloadDisplayName": "Global HTTP Proxy",
                "PayloadIdentifier": f"com.apple.proxy.http.global.{payload_uuid}",
                "PayloadType": "com.apple.proxy.http.global",
                "PayloadUUID": payload_uuid,
                "PayloadVersion": 1,
                "ProxyCaptiveLoginAllowed": False,
                "ProxyServer": server,
                "ProxyServerPort": server_port,
                "ProxyType": "Manual",
            },
            payload_uuid=GLOBAL_HTTP_PROXY_UUID,
            keybag_file=keybag_file,
        )

    async def remove_http_proxy(self) -> None:
        """Remove the global HTTP-proxy profile previously installed by `install_http_proxy`."""
        await self.remove_profile(GLOBAL_HTTP_PROXY_UUID)

    async def supervise(self, organization: str, keybag_file: Path) -> None:
        """
        Place the device under supervision by writing a cloud configuration.

        Sets a supervised cloud configuration that names the organization, registers the
        supervisor certificate, and skips all setup-assistant panes.

        :param organization: organization name recorded in the cloud configuration.
        :param keybag_file: path to a PEM file containing the supervisor certificate whose
            DER public bytes are registered as a supervisor host certificate.
        """
        cer = x509.load_pem_x509_certificate(keybag_file.read_bytes())
        public_key = cer.public_bytes(Encoding.DER)
        await self.set_cloud_configuration({
            "AllowPairing": True,
            "CloudConfigurationUIComplete": True,
            "ConfigurationSource": 2,
            "ConfigurationWasApplied": True,
            "IsMDMUnremovable": False,
            "IsMandatory": True,
            "IsMultiUser": False,
            "IsSupervised": True,
            "OrganizationMagic": str(uuid4()),
            "OrganizationName": organization,
            "PostSetupProfileWasInstalled": True,
            "SkipSetup": [
                "Location",
                "Restore",
                "SIMSetup",
                "Android",
                "AppleID",
                "IntendedUser",
                "TOS",
                "Siri",
                "ScreenTime",
                "Diagnostics",
                "SoftwareUpdate",
                "Passcode",
                "Biometric",
                "Payment",
                "Zoom",
                "DisplayTone",
                "MessagingActivationUsingPhoneNumber",
                "HomeButtonSensitivity",
                "CloudStorage",
                "ScreenSaver",
                "TapToSetup",
                "Keyboard",
                "PreferredLanguage",
                "SpokenLanguage",
                "WatchMigration",
                "OnBoarding",
                "TVProviderSignIn",
                "TVHomeScreenSync",
                "Privacy",
                "TVRoom",
                "iMessageAndFaceTime",
                "AppStore",
                "Safety",
                "Multitasking",
                "ActionButton",
                "TermsOfAddress",
                "AccessibilityAppearance",
                "Welcome",
                "Appearance",
                "RestoreCompleted",
                "UpdateCompleted",
                "WiFi",
                "Display",
                "Tone",
                "LanguageAndLocale",
                "TouchID",
                "TrueToneDisplay",
                "FileVault",
                "iCloudStorage",
                "iCloudDiagnostics",
                "Registration",
                "DeviceToDeviceMigration",
                "UnlockWithWatch",
                "Accessibility",
                "All",
                "ExpressLanguage",
                "Language",
                "N/A",
                "Region",
                "Avatar",
                "DeviceProtection",
                "Key",
                "LockdownMode",
                "Wallpaper",
                "PrivacySubtitle",
                "SecuritySubtitle",
                "DataSubtitle",
                "AppleIDSubtitle",
                "AppearanceSubtitle",
                "PreferredLang",
                "OnboardingSubtitle",
                "AppleTVSubtitle",
                "Intelligence",
                "WebContentFiltering",
                "CameraButton",
                "AdditionalPrivacySettings",
                "EnableLockdownMode",
                "OSShowcase",
                "SafetyAndHandling",
                "Tips",
                "AgeBasedSafetySettings",
                "LiquidGlass",
                "AgeAssurance",
                "DeviceFeaturesTour",
            ],
            "SupervisorHostCertificates": [public_key],
        })

    async def install_managed_profile(
        self,
        display_name: str,
        payload_content: dict[str, Any],
        payload_uuid: str = str(uuid4()),
        keybag_file: Optional[Path] = None,
    ) -> None:
        """
        Wrap a single payload in a ``Configuration`` profile and install it.

        :param display_name: profile display name.
        :param payload_content: the inner payload dictionary to wrap.
        :param payload_uuid: UUID used as both the profile identifier and UUID.
        :param keybag_file: when provided, install silently using this supervision identity;
            otherwise install with a user prompt.
        """
        profile_data = plistlib.dumps({
            "PayloadContent": [payload_content],
            "PayloadDisplayName": display_name,
            "PayloadIdentifier": payload_uuid,
            "PayloadRemovalDisallowed": False,
            "PayloadType": "Configuration",
            "PayloadUUID": payload_uuid,
            "PayloadVersion": 1,
        })
        if keybag_file is not None:
            await self.install_profile_silent(keybag_file, profile_data)
        else:
            await self.install_profile(profile_data)

    async def install_restrictions_profile(
        self,
        enforced_software_update_delay: int = 0,
        payload_uuid: str = GLOBAL_RESTRICTIONS_UUID,
        keybag_file: Optional[Path] = None,
    ) -> None:
        """
        Build and install a ``com.apple.applicationaccess`` restrictions profile.

        The profile permits essentially every restricted capability; only the software
        update delay is parameterized.

        :param enforced_software_update_delay: number of days to delay visibility of
            software updates.
        :param payload_uuid: UUID used as the profile identifier and UUID.
        :param keybag_file: when provided, install silently using this supervision identity;
            otherwise install with a user prompt.
        """
        await self.install_managed_profile(
            "Restrictions",
            {
                "PayloadDescription": "Configures restrictions",
                "PayloadDisplayName": "Restrictions",
                "PayloadIdentifier": f"com.apple.applicationaccess.{payload_uuid}",
                "PayloadType": "com.apple.applicationaccess",
                "PayloadUUID": payload_uuid,
                "PayloadVersion": 1,
                "allowActivityContinuation": True,
                "allowAddingGameCenterFriends": True,
                "allowAirPlayIncomingRequests": True,
                "allowAirPrint": True,
                "allowAirPrintCredentialsStorage": True,
                "allowAirPrintiBeaconDiscovery": True,
                "allowAppCellularDataModification": True,
                "allowAppClips": True,
                "allowAppInstallation": True,
                "allowAppRemoval": True,
                "allowApplePersonalizedAdvertising": True,
                "allowAssistant": True,
                "allowAssistantWhileLocked": True,
                "allowAutoCorrection": True,
                "allowAutoUnlock": True,
                "allowAutomaticAppDownloads": True,
                "allowBluetoothModification": True,
                "allowBookstore": True,
                "allowBookstoreErotica": True,
                "allowCamera": True,
                "allowCellularPlanModification": True,
                "allowChat": True,
                "allowCloudBackup": True,
                "allowCloudDocumentSync": True,
                "allowCloudPhotoLibrary": True,
                "allowContinuousPathKeyboard": True,
                "allowDefinitionLookup": True,
                "allowDeviceNameModification": True,
                "allowDeviceSleep": True,
                "allowDictation": True,
                "allowESIMModification": True,
                "allowEnablingRestrictions": True,
                "allowEnterpriseAppTrust": True,
                "allowEnterpriseBookBackup": True,
                "allowEnterpriseBookMetadataSync": True,
                "allowEraseContentAndSettings": True,
                "allowExplicitContent": True,
                "allowFilesNetworkDriveAccess": True,
                "allowFilesUSBDriveAccess": True,
                "allowFindMyDevice": True,
                "allowFindMyFriends": True,
                "allowFingerprintForUnlock": True,
                "allowFingerprintModification": True,
                "allowGameCenter": True,
                "allowGlobalBackgroundFetchWhenRoaming": True,
                "allowInAppPurchases": True,
                "allowKeyboardShortcuts": True,
                "allowManagedAppsCloudSync": True,
                "allowMultiplayerGaming": True,
                "allowMusicService": True,
                "allowNews": True,
                "allowNotificationsModification": True,
                "allowOpenFromManagedToUnmanaged": True,
                "allowOpenFromUnmanagedToManaged": True,
                "allowPairedWatch": True,
                "allowPassbookWhileLocked": True,
                "allowPasscodeModification": True,
                "allowPasswordAutoFill": True,
                "allowPasswordProximityRequests": True,
                "allowPasswordSharing": True,
                "allowPersonalHotspotModification": True,
                "allowPhotoStream": True,
                "allowPredictiveKeyboard": True,
                "allowProximitySetupToNewDevice": True,
                "allowRadioService": True,
                "allowRemoteAppPairing": True,
                "allowRemoteScreenObservation": True,
                "allowSafari": True,
                "allowScreenShot": True,
                "allowSharedStream": True,
                "allowSpellCheck": True,
                "allowSpotlightInternetResults": True,
                "allowSystemAppRemoval": True,
                "allowUIAppInstallation": True,
                "allowUIConfigurationProfileInstallation": True,
                "allowUSBRestrictedMode": True,
                "allowUnpairedExternalBootToRecovery": False,
                "allowUntrustedTLSPrompt": True,
                "allowVPNCreation": True,
                "allowVideoConferencing": True,
                "allowVoiceDialing": True,
                "allowWallpaperModification": True,
                "allowiTunes": True,
                "enforcedSoftwareUpdateDelay": enforced_software_update_delay,
                "forceAirDropUnmanaged": False,
                "forceAirPrintTrustedTLSRequirement": False,
                "forceAssistantProfanityFilter": False,
                "forceAuthenticationBeforeAutoFill": False,
                "forceAutomaticDateAndTime": False,
                "forceClassroomAutomaticallyJoinClasses": False,
                "forceClassroomRequestPermissionToLeaveClasses": False,
                "forceClassroomUnpromptedAppAndDeviceLock": False,
                "forceClassroomUnpromptedScreenObservation": False,
                "forceDelayedSoftwareUpdates": True,
                "forceEncryptedBackup": False,
                "forceITunesStorePasswordEntry": False,
                "forceLimitAdTracking": False,
                "forceWatchWristDetection": False,
                "forceWiFiPowerOn": False,
                "forceWiFiWhitelisting": False,
                "ratingApps": 1000,
                "ratingMovies": 1000,
                "ratingRegion": "us",
                "ratingTVShows": 1000,
                "safariAcceptCookies": 2.0,
                "safariAllowAutoFill": True,
                "safariAllowJavaScript": True,
                "safariAllowPopups": True,
                "safariForceFraudWarning": False,
            },
            payload_uuid=payload_uuid,
            keybag_file=keybag_file,
        )
```

### hello

```
hello() -> None
```

Perform the `HelloHostIdentifier` handshake with the service.

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def hello(self) -> None:
    """Perform the ``HelloHostIdentifier`` handshake with the service."""
    await self._send_recv({"RequestType": "HelloHostIdentifier"})
```

### flush

```
flush() -> None
```

Issue a `Flush` request to the service.

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def flush(self) -> None:
    """Issue a ``Flush`` request to the service."""
    await self._send_recv({"RequestType": "Flush"})
```

### escalate

```
escalate(keybag_file: Path) -> None
```

Authenticate as a supervisor to unlock silent/supervised operations.

Runs the `Escalate` challenge-response handshake using the supervision identity, then requests keybag migration. Must be called before silent profile installation.

Parameters:

| Name          | Type   | Description                                                                                      | Default    |
| ------------- | ------ | ------------------------------------------------------------------------------------------------ | ---------- |
| `keybag_file` | `Path` | path to a PEM file containing both the supervisor certificate and its (unencrypted) private key. | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def escalate(self, keybag_file: Path) -> None:
    """
    Authenticate as a supervisor to unlock silent/supervised operations.

    Runs the ``Escalate`` challenge-response handshake using the supervision identity,
    then requests keybag migration. Must be called before silent profile installation.

    :param keybag_file: path to a PEM file containing both the supervisor certificate
        and its (unencrypted) private key.
    """
    with open(keybag_file, "rb") as f:
        keybag_data = f.read()
    private_key = serialization.load_pem_private_key(keybag_data, password=None)
    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ProfileError(
            f"The supervision keybag must hold an RSA or EC private key, not {type(private_key).__name__}"
        )
    cer = x509.load_pem_x509_certificate(keybag_data)
    public_key = cer.public_bytes(Encoding.DER)
    escalate_response = await self._send_recv({"RequestType": "Escalate", "SupervisorCertificate": public_key})
    signed_challenge = (
        PKCS7SignatureBuilder()
        .set_data(escalate_response["Challenge"])
        .add_signer(cer, private_key, hashes.SHA256())
        .sign(Encoding.DER, [PKCS7Options.Binary])
    )
    await self._send_recv({"RequestType": "EscalateResponse", "SignedRequest": signed_challenge})
    await self._send_recv({"RequestType": "ProceedWithKeybagMigration"})
```

### get_stored_profile

```
get_stored_profile(purpose: Purpose = Purpose.PostSetupInstallation) -> dict[str, Any]
```

Retrieve a profile stored on the device for a given purpose.

Parameters:

| Name      | Type      | Description                           | Default                 |
| --------- | --------- | ------------------------------------- | ----------------------- |
| `purpose` | `Purpose` | purpose the profile was stored under. | `PostSetupInstallation` |

Returns:

| Type             | Description                  |
| ---------------- | ---------------------------- |
| `dict[str, Any]` | the device's response plist. |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def get_stored_profile(self, purpose: Purpose = Purpose.PostSetupInstallation) -> dict[str, Any]:
    """
    Retrieve a profile stored on the device for a given purpose.

    :param purpose: purpose the profile was stored under.
    :returns: the device's response plist.
    """
    return await self._send_recv({"RequestType": "GetStoredProfile", "Purpose": purpose.value})
```

### store_profile

```
store_profile(profile_data: bytes, purpose: Purpose = Purpose.PostSetupInstallation) -> None
```

Store a profile on the device for later use under a given purpose.

Parameters:

| Name           | Type      | Description                         | Default                 |
| -------------- | --------- | ----------------------------------- | ----------------------- |
| `profile_data` | `bytes`   | raw profile bytes to store.         | *required*              |
| `purpose`      | `Purpose` | purpose to store the profile under. | `PostSetupInstallation` |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def store_profile(self, profile_data: bytes, purpose: Purpose = Purpose.PostSetupInstallation) -> None:
    """
    Store a profile on the device for later use under a given purpose.

    :param profile_data: raw profile bytes to store.
    :param purpose: purpose to store the profile under.
    """
    await self._send_recv({"RequestType": "StoreProfile", "ProfileData": profile_data, "Purpose": purpose.value})
```

### get_cloud_configuration

```
get_cloud_configuration() -> Optional[dict[str, Any]]
```

Retrieve the device's cloud (supervision) configuration.

Returns:

| Type                       | Description                                            |
| -------------------------- | ------------------------------------------------------ |
| `Optional[dict[str, Any]]` | the CloudConfiguration dictionary, or None if not set. |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def get_cloud_configuration(self) -> Optional[dict[str, Any]]:
    """
    Retrieve the device's cloud (supervision) configuration.

    :returns: the ``CloudConfiguration`` dictionary, or None if not set.
    """
    return (await self._send_recv({"RequestType": "GetCloudConfiguration"})).get("CloudConfiguration")
```

### set_cloud_configuration

```
set_cloud_configuration(cloud_configuration: dict[str, Any]) -> None
```

Set the device's cloud (supervision) configuration.

Parameters:

| Name                  | Type             | Description                              | Default    |
| --------------------- | ---------------- | ---------------------------------------- | ---------- |
| `cloud_configuration` | `dict[str, Any]` | cloud configuration dictionary to apply. | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def set_cloud_configuration(self, cloud_configuration: dict[str, Any]) -> None:
    """
    Set the device's cloud (supervision) configuration.

    :param cloud_configuration: cloud configuration dictionary to apply.
    """
    await self._send_recv({"RequestType": "SetCloudConfiguration", "CloudConfiguration": cloud_configuration})
```

### download_and_apply_cloud_configuration

```
download_and_apply_cloud_configuration(username: Optional[str] = None, password: Optional[str] = None) -> None
```

Ask the device to download and apply its DEP cloud configuration.

Parameters:

| Name       | Type            | Description                       | Default |
| ---------- | --------------- | --------------------------------- | ------- |
| `username` | `Optional[str]` | optional MDM enrollment username. | `None`  |
| `password` | `Optional[str]` | optional MDM enrollment password. | `None`  |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def download_and_apply_cloud_configuration(
    self, username: Optional[str] = None, password: Optional[str] = None
) -> None:
    """
    Ask the device to download and apply its DEP cloud configuration.

    :param username: optional MDM enrollment username.
    :param password: optional MDM enrollment password.
    """
    await self._send_recv({
        "RequestType": "DownloadAndApplyCloudConfiguration",
        "MDMUsername": username or "",
        "MDMPassword": password or "",
    })
```

### establish_provisional_enrollment

```
establish_provisional_enrollment(nonce: bytes) -> None
```

Establish a provisional MDM enrollment.

Parameters:

| Name    | Type    | Description       | Default    |
| ------- | ------- | ----------------- | ---------- |
| `nonce` | `bytes` | enrollment nonce. | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def establish_provisional_enrollment(self, nonce: bytes) -> None:
    """
    Establish a provisional MDM enrollment.

    :param nonce: enrollment nonce.
    """
    await self._send_recv({"RequestType": "EstablishProvisionalEnrollment", "Nonce": nonce})
```

### set_wifi_power_state

```
set_wifi_power_state(state: bool) -> None
```

Turn the device's Wi-Fi radio on or off.

Parameters:

| Name    | Type   | Description                                    | Default    |
| ------- | ------ | ---------------------------------------------- | ---------- |
| `state` | `bool` | True to power Wi-Fi on, False to power it off. | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def set_wifi_power_state(self, state: bool) -> None:
    """
    Turn the device's Wi-Fi radio on or off.

    :param state: True to power Wi-Fi on, False to power it off.
    """
    await self._send_recv({"RequestType": "SetWiFiPowerState", "PowerState": state})
```

### erase_device

```
erase_device(preserve_data_plan: bool, disallow_proximity_setup: bool) -> None
```

Erase all content and settings from the device.

The connection is normally terminated by the device as it begins erasing; that termination is suppressed so the call returns cleanly.

Parameters:

| Name                       | Type   | Description                                                  | Default    |
| -------------------------- | ------ | ------------------------------------------------------------ | ---------- |
| `preserve_data_plan`       | `bool` | whether to preserve the cellular data plan across the erase. | *required* |
| `disallow_proximity_setup` | `bool` | whether to disallow proximity setup after the erase.         | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def erase_device(self, preserve_data_plan: bool, disallow_proximity_setup: bool) -> None:
    """
    Erase all content and settings from the device.

    The connection is normally terminated by the device as it begins erasing; that
    termination is suppressed so the call returns cleanly.

    :param preserve_data_plan: whether to preserve the cellular data plan across the erase.
    :param disallow_proximity_setup: whether to disallow proximity setup after the erase.
    """
    with contextlib.suppress(ConnectionTerminatedError):
        await self._send_recv({
            "RequestType": "EraseDevice",
            "PreserveDataPlan": preserve_data_plan,
            "DisallowProximitySetup": disallow_proximity_setup,
        })
```

### get_profile_list

```
get_profile_list() -> dict[str, Any]
```

List the configuration profiles installed on the device.

Returns:

| Type             | Description                                                                          |
| ---------------- | ------------------------------------------------------------------------------------ |
| `dict[str, Any]` | the device's response plist (including ProfileMetadata keyed by profile identifier). |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def get_profile_list(self) -> dict[str, Any]:
    """
    List the configuration profiles installed on the device.

    :returns: the device's response plist (including ``ProfileMetadata`` keyed by
        profile identifier).
    """
    return await self._send_recv({"RequestType": "GetProfileList"})
```

### install_profile

```
install_profile(payload: bytes) -> None
```

Install a configuration profile, prompting the user for confirmation.

Parameters:

| Name      | Type    | Description                                 | Default    |
| --------- | ------- | ------------------------------------------- | ---------- |
| `payload` | `bytes` | raw configuration profile bytes to install. | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def install_profile(self, payload: bytes) -> None:
    """
    Install a configuration profile, prompting the user for confirmation.

    :param payload: raw configuration profile bytes to install.
    """
    await self._send_recv({"RequestType": "InstallProfile", "Payload": payload})
```

### install_profile_silent

```
install_profile_silent(keybag_file: Path, profile: bytes) -> None
```

Install a configuration profile silently, without user interaction.

Escalates to supervisor privileges with the supervision identity, then installs the profile.

Parameters:

| Name          | Type    | Description                                                                                     | Default    |
| ------------- | ------- | ----------------------------------------------------------------------------------------------- | ---------- |
| `keybag_file` | `Path`  | path to a PEM file containing the supervisor certificate and its private key, used to escalate. | *required* |
| `profile`     | `bytes` | raw configuration profile bytes to install.                                                     | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def install_profile_silent(self, keybag_file: Path, profile: bytes) -> None:
    """
    Install a configuration profile silently, without user interaction.

    Escalates to supervisor privileges with the supervision identity, then installs
    the profile.

    :param keybag_file: path to a PEM file containing the supervisor certificate and
        its private key, used to escalate.
    :param profile: raw configuration profile bytes to install.
    """
    await self.escalate(keybag_file)
    await self._send_recv({"RequestType": "InstallProfileSilent", "Payload": profile})
```

### remove_profile

```
remove_profile(identifier: str) -> None
```

Remove an installed configuration profile by its identifier.

Looks up the profile's metadata in the installed profile list and, if present, sends a signed-free removal request. Does nothing if no profiles are installed or the identifier is not currently installed.

Parameters:

| Name         | Type  | Description                                  | Default    |
| ------------ | ----- | -------------------------------------------- | ---------- |
| `identifier` | `str` | payload identifier of the profile to remove. | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def remove_profile(self, identifier: str) -> None:
    """
    Remove an installed configuration profile by its identifier.

    Looks up the profile's metadata in the installed profile list and, if present,
    sends a signed-free removal request. Does nothing if no profiles are installed or
    the identifier is not currently installed.

    :param identifier: payload identifier of the profile to remove.
    """
    profiles = await self.get_profile_list()
    if not profiles:
        return
    if identifier not in profiles["ProfileMetadata"]:
        self.logger.info(f"Trying to remove not installed profile: {identifier}")
        return
    meta = profiles["ProfileMetadata"][identifier]
    data = plistlib.dumps({
        "PayloadType": "Configuration",
        "PayloadIdentifier": identifier,
        "PayloadUUID": meta["PayloadUUID"],
        "PayloadVersion": meta["PayloadVersion"],
    })
    await self._send_recv({"RequestType": "RemoveProfile", "ProfileIdentifier": data})
```

### request_unlock_token

```
request_unlock_token() -> bytes
```

Fetch the passcode unlock token, which `clear_passcode` can later use to remove a passcode.

Requires a connection escalated with `escalate`. The device must have no passcode set: while one is active the keybag refuses to mint a token.

Returns:

| Type    | Description           |
| ------- | --------------------- |
| `bytes` | the raw unlock token. |

Raises:

| Type               | Description                    |
| ------------------ | ------------------------------ |
| `PasscodeSetError` | the device has a passcode set. |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def request_unlock_token(self) -> bytes:
    """
    Fetch the passcode unlock token, which `clear_passcode` can later use to remove a passcode.

    Requires a connection escalated with `escalate`. The device must have no passcode set:
    while one is active the keybag refuses to mint a token.

    :returns: the raw unlock token.
    :raises PasscodeSetError: the device has a passcode set.
    """
    response = await self._send_recv({"RequestType": "RequestUnlockToken"}, redact=True)
    token = response.get("UnlockToken")
    if not isinstance(token, bytes):
        raise ProfileError("The RequestUnlockToken response carries no UnlockToken")
    return token
```

### clear_passcode

```
clear_passcode(unlock_token: bytes) -> None
```

Remove the device passcode without knowing it.

Requires a connection escalated with `escalate`. The device drops this host's pairing afterwards, as it does whenever the passcode changes; re-pair with `pair_supervised`.

Parameters:

| Name           | Type    | Description                                                                      | Default    |
| -------------- | ------- | -------------------------------------------------------------------------------- | ---------- |
| `unlock_token` | `bytes` | a token previously fetched by request_unlock_token, before the passcode was set. | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def clear_passcode(self, unlock_token: bytes) -> None:
    """
    Remove the device passcode without knowing it.

    Requires a connection escalated with `escalate`. The device drops this host's pairing
    afterwards, as it does whenever the passcode changes; re-pair with `pair_supervised`.

    :param unlock_token: a token previously fetched by `request_unlock_token`, before the
        passcode was set.
    """
    await self._send_recv({"RequestType": "ClearPasscode", "UnlockToken": unlock_token}, redact=True)
```

### clear_restrictions_password

```
clear_restrictions_password() -> None
```

Clear the Screen Time (restrictions) passcode. No unlock token is needed.

Requires a connection escalated with `escalate`. iOS 27.2 always fails it with a `ScreenTimeSettingsServiceClientError`: the device's own sandbox denies mc_mobile_tunnel the lookup of `com.apple.ScreenTimeSettingsAgent.private`.

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def clear_restrictions_password(self) -> None:
    """
    Clear the Screen Time (restrictions) passcode. No unlock token is needed.

    Requires a connection escalated with `escalate`. iOS 27.2 always fails it with a
    ``ScreenTimeSettingsServiceClientError``: the device's own sandbox denies mc_mobile_tunnel
    the lookup of ``com.apple.ScreenTimeSettingsAgent.private``.
    """
    await self._send_recv({"RequestType": "ClearRestrictionsPassword"})
```

### get_security_info

```
get_security_info() -> dict[str, Any]
```

Query the device's security status. Read-only; performs no keybag operation.

Requires a connection escalated with `escalate` (unescalated, the device answers `CommandFormatError`). The reply includes `PasscodePresent`, which reliably tells whether a passcode is set, unlike lockdown's `PasswordProtected` (which reflects whether the device is currently locked), along with passcode compliance, lock grace periods, hardware encryption capabilities and management status.

Returns:

| Type             | Description                  |
| ---------------- | ---------------------------- |
| `dict[str, Any]` | the SecurityInfo dictionary. |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def get_security_info(self) -> dict[str, Any]:
    """
    Query the device's security status. Read-only; performs no keybag operation.

    Requires a connection escalated with `escalate` (unescalated, the device answers
    ``CommandFormatError``). The reply includes ``PasscodePresent``, which reliably tells
    whether a passcode is set, unlike lockdown's ``PasswordProtected`` (which reflects whether
    the device is currently locked), along with passcode compliance, lock grace periods,
    hardware encryption capabilities and management status.

    :returns: the ``SecurityInfo`` dictionary.
    """
    info = (await self._send_recv({"RequestType": "SecurityInfo"})).get("SecurityInfo")
    if not isinstance(info, dict):
        raise ProfileError("The SecurityInfo response carries no SecurityInfo dictionary")
    return cast(dict[str, Any], info)
```

### set_wallpaper

```
set_wallpaper(image: bytes, screen: WallpaperScreen = WallpaperScreen.HOME) -> None
```

Set the device wallpaper via the `Settings` request's `Wallpaper` item.

Requires a connection escalated with `escalate`. Since iOS 16 the lock and home screen wallpapers form a pair, so the device may apply the image to both regardless of `screen`.

Parameters:

| Name     | Type              | Description                                | Default    |
| -------- | ----------------- | ------------------------------------------ | ---------- |
| `image`  | `bytes`           | JPEG or PNG image bytes.                   | *required* |
| `screen` | `WallpaperScreen` | which screen(s) to apply the wallpaper to. | `HOME`     |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def set_wallpaper(self, image: bytes, screen: WallpaperScreen = WallpaperScreen.HOME) -> None:
    """
    Set the device wallpaper via the ``Settings`` request's ``Wallpaper`` item.

    Requires a connection escalated with `escalate`. Since iOS 16 the lock and home screen
    wallpapers form a pair, so the device may apply the image to both regardless of `screen`.

    :param image: JPEG or PNG image bytes.
    :param screen: which screen(s) to apply the wallpaper to.
    """
    response = await self._send_recv({
        "RequestType": "Settings",
        "Settings": [{"Item": "Wallpaper", "Where": screen.value, "Image": image}],
    })
    settings = response.get("Settings")
    if not isinstance(settings, list) or not settings or not isinstance(settings[0], dict):
        raise ProfileError(f"The wallpaper Settings response carries no item status: {response}")
    item = cast(dict[str, Any], settings[0])
    if item.get("Status") != "Acknowledged":
        raise ProfileError(f"The device rejected the wallpaper: {item}")
```

### install_wifi_profile

```
install_wifi_profile(encryption_type: str, ssid: str, password: str, auto_join: bool = True, captive_bypass: bool = False, disable_association_mac_randomization: bool = False, hidden_network: bool = False, is_hotspot: bool = False, keybag_file: Optional[Path] = None) -> None
```

Build and install a `com.apple.wifi.managed` profile for a Wi-Fi network.

Parameters:

| Name                                    | Type             | Description                                                                                            | Default    |
| --------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------ | ---------- |
| `encryption_type`                       | `str`            | Wi-Fi encryption type (e.g. WPA, WEP, None).                                                           | *required* |
| `ssid`                                  | `str`            | network SSID.                                                                                          | *required* |
| `password`                              | `str`            | network password.                                                                                      | *required* |
| `auto_join`                             | `bool`           | whether the device should automatically join the network.                                              | `True`     |
| `captive_bypass`                        | `bool`           | whether to bypass the captive portal check.                                                            | `False`    |
| `disable_association_mac_randomization` | `bool`           | whether to disable MAC-address randomization when associating.                                         | `False`    |
| `hidden_network`                        | `bool`           | whether the network is hidden (does not broadcast its SSID).                                           | `False`    |
| `is_hotspot`                            | `bool`           | whether the network is treated as a personal hotspot.                                                  | `False`    |
| `keybag_file`                           | `Optional[Path]` | when provided, install silently using this supervision identity; otherwise install with a user prompt. | `None`     |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def install_wifi_profile(
    self,
    encryption_type: str,
    ssid: str,
    password: str,
    auto_join: bool = True,
    captive_bypass: bool = False,
    disable_association_mac_randomization: bool = False,
    hidden_network: bool = False,
    is_hotspot: bool = False,
    keybag_file: Optional[Path] = None,
) -> None:
    """
    Build and install a ``com.apple.wifi.managed`` profile for a Wi-Fi network.

    :param encryption_type: Wi-Fi encryption type (e.g. ``WPA``, ``WEP``, ``None``).
    :param ssid: network SSID.
    :param password: network password.
    :param auto_join: whether the device should automatically join the network.
    :param captive_bypass: whether to bypass the captive portal check.
    :param disable_association_mac_randomization: whether to disable MAC-address
        randomization when associating.
    :param hidden_network: whether the network is hidden (does not broadcast its SSID).
    :param is_hotspot: whether the network is treated as a personal hotspot.
    :param keybag_file: when provided, install silently using this supervision identity;
        otherwise install with a user prompt.
    """
    payload_uuid = str(uuid4())
    await self.install_managed_profile(
        f"WiFi Profile For {ssid}",
        {
            "AutoJoin": auto_join,
            "CaptiveBypass": captive_bypass,
            "DisableAssociationMACRandomization": disable_association_mac_randomization,
            "EncryptionType": encryption_type,
            "HIDDEN_NETWORK": hidden_network,
            "IsHotspot": is_hotspot,
            "Password": password,
            "PayloadDescription": "Configures Wi-Fi settings",
            "PayloadDisplayName": "Wi-Fi",
            "PayloadIdentifier": f"com.apple.wifi.managed.{payload_uuid}",
            "PayloadType": "com.apple.wifi.managed",
            "PayloadUUID": payload_uuid,
            "PayloadVersion": 1,
            "ProxyType": "None",
            "SSID_STR": ssid,
        },
        keybag_file=keybag_file,
    )
```

### install_http_proxy

```
install_http_proxy(server: str, server_port: int, keybag_file: Optional[Path] = None) -> None
```

Build and install a global manual HTTP-proxy profile.

The profile uses the fixed `GLOBAL_HTTP_PROXY_UUID` so it can later be removed by `remove_http_proxy`.

Parameters:

| Name          | Type             | Description                                                                                            | Default    |
| ------------- | ---------------- | ------------------------------------------------------------------------------------------------------ | ---------- |
| `server`      | `str`            | proxy server host.                                                                                     | *required* |
| `server_port` | `int`            | proxy server port.                                                                                     | *required* |
| `keybag_file` | `Optional[Path]` | when provided, install silently using this supervision identity; otherwise install with a user prompt. | `None`     |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def install_http_proxy(self, server: str, server_port: int, keybag_file: Optional[Path] = None) -> None:
    """
    Build and install a global manual HTTP-proxy profile.

    The profile uses the fixed `GLOBAL_HTTP_PROXY_UUID` so it can later be removed by
    `remove_http_proxy`.

    :param server: proxy server host.
    :param server_port: proxy server port.
    :param keybag_file: when provided, install silently using this supervision identity;
        otherwise install with a user prompt.
    """
    payload_uuid = str(uuid4())
    await self.install_managed_profile(
        f"HTTP Proxy for {server}:{server_port}",
        {
            "PayloadDescription": "Global HTTP Proxy",
            "PayloadDisplayName": "Global HTTP Proxy",
            "PayloadIdentifier": f"com.apple.proxy.http.global.{payload_uuid}",
            "PayloadType": "com.apple.proxy.http.global",
            "PayloadUUID": payload_uuid,
            "PayloadVersion": 1,
            "ProxyCaptiveLoginAllowed": False,
            "ProxyServer": server,
            "ProxyServerPort": server_port,
            "ProxyType": "Manual",
        },
        payload_uuid=GLOBAL_HTTP_PROXY_UUID,
        keybag_file=keybag_file,
    )
```

### remove_http_proxy

```
remove_http_proxy() -> None
```

Remove the global HTTP-proxy profile previously installed by `install_http_proxy`.

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def remove_http_proxy(self) -> None:
    """Remove the global HTTP-proxy profile previously installed by `install_http_proxy`."""
    await self.remove_profile(GLOBAL_HTTP_PROXY_UUID)
```

### supervise

```
supervise(organization: str, keybag_file: Path) -> None
```

Place the device under supervision by writing a cloud configuration.

Sets a supervised cloud configuration that names the organization, registers the supervisor certificate, and skips all setup-assistant panes.

Parameters:

| Name           | Type   | Description                                                                                                                      | Default    |
| -------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `organization` | `str`  | organization name recorded in the cloud configuration.                                                                           | *required* |
| `keybag_file`  | `Path` | path to a PEM file containing the supervisor certificate whose DER public bytes are registered as a supervisor host certificate. | *required* |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def supervise(self, organization: str, keybag_file: Path) -> None:
    """
    Place the device under supervision by writing a cloud configuration.

    Sets a supervised cloud configuration that names the organization, registers the
    supervisor certificate, and skips all setup-assistant panes.

    :param organization: organization name recorded in the cloud configuration.
    :param keybag_file: path to a PEM file containing the supervisor certificate whose
        DER public bytes are registered as a supervisor host certificate.
    """
    cer = x509.load_pem_x509_certificate(keybag_file.read_bytes())
    public_key = cer.public_bytes(Encoding.DER)
    await self.set_cloud_configuration({
        "AllowPairing": True,
        "CloudConfigurationUIComplete": True,
        "ConfigurationSource": 2,
        "ConfigurationWasApplied": True,
        "IsMDMUnremovable": False,
        "IsMandatory": True,
        "IsMultiUser": False,
        "IsSupervised": True,
        "OrganizationMagic": str(uuid4()),
        "OrganizationName": organization,
        "PostSetupProfileWasInstalled": True,
        "SkipSetup": [
            "Location",
            "Restore",
            "SIMSetup",
            "Android",
            "AppleID",
            "IntendedUser",
            "TOS",
            "Siri",
            "ScreenTime",
            "Diagnostics",
            "SoftwareUpdate",
            "Passcode",
            "Biometric",
            "Payment",
            "Zoom",
            "DisplayTone",
            "MessagingActivationUsingPhoneNumber",
            "HomeButtonSensitivity",
            "CloudStorage",
            "ScreenSaver",
            "TapToSetup",
            "Keyboard",
            "PreferredLanguage",
            "SpokenLanguage",
            "WatchMigration",
            "OnBoarding",
            "TVProviderSignIn",
            "TVHomeScreenSync",
            "Privacy",
            "TVRoom",
            "iMessageAndFaceTime",
            "AppStore",
            "Safety",
            "Multitasking",
            "ActionButton",
            "TermsOfAddress",
            "AccessibilityAppearance",
            "Welcome",
            "Appearance",
            "RestoreCompleted",
            "UpdateCompleted",
            "WiFi",
            "Display",
            "Tone",
            "LanguageAndLocale",
            "TouchID",
            "TrueToneDisplay",
            "FileVault",
            "iCloudStorage",
            "iCloudDiagnostics",
            "Registration",
            "DeviceToDeviceMigration",
            "UnlockWithWatch",
            "Accessibility",
            "All",
            "ExpressLanguage",
            "Language",
            "N/A",
            "Region",
            "Avatar",
            "DeviceProtection",
            "Key",
            "LockdownMode",
            "Wallpaper",
            "PrivacySubtitle",
            "SecuritySubtitle",
            "DataSubtitle",
            "AppleIDSubtitle",
            "AppearanceSubtitle",
            "PreferredLang",
            "OnboardingSubtitle",
            "AppleTVSubtitle",
            "Intelligence",
            "WebContentFiltering",
            "CameraButton",
            "AdditionalPrivacySettings",
            "EnableLockdownMode",
            "OSShowcase",
            "SafetyAndHandling",
            "Tips",
            "AgeBasedSafetySettings",
            "LiquidGlass",
            "AgeAssurance",
            "DeviceFeaturesTour",
        ],
        "SupervisorHostCertificates": [public_key],
    })
```

### install_managed_profile

```
install_managed_profile(display_name: str, payload_content: dict[str, Any], payload_uuid: str = str(uuid4()), keybag_file: Optional[Path] = None) -> None
```

Wrap a single payload in a `Configuration` profile and install it.

Parameters:

| Name              | Type             | Description                                                                                            | Default        |
| ----------------- | ---------------- | ------------------------------------------------------------------------------------------------------ | -------------- |
| `display_name`    | `str`            | profile display name.                                                                                  | *required*     |
| `payload_content` | `dict[str, Any]` | the inner payload dictionary to wrap.                                                                  | *required*     |
| `payload_uuid`    | `str`            | UUID used as both the profile identifier and UUID.                                                     | `str(uuid4())` |
| `keybag_file`     | `Optional[Path]` | when provided, install silently using this supervision identity; otherwise install with a user prompt. | `None`         |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def install_managed_profile(
    self,
    display_name: str,
    payload_content: dict[str, Any],
    payload_uuid: str = str(uuid4()),
    keybag_file: Optional[Path] = None,
) -> None:
    """
    Wrap a single payload in a ``Configuration`` profile and install it.

    :param display_name: profile display name.
    :param payload_content: the inner payload dictionary to wrap.
    :param payload_uuid: UUID used as both the profile identifier and UUID.
    :param keybag_file: when provided, install silently using this supervision identity;
        otherwise install with a user prompt.
    """
    profile_data = plistlib.dumps({
        "PayloadContent": [payload_content],
        "PayloadDisplayName": display_name,
        "PayloadIdentifier": payload_uuid,
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": payload_uuid,
        "PayloadVersion": 1,
    })
    if keybag_file is not None:
        await self.install_profile_silent(keybag_file, profile_data)
    else:
        await self.install_profile(profile_data)
```

### install_restrictions_profile

```
install_restrictions_profile(enforced_software_update_delay: int = 0, payload_uuid: str = GLOBAL_RESTRICTIONS_UUID, keybag_file: Optional[Path] = None) -> None
```

Build and install a `com.apple.applicationaccess` restrictions profile.

The profile permits essentially every restricted capability; only the software update delay is parameterized.

Parameters:

| Name                             | Type             | Description                                                                                            | Default                    |
| -------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------ | -------------------------- |
| `enforced_software_update_delay` | `int`            | number of days to delay visibility of software updates.                                                | `0`                        |
| `payload_uuid`                   | `str`            | UUID used as the profile identifier and UUID.                                                          | `GLOBAL_RESTRICTIONS_UUID` |
| `keybag_file`                    | `Optional[Path]` | when provided, install silently using this supervision identity; otherwise install with a user prompt. | `None`                     |

Source code in `pymobiledevice3/services/mobile_config.py`

```
async def install_restrictions_profile(
    self,
    enforced_software_update_delay: int = 0,
    payload_uuid: str = GLOBAL_RESTRICTIONS_UUID,
    keybag_file: Optional[Path] = None,
) -> None:
    """
    Build and install a ``com.apple.applicationaccess`` restrictions profile.

    The profile permits essentially every restricted capability; only the software
    update delay is parameterized.

    :param enforced_software_update_delay: number of days to delay visibility of
        software updates.
    :param payload_uuid: UUID used as the profile identifier and UUID.
    :param keybag_file: when provided, install silently using this supervision identity;
        otherwise install with a user prompt.
    """
    await self.install_managed_profile(
        "Restrictions",
        {
            "PayloadDescription": "Configures restrictions",
            "PayloadDisplayName": "Restrictions",
            "PayloadIdentifier": f"com.apple.applicationaccess.{payload_uuid}",
            "PayloadType": "com.apple.applicationaccess",
            "PayloadUUID": payload_uuid,
            "PayloadVersion": 1,
            "allowActivityContinuation": True,
            "allowAddingGameCenterFriends": True,
            "allowAirPlayIncomingRequests": True,
            "allowAirPrint": True,
            "allowAirPrintCredentialsStorage": True,
            "allowAirPrintiBeaconDiscovery": True,
            "allowAppCellularDataModification": True,
            "allowAppClips": True,
            "allowAppInstallation": True,
            "allowAppRemoval": True,
            "allowApplePersonalizedAdvertising": True,
            "allowAssistant": True,
            "allowAssistantWhileLocked": True,
            "allowAutoCorrection": True,
            "allowAutoUnlock": True,
            "allowAutomaticAppDownloads": True,
            "allowBluetoothModification": True,
            "allowBookstore": True,
            "allowBookstoreErotica": True,
            "allowCamera": True,
            "allowCellularPlanModification": True,
            "allowChat": True,
            "allowCloudBackup": True,
            "allowCloudDocumentSync": True,
            "allowCloudPhotoLibrary": True,
            "allowContinuousPathKeyboard": True,
            "allowDefinitionLookup": True,
            "allowDeviceNameModification": True,
            "allowDeviceSleep": True,
            "allowDictation": True,
            "allowESIMModification": True,
            "allowEnablingRestrictions": True,
            "allowEnterpriseAppTrust": True,
            "allowEnterpriseBookBackup": True,
            "allowEnterpriseBookMetadataSync": True,
            "allowEraseContentAndSettings": True,
            "allowExplicitContent": True,
            "allowFilesNetworkDriveAccess": True,
            "allowFilesUSBDriveAccess": True,
            "allowFindMyDevice": True,
            "allowFindMyFriends": True,
            "allowFingerprintForUnlock": True,
            "allowFingerprintModification": True,
            "allowGameCenter": True,
            "allowGlobalBackgroundFetchWhenRoaming": True,
            "allowInAppPurchases": True,
            "allowKeyboardShortcuts": True,
            "allowManagedAppsCloudSync": True,
            "allowMultiplayerGaming": True,
            "allowMusicService": True,
            "allowNews": True,
            "allowNotificationsModification": True,
            "allowOpenFromManagedToUnmanaged": True,
            "allowOpenFromUnmanagedToManaged": True,
            "allowPairedWatch": True,
            "allowPassbookWhileLocked": True,
            "allowPasscodeModification": True,
            "allowPasswordAutoFill": True,
            "allowPasswordProximityRequests": True,
            "allowPasswordSharing": True,
            "allowPersonalHotspotModification": True,
            "allowPhotoStream": True,
            "allowPredictiveKeyboard": True,
            "allowProximitySetupToNewDevice": True,
            "allowRadioService": True,
            "allowRemoteAppPairing": True,
            "allowRemoteScreenObservation": True,
            "allowSafari": True,
            "allowScreenShot": True,
            "allowSharedStream": True,
            "allowSpellCheck": True,
            "allowSpotlightInternetResults": True,
            "allowSystemAppRemoval": True,
            "allowUIAppInstallation": True,
            "allowUIConfigurationProfileInstallation": True,
            "allowUSBRestrictedMode": True,
            "allowUnpairedExternalBootToRecovery": False,
            "allowUntrustedTLSPrompt": True,
            "allowVPNCreation": True,
            "allowVideoConferencing": True,
            "allowVoiceDialing": True,
            "allowWallpaperModification": True,
            "allowiTunes": True,
            "enforcedSoftwareUpdateDelay": enforced_software_update_delay,
            "forceAirDropUnmanaged": False,
            "forceAirPrintTrustedTLSRequirement": False,
            "forceAssistantProfanityFilter": False,
            "forceAuthenticationBeforeAutoFill": False,
            "forceAutomaticDateAndTime": False,
            "forceClassroomAutomaticallyJoinClasses": False,
            "forceClassroomRequestPermissionToLeaveClasses": False,
            "forceClassroomUnpromptedAppAndDeviceLock": False,
            "forceClassroomUnpromptedScreenObservation": False,
            "forceDelayedSoftwareUpdates": True,
            "forceEncryptedBackup": False,
            "forceITunesStorePasswordEntry": False,
            "forceLimitAdTracking": False,
            "forceWatchWristDetection": False,
            "forceWiFiPowerOn": False,
            "forceWiFiWhitelisting": False,
            "ratingApps": 1000,
            "ratingMovies": 1000,
            "ratingRegion": "us",
            "ratingTVShows": 1000,
            "safariAcceptCookies": 2.0,
            "safariAllowAutoFill": True,
            "safariAllowJavaScript": True,
            "safariAllowPopups": True,
            "safariForceFraudWarning": False,
        },
        payload_uuid=payload_uuid,
        keybag_file=keybag_file,
    )
```

## pymobiledevice3.services.misagent.MisagentService

Bases: `LockdownService`

Manage provisioning profiles installed on the device.

Wraps the `com.apple.misagent` lockdown service to install, remove and enumerate provisioning profiles. Being a `LockdownService`, instances may be used as an async context manager::

```
async with MisagentService(lockdown) as misagent:
    profiles = await misagent.copy_all()
```

Source code in `pymobiledevice3/services/misagent.py`

```
class MisagentService(LockdownService):
    """
    Manage provisioning profiles installed on the device.

    Wraps the ``com.apple.misagent`` lockdown service to install, remove and enumerate
    provisioning profiles. Being a `LockdownService`, instances may be used as an async
    context manager::

        async with MisagentService(lockdown) as misagent:
            profiles = await misagent.copy_all()
    """

    SERVICE_NAME = "com.apple.misagent"
    RSD_SERVICE_NAME = "com.apple.misagent.shim.remote"

    async def install(self, plist: IO[bytes]) -> dict[str, Any]:
        """
        Install a provisioning profile on the device.

        :param plist: stream whose contents are the raw provisioning profile to install;
            read in full and sent to the device.
        :returns: the device's response plist.
        :raises PyMobileDevice3Exception: if the device reports a non-zero status.
        """
        response = await self.service.send_recv_plist({
            "MessageType": "Install",
            "Profile": plist.read(),
            "ProfileType": "Provisioning",
        })
        if response["Status"]:
            raise PyMobileDevice3Exception(f"The device refused to install the provisioning profile: {response}")

        return response

    async def remove(self, profile_id: str) -> dict[str, Any]:
        """
        Remove an installed provisioning profile.

        :param profile_id: identifier of the profile to remove.
        :returns: the device's response plist.
        :raises PyMobileDevice3Exception: if the device reports a non-zero status.
        """
        response = await self.service.send_recv_plist({
            "MessageType": "Remove",
            "ProfileID": profile_id,
            "ProfileType": "Provisioning",
        })
        if response["Status"]:
            raise PyMobileDevice3Exception(
                f"The device refused to remove provisioning profile {profile_id}: {response}"
            )

        return response

    async def copy_all(self) -> list[ProvisioningProfile]:
        """
        Retrieve all provisioning profiles installed on the device.

        :returns: list of `ProvisioningProfile` objects, one per installed profile.
        :raises PyMobileDevice3Exception: if the device reports a non-zero status.
        """
        response = await self.service.send_recv_plist({"MessageType": "CopyAll", "ProfileType": "Provisioning"})
        if response["Status"]:
            raise PyMobileDevice3Exception(f"The device refused to list the provisioning profiles: {response}")

        return [ProvisioningProfile(p) for p in cast(list[bytes], response["Payload"])]
```

### install

```
install(plist: IO[bytes]) -> dict[str, Any]
```

Install a provisioning profile on the device.

Parameters:

| Name    | Type        | Description                                                                                             | Default    |
| ------- | ----------- | ------------------------------------------------------------------------------------------------------- | ---------- |
| `plist` | `IO[bytes]` | stream whose contents are the raw provisioning profile to install; read in full and sent to the device. | *required* |

Returns:

| Type             | Description                  |
| ---------------- | ---------------------------- |
| `dict[str, Any]` | the device's response plist. |

Raises:

| Type                       | Description                              |
| -------------------------- | ---------------------------------------- |
| `PyMobileDevice3Exception` | if the device reports a non-zero status. |

Source code in `pymobiledevice3/services/misagent.py`

```
async def install(self, plist: IO[bytes]) -> dict[str, Any]:
    """
    Install a provisioning profile on the device.

    :param plist: stream whose contents are the raw provisioning profile to install;
        read in full and sent to the device.
    :returns: the device's response plist.
    :raises PyMobileDevice3Exception: if the device reports a non-zero status.
    """
    response = await self.service.send_recv_plist({
        "MessageType": "Install",
        "Profile": plist.read(),
        "ProfileType": "Provisioning",
    })
    if response["Status"]:
        raise PyMobileDevice3Exception(f"The device refused to install the provisioning profile: {response}")

    return response
```

### remove

```
remove(profile_id: str) -> dict[str, Any]
```

Remove an installed provisioning profile.

Parameters:

| Name         | Type  | Description                          | Default    |
| ------------ | ----- | ------------------------------------ | ---------- |
| `profile_id` | `str` | identifier of the profile to remove. | *required* |

Returns:

| Type             | Description                  |
| ---------------- | ---------------------------- |
| `dict[str, Any]` | the device's response plist. |

Raises:

| Type                       | Description                              |
| -------------------------- | ---------------------------------------- |
| `PyMobileDevice3Exception` | if the device reports a non-zero status. |

Source code in `pymobiledevice3/services/misagent.py`

```
async def remove(self, profile_id: str) -> dict[str, Any]:
    """
    Remove an installed provisioning profile.

    :param profile_id: identifier of the profile to remove.
    :returns: the device's response plist.
    :raises PyMobileDevice3Exception: if the device reports a non-zero status.
    """
    response = await self.service.send_recv_plist({
        "MessageType": "Remove",
        "ProfileID": profile_id,
        "ProfileType": "Provisioning",
    })
    if response["Status"]:
        raise PyMobileDevice3Exception(
            f"The device refused to remove provisioning profile {profile_id}: {response}"
        )

    return response
```

### copy_all

```
copy_all() -> list[ProvisioningProfile]
```

Retrieve all provisioning profiles installed on the device.

Returns:

| Type                        | Description                                                     |
| --------------------------- | --------------------------------------------------------------- |
| `list[ProvisioningProfile]` | list of ProvisioningProfile objects, one per installed profile. |

Raises:

| Type                       | Description                              |
| -------------------------- | ---------------------------------------- |
| `PyMobileDevice3Exception` | if the device reports a non-zero status. |

Source code in `pymobiledevice3/services/misagent.py`

```
async def copy_all(self) -> list[ProvisioningProfile]:
    """
    Retrieve all provisioning profiles installed on the device.

    :returns: list of `ProvisioningProfile` objects, one per installed profile.
    :raises PyMobileDevice3Exception: if the device reports a non-zero status.
    """
    response = await self.service.send_recv_plist({"MessageType": "CopyAll", "ProfileType": "Provisioning"})
    if response["Status"]:
        raise PyMobileDevice3Exception(f"The device refused to list the provisioning profiles: {response}")

    return [ProvisioningProfile(p) for p in cast(list[bytes], response["Payload"])]
```

## pymobiledevice3.services.file_relay.FileRelayService

Bases: `LockdownService`

Retrieve diagnostic data archives from the device.

Wraps the legacy `com.apple.mobile.file_relay` service, which bundles one or more named data sources (see `SRCFILES` for known source names) into a single gzip-compressed CPIO archive returned by `request_sources`.

Being a `LockdownService`, instances may be used as an async context manager::

```
async with FileRelayService(lockdown) as file_relay:
    archive = await file_relay.request_sources(["UserDatabases"])
```

Source code in `pymobiledevice3/services/file_relay.py`

```
class FileRelayService(LockdownService):
    """
    Retrieve diagnostic data archives from the device.

    Wraps the legacy ``com.apple.mobile.file_relay`` service, which bundles one or more
    named data sources (see `SRCFILES` for known source names) into a single gzip-compressed
    CPIO archive returned by `request_sources`.

    Being a `LockdownService`, instances may be used as an async context manager::

        async with FileRelayService(lockdown) as file_relay:
            archive = await file_relay.request_sources(["UserDatabases"])
    """

    SERVICE_NAME = "com.apple.mobile.file_relay"

    def __init__(self, lockdown: LockdownServiceProvider):
        super().__init__(lockdown, self.SERVICE_NAME)
        self.packet_num = 0

    async def stop_session(self):
        """Close the underlying service connection."""
        self.logger.info("Disconecting...")
        await self.service.close()

    async def request_sources(self, sources: Optional[list[str]] = None):
        """
        Request one or more data sources and return the combined archive.

        Sends the requested source names and, once the device acknowledges, reads the
        full response stream into memory.

        :param sources: list of source names to request (see `SRCFILES` for known names);
            defaults to ``["UserDatabases"]`` when not given.
        :returns: the gzip-compressed CPIO archive bytes on success, or None if the device
            did not acknowledge the request.
        """
        if sources is None:
            sources = ["UserDatabases"]
        await self.service.send_plist({"Sources": sources})
        while 1:
            res = await self.service.recv_plist()
            if res:
                s = res.get("Status")
                if s == "Acknowledged":
                    z = b""
                    while True:
                        x = await self.service.recv_any()
                        if not x:
                            break
                        z += x
                    return z
                else:
                    print(res.get("Error"))
                    break
        return None
```

### stop_session

```
stop_session()
```

Close the underlying service connection.

Source code in `pymobiledevice3/services/file_relay.py`

```
async def stop_session(self):
    """Close the underlying service connection."""
    self.logger.info("Disconecting...")
    await self.service.close()
```

### request_sources

```
request_sources(sources: Optional[list[str]] = None)
```

Request one or more data sources and return the combined archive.

Sends the requested source names and, once the device acknowledges, reads the full response stream into memory.

Parameters:

| Name      | Type                  | Description                                                                                                   | Default |
| --------- | --------------------- | ------------------------------------------------------------------------------------------------------------- | ------- |
| `sources` | `Optional[list[str]]` | list of source names to request (see SRCFILES for known names); defaults to ["UserDatabases"] when not given. | `None`  |

Returns:

| Type | Description                                                                                               |
| ---- | --------------------------------------------------------------------------------------------------------- |
|      | the gzip-compressed CPIO archive bytes on success, or None if the device did not acknowledge the request. |

Source code in `pymobiledevice3/services/file_relay.py`

```
async def request_sources(self, sources: Optional[list[str]] = None):
    """
    Request one or more data sources and return the combined archive.

    Sends the requested source names and, once the device acknowledges, reads the
    full response stream into memory.

    :param sources: list of source names to request (see `SRCFILES` for known names);
        defaults to ``["UserDatabases"]`` when not given.
    :returns: the gzip-compressed CPIO archive bytes on success, or None if the device
        did not acknowledge the request.
    """
    if sources is None:
        sources = ["UserDatabases"]
    await self.service.send_plist({"Sources": sources})
    while 1:
        res = await self.service.recv_plist()
        if res:
            s = res.get("Status")
            if s == "Acknowledged":
                z = b""
                while True:
                    x = await self.service.recv_any()
                    if not x:
                        break
                    z += x
                return z
            else:
                print(res.get("Error"))
                break
    return None
```

## Install records (iOS 17+)

`InstallCoordinationProxyService` is a RemoteXPC service: construct it with a `RemoteServiceDiscoveryService` (it requires an RSD tunnel), not a lockdown client.

## pymobiledevice3.services.install_coordination_proxy.InstallCoordinationProxyService

Bases: `RemoteService`

Query the install-coordination proxy (`com.apple.remote.installcoordination_proxy`).

Unlike most RemoteXPC services this one does not use XPC request/reply correlation: the daemon answers by sending fresh messages on the connection, so replies are read off the stream. Every request must carry `RequestVersion` and `ProtocolVersion`; if either is missing or wrong the daemon cancels the connection without answering.

Only the read-only `Query` request is implemented. The daemon also exposes `Install` (which streams its payload over an out-of-band XPC file transfer), `Uninstall` and `RevertStash`.

Requires an iOS 17+ RSD tunnel. Use as an async context manager.

Source code in `pymobiledevice3/services/install_coordination_proxy.py`

```
class InstallCoordinationProxyService(RemoteService):
    """
    Query the install-coordination proxy (``com.apple.remote.installcoordination_proxy``).

    Unlike most RemoteXPC services this one does not use XPC request/reply correlation: the daemon
    answers by sending fresh messages on the connection, so replies are read off the stream. Every
    request must carry ``RequestVersion`` and ``ProtocolVersion``; if either is missing or wrong the
    daemon cancels the connection without answering.

    Only the read-only ``Query`` request is implemented. The daemon also exposes ``Install``
    (which streams its payload over an out-of-band XPC file transfer), ``Uninstall`` and
    ``RevertStash``.

    Requires an iOS 17+ RSD tunnel. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.remote.installcoordination_proxy"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def query(self, bundle_identifier: str) -> InstallRecord:
        """
        Look up the install record for an installed application.

        :param bundle_identifier: bundle identifier to look up, e.g. ``com.apple.Preferences``.
        :raises InstallCoordinationError: if the application is unknown or the daemon reported a failure.
        """
        await self.service.send_request({
            "RequestVersion": XpcUInt64Type(REQUEST_VERSION),
            "ProtocolVersion": XpcUInt64Type(PROTOCOL_VERSION),
            "RequestType": XpcUInt64Type(REQUEST_TYPE_QUERY),
            "BundleID": bundle_identifier,
        })
        response = await self.service.receive_response()
        if not response.get("Success"):
            error_data = response.get("ErrorData")
            detail = _describe_error_data(error_data) if isinstance(error_data, bytes) else "no error detail"
            raise InstallCoordinationError(f"query failed for {bundle_identifier}: {detail}")
        return InstallRecord(
            db_uuid=response["DBUUID"],
            db_sequence=response["DBSequence"],
            install_path=decode_url(response.get("InstallPath")),
            persistent_identifier=response["PersistentIdentifier"],
        )
```

### query

```
query(bundle_identifier: str) -> InstallRecord
```

Look up the install record for an installed application.

Parameters:

| Name                | Type  | Description                                               | Default    |
| ------------------- | ----- | --------------------------------------------------------- | ---------- |
| `bundle_identifier` | `str` | bundle identifier to look up, e.g. com.apple.Preferences. | *required* |

Raises:

| Type                       | Description                                                     |
| -------------------------- | --------------------------------------------------------------- |
| `InstallCoordinationError` | if the application is unknown or the daemon reported a failure. |

Source code in `pymobiledevice3/services/install_coordination_proxy.py`

```
async def query(self, bundle_identifier: str) -> InstallRecord:
    """
    Look up the install record for an installed application.

    :param bundle_identifier: bundle identifier to look up, e.g. ``com.apple.Preferences``.
    :raises InstallCoordinationError: if the application is unknown or the daemon reported a failure.
    """
    await self.service.send_request({
        "RequestVersion": XpcUInt64Type(REQUEST_VERSION),
        "ProtocolVersion": XpcUInt64Type(PROTOCOL_VERSION),
        "RequestType": XpcUInt64Type(REQUEST_TYPE_QUERY),
        "BundleID": bundle_identifier,
    })
    response = await self.service.receive_response()
    if not response.get("Success"):
        error_data = response.get("ErrorData")
        detail = _describe_error_data(error_data) if isinstance(error_data, bytes) else "no error detail"
        raise InstallCoordinationError(f"query failed for {bundle_identifier}: {detail}")
    return InstallRecord(
        db_uuid=response["DBUUID"],
        db_sequence=response["DBSequence"],
        install_path=decode_url(response.get("InstallPath")),
        persistent_identifier=response["PersistentIdentifier"],
    )
```

## pymobiledevice3.services.install_coordination_proxy.InstallRecord

The LaunchServices install record the daemon holds for an installed application.

Source code in `pymobiledevice3/services/install_coordination_proxy.py`

```
@dataclasses.dataclass
class InstallRecord:
    """The LaunchServices install record the daemon holds for an installed application."""

    db_uuid: str
    db_sequence: int
    install_path: Optional[str]
    persistent_identifier: bytes
```
