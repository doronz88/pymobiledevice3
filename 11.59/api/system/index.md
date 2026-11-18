# System & device services

Services for device state, activation, notifications, power, and recovery.

## pymobiledevice3.services.amfi.AmfiService

Control Developer Mode on the device through the AMFI (Apple Mobile File Integrity) lockdown service.

Each method opens its own connection to the `com.apple.amfi.lockdown` service and sends a single `action` request. The actions correspond to revealing the Developer Mode toggle in Settings, requesting that it be enabled, confirming the post-restart prompt, and trusting the developer app signer of an installed provisioning profile.

Source code in `pymobiledevice3/services/amfi.py`

```
class AmfiService:
    """
    Control Developer Mode on the device through the AMFI (Apple Mobile File Integrity) lockdown service.

    Each method opens its own connection to the ``com.apple.amfi.lockdown`` service and sends a single
    ``action`` request. The actions correspond to revealing the Developer Mode toggle in Settings,
    requesting that it be enabled, confirming the post-restart prompt, and trusting the developer
    app signer of an installed provisioning profile.
    """

    DEVELOPER_MODE_REVEAL = 0
    DEVELOPER_MODE_ENABLE = 1
    DEVELOPER_MODE_ACCEPT = 2
    TRUST_APP_SIGNER = 4

    SERVICE_NAME = "com.apple.amfi.lockdown"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        self._lockdown = lockdown
        self._logger = logging.getLogger(self.__module__)

    async def reveal_developer_mode_option_in_ui(self):
        """
        Make the Developer Mode toggle visible in the device's Settings UI.

        Sends the reveal action, which causes AMFI to create an empty file at its
        ``AMFIShowOverridePath``.

        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_REVEAL})
        if not resp.get("success"):
            raise PyMobileDevice3Exception(f"The device did not reveal the Developer Mode setting: {resp}")

    async def enable_developer_mode(
        self, enable_post_restart: bool = True, reconnect_timeout: float = DEVELOPER_MODE_RECONNECT_TIMEOUT
    ):
        """
        Request that Developer Mode be enabled on the device.

        Sends the enable action. The device then reboots to apply the change. When
        ``enable_post_restart`` is True, this method keeps the connection alive via a heartbeat,
        waits for the same device (by UDID) to disconnect and reconnect over usbmux, and then answers
        the post-restart confirmation prompt by calling `enable_developer_mode_post_restart`.

        The reconnect always goes through usbmux, since the RSD tunnel or TCP connection the request
        was sent over does not survive the reboot. A device reached without usbmux (e.g. ``--rsd`` to a
        device that usbmuxd does not list) cannot be reconnected to, so the prompt has to be confirmed
        on the device itself.

        :param enable_post_restart: when True, wait for the device to restart and automatically
            confirm the final prompt; when False, return immediately after the enable request.
        :param reconnect_timeout: maximum time in seconds to wait for the device to come back after it
            restarts.
        :raises DeviceHasPasscodeSetError: if the device has a passcode set, which blocks the operation.
        :raises AmfiError: if AMFI returns any other error.
        :raises DeveloperModeError: if the enable or post-restart confirmation request does not succeed,
            or if the device cannot be reconnected to over usbmux after it restarts.
        """
        async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_ENABLE})
        error = resp.get("Error")

        if error is not None:
            if error == "Device has a passcode set":
                raise DeviceHasPasscodeSetError()
            raise AmfiError(f"AMFI refused to enable Developer Mode: {error}")

        if not resp.get("success"):
            raise DeveloperModeError(f"The device did not enable Developer Mode: {resp}")

        if not enable_post_restart:
            return

        udid = self._lockdown.udid
        confirm_on_device = "Once it has restarted, unlock it and confirm the Developer Mode prompt on the device."
        over_usbmux = isinstance(self._lockdown, UsbmuxLockdownClient)
        usbmux_address = self._lockdown.usbmux_address if isinstance(self._lockdown, UsbmuxLockdownClient) else None
        if udid is None or not (over_usbmux or await self._listed_by_usbmux(udid)):
            # Reached over RSD/TCP only: nothing to reconnect through once the reboot tears that down.
            raise DeveloperModeError(
                "Developer Mode was requested and the device is restarting, but it is not connected through "
                f"usbmux, so the post-restart prompt cannot be confirmed from here. {confirm_on_device}"
            )

        try:
            await HeartbeatService(self._lockdown).start()
        except (ConnectionTerminatedError, BrokenPipeError, IncompleteReadError):
            self._logger.debug("device disconnected, awaiting reconnect")

        lockdown = await retry_create_using_usbmux(reconnect_timeout, serial=udid, usbmux_address=usbmux_address)
        if lockdown is None:
            raise DeveloperModeError(
                f"Device {udid} did not reconnect over usbmux within {reconnect_timeout:.0f} seconds of "
                f"restarting. {confirm_on_device}"
            )
        self._lockdown = lockdown
        await self.enable_developer_mode_post_restart()

    @staticmethod
    async def _listed_by_usbmux(udid: str) -> bool:
        try:
            return await select_device(udid) is not None
        except MuxException:
            return False

    async def enable_developer_mode_post_restart(self):
        """
        Confirm the Developer Mode prompt shown after the device restarts.

        Sends the accept action, answering the post-restart confirmation prompt affirmatively.

        :raises DeveloperModeError: if the device does not report success.
        """
        async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_ACCEPT})
        if not resp.get("success"):
            raise DeveloperModeError(f"The device did not confirm Developer Mode after restarting: {resp}")

    async def trust_app_signer(self, profile_uuid: str) -> Optional[bool]:
        """
        Trust the developer app signer of an installed provisioning profile.

        Equivalent to tapping "Trust" under Settings > General > VPN & Device Management.

        :param profile_uuid: UUID of the installed provisioning profile whose signer should be trusted.
        :return: The ``status`` value of the reply, or None if the device omitted it.
        :raises AmfiError: if the device does not report success (e.g. no profile with that UUID).
        """
        async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            resp = await service.send_recv_plist({"action": self.TRUST_APP_SIGNER, "input_profile_uuid": profile_uuid})
        error = resp.get("Error")
        if error is not None:
            raise AmfiError(f"AMFI refused to trust the app signer of profile {profile_uuid}: {error}")
        if not resp.get("success"):
            raise AmfiError(f"The device did not trust the app signer of profile {profile_uuid}: {resp}")
        status = resp.get("status")
        return status if isinstance(status, bool) else None
```

### reveal_developer_mode_option_in_ui

```
reveal_developer_mode_option_in_ui()
```

Make the Developer Mode toggle visible in the device's Settings UI.

Sends the reveal action, which causes AMFI to create an empty file at its `AMFIShowOverridePath`.

Raises:

| Type                       | Description                            |
| -------------------------- | -------------------------------------- |
| `PyMobileDevice3Exception` | if the device does not report success. |

Source code in `pymobiledevice3/services/amfi.py`

```
async def reveal_developer_mode_option_in_ui(self):
    """
    Make the Developer Mode toggle visible in the device's Settings UI.

    Sends the reveal action, which causes AMFI to create an empty file at its
    ``AMFIShowOverridePath``.

    :raises PyMobileDevice3Exception: if the device does not report success.
    """
    async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
        resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_REVEAL})
    if not resp.get("success"):
        raise PyMobileDevice3Exception(f"The device did not reveal the Developer Mode setting: {resp}")
```

### enable_developer_mode

```
enable_developer_mode(enable_post_restart: bool = True, reconnect_timeout: float = DEVELOPER_MODE_RECONNECT_TIMEOUT)
```

Request that Developer Mode be enabled on the device.

Sends the enable action. The device then reboots to apply the change. When `enable_post_restart` is True, this method keeps the connection alive via a heartbeat, waits for the same device (by UDID) to disconnect and reconnect over usbmux, and then answers the post-restart confirmation prompt by calling `enable_developer_mode_post_restart`.

The reconnect always goes through usbmux, since the RSD tunnel or TCP connection the request was sent over does not survive the reboot. A device reached without usbmux (e.g. `--rsd` to a device that usbmuxd does not list) cannot be reconnected to, so the prompt has to be confirmed on the device itself.

Parameters:

| Name                  | Type    | Description                                                                                                                                    | Default                            |
| --------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `enable_post_restart` | `bool`  | when True, wait for the device to restart and automatically confirm the final prompt; when False, return immediately after the enable request. | `True`                             |
| `reconnect_timeout`   | `float` | maximum time in seconds to wait for the device to come back after it restarts.                                                                 | `DEVELOPER_MODE_RECONNECT_TIMEOUT` |

Raises:

| Type                        | Description                                                                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `DeviceHasPasscodeSetError` | if the device has a passcode set, which blocks the operation.                                                                                 |
| `AmfiError`                 | if AMFI returns any other error.                                                                                                              |
| `DeveloperModeError`        | if the enable or post-restart confirmation request does not succeed, or if the device cannot be reconnected to over usbmux after it restarts. |

Source code in `pymobiledevice3/services/amfi.py`

```
async def enable_developer_mode(
    self, enable_post_restart: bool = True, reconnect_timeout: float = DEVELOPER_MODE_RECONNECT_TIMEOUT
):
    """
    Request that Developer Mode be enabled on the device.

    Sends the enable action. The device then reboots to apply the change. When
    ``enable_post_restart`` is True, this method keeps the connection alive via a heartbeat,
    waits for the same device (by UDID) to disconnect and reconnect over usbmux, and then answers
    the post-restart confirmation prompt by calling `enable_developer_mode_post_restart`.

    The reconnect always goes through usbmux, since the RSD tunnel or TCP connection the request
    was sent over does not survive the reboot. A device reached without usbmux (e.g. ``--rsd`` to a
    device that usbmuxd does not list) cannot be reconnected to, so the prompt has to be confirmed
    on the device itself.

    :param enable_post_restart: when True, wait for the device to restart and automatically
        confirm the final prompt; when False, return immediately after the enable request.
    :param reconnect_timeout: maximum time in seconds to wait for the device to come back after it
        restarts.
    :raises DeviceHasPasscodeSetError: if the device has a passcode set, which blocks the operation.
    :raises AmfiError: if AMFI returns any other error.
    :raises DeveloperModeError: if the enable or post-restart confirmation request does not succeed,
        or if the device cannot be reconnected to over usbmux after it restarts.
    """
    async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
        resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_ENABLE})
    error = resp.get("Error")

    if error is not None:
        if error == "Device has a passcode set":
            raise DeviceHasPasscodeSetError()
        raise AmfiError(f"AMFI refused to enable Developer Mode: {error}")

    if not resp.get("success"):
        raise DeveloperModeError(f"The device did not enable Developer Mode: {resp}")

    if not enable_post_restart:
        return

    udid = self._lockdown.udid
    confirm_on_device = "Once it has restarted, unlock it and confirm the Developer Mode prompt on the device."
    over_usbmux = isinstance(self._lockdown, UsbmuxLockdownClient)
    usbmux_address = self._lockdown.usbmux_address if isinstance(self._lockdown, UsbmuxLockdownClient) else None
    if udid is None or not (over_usbmux or await self._listed_by_usbmux(udid)):
        # Reached over RSD/TCP only: nothing to reconnect through once the reboot tears that down.
        raise DeveloperModeError(
            "Developer Mode was requested and the device is restarting, but it is not connected through "
            f"usbmux, so the post-restart prompt cannot be confirmed from here. {confirm_on_device}"
        )

    try:
        await HeartbeatService(self._lockdown).start()
    except (ConnectionTerminatedError, BrokenPipeError, IncompleteReadError):
        self._logger.debug("device disconnected, awaiting reconnect")

    lockdown = await retry_create_using_usbmux(reconnect_timeout, serial=udid, usbmux_address=usbmux_address)
    if lockdown is None:
        raise DeveloperModeError(
            f"Device {udid} did not reconnect over usbmux within {reconnect_timeout:.0f} seconds of "
            f"restarting. {confirm_on_device}"
        )
    self._lockdown = lockdown
    await self.enable_developer_mode_post_restart()
```

### enable_developer_mode_post_restart

```
enable_developer_mode_post_restart()
```

Confirm the Developer Mode prompt shown after the device restarts.

Sends the accept action, answering the post-restart confirmation prompt affirmatively.

Raises:

| Type                 | Description                            |
| -------------------- | -------------------------------------- |
| `DeveloperModeError` | if the device does not report success. |

Source code in `pymobiledevice3/services/amfi.py`

```
async def enable_developer_mode_post_restart(self):
    """
    Confirm the Developer Mode prompt shown after the device restarts.

    Sends the accept action, answering the post-restart confirmation prompt affirmatively.

    :raises DeveloperModeError: if the device does not report success.
    """
    async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
        resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_ACCEPT})
    if not resp.get("success"):
        raise DeveloperModeError(f"The device did not confirm Developer Mode after restarting: {resp}")
```

### trust_app_signer

```
trust_app_signer(profile_uuid: str) -> Optional[bool]
```

Trust the developer app signer of an installed provisioning profile.

Equivalent to tapping "Trust" under Settings > General > VPN & Device Management.

Parameters:

| Name           | Type  | Description                                                                | Default    |
| -------------- | ----- | -------------------------------------------------------------------------- | ---------- |
| `profile_uuid` | `str` | UUID of the installed provisioning profile whose signer should be trusted. | *required* |

Returns:

| Type             | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| `Optional[bool]` | The status value of the reply, or None if the device omitted it. |

Raises:

| Type        | Description                                                             |
| ----------- | ----------------------------------------------------------------------- |
| `AmfiError` | if the device does not report success (e.g. no profile with that UUID). |

Source code in `pymobiledevice3/services/amfi.py`

```
async def trust_app_signer(self, profile_uuid: str) -> Optional[bool]:
    """
    Trust the developer app signer of an installed provisioning profile.

    Equivalent to tapping "Trust" under Settings > General > VPN & Device Management.

    :param profile_uuid: UUID of the installed provisioning profile whose signer should be trusted.
    :return: The ``status`` value of the reply, or None if the device omitted it.
    :raises AmfiError: if the device does not report success (e.g. no profile with that UUID).
    """
    async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
        resp = await service.send_recv_plist({"action": self.TRUST_APP_SIGNER, "input_profile_uuid": profile_uuid})
    error = resp.get("Error")
    if error is not None:
        raise AmfiError(f"AMFI refused to trust the app signer of profile {profile_uuid}: {error}")
    if not resp.get("success"):
        raise AmfiError(f"The device did not trust the app signer of profile {profile_uuid}: {resp}")
    status = resp.get("status")
    return status if isinstance(status, bool) else None
```

## pymobiledevice3.services.mobile_activation.MobileActivationService

Drive iOS device activation against Apple's activation servers via `com.apple.mobileactivationd`.

Orchestrates the full activation handshake: it gathers activation information from the device, exchanges it with Apple's activation and DRM-handshake endpoints over HTTP, optionally prompts the user for Apple ID credentials when the server requests them, and writes the resulting activation record back to the device. Both the modern session-based flow and the legacy lockdown flow are supported, with the session flow preferred when available.

A fresh lockdown service connection is opened for each request rather than reusing one, so this class does not inherit from the shared service base.

Source code in `pymobiledevice3/services/mobile_activation.py`

```
class MobileActivationService:
    """
    Drive iOS device activation against Apple's activation servers via ``com.apple.mobileactivationd``.

    Orchestrates the full activation handshake: it gathers activation information from the device,
    exchanges it with Apple's activation and DRM-handshake endpoints over HTTP, optionally prompts
    the user for Apple ID credentials when the server requests them, and writes the resulting
    activation record back to the device. Both the modern session-based flow and the legacy
    lockdown flow are supported, with the session flow preferred when available.

    A fresh lockdown service connection is opened for each request rather than reusing one, so this
    class does not inherit from the shared service base.
    """

    SERVICE_NAME = "com.apple.mobileactivationd"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        self.lockdown = lockdown
        self.logger = logging.getLogger(__name__)

    async def state(self):
        """
        Return the device's current activation state.

        Queries the activation daemon for the activation state, falling back to the lockdown
        ``ActivationState`` value if the daemon request fails.

        :returns: the activation state (e.g. ``"Unactivated"`` or ``"Activated"``).
        """
        try:
            return (await self.send_command("GetActivationStateRequest"))["Value"]
        except Exception:
            return await self.lockdown.get_value(key="ActivationState")

    async def wait_for_activation_session(self):
        """
        Block until the device produces a fresh activation session handshake.

        Repeatedly requests activation session info until the handshake request message changes,
        indicating the device is ready with a new session. Returns immediately if the device does
        not support the session-based flow.
        """
        try:
            blob = await self.create_activation_session_info()
        except Exception:
            return
        handshake_request_message = blob["HandshakeRequestMessage"]
        while handshake_request_message == blob["HandshakeRequestMessage"]:
            blob = await self.create_activation_session_info()

    @staticmethod
    def _get_activation_form_from_response(content: str) -> ActivationForm:
        root = ET.fromstring(content)
        navigation_bar = root.find("page/navigationBar")
        footer = root.find("page/tableView/section/footer")
        server_info_node = root.find("serverInfo")
        if navigation_bar is None or footer is None or server_info_node is None:
            raise MobileActivationException("Could not parse the page sent by Apple's activation server.")
        title = navigation_bar.get("title")
        description = footer.text
        fields: list[Field] = []
        for editable in root.findall("page//editableTextRow"):
            fields.append(
                Field(
                    id=editable.get("id"),
                    label=editable.get("label"),
                    placeholder=editable.get("placeholder"),
                    secure=bool(editable.get("secure", False)),
                )
            )
        server_info: dict[str, str] = {}
        for k, v in server_info_node.items():
            server_info[k] = v
        return ActivationForm(title=title, description=description, fields=fields, server_info=server_info)

    async def activate(self, skip_apple_id_query: bool = False) -> None:
        """
        Activate the device end-to-end against Apple's activation servers.

        Does nothing if the device is already activated. Otherwise it collects activation info from
        the device (preferring the session-based flow, including a DRM handshake with Apple when
        available), posts it to the activation server, and applies the returned activation record.
        If the server responds with a BuddyML form requesting Apple ID credentials, the user is
        prompted interactively and the form is resubmitted. On success, the device's
        ``ActivationStateAcknowledged`` value is set.

        :param skip_apple_id_query: when True, do not prompt for Apple ID credentials; instead treat
            a credentials request as an iCloud lock and raise.
        :raises MobileActivationException: if the device is iCloud locked (with
            ``skip_apple_id_query`` set) or the activation server response is invalid.
        """
        if await self.state() != "Unactivated":
            self.logger.error("Device is already activated!")
            return

        blob = None
        try:
            blob = await self.create_activation_session_info()
            session_mode = True
        except Exception:
            session_mode = False

        # create drmHandshake request with blob from device
        headers = {"Content-Type": "application/x-apple-plist"}
        headers.update(DEFAULT_HEADERS)
        content = None
        if session_mode:
            assert blob is not None  # session_mode is True only when the session info was created
            content, headers = self.post(
                ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL, data=plistlib.dumps(blob), headers=headers
            )

        activation_request: dict[str, Any] = {}
        if session_mode:
            activation_info = await self.create_activation_info_with_session(content)
        else:
            activation_info = await self.lockdown.get_value(key="ActivationInfo")
            activation_request.update({
                "InStoreActivation": False,
                "AppleSerialNumber": await self.lockdown.get_value(key="SerialNumber"),
            })
            if self.lockdown.all_values.get("TelephonyCapability"):
                req_pair = {
                    "IMEI": "InternationalMobileEquipmentIdentity",
                    "MEID": "MobileEquipmentIdentifier",
                    "IMSI": "InternationalMobileSubscriberIdentity",
                    "ICCID": "IntegratedCircuitCardIdentity",
                }

                has_meid = False
                for k, v in req_pair.items():
                    lv = self.lockdown.all_values.get(v)
                    if lv is not None:
                        activation_request.update({k: lv})
                        continue
                    else:
                        self.logger.warning(f"Unable to get {k} from lockdownd")
                        if k == "MEID" and has_meid:
                            # Something is wrong if both IMEI & MEID is missing
                            raise MobileActivationException(
                                "Could not read either the IMEI or the MEID from the device."
                            )

                    # Either IMEI or MEID, or both
                    if k == "IMEI":
                        has_meid = lv is None
        activation_request.update({"activation-info": plistlib.dumps(activation_info)})

        content, headers = self.post(ACTIVATION_DEFAULT_URL, data=activation_request)
        content_type = headers["Content-Type"]

        if content_type == "application/x-buddyml":
            if skip_apple_id_query:
                raise MobileActivationException("The device is iCloud locked (Activation Lock).")
            try:
                activation_form = self._get_activation_form_from_response(content.decode())
            except Exception as e:
                raise MobileActivationException("Could not parse the page sent by Apple's activation server.") from e
            else:
                typer.secho(activation_form.title, bold=True)
                typer.secho(activation_form.description)
                data: dict[str, Any] = {}
                for field in activation_form.fields:
                    if field.id is None:
                        # an id-less field cannot be submitted as form data
                        continue
                    prompt = questionary.password if field.secure else questionary.text
                    data[field.id] = ask_prompt(prompt(f"{field.label}"))
                data.update(activation_form.server_info)
                content, headers = self.post(ACTIVATION_DEFAULT_URL, data=data)
                content_type = headers["Content-Type"]

        assert content_type == "text/xml"
        if session_mode:
            await self.activate_with_session(content, headers)
        else:
            await self.activate_with_lockdown(content)

        # set ActivationStateAcknowledged if we succeeded
        await self.lockdown.set_value(True, key="ActivationStateAcknowledged")

    async def deactivate(self):
        """
        Deactivate the device.

        Sends a ``DeactivateRequest`` to the activation daemon, falling back to the lockdown
        ``Deactivate`` request if that fails.

        :returns: the response from whichever deactivation path succeeds.
        """
        try:
            return await self.send_command("DeactivateRequest")
        except Exception:
            assert isinstance(self.lockdown, LockdownClient)
            return await self.lockdown._request("Deactivate")

    async def create_activation_session_info(self) -> dict[str, Any]:
        """
        Request the device's session-based activation handshake info.

        Sends a ``CreateTunnel1SessionInfoRequest`` to the activation daemon.

        :returns: the session info blob (the ``Value`` entry), including the handshake request message.
        :raises MobileActivationException: if the daemon returns an error.
        """
        response = await self.send_command("CreateTunnel1SessionInfoRequest")
        error = response.get("Error")
        if error is not None:
            raise MobileActivationException(f"The device refused to create an activation session: {response}")
        return cast(dict[str, Any], response["Value"])

    async def create_activation_info_with_session(self, handshake_response: Any) -> dict[str, Any]:
        """
        Build the device's activation info from a completed DRM handshake.

        Sends a ``CreateTunnel1ActivationInfoRequest`` to the activation daemon, passing the DRM
        handshake response received from Apple.

        :param handshake_response: the DRM handshake response content returned by Apple's server.
        :returns: the activation info blob (the ``Value`` entry) to post to the activation server.
        :raises MobileActivationException: if the daemon returns an error.
        """
        response = await self.send_command("CreateTunnel1ActivationInfoRequest", handshake_response)
        error = response.get("Error")
        if error is not None:
            raise MobileActivationException(f"The device refused to create its activation info: {response}")
        return cast(dict[str, Any], response["Value"])

    async def activate_with_lockdown(self, activation_record: bytes):
        """
        Apply an activation record to the device using the legacy lockdown flow.

        Parses the activation record, extracts the ``iphone-activation`` or ``device-activation``
        node, and submits its activation record via the lockdown ``Activate`` request.

        :param activation_record: the serialized activation record returned by the activation server.
        :raises MobileActivationException: if the activation record does not contain a recognized
            activation node.
        """
        record = plistlib.loads(activation_record)
        node = record.get("iphone-activation")
        if node is None:
            node = record.get("device-activation")
        if node is None:
            raise MobileActivationException("The activation record from Apple's server has no device activation entry.")

        assert isinstance(self.lockdown, LockdownClient)
        await self.lockdown._request("Activate", {"ActivationRecord": node.get("activation-record")})

    async def activate_with_session(self, activation_record: Any, headers: CaseInsensitiveDict[str]):
        """
        Apply an activation record to the device using the session-based flow.

        Sends a ``HandleActivationInfoWithSessionRequest`` to the activation daemon, including the
        activation record and, if provided, the HTTP response headers from the activation server.

        :param activation_record: the activation record returned by the activation server.
        :param headers: HTTP response headers from the activation server, forwarded as
            ``ActivationResponseHeaders``; may be falsy to omit them.
        :returns: the daemon's response to the request.
        """
        data: dict[str, Any] = {
            "Command": "HandleActivationInfoWithSessionRequest",
            "Value": activation_record,
        }
        if headers:
            data["ActivationResponseHeaders"] = dict(headers)
        async with await self.lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            return await service.send_recv_plist(data)

    async def send_command(self, command: str, value: str = ""):
        """
        Send a single command to the activation daemon over a fresh service connection.

        Opens the ``com.apple.mobileactivationd`` service, sends the command (with an optional
        ``Value``), and returns the response. The connection is closed afterwards.

        :param command: the activation daemon command name.
        :param value: optional value sent alongside the command; omitted when empty.
        :returns: the daemon's response plist.
        """
        data = {"Command": command}
        if value:
            data["Value"] = value
        async with await self.lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            return await service.send_recv_plist(data)

    def post(
        self, url: str, data: Union[dict[str, Any], bytes], headers: Optional[dict[str, str]] = None
    ) -> tuple[bytes, CaseInsensitiveDict[str]]:
        """
        Perform an HTTP POST to an activation server endpoint.

        :param url: the activation endpoint to post to.
        :param data: the form data or request body to send.
        :param headers: optional request headers; the module's default activation headers are used
            when omitted.
        :returns: a tuple of the response body bytes and the response headers.
        """
        if headers is None:
            headers = DEFAULT_HEADERS

        resp = requests.post(url, data=data, headers=headers, timeout=30)
        return resp.content, resp.headers
```

### state

```
state()
```

Return the device's current activation state.

Queries the activation daemon for the activation state, falling back to the lockdown `ActivationState` value if the daemon request fails.

Returns:

| Type | Description                                               |
| ---- | --------------------------------------------------------- |
|      | the activation state (e.g. "Unactivated" or "Activated"). |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def state(self):
    """
    Return the device's current activation state.

    Queries the activation daemon for the activation state, falling back to the lockdown
    ``ActivationState`` value if the daemon request fails.

    :returns: the activation state (e.g. ``"Unactivated"`` or ``"Activated"``).
    """
    try:
        return (await self.send_command("GetActivationStateRequest"))["Value"]
    except Exception:
        return await self.lockdown.get_value(key="ActivationState")
```

### wait_for_activation_session

```
wait_for_activation_session()
```

Block until the device produces a fresh activation session handshake.

Repeatedly requests activation session info until the handshake request message changes, indicating the device is ready with a new session. Returns immediately if the device does not support the session-based flow.

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def wait_for_activation_session(self):
    """
    Block until the device produces a fresh activation session handshake.

    Repeatedly requests activation session info until the handshake request message changes,
    indicating the device is ready with a new session. Returns immediately if the device does
    not support the session-based flow.
    """
    try:
        blob = await self.create_activation_session_info()
    except Exception:
        return
    handshake_request_message = blob["HandshakeRequestMessage"]
    while handshake_request_message == blob["HandshakeRequestMessage"]:
        blob = await self.create_activation_session_info()
```

### activate

```
activate(skip_apple_id_query: bool = False) -> None
```

Activate the device end-to-end against Apple's activation servers.

Does nothing if the device is already activated. Otherwise it collects activation info from the device (preferring the session-based flow, including a DRM handshake with Apple when available), posts it to the activation server, and applies the returned activation record. If the server responds with a BuddyML form requesting Apple ID credentials, the user is prompted interactively and the form is resubmitted. On success, the device's `ActivationStateAcknowledged` value is set.

Parameters:

| Name                  | Type   | Description                                                                                                         | Default |
| --------------------- | ------ | ------------------------------------------------------------------------------------------------------------------- | ------- |
| `skip_apple_id_query` | `bool` | when True, do not prompt for Apple ID credentials; instead treat a credentials request as an iCloud lock and raise. | `False` |

Raises:

| Type                        | Description                                                                                                 |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `MobileActivationException` | if the device is iCloud locked (with skip_apple_id_query set) or the activation server response is invalid. |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def activate(self, skip_apple_id_query: bool = False) -> None:
    """
    Activate the device end-to-end against Apple's activation servers.

    Does nothing if the device is already activated. Otherwise it collects activation info from
    the device (preferring the session-based flow, including a DRM handshake with Apple when
    available), posts it to the activation server, and applies the returned activation record.
    If the server responds with a BuddyML form requesting Apple ID credentials, the user is
    prompted interactively and the form is resubmitted. On success, the device's
    ``ActivationStateAcknowledged`` value is set.

    :param skip_apple_id_query: when True, do not prompt for Apple ID credentials; instead treat
        a credentials request as an iCloud lock and raise.
    :raises MobileActivationException: if the device is iCloud locked (with
        ``skip_apple_id_query`` set) or the activation server response is invalid.
    """
    if await self.state() != "Unactivated":
        self.logger.error("Device is already activated!")
        return

    blob = None
    try:
        blob = await self.create_activation_session_info()
        session_mode = True
    except Exception:
        session_mode = False

    # create drmHandshake request with blob from device
    headers = {"Content-Type": "application/x-apple-plist"}
    headers.update(DEFAULT_HEADERS)
    content = None
    if session_mode:
        assert blob is not None  # session_mode is True only when the session info was created
        content, headers = self.post(
            ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL, data=plistlib.dumps(blob), headers=headers
        )

    activation_request: dict[str, Any] = {}
    if session_mode:
        activation_info = await self.create_activation_info_with_session(content)
    else:
        activation_info = await self.lockdown.get_value(key="ActivationInfo")
        activation_request.update({
            "InStoreActivation": False,
            "AppleSerialNumber": await self.lockdown.get_value(key="SerialNumber"),
        })
        if self.lockdown.all_values.get("TelephonyCapability"):
            req_pair = {
                "IMEI": "InternationalMobileEquipmentIdentity",
                "MEID": "MobileEquipmentIdentifier",
                "IMSI": "InternationalMobileSubscriberIdentity",
                "ICCID": "IntegratedCircuitCardIdentity",
            }

            has_meid = False
            for k, v in req_pair.items():
                lv = self.lockdown.all_values.get(v)
                if lv is not None:
                    activation_request.update({k: lv})
                    continue
                else:
                    self.logger.warning(f"Unable to get {k} from lockdownd")
                    if k == "MEID" and has_meid:
                        # Something is wrong if both IMEI & MEID is missing
                        raise MobileActivationException(
                            "Could not read either the IMEI or the MEID from the device."
                        )

                # Either IMEI or MEID, or both
                if k == "IMEI":
                    has_meid = lv is None
    activation_request.update({"activation-info": plistlib.dumps(activation_info)})

    content, headers = self.post(ACTIVATION_DEFAULT_URL, data=activation_request)
    content_type = headers["Content-Type"]

    if content_type == "application/x-buddyml":
        if skip_apple_id_query:
            raise MobileActivationException("The device is iCloud locked (Activation Lock).")
        try:
            activation_form = self._get_activation_form_from_response(content.decode())
        except Exception as e:
            raise MobileActivationException("Could not parse the page sent by Apple's activation server.") from e
        else:
            typer.secho(activation_form.title, bold=True)
            typer.secho(activation_form.description)
            data: dict[str, Any] = {}
            for field in activation_form.fields:
                if field.id is None:
                    # an id-less field cannot be submitted as form data
                    continue
                prompt = questionary.password if field.secure else questionary.text
                data[field.id] = ask_prompt(prompt(f"{field.label}"))
            data.update(activation_form.server_info)
            content, headers = self.post(ACTIVATION_DEFAULT_URL, data=data)
            content_type = headers["Content-Type"]

    assert content_type == "text/xml"
    if session_mode:
        await self.activate_with_session(content, headers)
    else:
        await self.activate_with_lockdown(content)

    # set ActivationStateAcknowledged if we succeeded
    await self.lockdown.set_value(True, key="ActivationStateAcknowledged")
```

### deactivate

```
deactivate()
```

Deactivate the device.

Sends a `DeactivateRequest` to the activation daemon, falling back to the lockdown `Deactivate` request if that fails.

Returns:

| Type | Description                                             |
| ---- | ------------------------------------------------------- |
|      | the response from whichever deactivation path succeeds. |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def deactivate(self):
    """
    Deactivate the device.

    Sends a ``DeactivateRequest`` to the activation daemon, falling back to the lockdown
    ``Deactivate`` request if that fails.

    :returns: the response from whichever deactivation path succeeds.
    """
    try:
        return await self.send_command("DeactivateRequest")
    except Exception:
        assert isinstance(self.lockdown, LockdownClient)
        return await self.lockdown._request("Deactivate")
```

### create_activation_session_info

```
create_activation_session_info() -> dict[str, Any]
```

Request the device's session-based activation handshake info.

Sends a `CreateTunnel1SessionInfoRequest` to the activation daemon.

Returns:

| Type             | Description                                                                       |
| ---------------- | --------------------------------------------------------------------------------- |
| `dict[str, Any]` | the session info blob (the Value entry), including the handshake request message. |

Raises:

| Type                        | Description                     |
| --------------------------- | ------------------------------- |
| `MobileActivationException` | if the daemon returns an error. |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def create_activation_session_info(self) -> dict[str, Any]:
    """
    Request the device's session-based activation handshake info.

    Sends a ``CreateTunnel1SessionInfoRequest`` to the activation daemon.

    :returns: the session info blob (the ``Value`` entry), including the handshake request message.
    :raises MobileActivationException: if the daemon returns an error.
    """
    response = await self.send_command("CreateTunnel1SessionInfoRequest")
    error = response.get("Error")
    if error is not None:
        raise MobileActivationException(f"The device refused to create an activation session: {response}")
    return cast(dict[str, Any], response["Value"])
```

### create_activation_info_with_session

```
create_activation_info_with_session(handshake_response: Any) -> dict[str, Any]
```

Build the device's activation info from a completed DRM handshake.

Sends a `CreateTunnel1ActivationInfoRequest` to the activation daemon, passing the DRM handshake response received from Apple.

Parameters:

| Name                 | Type  | Description                                                    | Default    |
| -------------------- | ----- | -------------------------------------------------------------- | ---------- |
| `handshake_response` | `Any` | the DRM handshake response content returned by Apple's server. | *required* |

Returns:

| Type             | Description                                                                  |
| ---------------- | ---------------------------------------------------------------------------- |
| `dict[str, Any]` | the activation info blob (the Value entry) to post to the activation server. |

Raises:

| Type                        | Description                     |
| --------------------------- | ------------------------------- |
| `MobileActivationException` | if the daemon returns an error. |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def create_activation_info_with_session(self, handshake_response: Any) -> dict[str, Any]:
    """
    Build the device's activation info from a completed DRM handshake.

    Sends a ``CreateTunnel1ActivationInfoRequest`` to the activation daemon, passing the DRM
    handshake response received from Apple.

    :param handshake_response: the DRM handshake response content returned by Apple's server.
    :returns: the activation info blob (the ``Value`` entry) to post to the activation server.
    :raises MobileActivationException: if the daemon returns an error.
    """
    response = await self.send_command("CreateTunnel1ActivationInfoRequest", handshake_response)
    error = response.get("Error")
    if error is not None:
        raise MobileActivationException(f"The device refused to create its activation info: {response}")
    return cast(dict[str, Any], response["Value"])
```

### activate_with_lockdown

```
activate_with_lockdown(activation_record: bytes)
```

Apply an activation record to the device using the legacy lockdown flow.

Parses the activation record, extracts the `iphone-activation` or `device-activation` node, and submits its activation record via the lockdown `Activate` request.

Parameters:

| Name                | Type    | Description                                                         | Default    |
| ------------------- | ------- | ------------------------------------------------------------------- | ---------- |
| `activation_record` | `bytes` | the serialized activation record returned by the activation server. | *required* |

Raises:

| Type                        | Description                                                             |
| --------------------------- | ----------------------------------------------------------------------- |
| `MobileActivationException` | if the activation record does not contain a recognized activation node. |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def activate_with_lockdown(self, activation_record: bytes):
    """
    Apply an activation record to the device using the legacy lockdown flow.

    Parses the activation record, extracts the ``iphone-activation`` or ``device-activation``
    node, and submits its activation record via the lockdown ``Activate`` request.

    :param activation_record: the serialized activation record returned by the activation server.
    :raises MobileActivationException: if the activation record does not contain a recognized
        activation node.
    """
    record = plistlib.loads(activation_record)
    node = record.get("iphone-activation")
    if node is None:
        node = record.get("device-activation")
    if node is None:
        raise MobileActivationException("The activation record from Apple's server has no device activation entry.")

    assert isinstance(self.lockdown, LockdownClient)
    await self.lockdown._request("Activate", {"ActivationRecord": node.get("activation-record")})
```

### activate_with_session

```
activate_with_session(activation_record: Any, headers: CaseInsensitiveDict[str])
```

Apply an activation record to the device using the session-based flow.

Sends a `HandleActivationInfoWithSessionRequest` to the activation daemon, including the activation record and, if provided, the HTTP response headers from the activation server.

Parameters:

| Name                | Type                       | Description                                                                                                          | Default    |
| ------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------- |
| `activation_record` | `Any`                      | the activation record returned by the activation server.                                                             | *required* |
| `headers`           | `CaseInsensitiveDict[str]` | HTTP response headers from the activation server, forwarded as ActivationResponseHeaders; may be falsy to omit them. | *required* |

Returns:

| Type | Description                           |
| ---- | ------------------------------------- |
|      | the daemon's response to the request. |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def activate_with_session(self, activation_record: Any, headers: CaseInsensitiveDict[str]):
    """
    Apply an activation record to the device using the session-based flow.

    Sends a ``HandleActivationInfoWithSessionRequest`` to the activation daemon, including the
    activation record and, if provided, the HTTP response headers from the activation server.

    :param activation_record: the activation record returned by the activation server.
    :param headers: HTTP response headers from the activation server, forwarded as
        ``ActivationResponseHeaders``; may be falsy to omit them.
    :returns: the daemon's response to the request.
    """
    data: dict[str, Any] = {
        "Command": "HandleActivationInfoWithSessionRequest",
        "Value": activation_record,
    }
    if headers:
        data["ActivationResponseHeaders"] = dict(headers)
    async with await self.lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
        return await service.send_recv_plist(data)
```

### send_command

```
send_command(command: str, value: str = '')
```

Send a single command to the activation daemon over a fresh service connection.

Opens the `com.apple.mobileactivationd` service, sends the command (with an optional `Value`), and returns the response. The connection is closed afterwards.

Parameters:

| Name      | Type  | Description                                                    | Default    |
| --------- | ----- | -------------------------------------------------------------- | ---------- |
| `command` | `str` | the activation daemon command name.                            | *required* |
| `value`   | `str` | optional value sent alongside the command; omitted when empty. | `''`       |

Returns:

| Type | Description                  |
| ---- | ---------------------------- |
|      | the daemon's response plist. |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
async def send_command(self, command: str, value: str = ""):
    """
    Send a single command to the activation daemon over a fresh service connection.

    Opens the ``com.apple.mobileactivationd`` service, sends the command (with an optional
    ``Value``), and returns the response. The connection is closed afterwards.

    :param command: the activation daemon command name.
    :param value: optional value sent alongside the command; omitted when empty.
    :returns: the daemon's response plist.
    """
    data = {"Command": command}
    if value:
        data["Value"] = value
    async with await self.lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
        return await service.send_recv_plist(data)
```

### post

```
post(url: str, data: Union[dict[str, Any], bytes], headers: Optional[dict[str, str]] = None) -> tuple[bytes, CaseInsensitiveDict[str]]
```

Perform an HTTP POST to an activation server endpoint.

Parameters:

| Name      | Type                           | Description                                                                              | Default    |
| --------- | ------------------------------ | ---------------------------------------------------------------------------------------- | ---------- |
| `url`     | `str`                          | the activation endpoint to post to.                                                      | *required* |
| `data`    | `Union[dict[str, Any], bytes]` | the form data or request body to send.                                                   | *required* |
| `headers` | `Optional[dict[str, str]]`     | optional request headers; the module's default activation headers are used when omitted. | `None`     |

Returns:

| Type                                     | Description                                                  |
| ---------------------------------------- | ------------------------------------------------------------ |
| `tuple[bytes, CaseInsensitiveDict[str]]` | a tuple of the response body bytes and the response headers. |

Source code in `pymobiledevice3/services/mobile_activation.py`

```
def post(
    self, url: str, data: Union[dict[str, Any], bytes], headers: Optional[dict[str, str]] = None
) -> tuple[bytes, CaseInsensitiveDict[str]]:
    """
    Perform an HTTP POST to an activation server endpoint.

    :param url: the activation endpoint to post to.
    :param data: the form data or request body to send.
    :param headers: optional request headers; the module's default activation headers are used
        when omitted.
    :returns: a tuple of the response body bytes and the response headers.
    """
    if headers is None:
        headers = DEFAULT_HEADERS

    resp = requests.post(url, data=data, headers=headers, timeout=30)
    return resp.content, resp.headers
```

## pymobiledevice3.services.notification_proxy.NotificationProxyService

Bases: `LockdownService`

Post and observe Darwin notifications on the device via the notification proxy lockdown service.

Allows sending notifications to the device, registering interest in notifications so the device relays them back, and iterating over the relayed notifications. A secure or insecure variant of the service is selected by the `insecure` flag, and the RSD/tunnel variant is chosen automatically for `RemoteServiceDiscoveryService` providers. This is a lockdown service and is used as an async context manager.

Source code in `pymobiledevice3/services/notification_proxy.py`

```
class NotificationProxyService(LockdownService):
    """
    Post and observe Darwin notifications on the device via the notification proxy lockdown service.

    Allows sending notifications to the device, registering interest in notifications so the device
    relays them back, and iterating over the relayed notifications. A secure or insecure variant of
    the service is selected by the ``insecure`` flag, and the RSD/tunnel variant is chosen
    automatically for `RemoteServiceDiscoveryService` providers. This is a lockdown service and is
    used as an async context manager.
    """

    SERVICE_NAME = "com.apple.mobile.notification_proxy"
    RSD_SERVICE_NAME = "com.apple.mobile.notification_proxy.shim.remote"

    INSECURE_SERVICE_NAME = "com.apple.mobile.insecure_notification_proxy"
    RSD_INSECURE_SERVICE_NAME = "com.apple.mobile.insecure_notification_proxy.shim.remote"

    def __init__(
        self, lockdown: LockdownServiceProvider, insecure: bool = False, timeout: Optional[Union[float, int]] = None
    ):
        """
        :param lockdown: service provider used to start the service and reach the device.
        :param insecure: when True, use the insecure notification proxy service instead of the secure one.
        :param timeout: optional time in seconds `receive_notification` waits for each notification.
        """
        if isinstance(lockdown, RemoteServiceDiscoveryService):
            secure_service_name = self.RSD_SERVICE_NAME
            insecure_service_name = self.RSD_INSECURE_SERVICE_NAME
        else:
            secure_service_name = self.SERVICE_NAME
            insecure_service_name = self.INSECURE_SERVICE_NAME

        if insecure:
            super().__init__(lockdown, insecure_service_name)
        else:
            super().__init__(lockdown, secure_service_name)

        self.timeout = timeout

    async def notify_post(self, name: str) -> None:
        """
        Post a notification on the device.

        Sends a ``PostNotification`` command, causing the device to broadcast the named notification.

        :param name: notification name to post (e.g. a Darwin notification name).
        """
        await self.service.send_plist({"Command": "PostNotification", "Name": name})

    async def notify_register_dispatch(self, name: str) -> None:
        """
        Register interest in a notification so the device relays it back.

        Sends an ``ObserveNotification`` command; once registered, the device sends a message
        whenever the named notification fires, which can be read via `receive_notification`.

        :param name: notification name to observe.
        """
        self.logger.debug(f"Observing {name}")
        await self.service.send_plist({"Command": "ObserveNotification", "Name": name})

    async def notify_set_state(self, name: str, state: int) -> None:
        """
        Set the 64-bit state of a notification (``notify_set_state``). Requires iOS 27.2+.

        The device holds the state only while this connection stays open, and resets it to 0 when
        it closes. Setting the state does not post the notification; call `notify_post` for that.
        The insecure service ignores the request. Reading a state back needs
        `RemoteNotificationProxyService.notify_get_state`.

        :param name: notification name.
        :param state: the state, as a signed or unsigned 64-bit integer.
        """
        await self.service.send_plist({"Command": "SetNotificationState", "Name": name, "State": state})

    async def receive_notification(self) -> AsyncGenerator[NotificationEvent, None]:
        """
        Yield notifications relayed from the device for previously observed names.

        Continuously reads from the service and yields each received message until the connection
        is closed.

        :returns: an async generator of the received notifications.
        :raises NotificationTimeoutError: if no notification arrives within the configured timeout.
        """
        while True:
            try:
                message = await asyncio.wait_for(self.service.recv_plist(), self.timeout)
            except asyncio.TimeoutError as e:
                raise NotificationTimeoutError from e
            yield NotificationEvent.from_message(message)
```

### notify_post

```
notify_post(name: str) -> None
```

Post a notification on the device.

Sends a `PostNotification` command, causing the device to broadcast the named notification.

Parameters:

| Name   | Type  | Description                                                  | Default    |
| ------ | ----- | ------------------------------------------------------------ | ---------- |
| `name` | `str` | notification name to post (e.g. a Darwin notification name). | *required* |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def notify_post(self, name: str) -> None:
    """
    Post a notification on the device.

    Sends a ``PostNotification`` command, causing the device to broadcast the named notification.

    :param name: notification name to post (e.g. a Darwin notification name).
    """
    await self.service.send_plist({"Command": "PostNotification", "Name": name})
```

### notify_register_dispatch

```
notify_register_dispatch(name: str) -> None
```

Register interest in a notification so the device relays it back.

Sends an `ObserveNotification` command; once registered, the device sends a message whenever the named notification fires, which can be read via `receive_notification`.

Parameters:

| Name   | Type  | Description                   | Default    |
| ------ | ----- | ----------------------------- | ---------- |
| `name` | `str` | notification name to observe. | *required* |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def notify_register_dispatch(self, name: str) -> None:
    """
    Register interest in a notification so the device relays it back.

    Sends an ``ObserveNotification`` command; once registered, the device sends a message
    whenever the named notification fires, which can be read via `receive_notification`.

    :param name: notification name to observe.
    """
    self.logger.debug(f"Observing {name}")
    await self.service.send_plist({"Command": "ObserveNotification", "Name": name})
```

### notify_set_state

```
notify_set_state(name: str, state: int) -> None
```

Set the 64-bit state of a notification (`notify_set_state`). Requires iOS 27.2+.

The device holds the state only while this connection stays open, and resets it to 0 when it closes. Setting the state does not post the notification; call `notify_post` for that. The insecure service ignores the request. Reading a state back needs `RemoteNotificationProxyService.notify_get_state`.

Parameters:

| Name    | Type  | Description                                        | Default    |
| ------- | ----- | -------------------------------------------------- | ---------- |
| `name`  | `str` | notification name.                                 | *required* |
| `state` | `int` | the state, as a signed or unsigned 64-bit integer. | *required* |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def notify_set_state(self, name: str, state: int) -> None:
    """
    Set the 64-bit state of a notification (``notify_set_state``). Requires iOS 27.2+.

    The device holds the state only while this connection stays open, and resets it to 0 when
    it closes. Setting the state does not post the notification; call `notify_post` for that.
    The insecure service ignores the request. Reading a state back needs
    `RemoteNotificationProxyService.notify_get_state`.

    :param name: notification name.
    :param state: the state, as a signed or unsigned 64-bit integer.
    """
    await self.service.send_plist({"Command": "SetNotificationState", "Name": name, "State": state})
```

### receive_notification

```
receive_notification() -> AsyncGenerator[NotificationEvent, None]
```

Yield notifications relayed from the device for previously observed names.

Continuously reads from the service and yields each received message until the connection is closed.

Returns:

| Type                                      | Description                                       |
| ----------------------------------------- | ------------------------------------------------- |
| `AsyncGenerator[NotificationEvent, None]` | an async generator of the received notifications. |

Raises:

| Type                       | Description                                               |
| -------------------------- | --------------------------------------------------------- |
| `NotificationTimeoutError` | if no notification arrives within the configured timeout. |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def receive_notification(self) -> AsyncGenerator[NotificationEvent, None]:
    """
    Yield notifications relayed from the device for previously observed names.

    Continuously reads from the service and yields each received message until the connection
    is closed.

    :returns: an async generator of the received notifications.
    :raises NotificationTimeoutError: if no notification arrives within the configured timeout.
    """
    while True:
        try:
            message = await asyncio.wait_for(self.service.recv_plist(), self.timeout)
        except asyncio.TimeoutError as e:
            raise NotificationTimeoutError from e
        yield NotificationEvent.from_message(message)
```

## pymobiledevice3.services.notification_proxy.NotificationEvent

Bases: `dict[str, Any]`

A message relayed by the notification proxy.

It is still the message the device sent, so `event["Name"]`, `event.get("State")`, comparison with a plain dict and JSON serialization keep working; the fields are typed accessors for the same values.

Source code in `pymobiledevice3/services/notification_proxy.py`

```
@dataclasses.dataclass(eq=False, repr=False)
class NotificationEvent(dict[str, Any]):
    """
    A message relayed by the notification proxy.

    It is still the message the device sent, so ``event["Name"]``, ``event.get("State")``,
    comparison with a plain dict and JSON serialization keep working; the fields are typed
    accessors for the same values.
    """

    #: ``RelayNotification`` for an observed notification, ``ProxyDeath`` when the proxy shuts down.
    command: str
    #: Name of the notification, when the message carries one.
    name: Optional[str] = None
    #: The notification's 64-bit ``notify_get_state()`` value. Sent by the secure service since
    #: iOS 27.2; ``None`` otherwise.
    state: Optional[int] = None

    @classmethod
    def from_message(cls, message: dict[str, Any]) -> "NotificationEvent":
        event = cls(command=message.get("Command", ""), name=message.get("Name"), state=message.get("State"))
        event.update(message)
        return event
```

## pymobiledevice3.services.notification_proxy.RemoteNotificationProxyService

Bases: `RemoteService`

Post and observe Darwin notifications over the native RemoteXPC notification proxy.

This is the RSD-native counterpart of `NotificationProxyService`: instead of tunnelling the classic lockdown service through its `.shim.remote` alias, it talks to the notification proxy daemon directly over RemoteXPC. The message vocabulary is identical (`PostNotification` / `ObserveNotification` / `RelayNotification`), only the transport differs.

Requires an iOS 17+ RSD tunnel. Use as an async context manager.

Source code in `pymobiledevice3/services/notification_proxy.py`

```
class RemoteNotificationProxyService(RemoteService):
    """
    Post and observe Darwin notifications over the native RemoteXPC notification proxy.

    This is the RSD-native counterpart of `NotificationProxyService`: instead of tunnelling the
    classic lockdown service through its ``.shim.remote`` alias, it talks to the notification proxy
    daemon directly over RemoteXPC. The message vocabulary is identical (``PostNotification`` /
    ``ObserveNotification`` / ``RelayNotification``), only the transport differs.

    Requires an iOS 17+ RSD tunnel. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.mobile.notification_proxy.remote"
    INSECURE_SERVICE_NAME = "com.apple.mobile.insecure_notification_proxy.remote"

    def __init__(self, rsd: RemoteServiceDiscoveryService, insecure: bool = False):
        """
        :param rsd: RSD provider used to open the RemoteXPC service.
        :param insecure: when True, use the insecure relay meant for untrusted clients.
        """
        super().__init__(rsd, self.INSECURE_SERVICE_NAME if insecure else self.SERVICE_NAME)

    async def notify_post(self, name: str) -> None:
        """
        Post a notification on the device.

        :param name: notification name to post (e.g. a Darwin notification name).
        """
        await self.service.send_request({"Command": "PostNotification", "Name": name})

    async def notify_register_dispatch(self, name: str) -> None:
        """
        Register interest in a notification so the device relays it back.

        Once registered, the device sends a ``RelayNotification`` message whenever the named
        notification fires, which can be read via `receive_notification`.

        :param name: notification name to observe.
        """
        self.logger.debug(f"Observing {name}")
        await self.service.send_request({"Command": "ObserveNotification", "Name": name})

    async def notify_set_state(self, name: str, state: int) -> None:
        """
        Set the 64-bit state of a notification (``notify_set_state``). Requires iOS 27.2+.

        The device holds the state only while this connection stays open, and resets it to 0 when
        it closes. Setting the state does not post the notification; call `notify_post` for that.
        The insecure service ignores the request.

        :param name: notification name.
        :param state: the state, as a signed or unsigned 64-bit integer.
        """
        typed_state = XpcInt64Type(state) if state < (1 << 63) else XpcUInt64Type(state)
        await self.service.send_request({"Command": "SetNotificationState", "Name": name, "State": typed_state})

    async def notify_get_state(self, name: str) -> int:
        """
        Read the 64-bit state of a notification (``notify_get_state``). Requires iOS 27.2+.

        System daemons publish a current value this way, e.g. ``com.apple.springboard.lockstate``.
        A name nobody set reads as 0. Use a connection that observes nothing: a notification
        relayed while the reply is awaited is discarded.

        :param name: notification name.
        :returns: the state, as a signed 64-bit integer.
        :raises NotificationStateError: if the device reports a failure (always, on the insecure service).
        """
        await self.service.send_request({"Command": "GetNotificationState", "Name": name}, wanting_reply=True)
        while True:
            response = await self.service.receive_response()
            if response.get("Command") == "RelayNotificationState" and response.get("Name") == name:
                break
        status = response.get("Status", 0)
        if status:
            raise NotificationStateError(name, status)
        return int(response["State"])

    async def receive_notification(self) -> AsyncGenerator[NotificationEvent, None]:
        """
        Yield notifications relayed from the device for previously observed names.

        Each yielded message is of the form
        ``{"Command": "RelayNotification", "Name": <notification name>}``. Since iOS 27.2 the secure
        service also includes ``"State"``, the notification's 64-bit ``notify_get_state()`` value.

        :returns: an async generator of the relayed notifications.
        """
        while True:
            yield NotificationEvent.from_message(await self.service.receive_response())
```

### notify_post

```
notify_post(name: str) -> None
```

Post a notification on the device.

Parameters:

| Name   | Type  | Description                                                  | Default    |
| ------ | ----- | ------------------------------------------------------------ | ---------- |
| `name` | `str` | notification name to post (e.g. a Darwin notification name). | *required* |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def notify_post(self, name: str) -> None:
    """
    Post a notification on the device.

    :param name: notification name to post (e.g. a Darwin notification name).
    """
    await self.service.send_request({"Command": "PostNotification", "Name": name})
```

### notify_register_dispatch

```
notify_register_dispatch(name: str) -> None
```

Register interest in a notification so the device relays it back.

Once registered, the device sends a `RelayNotification` message whenever the named notification fires, which can be read via `receive_notification`.

Parameters:

| Name   | Type  | Description                   | Default    |
| ------ | ----- | ----------------------------- | ---------- |
| `name` | `str` | notification name to observe. | *required* |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def notify_register_dispatch(self, name: str) -> None:
    """
    Register interest in a notification so the device relays it back.

    Once registered, the device sends a ``RelayNotification`` message whenever the named
    notification fires, which can be read via `receive_notification`.

    :param name: notification name to observe.
    """
    self.logger.debug(f"Observing {name}")
    await self.service.send_request({"Command": "ObserveNotification", "Name": name})
```

### notify_set_state

```
notify_set_state(name: str, state: int) -> None
```

Set the 64-bit state of a notification (`notify_set_state`). Requires iOS 27.2+.

The device holds the state only while this connection stays open, and resets it to 0 when it closes. Setting the state does not post the notification; call `notify_post` for that. The insecure service ignores the request.

Parameters:

| Name    | Type  | Description                                        | Default    |
| ------- | ----- | -------------------------------------------------- | ---------- |
| `name`  | `str` | notification name.                                 | *required* |
| `state` | `int` | the state, as a signed or unsigned 64-bit integer. | *required* |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def notify_set_state(self, name: str, state: int) -> None:
    """
    Set the 64-bit state of a notification (``notify_set_state``). Requires iOS 27.2+.

    The device holds the state only while this connection stays open, and resets it to 0 when
    it closes. Setting the state does not post the notification; call `notify_post` for that.
    The insecure service ignores the request.

    :param name: notification name.
    :param state: the state, as a signed or unsigned 64-bit integer.
    """
    typed_state = XpcInt64Type(state) if state < (1 << 63) else XpcUInt64Type(state)
    await self.service.send_request({"Command": "SetNotificationState", "Name": name, "State": typed_state})
```

### notify_get_state

```
notify_get_state(name: str) -> int
```

Read the 64-bit state of a notification (`notify_get_state`). Requires iOS 27.2+.

System daemons publish a current value this way, e.g. `com.apple.springboard.lockstate`. A name nobody set reads as 0. Use a connection that observes nothing: a notification relayed while the reply is awaited is discarded.

Parameters:

| Name   | Type  | Description        | Default    |
| ------ | ----- | ------------------ | ---------- |
| `name` | `str` | notification name. | *required* |

Returns:

| Type  | Description                            |
| ----- | -------------------------------------- |
| `int` | the state, as a signed 64-bit integer. |

Raises:

| Type                     | Description                                                        |
| ------------------------ | ------------------------------------------------------------------ |
| `NotificationStateError` | if the device reports a failure (always, on the insecure service). |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def notify_get_state(self, name: str) -> int:
    """
    Read the 64-bit state of a notification (``notify_get_state``). Requires iOS 27.2+.

    System daemons publish a current value this way, e.g. ``com.apple.springboard.lockstate``.
    A name nobody set reads as 0. Use a connection that observes nothing: a notification
    relayed while the reply is awaited is discarded.

    :param name: notification name.
    :returns: the state, as a signed 64-bit integer.
    :raises NotificationStateError: if the device reports a failure (always, on the insecure service).
    """
    await self.service.send_request({"Command": "GetNotificationState", "Name": name}, wanting_reply=True)
    while True:
        response = await self.service.receive_response()
        if response.get("Command") == "RelayNotificationState" and response.get("Name") == name:
            break
    status = response.get("Status", 0)
    if status:
        raise NotificationStateError(name, status)
    return int(response["State"])
```

### receive_notification

```
receive_notification() -> AsyncGenerator[NotificationEvent, None]
```

Yield notifications relayed from the device for previously observed names.

Each yielded message is of the form `{"Command": "RelayNotification", "Name": <notification name>}`. Since iOS 27.2 the secure service also includes `"State"`, the notification's 64-bit `notify_get_state()` value.

Returns:

| Type                                      | Description                                      |
| ----------------------------------------- | ------------------------------------------------ |
| `AsyncGenerator[NotificationEvent, None]` | an async generator of the relayed notifications. |

Source code in `pymobiledevice3/services/notification_proxy.py`

```
async def receive_notification(self) -> AsyncGenerator[NotificationEvent, None]:
    """
    Yield notifications relayed from the device for previously observed names.

    Each yielded message is of the form
    ``{"Command": "RelayNotification", "Name": <notification name>}``. Since iOS 27.2 the secure
    service also includes ``"State"``, the notification's 64-bit ``notify_get_state()`` value.

    :returns: an async generator of the relayed notifications.
    """
    while True:
        yield NotificationEvent.from_message(await self.service.receive_response())
```

## pymobiledevice3.services.timesync.TimeSyncService

Bases: `RemoteService`

Measure the device clock against the host clock over RemoteXPC.

The device's `timed` answers SNTP (RFC 4330) requests carried as RemoteXPC messages instead of UDP datagrams, which gives a sub-millisecond reading of the device's wall clock without touching it. The service only answers; it does not let the host set the device time.

Requires an RSD tunnel. Verified on iOS 27.2. Use as an async context manager.

Source code in `pymobiledevice3/services/timesync.py`

```
class TimeSyncService(RemoteService):
    """
    Measure the device clock against the host clock over RemoteXPC.

    The device's ``timed`` answers SNTP (RFC 4330) requests carried as RemoteXPC messages instead of
    UDP datagrams, which gives a sub-millisecond reading of the device's wall clock without touching
    it. The service only answers; it does not let the host set the device time.

    Requires an RSD tunnel. Verified on iOS 27.2. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.timed.remote"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        """
        :param rsd: RSD provider used to open the RemoteXPC service.
        """
        super().__init__(rsd, self.SERVICE_NAME)

    async def exchange(self) -> TimeSyncSample:
        """
        Perform a single SNTP exchange.

        :returns: the measured offset and delay, along with the server fields of the reply.
        :raises PyMobileDevice3Exception: if the device's reply is not a valid answer to the request.
        """
        t1 = time.time()
        transmit_timestamp = _pack_timestamp(t1)
        request = bytes([SNTP_CLIENT_HEADER]) + bytes(_TRANSMIT_TIMESTAMP_OFFSET - 1) + transmit_timestamp
        response = await self.service.send_receive_request({"MessageType": "Timesync", "TimesyncPayload": request})
        t4 = time.time()

        payload = response.get("TimesyncPayload")
        if not isinstance(payload, bytes) or len(payload) != SNTP_PACKET_SIZE:
            raise ProtocolError(f"The device sent a malformed time sync reply: {response}")
        if payload[0] & 0x7 != SNTP_MODE_SERVER:
            raise ProtocolError(f"The device's time sync reply is not an SNTP server packet: {payload.hex()}")
        if payload[_ORIGINATE_TIMESTAMP_OFFSET:_RECEIVE_TIMESTAMP_OFFSET] != transmit_timestamp:
            raise ProtocolError("The device's time sync reply does not answer the request that was sent.")

        t2 = _unpack_timestamp(payload[_RECEIVE_TIMESTAMP_OFFSET:_TRANSMIT_TIMESTAMP_OFFSET])
        t3 = _unpack_timestamp(payload[_TRANSMIT_TIMESTAMP_OFFSET:])
        return TimeSyncSample(
            offset=((t2 - t1) + (t3 - t4)) / 2,
            delay=(t4 - t1) - (t3 - t2),
            device_time=t3,
            root_dispersion=struct.unpack(">I", payload[8:12])[0] / (1 << 16),
            stratum=payload[1],
            reference_id=payload[12:16],
        )

    async def measure(self, samples: int = 8) -> TimeSyncSample:
        """
        Perform several exchanges and keep the one with the smallest round-trip delay.

        The offset error of an exchange is bounded by half its delay, so the quickest exchange is
        the most accurate one.

        :param samples: number of exchanges to perform.
        :returns: the sample with the lowest delay.
        """
        best = await self.exchange()
        for _ in range(samples - 1):
            sample = await self.exchange()
            if sample.delay < best.delay:
                best = sample
        return best
```

### exchange

```
exchange() -> TimeSyncSample
```

Perform a single SNTP exchange.

Returns:

| Type             | Description                                                               |
| ---------------- | ------------------------------------------------------------------------- |
| `TimeSyncSample` | the measured offset and delay, along with the server fields of the reply. |

Raises:

| Type                       | Description                                                 |
| -------------------------- | ----------------------------------------------------------- |
| `PyMobileDevice3Exception` | if the device's reply is not a valid answer to the request. |

Source code in `pymobiledevice3/services/timesync.py`

```
async def exchange(self) -> TimeSyncSample:
    """
    Perform a single SNTP exchange.

    :returns: the measured offset and delay, along with the server fields of the reply.
    :raises PyMobileDevice3Exception: if the device's reply is not a valid answer to the request.
    """
    t1 = time.time()
    transmit_timestamp = _pack_timestamp(t1)
    request = bytes([SNTP_CLIENT_HEADER]) + bytes(_TRANSMIT_TIMESTAMP_OFFSET - 1) + transmit_timestamp
    response = await self.service.send_receive_request({"MessageType": "Timesync", "TimesyncPayload": request})
    t4 = time.time()

    payload = response.get("TimesyncPayload")
    if not isinstance(payload, bytes) or len(payload) != SNTP_PACKET_SIZE:
        raise ProtocolError(f"The device sent a malformed time sync reply: {response}")
    if payload[0] & 0x7 != SNTP_MODE_SERVER:
        raise ProtocolError(f"The device's time sync reply is not an SNTP server packet: {payload.hex()}")
    if payload[_ORIGINATE_TIMESTAMP_OFFSET:_RECEIVE_TIMESTAMP_OFFSET] != transmit_timestamp:
        raise ProtocolError("The device's time sync reply does not answer the request that was sent.")

    t2 = _unpack_timestamp(payload[_RECEIVE_TIMESTAMP_OFFSET:_TRANSMIT_TIMESTAMP_OFFSET])
    t3 = _unpack_timestamp(payload[_TRANSMIT_TIMESTAMP_OFFSET:])
    return TimeSyncSample(
        offset=((t2 - t1) + (t3 - t4)) / 2,
        delay=(t4 - t1) - (t3 - t2),
        device_time=t3,
        root_dispersion=struct.unpack(">I", payload[8:12])[0] / (1 << 16),
        stratum=payload[1],
        reference_id=payload[12:16],
    )
```

### measure

```
measure(samples: int = 8) -> TimeSyncSample
```

Perform several exchanges and keep the one with the smallest round-trip delay.

The offset error of an exchange is bounded by half its delay, so the quickest exchange is the most accurate one.

Parameters:

| Name      | Type  | Description                     | Default |
| --------- | ----- | ------------------------------- | ------- |
| `samples` | `int` | number of exchanges to perform. | `8`     |

Returns:

| Type             | Description                       |
| ---------------- | --------------------------------- |
| `TimeSyncSample` | the sample with the lowest delay. |

Source code in `pymobiledevice3/services/timesync.py`

```
async def measure(self, samples: int = 8) -> TimeSyncSample:
    """
    Perform several exchanges and keep the one with the smallest round-trip delay.

    The offset error of an exchange is bounded by half its delay, so the quickest exchange is
    the most accurate one.

    :param samples: number of exchanges to perform.
    :returns: the sample with the lowest delay.
    """
    best = await self.exchange()
    for _ in range(samples - 1):
        sample = await self.exchange()
        if sample.delay < best.delay:
            best = sample
    return best
```

## pymobiledevice3.services.power_assertion.PowerAssertionService

Bases: `LockdownService`

Hold an IOKit power assertion on the device through the assertion agent lockdown service.

A power assertion prevents the device from sleeping (or otherwise alters its power behavior) for as long as it is held. This is a lockdown service and is used as an async context manager; the RSD/tunnel variant is selected automatically for non-`LockdownClient` providers.

Source code in `pymobiledevice3/services/power_assertion.py`

```
class PowerAssertionService(LockdownService):
    """
    Hold an IOKit power assertion on the device through the assertion agent lockdown service.

    A power assertion prevents the device from sleeping (or otherwise alters its power behavior)
    for as long as it is held. This is a lockdown service and is used as an async context manager;
    the RSD/tunnel variant is selected automatically for non-`LockdownClient` providers.
    """

    RSD_SERVICE_NAME = "com.apple.mobile.assertion_agent.shim.remote"
    SERVICE_NAME = "com.apple.mobile.assertion_agent"

    @contextlib.asynccontextmanager
    async def create_power_assertion(self, type_: str, name: str, timeout: float, details: Optional[str] = None):
        """
        Create a power assertion on the device, held for the duration of the ``with`` block.

        Sends a create-assertion command to the agent, which calls ``IOPMAssertionCreateWithName``
        on the device. This is an async context manager: the assertion stays active while the block
        is open.

        :param type_: IOKit assertion type (e.g. the assertion-type string passed to
            ``IOPMAssertionCreateWithName``).
        :param name: human-readable name identifying the assertion.
        :param timeout: assertion timeout in seconds, after which the device may release it.
        :param details: optional descriptive detail string attached to the assertion.
        """
        msg: dict[str, Any] = {
            "CommandKey": "CommandCreateAssertion",
            "AssertionTypeKey": type_,
            "AssertionNameKey": name,
            "AssertionTimeoutKey": timeout,
        }

        if details is not None:
            msg["AssertionDetailKey"] = details

        await self.service.send_recv_plist(msg)
        yield
```

### create_power_assertion

```
create_power_assertion(type_: str, name: str, timeout: float, details: Optional[str] = None)
```

Create a power assertion on the device, held for the duration of the `with` block.

Sends a create-assertion command to the agent, which calls `IOPMAssertionCreateWithName` on the device. This is an async context manager: the assertion stays active while the block is open.

Parameters:

| Name      | Type            | Description                                                                                  | Default    |
| --------- | --------------- | -------------------------------------------------------------------------------------------- | ---------- |
| `type_`   | `str`           | IOKit assertion type (e.g. the assertion-type string passed to IOPMAssertionCreateWithName). | *required* |
| `name`    | `str`           | human-readable name identifying the assertion.                                               | *required* |
| `timeout` | `float`         | assertion timeout in seconds, after which the device may release it.                         | *required* |
| `details` | `Optional[str]` | optional descriptive detail string attached to the assertion.                                | `None`     |

Source code in `pymobiledevice3/services/power_assertion.py`

```
@contextlib.asynccontextmanager
async def create_power_assertion(self, type_: str, name: str, timeout: float, details: Optional[str] = None):
    """
    Create a power assertion on the device, held for the duration of the ``with`` block.

    Sends a create-assertion command to the agent, which calls ``IOPMAssertionCreateWithName``
    on the device. This is an async context manager: the assertion stays active while the block
    is open.

    :param type_: IOKit assertion type (e.g. the assertion-type string passed to
        ``IOPMAssertionCreateWithName``).
    :param name: human-readable name identifying the assertion.
    :param timeout: assertion timeout in seconds, after which the device may release it.
    :param details: optional descriptive detail string attached to the assertion.
    """
    msg: dict[str, Any] = {
        "CommandKey": "CommandCreateAssertion",
        "AssertionTypeKey": type_,
        "AssertionNameKey": name,
        "AssertionTimeoutKey": timeout,
    }

    if details is not None:
        msg["AssertionDetailKey"] = details

    await self.service.send_recv_plist(msg)
    yield
```

## pymobiledevice3.services.heartbeat.HeartbeatService

Keep an active connection alive with the device's heartbeat lockdown service.

The device periodically sends `Marco` messages over `com.apple.mobile.heartbeat` and expects a `Polo` reply; exchanging them prevents the connection from being torn down. The RSD/tunnel variant of the service is selected automatically when the provider is not a plain `LockdownClient`.

Source code in `pymobiledevice3/services/heartbeat.py`

```
class HeartbeatService:
    """
    Keep an active connection alive with the device's heartbeat lockdown service.

    The device periodically sends ``Marco`` messages over ``com.apple.mobile.heartbeat`` and expects a
    ``Polo`` reply; exchanging them prevents the connection from being torn down. The RSD/tunnel variant
    of the service is selected automatically when the provider is not a plain `LockdownClient`.
    """

    SERVICE_NAME = "com.apple.mobile.heartbeat"
    RSD_SERVICE_NAME = "com.apple.mobile.heartbeat.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

        if isinstance(lockdown, LockdownClient):
            self.service_name = self.SERVICE_NAME
        else:
            self.service_name = self.RSD_SERVICE_NAME

    async def start(self, interval: Optional[float] = None) -> None:
        """
        Start the heartbeat exchange loop.

        Opens the heartbeat service and, in a loop, receives each message from the device and replies
        with ``Polo`` to keep the connection alive.

        :param interval: when set, stop the loop once roughly this many seconds have elapsed since it
            started; when None, the loop runs indefinitely.
        """
        start = time.time()
        async with await self.lockdown.start_lockdown_service(self.service_name) as service:
            while True:
                response = await service.recv_plist()
                self.logger.debug(response)

                if interval is not None and time.time() >= start + interval:
                    break

                await service.send_plist({"Command": "Polo"})
```

### start

```
start(interval: Optional[float] = None) -> None
```

Start the heartbeat exchange loop.

Opens the heartbeat service and, in a loop, receives each message from the device and replies with `Polo` to keep the connection alive.

Parameters:

| Name       | Type              | Description                                                                                                                  | Default |
| ---------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------- |
| `interval` | `Optional[float]` | when set, stop the loop once roughly this many seconds have elapsed since it started; when None, the loop runs indefinitely. | `None`  |

Source code in `pymobiledevice3/services/heartbeat.py`

```
async def start(self, interval: Optional[float] = None) -> None:
    """
    Start the heartbeat exchange loop.

    Opens the heartbeat service and, in a loop, receives each message from the device and replies
    with ``Polo`` to keep the connection alive.

    :param interval: when set, stop the loop once roughly this many seconds have elapsed since it
        started; when None, the loop runs indefinitely.
    """
    start = time.time()
    async with await self.lockdown.start_lockdown_service(self.service_name) as service:
        while True:
            response = await service.recv_plist()
            self.logger.debug(response)

            if interval is not None and time.time() >= start + interval:
                break

            await service.send_plist({"Command": "Polo"})
```

## pymobiledevice3.services.companion.CompanionProxyService

Bases: `LockdownService`

Query and interact with companion devices (e.g. a paired Apple Watch) via the companion proxy lockdown service.

Provides access to the paired-device registry, live notifications of companion devices coming and going, registry value lookups, and TCP port forwarding to a companion device. This is a lockdown service and is used as an async context manager; the RSD/tunnel variant is selected automatically for non-`LockdownClient` providers.

Source code in `pymobiledevice3/services/companion.py`

```
class CompanionProxyService(LockdownService):
    """
    Query and interact with companion devices (e.g. a paired Apple Watch) via the companion proxy
    lockdown service.

    Provides access to the paired-device registry, live notifications of companion devices coming
    and going, registry value lookups, and TCP port forwarding to a companion device. This is a
    lockdown service and is used as an async context manager; the RSD/tunnel variant is selected
    automatically for non-`LockdownClient` providers.
    """

    SERVICE_NAME = "com.apple.companion_proxy"
    RSD_SERVICE_NAME = "com.apple.companion_proxy.shim.remote"

    async def list(self):
        """
        List the companion devices currently paired with the device.

        Sends a ``GetDeviceRegistry`` command and returns the paired-device registry.

        :returns: the list of paired devices (the ``PairedDevicesArray`` entry), or an empty list
            if none are present.
        """
        async with await self.lockdown.start_lockdown_service(self.service_name) as service:
            return (await service.send_recv_plist({"Command": "GetDeviceRegistry"})).get("PairedDevicesArray", [])

    async def listen_for_devices(self):
        """
        Yield events as companion devices appear and disappear.

        Sends ``StartListeningForDevices`` and then continuously yields each event message the
        device emits.

        :returns: an async generator of device registry change events.
        """
        async with await self.lockdown.start_lockdown_service(self.service_name) as service:
            await service.send_plist({"Command": "StartListeningForDevices"})
            while True:
                yield await service.recv_plist()

    async def get_value(self, udid: str, key: str):
        """
        Read a single value from the registry of a specific companion device.

        Sends a ``GetValueFromRegistry`` command for the given device and key.

        :param udid: UDID of the companion device to query.
        :param key: registry key whose value should be retrieved.
        :returns: the retrieved value dictionary.
        :raises PyMobileDevice3Exception: if the device returns an error instead of a value.
        """
        async with await self.lockdown.start_lockdown_service(self.service_name) as service:
            response = await service.send_recv_plist({
                "Command": "GetValueFromRegistry",
                "GetValueGizmoUDIDKey": udid,
                "GetValueKeyKey": key,
            })

        value = response.get("RetrievedValueDictionary")
        if value is not None:
            return value

        error = response.get("Error")
        raise PyMobileDevice3Exception(f"The device could not read {key!r} from the paired watch {udid}: {error}")

    async def start_forwarding_service_port(
        self, remote_port: int, service_name: Optional[str] = None, options: Optional[dict[str, Any]] = None
    ):
        """
        Start forwarding a port on the companion device through the proxy.

        Sends a ``StartForwardingServicePort`` command for the given remote port. The request
        defaults the forwarded service to non-low-priority and does not prefer Wi-Fi; these and any
        other fields may be overridden via ``options``.

        :param remote_port: port number on the companion device to forward.
        :param service_name: optional name of the forwarded service, sent as ``ForwardedServiceName``.
        :param options: optional dictionary merged into the request to override default fields.
        :returns: the local proxy port assigned for the forwarded connection
            (the ``CompanionProxyServicePort`` value).
        """
        service = await self.lockdown.start_lockdown_service(self.service_name)

        request: dict[str, Any] = {
            "Command": "StartForwardingServicePort",
            "GizmoRemotePortNumber": remote_port,
            "IsServiceLowPriority": False,
            "PreferWifi": False,
        }

        if service_name is not None:
            request["ForwardedServiceName"] = service_name

        if options is not None:
            request.update(options)

        return (await service.send_recv_plist(request)).get("CompanionProxyServicePort")

    async def stop_forwarding_service_port(self, remote_port: int):
        """
        Stop a port forward previously started with `start_forwarding_service_port`.

        Sends a ``StopForwardingServicePort`` command for the given remote port.

        :param remote_port: port number on the companion device whose forwarding should be stopped.
        :returns: the device's response to the stop command.
        """
        service = await self.lockdown.start_lockdown_service(self.service_name)

        request: dict[str, Any] = {"Command": "StopForwardingServicePort", "GizmoRemotePortNumber": remote_port}

        return await service.send_recv_plist(request)
```

### list

```
list()
```

List the companion devices currently paired with the device.

Sends a `GetDeviceRegistry` command and returns the paired-device registry.

Returns:

| Type | Description                                                                                      |
| ---- | ------------------------------------------------------------------------------------------------ |
|      | the list of paired devices (the PairedDevicesArray entry), or an empty list if none are present. |

Source code in `pymobiledevice3/services/companion.py`

```
async def list(self):
    """
    List the companion devices currently paired with the device.

    Sends a ``GetDeviceRegistry`` command and returns the paired-device registry.

    :returns: the list of paired devices (the ``PairedDevicesArray`` entry), or an empty list
        if none are present.
    """
    async with await self.lockdown.start_lockdown_service(self.service_name) as service:
        return (await service.send_recv_plist({"Command": "GetDeviceRegistry"})).get("PairedDevicesArray", [])
```

### listen_for_devices

```
listen_for_devices()
```

Yield events as companion devices appear and disappear.

Sends `StartListeningForDevices` and then continuously yields each event message the device emits.

Returns:

| Type | Description                                          |
| ---- | ---------------------------------------------------- |
|      | an async generator of device registry change events. |

Source code in `pymobiledevice3/services/companion.py`

```
async def listen_for_devices(self):
    """
    Yield events as companion devices appear and disappear.

    Sends ``StartListeningForDevices`` and then continuously yields each event message the
    device emits.

    :returns: an async generator of device registry change events.
    """
    async with await self.lockdown.start_lockdown_service(self.service_name) as service:
        await service.send_plist({"Command": "StartListeningForDevices"})
        while True:
            yield await service.recv_plist()
```

### get_value

```
get_value(udid: str, key: str)
```

Read a single value from the registry of a specific companion device.

Sends a `GetValueFromRegistry` command for the given device and key.

Parameters:

| Name   | Type  | Description                                   | Default    |
| ------ | ----- | --------------------------------------------- | ---------- |
| `udid` | `str` | UDID of the companion device to query.        | *required* |
| `key`  | `str` | registry key whose value should be retrieved. | *required* |

Returns:

| Type | Description                     |
| ---- | ------------------------------- |
|      | the retrieved value dictionary. |

Raises:

| Type                       | Description                                        |
| -------------------------- | -------------------------------------------------- |
| `PyMobileDevice3Exception` | if the device returns an error instead of a value. |

Source code in `pymobiledevice3/services/companion.py`

```
async def get_value(self, udid: str, key: str):
    """
    Read a single value from the registry of a specific companion device.

    Sends a ``GetValueFromRegistry`` command for the given device and key.

    :param udid: UDID of the companion device to query.
    :param key: registry key whose value should be retrieved.
    :returns: the retrieved value dictionary.
    :raises PyMobileDevice3Exception: if the device returns an error instead of a value.
    """
    async with await self.lockdown.start_lockdown_service(self.service_name) as service:
        response = await service.send_recv_plist({
            "Command": "GetValueFromRegistry",
            "GetValueGizmoUDIDKey": udid,
            "GetValueKeyKey": key,
        })

    value = response.get("RetrievedValueDictionary")
    if value is not None:
        return value

    error = response.get("Error")
    raise PyMobileDevice3Exception(f"The device could not read {key!r} from the paired watch {udid}: {error}")
```

### start_forwarding_service_port

```
start_forwarding_service_port(remote_port: int, service_name: Optional[str] = None, options: Optional[dict[str, Any]] = None)
```

Start forwarding a port on the companion device through the proxy.

Sends a `StartForwardingServicePort` command for the given remote port. The request defaults the forwarded service to non-low-priority and does not prefer Wi-Fi; these and any other fields may be overridden via `options`.

Parameters:

| Name           | Type                       | Description                                                             | Default    |
| -------------- | -------------------------- | ----------------------------------------------------------------------- | ---------- |
| `remote_port`  | `int`                      | port number on the companion device to forward.                         | *required* |
| `service_name` | `Optional[str]`            | optional name of the forwarded service, sent as ForwardedServiceName.   | `None`     |
| `options`      | `Optional[dict[str, Any]]` | optional dictionary merged into the request to override default fields. | `None`     |

Returns:

| Type | Description                                                                                       |
| ---- | ------------------------------------------------------------------------------------------------- |
|      | the local proxy port assigned for the forwarded connection (the CompanionProxyServicePort value). |

Source code in `pymobiledevice3/services/companion.py`

```
async def start_forwarding_service_port(
    self, remote_port: int, service_name: Optional[str] = None, options: Optional[dict[str, Any]] = None
):
    """
    Start forwarding a port on the companion device through the proxy.

    Sends a ``StartForwardingServicePort`` command for the given remote port. The request
    defaults the forwarded service to non-low-priority and does not prefer Wi-Fi; these and any
    other fields may be overridden via ``options``.

    :param remote_port: port number on the companion device to forward.
    :param service_name: optional name of the forwarded service, sent as ``ForwardedServiceName``.
    :param options: optional dictionary merged into the request to override default fields.
    :returns: the local proxy port assigned for the forwarded connection
        (the ``CompanionProxyServicePort`` value).
    """
    service = await self.lockdown.start_lockdown_service(self.service_name)

    request: dict[str, Any] = {
        "Command": "StartForwardingServicePort",
        "GizmoRemotePortNumber": remote_port,
        "IsServiceLowPriority": False,
        "PreferWifi": False,
    }

    if service_name is not None:
        request["ForwardedServiceName"] = service_name

    if options is not None:
        request.update(options)

    return (await service.send_recv_plist(request)).get("CompanionProxyServicePort")
```

### stop_forwarding_service_port

```
stop_forwarding_service_port(remote_port: int)
```

Stop a port forward previously started with `start_forwarding_service_port`.

Sends a `StopForwardingServicePort` command for the given remote port.

Parameters:

| Name          | Type  | Description                                                             | Default    |
| ------------- | ----- | ----------------------------------------------------------------------- | ---------- |
| `remote_port` | `int` | port number on the companion device whose forwarding should be stopped. | *required* |

Returns:

| Type | Description                                |
| ---- | ------------------------------------------ |
|      | the device's response to the stop command. |

Source code in `pymobiledevice3/services/companion.py`

```
async def stop_forwarding_service_port(self, remote_port: int):
    """
    Stop a port forward previously started with `start_forwarding_service_port`.

    Sends a ``StopForwardingServicePort`` command for the given remote port.

    :param remote_port: port number on the companion device whose forwarding should be stopped.
    :returns: the device's response to the stop command.
    """
    service = await self.lockdown.start_lockdown_service(self.service_name)

    request: dict[str, Any] = {"Command": "StopForwardingServicePort", "GizmoRemotePortNumber": remote_port}

    return await service.send_recv_plist(request)
```

## pymobiledevice3.services.preboard.PreboardService

Bases: `LockdownService`

Manage preboard stashbags on the device via the `com.apple.preboardservice_v2` lockdown service.

A stashbag holds key material that allows the device to unlock data-protection classes during an unattended reboot (e.g. before the user enters their passcode). This service creates and commits such stashbags. This is a lockdown service and is used as an async context manager; the RSD/tunnel variant is selected automatically for non-`LockdownClient` providers.

Source code in `pymobiledevice3/services/preboard.py`

```
class PreboardService(LockdownService):
    """
    Manage preboard stashbags on the device via the ``com.apple.preboardservice_v2`` lockdown service.

    A stashbag holds key material that allows the device to unlock data-protection classes during an
    unattended reboot (e.g. before the user enters their passcode). This service creates and commits
    such stashbags. This is a lockdown service and is used as an async context manager; the
    RSD/tunnel variant is selected automatically for non-`LockdownClient` providers.
    """

    RSD_SERVICE_NAME = "com.apple.preboardservice_v2.shim.remote"
    SERVICE_NAME = "com.apple.preboardservice_v2"

    async def create_stashbag(self, manifest: bytes):
        """
        Create a stashbag on the device.

        Sends a ``CreateStashbag`` command with the given manifest.

        :param manifest: the stashbag manifest describing the key material to stash.
        :returns: the device's response to the command.
        """
        return await self.service.send_recv_plist({"Command": "CreateStashbag", "Manifest": manifest})

    async def commit(self, manifest: bytes):
        """
        Commit a previously created stashbag on the device.

        Sends a ``CommitStashbag`` command with the given manifest.

        :param manifest: the stashbag manifest to commit.
        :returns: the device's response to the command.
        """
        return await self.service.send_recv_plist({"Command": "CommitStashbag", "Manifest": manifest})
```

### create_stashbag

```
create_stashbag(manifest: bytes)
```

Create a stashbag on the device.

Sends a `CreateStashbag` command with the given manifest.

Parameters:

| Name       | Type    | Description                                                 | Default    |
| ---------- | ------- | ----------------------------------------------------------- | ---------- |
| `manifest` | `bytes` | the stashbag manifest describing the key material to stash. | *required* |

Returns:

| Type | Description                           |
| ---- | ------------------------------------- |
|      | the device's response to the command. |

Source code in `pymobiledevice3/services/preboard.py`

```
async def create_stashbag(self, manifest: bytes):
    """
    Create a stashbag on the device.

    Sends a ``CreateStashbag`` command with the given manifest.

    :param manifest: the stashbag manifest describing the key material to stash.
    :returns: the device's response to the command.
    """
    return await self.service.send_recv_plist({"Command": "CreateStashbag", "Manifest": manifest})
```

### commit

```
commit(manifest: bytes)
```

Commit a previously created stashbag on the device.

Sends a `CommitStashbag` command with the given manifest.

Parameters:

| Name       | Type    | Description                      | Default    |
| ---------- | ------- | -------------------------------- | ---------- |
| `manifest` | `bytes` | the stashbag manifest to commit. | *required* |

Returns:

| Type | Description                           |
| ---- | ------------------------------------- |
|      | the device's response to the command. |

Source code in `pymobiledevice3/services/preboard.py`

```
async def commit(self, manifest: bytes):
    """
    Commit a previously created stashbag on the device.

    Sends a ``CommitStashbag`` command with the given manifest.

    :param manifest: the stashbag manifest to commit.
    :returns: the device's response to the command.
    """
    return await self.service.send_recv_plist({"Command": "CommitStashbag", "Manifest": manifest})
```

## pymobiledevice3.services.restore_service.RestoreService

Bases: `RemoteService`

Issue restore-time control commands to `restoreserviced` over RemoteXPC.

Wraps the `com.apple.RestoreRemoteServices.restoreserviced` remote service, exposing commands used during the restore/recovery flow such as entering recovery, rebooting, and reading nonces and preflight information. This is a remote service reached over RSD and is used as an async context manager.

Source code in `pymobiledevice3/services/restore_service.py`

```
class RestoreService(RemoteService):
    """
    Issue restore-time control commands to ``restoreserviced`` over RemoteXPC.

    Wraps the ``com.apple.RestoreRemoteServices.restoreserviced`` remote service, exposing commands
    used during the restore/recovery flow such as entering recovery, rebooting, and reading nonces
    and preflight information. This is a remote service reached over RSD and is used as an async
    context manager.
    """

    SERVICE_NAME = "com.apple.RestoreRemoteServices.restoreserviced"

    def __init__(self, lockdown: RemoteServiceDiscoveryService):
        super().__init__(lockdown, self.SERVICE_NAME)

    async def delay_recovery_image(self) -> None:
        """
        Request that the recovery image be delayed.

        Sends the ``delayrecoveryimage`` command, which is only honored on devices of ProductType
        ``0x1677b394`` and otherwise fails.

        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        await self.validate_command("delayrecoveryimage")

    async def enter_recovery(self) -> None:
        """
        Put the device into recovery mode.

        Sends the ``recovery`` command.

        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        await self.validate_command("recovery")

    async def reboot(self) -> None:
        """
        Reboot the device.

        Sends the ``reboot`` command.

        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        await self.validate_command("reboot")

    async def get_preflightinfo(self) -> dict[str, Any]:
        """
        Retrieve restore preflight information from the device.

        Sends the ``getpreflightinfo`` command.

        :returns: the device's preflight info response.
        """
        return await self.service.send_receive_request({"command": "getpreflightinfo"})

    async def get_device_side_preflightinfo(self, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """
        Run the updaters' preflight on the device and return what they report.

        Sends the ``getdevicesidepreflightinfo`` command. Without a payload the reply is the same
        per-updater ``DeviceInfo`` lockdown's ``PreflightInfo`` carries. With a ``payload`` of the
        form ``{"BuildIdentity": <identity>, "<Updater>": {<manifest tag>: <firmware bytes>}}`` the
        device also builds the TSS request of every updater named in it (``DeviceInfoRequests``)
        and reports its tags (``DeviceInfoTags``) — the same request restored sends during a restore.
        See :func:`pymobiledevice3.restore.preflight.build_tethered_preflight_payload`.

        :param payload: the tethered preflight payload, or None for the plain query.
        :returns: the ``preflightinfo`` dictionary of the reply.
        :raises PyMobileDevice3Exception: if the device reports an error.
        """
        request: dict[str, Any] = {"command": "getdevicesidepreflightinfo"}
        if payload is not None:
            request["payload"] = _xpc_encodable(payload)
        response = await self.service.send_receive_request(request)
        if response.get("result") != "preflightinfo":
            raise PyMobileDevice3Exception(f"The device failed the restore preflight info request: {response}")
        return response["preflightinfo"]

    async def get_nonces(self) -> dict[str, Any]:
        """
        Retrieve the device's restore nonces.

        Sends the ``getnonces`` command.

        :returns: the response containing the ApNonce and SEPNonce.
        """
        return await self.service.send_receive_request({"command": "getnonces"})

    async def get_app_parameters(self) -> dict[str, Any]:
        """
        Retrieve restore app parameters from the device.

        Sends the ``getappparameters`` command.

        :returns: the device's app parameters response.
        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        return await self.validate_command("getappparameters")

    async def restore_lang(self, language: str) -> dict[str, Any]:
        """
        Set the restore language.

        Sends the ``restorelang`` command with the given language as its argument.

        :param language: the language identifier to set for the restore.
        :returns: the device's response to the command.
        """
        return await self.service.send_receive_request({"command": "restorelang", "argument": language})

    async def validate_command(self, command: str) -> dict[str, Any]:
        """
        Send a command and assert that the device reports success.

        Sends the given command and verifies the response ``result`` is ``"success"``.

        :param command: the restore command name to send.
        :returns: the device's response.
        :raises PyMobileDevice3Exception: if the response result is not ``"success"``.
        """
        response = await self.service.send_receive_request({"command": command})
        if response.get("result") != "success":
            raise PyMobileDevice3Exception(f"The device failed the {command} restore command: {response}")
        return response
```

### delay_recovery_image

```
delay_recovery_image() -> None
```

Request that the recovery image be delayed.

Sends the `delayrecoveryimage` command, which is only honored on devices of ProductType `0x1677b394` and otherwise fails.

Raises:

| Type                       | Description                            |
| -------------------------- | -------------------------------------- |
| `PyMobileDevice3Exception` | if the device does not report success. |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def delay_recovery_image(self) -> None:
    """
    Request that the recovery image be delayed.

    Sends the ``delayrecoveryimage`` command, which is only honored on devices of ProductType
    ``0x1677b394`` and otherwise fails.

    :raises PyMobileDevice3Exception: if the device does not report success.
    """
    await self.validate_command("delayrecoveryimage")
```

### enter_recovery

```
enter_recovery() -> None
```

Put the device into recovery mode.

Sends the `recovery` command.

Raises:

| Type                       | Description                            |
| -------------------------- | -------------------------------------- |
| `PyMobileDevice3Exception` | if the device does not report success. |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def enter_recovery(self) -> None:
    """
    Put the device into recovery mode.

    Sends the ``recovery`` command.

    :raises PyMobileDevice3Exception: if the device does not report success.
    """
    await self.validate_command("recovery")
```

### reboot

```
reboot() -> None
```

Reboot the device.

Sends the `reboot` command.

Raises:

| Type                       | Description                            |
| -------------------------- | -------------------------------------- |
| `PyMobileDevice3Exception` | if the device does not report success. |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def reboot(self) -> None:
    """
    Reboot the device.

    Sends the ``reboot`` command.

    :raises PyMobileDevice3Exception: if the device does not report success.
    """
    await self.validate_command("reboot")
```

### get_preflightinfo

```
get_preflightinfo() -> dict[str, Any]
```

Retrieve restore preflight information from the device.

Sends the `getpreflightinfo` command.

Returns:

| Type             | Description                           |
| ---------------- | ------------------------------------- |
| `dict[str, Any]` | the device's preflight info response. |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def get_preflightinfo(self) -> dict[str, Any]:
    """
    Retrieve restore preflight information from the device.

    Sends the ``getpreflightinfo`` command.

    :returns: the device's preflight info response.
    """
    return await self.service.send_receive_request({"command": "getpreflightinfo"})
```

### get_device_side_preflightinfo

```
get_device_side_preflightinfo(payload: Optional[dict[str, Any]] = None) -> dict[str, Any]
```

Run the updaters' preflight on the device and return what they report.

Sends the `getdevicesidepreflightinfo` command. Without a payload the reply is the same per-updater `DeviceInfo` lockdown's `PreflightInfo` carries. With a `payload` of the form `{"BuildIdentity": <identity>, "<Updater>": {<manifest tag>: <firmware bytes>}}` the device also builds the TSS request of every updater named in it (`DeviceInfoRequests`) and reports its tags (`DeviceInfoTags`) — the same request restored sends during a restore. See :func:`pymobiledevice3.restore.preflight.build_tethered_preflight_payload`.

Parameters:

| Name      | Type                       | Description                                                  | Default |
| --------- | -------------------------- | ------------------------------------------------------------ | ------- |
| `payload` | `Optional[dict[str, Any]]` | the tethered preflight payload, or None for the plain query. | `None`  |

Returns:

| Type             | Description                                |
| ---------------- | ------------------------------------------ |
| `dict[str, Any]` | the preflightinfo dictionary of the reply. |

Raises:

| Type                       | Description                     |
| -------------------------- | ------------------------------- |
| `PyMobileDevice3Exception` | if the device reports an error. |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def get_device_side_preflightinfo(self, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """
    Run the updaters' preflight on the device and return what they report.

    Sends the ``getdevicesidepreflightinfo`` command. Without a payload the reply is the same
    per-updater ``DeviceInfo`` lockdown's ``PreflightInfo`` carries. With a ``payload`` of the
    form ``{"BuildIdentity": <identity>, "<Updater>": {<manifest tag>: <firmware bytes>}}`` the
    device also builds the TSS request of every updater named in it (``DeviceInfoRequests``)
    and reports its tags (``DeviceInfoTags``) — the same request restored sends during a restore.
    See :func:`pymobiledevice3.restore.preflight.build_tethered_preflight_payload`.

    :param payload: the tethered preflight payload, or None for the plain query.
    :returns: the ``preflightinfo`` dictionary of the reply.
    :raises PyMobileDevice3Exception: if the device reports an error.
    """
    request: dict[str, Any] = {"command": "getdevicesidepreflightinfo"}
    if payload is not None:
        request["payload"] = _xpc_encodable(payload)
    response = await self.service.send_receive_request(request)
    if response.get("result") != "preflightinfo":
        raise PyMobileDevice3Exception(f"The device failed the restore preflight info request: {response}")
    return response["preflightinfo"]
```

### get_nonces

```
get_nonces() -> dict[str, Any]
```

Retrieve the device's restore nonces.

Sends the `getnonces` command.

Returns:

| Type             | Description                                       |
| ---------------- | ------------------------------------------------- |
| `dict[str, Any]` | the response containing the ApNonce and SEPNonce. |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def get_nonces(self) -> dict[str, Any]:
    """
    Retrieve the device's restore nonces.

    Sends the ``getnonces`` command.

    :returns: the response containing the ApNonce and SEPNonce.
    """
    return await self.service.send_receive_request({"command": "getnonces"})
```

### get_app_parameters

```
get_app_parameters() -> dict[str, Any]
```

Retrieve restore app parameters from the device.

Sends the `getappparameters` command.

Returns:

| Type             | Description                           |
| ---------------- | ------------------------------------- |
| `dict[str, Any]` | the device's app parameters response. |

Raises:

| Type                       | Description                            |
| -------------------------- | -------------------------------------- |
| `PyMobileDevice3Exception` | if the device does not report success. |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def get_app_parameters(self) -> dict[str, Any]:
    """
    Retrieve restore app parameters from the device.

    Sends the ``getappparameters`` command.

    :returns: the device's app parameters response.
    :raises PyMobileDevice3Exception: if the device does not report success.
    """
    return await self.validate_command("getappparameters")
```

### restore_lang

```
restore_lang(language: str) -> dict[str, Any]
```

Set the restore language.

Sends the `restorelang` command with the given language as its argument.

Parameters:

| Name       | Type  | Description                                     | Default    |
| ---------- | ----- | ----------------------------------------------- | ---------- |
| `language` | `str` | the language identifier to set for the restore. | *required* |

Returns:

| Type             | Description                           |
| ---------------- | ------------------------------------- |
| `dict[str, Any]` | the device's response to the command. |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def restore_lang(self, language: str) -> dict[str, Any]:
    """
    Set the restore language.

    Sends the ``restorelang`` command with the given language as its argument.

    :param language: the language identifier to set for the restore.
    :returns: the device's response to the command.
    """
    return await self.service.send_receive_request({"command": "restorelang", "argument": language})
```

### validate_command

```
validate_command(command: str) -> dict[str, Any]
```

Send a command and assert that the device reports success.

Sends the given command and verifies the response `result` is `"success"`.

Parameters:

| Name      | Type  | Description                       | Default    |
| --------- | ----- | --------------------------------- | ---------- |
| `command` | `str` | the restore command name to send. | *required* |

Returns:

| Type             | Description            |
| ---------------- | ---------------------- |
| `dict[str, Any]` | the device's response. |

Raises:

| Type                       | Description                              |
| -------------------------- | ---------------------------------------- |
| `PyMobileDevice3Exception` | if the response result is not "success". |

Source code in `pymobiledevice3/services/restore_service.py`

```
async def validate_command(self, command: str) -> dict[str, Any]:
    """
    Send a command and assert that the device reports success.

    Sends the given command and verifies the response ``result`` is ``"success"``.

    :param command: the restore command name to send.
    :returns: the device's response.
    :raises PyMobileDevice3Exception: if the response result is not ``"success"``.
    """
    response = await self.service.send_receive_request({"command": command})
    if response.get("result") != "success":
        raise PyMobileDevice3Exception(f"The device failed the {command} restore command: {response}")
    return response
```

## pymobiledevice3.services.device_arbitration.DtDeviceArbitration

Bases: `LockdownService`

Claim and release exclusive use of a device via the `com.apple.dt.devicearbitration` service.

Device arbitration lets a host check a device in (claiming it, optionally forcibly) so other hosts know it is in use, and check it back out when done. This is a developer lockdown service (it requires the DeveloperDiskImage to be mounted) and is used as an async context manager.

Source code in `pymobiledevice3/services/device_arbitration.py`

```
class DtDeviceArbitration(LockdownService):
    """
    Claim and release exclusive use of a device via the ``com.apple.dt.devicearbitration`` service.

    Device arbitration lets a host check a device in (claiming it, optionally forcibly) so other
    hosts know it is in use, and check it back out when done. This is a developer lockdown service
    (it requires the DeveloperDiskImage to be mounted) and is used as an async context manager.
    """

    SERVICE_NAME = "com.apple.dt.devicearbitration"

    def __init__(self, lockdown: LockdownServiceProvider):
        super().__init__(lockdown, self.SERVICE_NAME, is_developer_service=True)

    async def _send_recv(self, request: dict[str, Any]) -> dict[str, Any]:
        return await self.service.send_recv_plist(request)

    async def version(self) -> dict[str, Any]:
        """
        Query the arbitration service version.

        Sends the ``version`` command.

        :returns: the device's version response.
        """
        return await self._send_recv({"command": "version"})

    async def check_in(self, hostname: str, force: bool = False):
        """
        Claim the device for the given host.

        Sends a ``check-in`` command tagging the device with ``hostname``. When ``force`` is True,
        a ``force-check-in`` command is sent instead, taking the device even if another host holds it.

        :param hostname: identifier of the host claiming the device.
        :param force: when True, forcibly claim the device even if it is already in use.
        :raises DeviceAlreadyInUseError: if the device is already checked in by another host
            (and ``force`` is not used).
        """
        request = {"command": "check-in", "hostname": hostname}
        if force:
            request["command"] = "force-check-in"
        response = await self._send_recv(request)
        if response.get("result") != "success":
            raise DeviceAlreadyInUseError(response)

    async def check_out(self):
        """
        Release a previously claimed device.

        Sends the ``check-out`` command.

        :raises ArbitrationError: if the device does not report success.
        """
        request = {"command": "check-out"}
        response = await self._send_recv(request)
        if response.get("result") != "success":
            raise ArbitrationError(
                f"The device arbitration service refused to release (check out) the device: {response}"
            )
```

### version

```
version() -> dict[str, Any]
```

Query the arbitration service version.

Sends the `version` command.

Returns:

| Type             | Description                    |
| ---------------- | ------------------------------ |
| `dict[str, Any]` | the device's version response. |

Source code in `pymobiledevice3/services/device_arbitration.py`

```
async def version(self) -> dict[str, Any]:
    """
    Query the arbitration service version.

    Sends the ``version`` command.

    :returns: the device's version response.
    """
    return await self._send_recv({"command": "version"})
```

### check_in

```
check_in(hostname: str, force: bool = False)
```

Claim the device for the given host.

Sends a `check-in` command tagging the device with `hostname`. When `force` is True, a `force-check-in` command is sent instead, taking the device even if another host holds it.

Parameters:

| Name       | Type   | Description                                                        | Default    |
| ---------- | ------ | ------------------------------------------------------------------ | ---------- |
| `hostname` | `str`  | identifier of the host claiming the device.                        | *required* |
| `force`    | `bool` | when True, forcibly claim the device even if it is already in use. | `False`    |

Raises:

| Type                      | Description                                                                  |
| ------------------------- | ---------------------------------------------------------------------------- |
| `DeviceAlreadyInUseError` | if the device is already checked in by another host (and force is not used). |

Source code in `pymobiledevice3/services/device_arbitration.py`

```
async def check_in(self, hostname: str, force: bool = False):
    """
    Claim the device for the given host.

    Sends a ``check-in`` command tagging the device with ``hostname``. When ``force`` is True,
    a ``force-check-in`` command is sent instead, taking the device even if another host holds it.

    :param hostname: identifier of the host claiming the device.
    :param force: when True, forcibly claim the device even if it is already in use.
    :raises DeviceAlreadyInUseError: if the device is already checked in by another host
        (and ``force`` is not used).
    """
    request = {"command": "check-in", "hostname": hostname}
    if force:
        request["command"] = "force-check-in"
    response = await self._send_recv(request)
    if response.get("result") != "success":
        raise DeviceAlreadyInUseError(response)
```

### check_out

```
check_out()
```

Release a previously claimed device.

Sends the `check-out` command.

Raises:

| Type               | Description                            |
| ------------------ | -------------------------------------- |
| `ArbitrationError` | if the device does not report success. |

Source code in `pymobiledevice3/services/device_arbitration.py`

```
async def check_out(self):
    """
    Release a previously claimed device.

    Sends the ``check-out`` command.

    :raises ArbitrationError: if the device does not report success.
    """
    request = {"command": "check-out"}
    response = await self._send_recv(request)
    if response.get("result") != "success":
        raise ArbitrationError(
            f"The device arbitration service refused to release (check out) the device: {response}"
        )
```

## pymobiledevice3.services.idam.IDAMService

Bases: `LockdownService`

Query and set the device's IDAM configuration via the `com.apple.idamd` lockdown service.

Exposes reading the current IDAM configuration and toggling it. This is a lockdown service and is used as an async context manager; the RSD/tunnel variant is selected automatically for non-`LockdownClient` providers.

Source code in `pymobiledevice3/services/idam.py`

```
class IDAMService(LockdownService):
    """
    Query and set the device's IDAM configuration via the ``com.apple.idamd`` lockdown service.

    Exposes reading the current IDAM configuration and toggling it. This is a lockdown service and
    is used as an async context manager; the RSD/tunnel variant is selected automatically for
    non-`LockdownClient` providers.
    """

    RSD_SERVICE_NAME = "com.apple.idamd.shim.remote"
    SERVICE_NAME = "com.apple.idamd"

    async def configuration_inquiry(self) -> dict[str, Any]:
        """
        Read the device's current IDAM configuration.

        Sends a ``Configuration Inquiry`` request.

        :returns: the device's IDAM configuration response.
        """
        return await self.service.send_recv_plist({"Configuration Inquiry": True})

    async def set_idam_configuration(self, value: bool) -> None:
        """
        Set the device's IDAM configuration.

        Sends a ``Set IDAM Configuration`` request with the given value.

        :param value: the IDAM configuration flag to apply.
        """
        await self.service.send_recv_plist({"Set IDAM Configuration": value})
```

### configuration_inquiry

```
configuration_inquiry() -> dict[str, Any]
```

Read the device's current IDAM configuration.

Sends a `Configuration Inquiry` request.

Returns:

| Type             | Description                               |
| ---------------- | ----------------------------------------- |
| `dict[str, Any]` | the device's IDAM configuration response. |

Source code in `pymobiledevice3/services/idam.py`

```
async def configuration_inquiry(self) -> dict[str, Any]:
    """
    Read the device's current IDAM configuration.

    Sends a ``Configuration Inquiry`` request.

    :returns: the device's IDAM configuration response.
    """
    return await self.service.send_recv_plist({"Configuration Inquiry": True})
```

### set_idam_configuration

```
set_idam_configuration(value: bool) -> None
```

Set the device's IDAM configuration.

Sends a `Set IDAM Configuration` request with the given value.

Parameters:

| Name    | Type   | Description                           | Default    |
| ------- | ------ | ------------------------------------- | ---------- |
| `value` | `bool` | the IDAM configuration flag to apply. | *required* |

Source code in `pymobiledevice3/services/idam.py`

```
async def set_idam_configuration(self, value: bool) -> None:
    """
    Set the device's IDAM configuration.

    Sends a ``Set IDAM Configuration`` request with the given value.

    :param value: the IDAM configuration flag to apply.
    """
    await self.service.send_recv_plist({"Set IDAM Configuration": value})
```
