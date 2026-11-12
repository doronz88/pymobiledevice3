# Connecting to a device

These are the entry points for obtaining a **service provider**, the object every service is built on top of: a lockdown client for classic services, or a `RemoteServiceDiscoveryService` (RSD) for iOS 17+ developer services.

## Lockdown (USB / network)

## pymobiledevice3.lockdown.create_using_usbmux

```
create_using_usbmux(serial: Optional[str] = None, identifier: Optional[str] = None, label: str = DEFAULT_LABEL, autopair: bool = True, connection_type: Optional[str] = None, pair_timeout: Optional[float] = None, local_hostname: Optional[str] = None, pair_record: Optional[dict[str, Any]] = None, pairing_records_cache_folder: Optional[Path] = None, port: int = SERVICE_PORT, usbmux_address: Optional[str] = None) -> UsbmuxLockdownClient
```

Connect to a device over usbmuxd and return a ready-to-use lockdown client.

Opens a lockdownd connection through usbmuxd, queries the device's values, and (when `autopair` is set) validates an existing pairing or performs a new one. Returns a `PlistUsbmuxLockdownClient` when the connected usbmuxd speaks the plist protocol, otherwise a `UsbmuxLockdownClient`. The connection is closed automatically if setup fails.

Parameters:

| Name                           | Type                       | Description                                                                                                     | Default         |
| ------------------------------ | -------------------------- | --------------------------------------------------------------------------------------------------------------- | --------------- |
| `serial`                       | `Optional[str]`            | usbmux serial of the target device, or None to use the first available device.                                  | `None`          |
| `identifier`                   | `Optional[str]`            | Device identifier used to locate the matching pair record; defaults to the device's serial reported by usbmuxd. | `None`          |
| `label`                        | `str`                      | User-agent label included in every request sent to lockdownd.                                                   | `DEFAULT_LABEL` |
| `autopair`                     | `bool`                     | When True, pair with the device (blocking) if it is not already paired.                                         | `True`          |
| `connection_type`              | `Optional[str]`            | Restrict to a specific usbmux connection type ("USB" or "Network").                                             | `None`          |
| `pair_timeout`                 | `Optional[float]`          | Maximum time in seconds to wait for the user to accept the pairing dialog.                                      | `None`          |
| `local_hostname`               | `Optional[str]`            | Seed used to generate the HostID.                                                                               | `None`          |
| `pair_record`                  | `Optional[dict[str, Any]]` | A pre-loaded pair record to use instead of looking one up.                                                      | `None`          |
| `pairing_records_cache_folder` | `Optional[Path]`           | Directory used to search for and persist pair records.                                                          | `None`          |
| `port`                         | `int`                      | TCP port of the lockdownd service on the device.                                                                | `SERVICE_PORT`  |
| `usbmux_address`               | `Optional[str]`            | Address of the usbmuxd socket to use, or None for the default.                                                  | `None`          |

Returns:

| Type                   | Description                         |
| ---------------------- | ----------------------------------- |
| `UsbmuxLockdownClient` | A connected usbmux lockdown client. |

Source code in `pymobiledevice3/lockdown.py`

```
async def create_using_usbmux(
    serial: Optional[str] = None,
    identifier: Optional[str] = None,
    label: str = DEFAULT_LABEL,
    autopair: bool = True,
    connection_type: Optional[str] = None,
    pair_timeout: Optional[float] = None,
    local_hostname: Optional[str] = None,
    pair_record: Optional[dict[str, Any]] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    port: int = SERVICE_PORT,
    usbmux_address: Optional[str] = None,
) -> UsbmuxLockdownClient:
    """Connect to a device over usbmuxd and return a ready-to-use lockdown client.

    Opens a lockdownd connection through usbmuxd, queries the device's values, and (when ``autopair`` is set)
    validates an existing pairing or performs a new one. Returns a `PlistUsbmuxLockdownClient` when the
    connected usbmuxd speaks the plist protocol, otherwise a `UsbmuxLockdownClient`. The connection is
    closed automatically if setup fails.

    :param serial: usbmux serial of the target device, or ``None`` to use the first available device.
    :param identifier: Device identifier used to locate the matching pair record; defaults to the device's
        serial reported by usbmuxd.
    :param label: User-agent label included in every request sent to lockdownd.
    :param autopair: When True, pair with the device (blocking) if it is not already paired.
    :param connection_type: Restrict to a specific usbmux connection type (``"USB"`` or ``"Network"``).
    :param pair_timeout: Maximum time in seconds to wait for the user to accept the pairing dialog.
    :param local_hostname: Seed used to generate the HostID.
    :param pair_record: A pre-loaded pair record to use instead of looking one up.
    :param pairing_records_cache_folder: Directory used to search for and persist pair records.
    :param port: TCP port of the lockdownd service on the device.
    :param usbmux_address: Address of the usbmuxd socket to use, or ``None`` for the default.
    :returns: A connected usbmux lockdown client.
    """
    service = await ServiceConnection.create_using_usbmux(
        serial, port, connection_type=connection_type, usbmux_address=usbmux_address
    )
    try:
        cls = UsbmuxLockdownClient
        system_buid = SYSTEM_BUID
        async with await usbmux.create_mux(usbmux_address=usbmux_address) as client:
            if isinstance(client, PlistMuxConnection):
                # Only the Plist version of usbmuxd supports this message type
                system_buid = await client.get_buid()
                cls = PlistUsbmuxLockdownClient

        if identifier is None and service.mux_device is not None:
            # attempt get identifier from mux device serial
            identifier = service.mux_device.serial

        host_id = generate_host_id(local_hostname)
        pairing_records_cache_folder = create_pairing_records_cache_folder(pairing_records_cache_folder)
        lockdown_client = cls(
            service,
            host_id=host_id,
            identifier=identifier,
            label=label,
            system_buid=system_buid,
            pair_record=pair_record,
            pairing_records_cache_folder=pairing_records_cache_folder,
            port=port,
            usbmux_address=usbmux_address,
        )
        await lockdown_client._initialize()
        await lockdown_client._handle_autopair(autopair, pair_timeout)
    except Exception:
        await service.close()
        raise
    else:
        return lockdown_client
```

## pymobiledevice3.lockdown.LockdownClient

Bases: `ABC`, `LockdownServiceProvider`

Client for the device's lockdownd daemon.

lockdownd is the entry-point daemon on an iOS device: it reports device values, manages host pairing, and starts the other on-device services. This abstract base implements the lockdown protocol (querying and setting values, pairing, session establishment with optional SSL, and starting named services); concrete subclasses supply the transport-specific way to open a connection by overriding `create_service_connection`.

Do not instantiate directly. Obtain an instance from a `create_using_*` factory (`create_using_usbmux`, `create_using_tcp`, `create_using_remote`) or from the `create` classmethod. Instances are async context managers; on exit the underlying connection is closed.

Source code in `pymobiledevice3/lockdown.py`

```
class LockdownClient(ABC, LockdownServiceProvider):
    """Client for the device's lockdownd daemon.

    lockdownd is the entry-point daemon on an iOS device: it reports device values, manages host pairing,
    and starts the other on-device services. This abstract base implements the lockdown protocol (querying
    and setting values, pairing, session establishment with optional SSL, and starting named services);
    concrete subclasses supply the transport-specific way to open a connection by overriding
    `create_service_connection`.

    Do not instantiate directly. Obtain an instance from a ``create_using_*`` factory
    (`create_using_usbmux`, `create_using_tcp`, `create_using_remote`) or from the
    `create` classmethod. Instances are async context managers; on exit the underlying connection
    is closed.
    """

    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict[str, Any]] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
    ):
        """Initialize a new LockdownClient instance.

        This is an abstract base class. Instances are normally not constructed directly; use one of the
        ``create_using_*`` factory functions (e.g. `create_using_usbmux`) or the `create`
        classmethod, which build the underlying service connection, initialize device values and optionally
        pair before returning a ready-to-use client.

        :param service: An already-established lockdownd connection used to send/receive plist requests.
        :param host_id: The HostID identifying this host to the device during pairing/session establishment.
        :param identifier: Device identifier (typically its UDID) used to locate the matching pair record on
            the host. ``None`` if unknown.
        :param label: User-agent label included in every request sent to lockdownd.
        :param system_buid: The host's SystemBUID, included when starting a session.
        :param pair_record: A pre-loaded pair record to use instead of looking one up on the host.
        :param pairing_records_cache_folder: Directory used to search for and persist pair records.
        :param port: TCP port of the lockdownd service on the device.
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.service = service
        self.identifier = identifier
        self.label = label
        self.host_id: str = host_id
        self.system_buid: str = system_buid
        self.pair_record: Optional[dict[str, Any]] = pair_record
        self.paired = False
        self.session_id = None
        self.pairing_records_cache_folder = pairing_records_cache_folder
        self.port = port
        self._reestablishing_connection = False

        self.all_values = {}
        self.udid = None
        self.unique_chip_id: Optional[int] = None
        self.device_public_key: Optional[bytes] = None
        self.product_type = None

    @classmethod
    async def create(
        cls,
        service: ServiceConnection,
        identifier: Optional[str] = None,
        system_buid: str = SYSTEM_BUID,
        label: str = DEFAULT_LABEL,
        autopair: bool = True,
        pair_timeout: Optional[float] = None,
        local_hostname: Optional[str] = None,
        pair_record: Optional[dict[str, Any]] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
        private_key: Optional[RSAPrivateKey] = None,
        **cls_specific_args: Any,
    ):
        """Build a client around an existing service connection, initialize it and optionally pair.

        Generates a HostID, resolves the pairing-records cache folder, constructs the client, queries the
        device's values, and (when ``autopair`` is set) validates an existing pairing or performs a new one.

        :param service: An already-established lockdownd connection.
        :param identifier: Device identifier (typically its UDID) used to locate the matching pair record.
        :param system_buid: The host's SystemBUID, included when starting a session.
        :param label: User-agent label included in every request sent to lockdownd.
        :param autopair: When True, pair with the device (blocking) if it is not already paired.
        :param pair_timeout: Maximum time in seconds to wait for the user to accept the pairing dialog. A
            value of 0 fails immediately if the dialog is pending; ``None`` waits indefinitely.
        :param local_hostname: Seed used to generate the HostID.
        :param pair_record: A pre-loaded pair record to use instead of looking one up on the host.
        :param pairing_records_cache_folder: Directory used to search for and persist pair records.
        :param port: TCP port of the lockdownd service on the device.
        :param private_key: RSA private key to use when generating the pairing certificate chain; a new key
            is generated if omitted.
        :param cls_specific_args: Extra keyword arguments forwarded to the concrete client's constructor.
        :returns: A connected, initialized client instance.
        :raises IncorrectModeError: The connected daemon is not lockdownd.
        :raises FatalPairingError: Pairing succeeded but the subsequent validation failed.
        """
        host_id = generate_host_id(local_hostname)
        pairing_records_cache_folder = create_pairing_records_cache_folder(pairing_records_cache_folder)

        lockdown_client = cls(
            service,
            host_id=host_id,
            identifier=identifier,
            label=label,
            system_buid=system_buid,
            pair_record=pair_record,
            pairing_records_cache_folder=pairing_records_cache_folder,
            port=port,
            **cls_specific_args,
        )
        await lockdown_client._initialize()
        await lockdown_client._handle_autopair(autopair, pair_timeout, private_key=private_key)
        return lockdown_client

    async def _initialize(self) -> None:
        """
        Asynchronously initializes the object by performing a series of queries and assignments
        to set key device-related attributes. This function ensures that the operation mode is
        correct before retrieving and assigning values such as the unique device identifier,
        chip ID, public key, and product type.

        :param self: The instance of the class in which this method is executed.
        :raises IncorrectModeError: If the queried type does not match "com.apple.mobile.lockdown".

        :return: None
        """
        if (await self.query_type()) != "com.apple.mobile.lockdown":
            raise IncorrectModeError()
        self.all_values = await self.get_value()
        self.udid = self.all_values.get("UniqueDeviceID")
        self.unique_chip_id = self.all_values.get("UniqueChipID")
        self.device_public_key = self.all_values.get("DevicePublicKey")
        self.product_type = self.all_values.get("ProductType")

    def __repr__(self) -> str:
        """
        Provides a string representation of the object instance for debugging and logging
        purposes. This method returns relevant details about the instance to assist in
        understanding its current state.

        :return: A formatted string containing the class name and specific attribute values
        """
        return (
            f"<{self.__class__.__name__} ID:{self.identifier} VERSION:{self.product_version} "
            f"TYPE:{self.product_type} PAIRED:{self.paired}>"
        )

    async def __aenter__(self) -> Self:
        """Enter the async context manager and return this client.

        :return: Result of the operation.
        """
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit the async context manager and close open resources.

        :param exc_type: Exc type.
        :param exc_val: Exc val.
        :param exc_tb: Exc tb.

        :return: None.
        """
        await self.close()

    @property
    def product_version(self) -> str:
        """The device's iOS/OS version (``ProductVersion``), e.g. ``"17.0"``.

        :returns: The product version, or ``"1.0"`` when the device did not report one.
        """
        return self.all_values.get("ProductVersion") or "1.0"

    @property
    def product_build_version(self) -> Optional[str]:
        """The device's OS build version (``BuildVersion``), e.g. ``"21A329"``.

        :returns: The build version, or ``None`` when the device did not report one.
        """
        return self.all_values.get("BuildVersion")

    @property
    def device_class(self) -> DeviceClass:
        """The device family (iPhone, iPad, Watch, ...) derived from the reported ``DeviceClass`` value.

        :returns: The matching `DeviceClass`, or `UNKNOWN` when the reported value
            is unrecognized.
        """
        try:
            return DeviceClass(self.all_values.get("DeviceClass"))
        except ValueError:
            return DeviceClass("Unknown")

    @property
    def wifi_mac_address(self) -> Optional[str]:
        """The device's Wi-Fi MAC address (``WiFiAddress``).

        :returns: The Wi-Fi MAC address, or ``None`` when the device did not report one.
        """
        return self.all_values.get("WiFiAddress")

    @property
    def short_info(self) -> dict[str, Any]:
        """A compact subset of the device's values, suitable for listing devices.

        :returns: A dict containing ``Identifier`` plus ``DeviceClass``, ``DeviceName``, ``BuildVersion``,
            ``ProductVersion``, ``ProductType`` and ``UniqueDeviceID`` (each ``None`` if not reported).
        """
        keys_to_copy = ["DeviceClass", "DeviceName", "BuildVersion", "ProductVersion", "ProductType", "UniqueDeviceID"]
        result = {
            "Identifier": self.identifier,
        }
        for key in keys_to_copy:
            result[key] = self.all_values.get(key)
        return result

    @property
    def ecid(self) -> int:
        """The device's ECID (unique chip identifier), taken from the reported ``UniqueChipID`` value.

        :returns: The ECID as an integer.
        :raises KeyError: The device did not report a ``UniqueChipID``.
        """
        return self.all_values["UniqueChipID"]

    @property
    def preflight_info(self) -> Optional[dict[str, Any]]:
        """The device's ``PreflightInfo`` value.

        :returns: The preflight info dict, or ``None`` when the device did not report one.
        """
        return self.all_values.get("PreflightInfo")

    @property
    def firmware_preflight_info(self) -> Optional[dict[str, Any]]:
        """The device's ``FirmwarePreflightInfo`` value.

        :returns: The firmware preflight info dict, or ``None`` when the device did not report one.
        """
        return self.all_values.get("FirmwarePreflightInfo")

    @property
    def display_name(self) -> Optional[str]:
        """The human-readable marketing name for the device, resolved from its product type.

        Looks the device's ``ProductType`` up in the built-in device table.

        :returns: The display name, or ``None`` when the product type is not in the table.
        """
        for irecv_device in cast(Iterable[IRecvDevice], IRECV_DEVICES):
            if irecv_device.product_type == self.product_type:
                return irecv_device.display_name
        return None

    @property
    def hardware_model(self) -> Optional[str]:
        """The hardware model (e.g. board identifier) for the device, resolved from its product type.

        Looks the device's ``ProductType`` up in the built-in device table.

        :returns: The hardware model, or ``None`` when the product type is not in the table.
        """
        for irecv_device in cast(Iterable[IRecvDevice], IRECV_DEVICES):
            if irecv_device.product_type == self.product_type:
                return irecv_device.hardware_model
        return None

    @property
    def board_id(self) -> Optional[int]:
        """The board ID for the device, resolved from its product type.

        Looks the device's ``ProductType`` up in the built-in device table.

        :returns: The board ID, or ``None`` when the product type is not in the table.
        """
        for irecv_device in cast(Iterable[IRecvDevice], IRECV_DEVICES):
            if irecv_device.product_type == self.product_type:
                return irecv_device.board_id
        return None

    @property
    def chip_id(self) -> Optional[int]:
        """The chip ID for the device, resolved from its product type.

        Looks the device's ``ProductType`` up in the built-in device table.

        :returns: The chip ID, or ``None`` when the product type is not in the table.
        """
        for irecv_device in cast(Iterable[IRecvDevice], IRECV_DEVICES):
            if irecv_device.product_type == self.product_type:
                return irecv_device.chip_id
        return None

    async def query_type(self) -> str:
        """Query the type of the daemon at the other end of the connection.

        Sends a ``QueryType`` request; for a real lockdownd connection this returns
        ``"com.apple.mobile.lockdown"``.

        :returns: The reported daemon type string.
        """
        return (await self._request("QueryType")).get("Type", "")

    async def set_uses24hClock(self, value: bool) -> None:
        """Alias of `set_uses24h_clock`.

        :param value: True for 24-hour format, False for 12-hour format.
        """
        await self.set_uses24h_clock(value)

    async def enter_recovery(self):
        """Request that the device reboot into recovery mode.

        Sends an ``EnterRecovery`` request to lockdownd.

        :returns: The lockdownd response to the request.
        """
        return await self._request("EnterRecovery")

    async def stop_session(self) -> dict[str, Any]:
        """Stop the current lockdownd session.

        Sends a ``StopSession`` request for the active session and clears the local session id.

        :returns: The lockdownd response to the request.
        :raises CannotStopSessionError: There is no active session, or lockdownd did not report success.
        """
        if self.session_id and self.service:
            response = await self._request("StopSession", {"SessionID": self.session_id})
            self.session_id = None
            if not response or response.get("Result") != "Success":
                raise CannotStopSessionError()
            return response
        raise CannotStopSessionError("Cannot stop the lockdown session: no session is active.")

    async def validate_pairing(self) -> bool:
        """Validate the existing pairing and establish a session with the device.

        Loads a pair record if one is not already set, validates it (using the legacy ``ValidatePair``
        request for devices older than iOS 7), starts a session and, when the device requests it, upgrades
        the connection to SSL. On success, marks the client paired and reloads the device's values. If the
        pair record turns out to be missing or rejected on-device, the connection is re-established and the
        method returns False.

        :returns: True if pairing was validated and a session established; False otherwise (e.g. no pair
            record, an invalid host id, or an on-device pairing that was removed).
        """
        if self.pair_record is None:
            await self.fetch_pair_record()

        if self.pair_record is None:
            return False

        if (Version(self.product_version) < Version("7.0")) and (self.device_class != DeviceClass.WATCH):
            try:
                await self._request("ValidatePair", {"PairRecord": self.pair_record})
            except PairingError:
                return False

        self.host_id = self.pair_record.get("HostID", self.host_id)
        self.system_buid = self.pair_record.get("SystemBUID", self.system_buid)

        try:
            start_session = await self._request(
                "StartSession", {"HostID": self.host_id, "SystemBUID": self.system_buid}
            )
        except (InvalidHostIDError, InvalidConnectionError):
            # no host id means there is no such pairing record
            return False

        self.session_id = start_session.get("SessionID")
        if start_session.get("EnableSessionSSL"):
            minimum_version, maximum_version = TLSVersion.TLSv1_2, TLSVersion.TLSv1_3
            if (Version(self.product_version) < Version("5.0")) and (self.device_class != DeviceClass.WATCH):
                # TLS v1 is the protocol required for versions prior to iOS 5
                minimum_version, maximum_version = TLSVersion.SSLv3, TLSVersion.TLSv1

            with self.ssl_file() as f:
                try:
                    await self.service.start_tls(
                        create_ssl_context(f, minimum_version=minimum_version, maximum_version=maximum_version)
                    )
                except (SSLZeroReturnError, ConnectionTerminatedError):
                    # possible when we have a pair record, but it was removed on-device
                    self.pair_record = None
                    await self.areestablish_connection()
                    return False

        self.paired = True

        # reload data after pairing
        self.all_values = await self.get_value()
        self.udid = self.all_values.get("UniqueDeviceID")

        return True

    async def pair(self, timeout: Optional[float] = None, private_key: Optional[RSAPrivateKey] = None) -> None:
        """Pair this host with the device.

        Retrieves the device's public key, generates a host key and certificate chain, builds a pair record
        and sends a ``Pair`` request. On success the pair record (including any returned escrow bag) is saved
        to the cache folder and the client is marked paired. Pairing requires the user to accept the on-device
        trust dialog.

        :param timeout: Maximum time in seconds to wait for the user to accept the pairing dialog. A value of
            0 fails immediately if the dialog is pending; ``None`` waits indefinitely.
        :param private_key: RSA private key to use when generating the pairing certificate chain; a new key
            is generated if omitted.
        :raises PairingError: The device public key could not be retrieved.
        :raises PairingDialogResponsePendingError: The user did not accept the pairing dialog in time.
        :raises UserDeniedPairingError: The user declined the pairing request.
        """
        self.device_public_key = await self.get_value("", "DevicePublicKey")
        if not self.device_public_key:
            self.logger.error("Unable to retrieve DevicePublicKey")
            await self.service.close()
            raise PairingError()

        self.logger.info("Creating host key & certificate")
        host_cert_pem, host_key_pem, device_cert_pem, root_cert_pem, root_key_pem = generate_pairing_cert_chain(
            self.device_public_key,
            private_key=private_key,
            # TODO: consider parsing product_version to support iOS < 4
        )

        pair_record: dict[str, Any] = {
            "DeviceCertificate": device_cert_pem,
            "HostCertificate": host_cert_pem,
            "HostID": self.host_id,
            "RootCertificate": root_cert_pem,
            "RootPrivateKey": root_key_pem,
            "WiFiMACAddress": self.wifi_mac_address,
            "SystemBUID": self.system_buid,
        }

        pair_options: dict[str, Any] = {
            "HostName": socket.gethostname(),
            "PairRecord": pair_record,
            "ProtocolVersion": "2",
            "PairingOptions": {"ExtendedPairingErrors": True},
        }

        pair = await self._request_pair(pair_options, timeout=timeout)

        pair_record["HostPrivateKey"] = host_key_pem
        escrow_bag = pair.get("EscrowBag")

        if escrow_bag is not None:
            pair_record["EscrowBag"] = pair.get("EscrowBag")

        self.pair_record = pair_record
        await self.save_pair_record()
        self.paired = True

    async def pair_supervised(self, keybag_file: Path, timeout: Optional[float] = None) -> None:
        """Pair this host with a supervised device using a supervision identity.

        Loads the supervisor private key and certificate from ``keybag_file`` and performs the supervised
        pairing flow: it sends an initial ``Pair`` request carrying the supervisor certificate and, if the
        device responds with an ``MCChallengeRequired`` challenge, signs the challenge (PKCS#7) and sends a
        second request with the challenge response. On success the pair record (including any returned escrow
        bag) is saved and the client is marked paired. Because supervision authorizes the host, this does not
        require the user to accept an on-device dialog.

        :param keybag_file: Path to a PEM file containing both the supervisor private key and certificate.
        :param timeout: Maximum time in seconds to wait for each pairing request; ``None`` waits indefinitely.
        :raises PairingError: The device public key could not be retrieved.
        """
        keybag_data = Path(keybag_file).read_bytes()
        private_key = serialization.load_pem_private_key(keybag_data, password=None)
        if not isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey)):
            raise PairingError(
                f"The supervisor keybag must hold an RSA or EC private key, not {type(private_key).__name__}."
            )
        cer = x509.load_pem_x509_certificate(keybag_data)
        public_key = cer.public_bytes(Encoding.DER)

        self.device_public_key = await self.get_value("", "DevicePublicKey")
        if not self.device_public_key:
            self.logger.error("Unable to retrieve DevicePublicKey")
            await self.service.close()
            raise PairingError()

        self.logger.info("Creating host key & certificate")
        host_cert_pem, host_key_pem, device_cert_pem, root_cert_pem, root_key_pem = generate_pairing_cert_chain(
            self.device_public_key
            # TODO: consider parsing product_version to support iOS < 4
        )

        pair_record: dict[str, Any] = {
            "DeviceCertificate": device_cert_pem,
            "HostCertificate": host_cert_pem,
            "HostID": self.host_id,
            "RootCertificate": root_cert_pem,
            "RootPrivateKey": root_key_pem,
            "WiFiMACAddress": self.wifi_mac_address,
            "SystemBUID": self.system_buid,
        }

        pair_options: dict[str, Any] = {
            "PairRecord": pair_record,
            "ProtocolVersion": "2",
            "PairingOptions": {"SupervisorCertificate": public_key, "ExtendedPairingErrors": True},
        }

        # first pair with SupervisorCertificate as PairingOptions to get PairingChallenge
        pair = await self._request_pair(pair_options, timeout=timeout)
        if pair.get("Error") == "MCChallengeRequired":
            extended_response = pair.get("ExtendedResponse")
            if extended_response is not None:
                pairing_challenge = extended_response.get("PairingChallenge")
                signed_response = (
                    PKCS7SignatureBuilder()
                    .set_data(pairing_challenge)
                    .add_signer(cer, private_key, hashes.SHA256())
                    .sign(Encoding.DER, [PKCS7Options.Binary])
                )
                pair_options = {
                    "PairRecord": pair_record,
                    "ProtocolVersion": "2",
                    "PairingOptions": {"ChallengeResponse": signed_response, "ExtendedPairingErrors": True},
                }
                # second pair with Response to Challenge
                pair = await self._request_pair(pair_options, timeout=timeout)

        pair_record["HostPrivateKey"] = host_key_pem
        escrow_bag = pair.get("EscrowBag")

        if escrow_bag is not None:
            pair_record["EscrowBag"] = pair.get("EscrowBag")

        self.pair_record = pair_record
        await self.save_pair_record()
        self.paired = True

    async def unpair(self, host_id: Optional[str] = None) -> None:
        """Remove a pairing from the device.

        Sends an ``Unpair`` request. With no ``host_id`` the current pair record is unpaired; otherwise the
        pairing identified by ``host_id`` is removed.

        :param host_id: HostID of the pairing to remove; defaults to the current pair record.
        """
        pair_record = self.pair_record if host_id is None else {"HostID": host_id}
        await self._request("Unpair", {"PairRecord": pair_record, "ProtocolVersion": "2"}, verify_request=False)
        unpaired_host_id = pair_record.get("HostID") if pair_record is not None else None
        if unpaired_host_id is not None:
            await self._forget_pair_record(unpaired_host_id)

    async def _forget_pair_record(self, host_id: str) -> None:
        """Delete the host-side pair records the device no longer accepts after an ``Unpair``.

        Only records belonging to ``host_id`` are removed, so unpairing another host leaves ours intact.

        :param host_id: HostID of the pairing that was removed from the device.
        """
        if self.pair_record is not None and self.pair_record.get("HostID") == host_id:
            self.pair_record = None
            self.paired = False
        if self.identifier is None or self.pairing_records_cache_folder is None:
            return
        local_record = get_local_pairing_record(self.identifier, self.pairing_records_cache_folder)
        if local_record is not None and local_record.get("HostID") == host_id:
            device_file_path(self.pairing_records_cache_folder, self.identifier, ".plist").unlink()

    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        """Read a value from the device via a ``GetValue`` request.

        With neither ``domain`` nor ``key`` given, returns the full values dict and also refreshes the cached
        `all_values`. Otherwise narrows the lookup to the given domain and/or key. Binary blobs are
        returned as their raw bytes.

        :param domain: Domain to read from, or ``None`` for the default domain.
        :param key: Specific key to read, or ``None`` to read the whole domain.
        :returns: The requested value, or ``None`` if nothing was returned.
        """
        options: dict[str, Any] = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        result = await self._request("GetValue", options)
        if not result:
            return None
        r = result.get("Value")
        if r is None:
            return None
        if hasattr(r, "data"):
            return r.data
        if domain is None and key is None and isinstance(r, dict):
            self.all_values = r
        return cast(Any, r)

    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        """Remove a value on the device via a ``RemoveValue`` request.

        :param domain: Domain to remove from, or ``None`` for the default domain.
        :param key: Specific key to remove, or ``None``.
        :returns: The lockdownd response to the request.
        """
        options: dict[str, Any] = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        return await self._request("RemoveValue", options)

    async def set_value(self, value: Any, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        """Write a value to the device via a ``SetValue`` request.

        :param value: The value to write.
        :param domain: Domain to write to, or ``None`` for the default domain.
        :param key: Specific key to write, or ``None``.
        :returns: The lockdownd response to the request.
        """
        options: dict[str, Any] = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        options["Value"] = value
        return await self._request("SetValue", options)

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
        """Ask lockdownd to start a named service and return its connection attributes.

        Sends a ``StartService`` request for the given service. The returned dict includes the ``Port`` to
        connect on and whether SSL must be enabled (``EnableServiceSSL``). Use `start_lockdown_service`
        to also open the connection.

        :param name: The lockdownd service name to start (e.g. ``"com.apple.afc"``).
        :param include_escrow_bag: When True, include the pair record's escrow bag in the request (required by
            some services to operate while the device is locked).
        :returns: The service connection attributes (including ``Port`` and possibly ``EnableServiceSSL``).
        :raises NotPairedError: The client is not paired with the device.
        :raises PasswordRequiredError: The device is passcode-protected and must be unlocked first.
        :raises StartServiceError: lockdownd refused to start the service.
        """
        if not self.paired:
            raise NotPairedError()

        options = {"Service": name}
        if include_escrow_bag:
            if self.pair_record is None:
                raise NotPairedError()
            options["EscrowBag"] = self.pair_record["EscrowBag"]

        response = await self._request("StartService", options)
        if not response or response.get("Error"):
            if response.get("Error", "") == "PasswordProtected":
                raise PasswordRequiredError("The device is protected with a passcode. Unlock it and try again.")
            raise StartServiceError(name, response.get("Error", ""))
        return response

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """Start a named lockdownd service and open a connection to it.

        Asks lockdownd to start the service (see `get_service_connection_attributes`), opens a new
        connection to the reported port, and upgrades it to SSL when the service requires it.

        :param name: The lockdownd service name to start (e.g. ``"com.apple.afc"``).
        :param include_escrow_bag: When True, include the pair record's escrow bag in the start request
            (required by some services to operate while the device is locked).
        :returns: A connected `ServiceConnection` for the started service.
        :raises NotPairedError: The client is not paired with the device.
        :raises PasswordRequiredError: The device is passcode-protected and must be unlocked first.
        :raises StartServiceError: lockdownd refused to start the service.
        """
        attr = await self.get_service_connection_attributes(name, include_escrow_bag=include_escrow_bag)
        ssl_context = None
        if attr.get("EnableServiceSSL", False):
            with self.ssl_file() as f:
                ssl_context = create_ssl_context(f)
        return await self.create_service_connection(attr["Port"], ssl_context=ssl_context)

    async def close(self) -> None:
        """Close the underlying lockdownd connection.

        Called automatically when the client is used as an async context manager.
        """
        await self.service.close()

    @contextmanager
    def ssl_file(self) -> Generator[str, Any, None]:
        """Yield a temporary file holding the host certificate and private key for SSL handshakes.

        Writes the pair record's host certificate and private key (PEM) to a temporary file for the duration
        of the ``with`` block and deletes it on exit, even if an exception is raised.

        :yield: Path to the temporary PEM file containing the host certificate followed by its private key.
        """
        if self.pair_record is None:
            raise NotPairedError()
        cert_pem = self.pair_record["HostCertificate"]
        private_key_pem = self.pair_record["HostPrivateKey"]

        # use delete=False and manage the deletion ourselves because Windows
        # cannot use in-use files
        with tempfile.NamedTemporaryFile("w+b", delete=False) as f:
            f.write(cert_pem + b"\n" + private_key_pem)
            filename = f.name

        try:
            yield filename
        finally:
            os.unlink(filename)

    async def _handle_autopair(
        self, autopair: bool, timeout: Optional[float], private_key: Optional[RSAPrivateKey] = None
    ) -> None:
        """Internal helper for handle autopair.

        :param autopair: Autopair.
        :param timeout: Timeout.
        :param private_key: Private key. Defaults to None.

        :return: None.
        """
        if await self.validate_pairing():
            return

        # device is not paired yet
        if not autopair:
            # but pairing by default was not requested
            return
        await self.pair(timeout=timeout, private_key=private_key)
        # get session_id
        if not await self.validate_pairing():
            raise FatalPairingError()

    @abstractmethod
    async def create_service_connection(
        self, port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False
    ) -> ServiceConnection:
        """Open a new connection to the device on the given port.

        Abstract: each concrete client implements this for its transport (usbmux, TCP, ...). Used to open
        service connections and to re-establish the lockdownd connection after it drops.

        :param port: The device-side port to connect to.
        :param ssl_context: Negotiate TLS with this context before any service traffic.
        :param strip_ssl: Carry the traffic in plaintext once the TLS handshake completes.
        :returns: A connected `ServiceConnection`.
        """
        pass

    async def _create_service_connection(self, port: int) -> ServiceConnection:
        """
        Establishes a service connection asynchronously.

        This function is used to create and establish a connection to a service
        using the specified port. It utilizes the `create_service_connection`
        method to perform the actual connection process.

        :param port: The port number to be used for the service connection.
        :return: An instance of ServiceConnection representing the established
            connection.
        """
        return await self.create_service_connection(port)

    async def _request(
        self, request: str, options: Optional[dict[str, Any]] = None, verify_request: bool = True
    ) -> dict[str, Any]:
        """
        Sends a request to the associated service, processes the response, and verifies
        the result. Reconnects and retries the request if a connection-related error
        occurs.

        :param request: The request string containing the operation or data to be sent.
        :param options: Additional options to include in the request message, defaults
            to None.
        :param verify_request: Indicates whether to verify the response after receiving
            it, defaults to True.
        :return: The processed response received from the service.
        :raises ConnectionResetError: If the connection is reset during the operation.
        :raises ConnectionTerminatedError: If the connection is terminated unexpectedly.
        :raises RuntimeError: If a runtime error occurs, that is not related to a
            different event loop.
        :raises InvalidConnectionError: If the connection is deemed invalid during
            verification.
        :raises LockdownError: If a lockdown-specific error occurs during verification.
        """
        message = {"Label": self.label, "Request": request}
        if options:
            message.update(options)

        try:
            try:
                response = await self.service.send_recv_plist(message)
            except (ConnectionResetError, ConnectionTerminatedError, RuntimeError) as e:
                # ServiceConnection streams are loop-bound; reconnect if this client was created in another loop.
                if isinstance(e, RuntimeError) and "different event loop" not in str(e):
                    raise
                if self._reestablishing_connection:
                    raise
                await self.areestablish_connection()
                response = await self.service.send_recv_plist(message)
            try:
                return self._verify_request_response(request, response, verify_request=verify_request)
            except (InvalidConnectionError, LockdownError) as e:
                if not (isinstance(e, InvalidConnectionError) or e.error == "SessionInactive"):
                    raise
                if self._reestablishing_connection:
                    raise
                await self.areestablish_connection()
                response = await self.service.send_recv_plist(message)
                return self._verify_request_response(request, response, verify_request=verify_request)
        except asyncio.CancelledError:
            # Service connection is now in an inconsistent state.
            # Instead of calling `areestablish_connection` here, which is likely not desirable in a cancellation
            # scenario, simply close the connection and reconnect on the next call to `_request`.
            await self.service.close()
            raise

    def _verify_request_response(
        self, request: str, response: dict[str, Any], *, verify_request: bool = True
    ) -> dict[str, Any]:
        """Internal helper for verify request response.

        :param request: Request.
        :param response: Response.
        :param verify_request: Verify request. Defaults to True.

        :return: Result of the operation.
        """
        if verify_request and response.get("Request") != request:
            if response.get("Type") == RESTORED_SERVICE_TYPE:
                raise IncorrectModeError(f"Incorrect mode returned. Got: {response}")
            raise LockdownError(f"Incorrect response returned. Got: {response}", self.identifier, self.product_version)

        error = response.get("Error")
        if error is not None:
            # return response if supervisor cert challenge is required, to work with pair_supervisor
            if error == "MCChallengeRequired":
                return response
            exception_errors: dict[str, type[PyMobileDevice3Exception]] = {
                "PasswordProtected": PasswordRequiredError,
                "PairingDialogResponsePending": PairingDialogResponsePendingError,
                "UserDeniedPairing": UserDeniedPairingError,
                "InvalidHostID": InvalidHostIDError,
                "GetProhibited": GetProhibitedError,
                "SetProhibited": SetProhibitedError,
                "MissingValue": MissingValueError,
                "InvalidService": InvalidServiceError,
                "InvalidConnection": InvalidConnectionError,
                "MCProtected": MCProtectedError,
                "PasscodeRequired": PasscodeRequiredError,
                "SessionActive": SessionActiveError,
            }
            error_type = exception_errors.get(error, LockdownError)
            message = (
                f"lockdownd failed {request}: {error}"
                if error_type is LockdownError
                else (error_type.describe() or error)
            )
            if issubclass(error_type, LockdownError):
                raise error_type(message, self.identifier, self.product_version, error=error)
            raise error_type(message)

        # iOS < 5: 'Error' is not present, so we need to check the 'Result' instead
        if response.get("Result") == "Failure":
            raise LockdownError("", self.identifier, self.product_version)

        return response

    async def _request_pair(self, pair_options: dict[str, Any], timeout: Optional[float] = None) -> dict[str, Any]:
        """
        Asynchronously requests pairing using the provided pair options. This method handles
        pairing dialog responses and waits for user input within the given timeout period.
        If the timeout elapses or certain conditions are met, it raises an error accordingly.

        :param pair_options: A dictionary containing the options required for the pairing request.
        :param timeout: An optional timeout value (in seconds) indicating how long
            to wait for user input. If None, waits indefinitely.
            A value of 0 skips waiting and raises an error immediately.
        :return: A dictionary representing the response of the pairing request.
        :raises PairingDialogResponsePendingError: Raised if the pairing dialog response is
            still pending and the timeout is exceeded.
        """
        try:
            return await self._request("Pair", pair_options)
        except PairingDialogResponsePendingError:
            if timeout == 0:
                raise

        self.logger.info("waiting user pairing dialog...")
        start = time.time()
        while timeout is None or time.time() <= start + timeout:
            with suppress(PairingDialogResponsePendingError):
                return await self._request("Pair", pair_options)
            await asyncio.sleep(1)
        raise PairingDialogResponsePendingError()

    async def fetch_pair_record(self) -> None:
        """Load the preferred pair record for this device into `pair_record`.

        Looks up the record matching `identifier` in the cache folder (and other known locations). Does
        nothing if `identifier` is not set.
        """
        if self.identifier is not None and self.pairing_records_cache_folder is not None:
            self.pair_record = await get_preferred_pair_record(self.identifier, self.pairing_records_cache_folder)

    async def save_pair_record(self) -> None:
        """Persist the current pair record to the cache folder.

        Writes `pair_record` as a plist named ``<identifier>.plist`` in the pairing-records cache folder.
        When running under sudo, the file's ownership is handed back to the invoking user so a later
        unprivileged run can rewrite it.
        """
        assert self.pairing_records_cache_folder is not None and self.pair_record is not None
        if self.identifier is None:
            raise ValueError("Cannot save a pairing record without a device identifier")
        pair_record_file = device_file_path(self.pairing_records_cache_folder, self.identifier, ".plist")
        pair_record_file.write_bytes(plistlib.dumps(self.pair_record))
        # When pairing under sudo, hand the record back to the invoking user (no-op otherwise),
        # so a later unprivileged run can still rewrite it. Without this, a sudo run leaves a
        # root-owned plist that breaks subsequent non-root pairing with EPERM.
        OSUTIL.chown_to_non_sudo_if_needed(pair_record_file)

    def _reestablish_connection(self) -> None:
        """Internal helper for reestablish connection.

        :return: None.
        """
        raise RuntimeError("Sync reconnection path was removed. Use asyncio APIs.")

    async def areestablish_connection(self) -> None:
        """Re-establish the lockdownd connection after it has dropped.

        Closes the current connection, clears the session, opens a fresh connection on `port`, and
        re-validates pairing if a pair record is present. Called internally to recover from connection
        errors mid-request.
        """
        await self.close()
        self.session_id = None
        self.service = await self.create_service_connection(self.port)
        self.paired = False
        if self.pair_record is not None:
            # A failure in the pairing requests below must propagate instead of reconnecting again;
            # otherwise a device that drops every request recurses until RecursionError.
            self._reestablishing_connection = True
            try:
                await self.validate_pairing()
            finally:
                self._reestablishing_connection = False
```

### product_version

```
product_version: str
```

The device's iOS/OS version (`ProductVersion`), e.g. `"17.0"`.

Returns:

| Type  | Description                                                       |
| ----- | ----------------------------------------------------------------- |
| `str` | The product version, or "1.0" when the device did not report one. |

### product_build_version

```
product_build_version: Optional[str]
```

The device's OS build version (`BuildVersion`), e.g. `"21A329"`.

Returns:

| Type            | Description                                                    |
| --------------- | -------------------------------------------------------------- |
| `Optional[str]` | The build version, or None when the device did not report one. |

### device_class

```
device_class: DeviceClass
```

The device family (iPhone, iPad, Watch, ...) derived from the reported `DeviceClass` value.

Returns:

| Type          | Description                                                                   |
| ------------- | ----------------------------------------------------------------------------- |
| `DeviceClass` | The matching DeviceClass, or UNKNOWN when the reported value is unrecognized. |

### wifi_mac_address

```
wifi_mac_address: Optional[str]
```

The device's Wi-Fi MAC address (`WiFiAddress`).

Returns:

| Type            | Description                                                        |
| --------------- | ------------------------------------------------------------------ |
| `Optional[str]` | The Wi-Fi MAC address, or None when the device did not report one. |

### short_info

```
short_info: dict[str, Any]
```

A compact subset of the device's values, suitable for listing devices.

Returns:

| Type             | Description                                                                                                                                          |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dict[str, Any]` | A dict containing Identifier plus DeviceClass, DeviceName, BuildVersion, ProductVersion, ProductType and UniqueDeviceID (each None if not reported). |

### ecid

```
ecid: int
```

The device's ECID (unique chip identifier), taken from the reported `UniqueChipID` value.

Returns:

| Type  | Description             |
| ----- | ----------------------- |
| `int` | The ECID as an integer. |

Raises:

| Type       | Description                               |
| ---------- | ----------------------------------------- |
| `KeyError` | The device did not report a UniqueChipID. |

### preflight_info

```
preflight_info: Optional[dict[str, Any]]
```

The device's `PreflightInfo` value.

Returns:

| Type                       | Description                                                          |
| -------------------------- | -------------------------------------------------------------------- |
| `Optional[dict[str, Any]]` | The preflight info dict, or None when the device did not report one. |

### firmware_preflight_info

```
firmware_preflight_info: Optional[dict[str, Any]]
```

The device's `FirmwarePreflightInfo` value.

Returns:

| Type                       | Description                                                                   |
| -------------------------- | ----------------------------------------------------------------------------- |
| `Optional[dict[str, Any]]` | The firmware preflight info dict, or None when the device did not report one. |

### display_name

```
display_name: Optional[str]
```

The human-readable marketing name for the device, resolved from its product type.

Looks the device's `ProductType` up in the built-in device table.

Returns:

| Type            | Description                                                          |
| --------------- | -------------------------------------------------------------------- |
| `Optional[str]` | The display name, or None when the product type is not in the table. |

### hardware_model

```
hardware_model: Optional[str]
```

The hardware model (e.g. board identifier) for the device, resolved from its product type.

Looks the device's `ProductType` up in the built-in device table.

Returns:

| Type            | Description                                                            |
| --------------- | ---------------------------------------------------------------------- |
| `Optional[str]` | The hardware model, or None when the product type is not in the table. |

### board_id

```
board_id: Optional[int]
```

The board ID for the device, resolved from its product type.

Looks the device's `ProductType` up in the built-in device table.

Returns:

| Type            | Description                                                      |
| --------------- | ---------------------------------------------------------------- |
| `Optional[int]` | The board ID, or None when the product type is not in the table. |

### chip_id

```
chip_id: Optional[int]
```

The chip ID for the device, resolved from its product type.

Looks the device's `ProductType` up in the built-in device table.

Returns:

| Type            | Description                                                     |
| --------------- | --------------------------------------------------------------- |
| `Optional[int]` | The chip ID, or None when the product type is not in the table. |

### create

```
create(service: ServiceConnection, identifier: Optional[str] = None, system_buid: str = SYSTEM_BUID, label: str = DEFAULT_LABEL, autopair: bool = True, pair_timeout: Optional[float] = None, local_hostname: Optional[str] = None, pair_record: Optional[dict[str, Any]] = None, pairing_records_cache_folder: Optional[Path] = None, port: int = SERVICE_PORT, private_key: Optional[RSAPrivateKey] = None, **cls_specific_args: Any)
```

Build a client around an existing service connection, initialize it and optionally pair.

Generates a HostID, resolves the pairing-records cache folder, constructs the client, queries the device's values, and (when `autopair` is set) validates an existing pairing or performs a new one.

Parameters:

| Name                           | Type                       | Description                                                                                                                                                  | Default         |
| ------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------- |
| `service`                      | `ServiceConnection`        | An already-established lockdownd connection.                                                                                                                 | *required*      |
| `identifier`                   | `Optional[str]`            | Device identifier (typically its UDID) used to locate the matching pair record.                                                                              | `None`          |
| `system_buid`                  | `str`                      | The host's SystemBUID, included when starting a session.                                                                                                     | `SYSTEM_BUID`   |
| `label`                        | `str`                      | User-agent label included in every request sent to lockdownd.                                                                                                | `DEFAULT_LABEL` |
| `autopair`                     | `bool`                     | When True, pair with the device (blocking) if it is not already paired.                                                                                      | `True`          |
| `pair_timeout`                 | `Optional[float]`          | Maximum time in seconds to wait for the user to accept the pairing dialog. A value of 0 fails immediately if the dialog is pending; None waits indefinitely. | `None`          |
| `local_hostname`               | `Optional[str]`            | Seed used to generate the HostID.                                                                                                                            | `None`          |
| `pair_record`                  | `Optional[dict[str, Any]]` | A pre-loaded pair record to use instead of looking one up on the host.                                                                                       | `None`          |
| `pairing_records_cache_folder` | `Optional[Path]`           | Directory used to search for and persist pair records.                                                                                                       | `None`          |
| `port`                         | `int`                      | TCP port of the lockdownd service on the device.                                                                                                             | `SERVICE_PORT`  |
| `private_key`                  | `Optional[RSAPrivateKey]`  | RSA private key to use when generating the pairing certificate chain; a new key is generated if omitted.                                                     | `None`          |
| `cls_specific_args`            | `Any`                      | Extra keyword arguments forwarded to the concrete client's constructor.                                                                                      | `{}`            |

Returns:

| Type | Description                               |
| ---- | ----------------------------------------- |
|      | A connected, initialized client instance. |

Raises:

| Type                 | Description                                             |
| -------------------- | ------------------------------------------------------- |
| `IncorrectModeError` | The connected daemon is not lockdownd.                  |
| `FatalPairingError`  | Pairing succeeded but the subsequent validation failed. |

Source code in `pymobiledevice3/lockdown.py`

```
@classmethod
async def create(
    cls,
    service: ServiceConnection,
    identifier: Optional[str] = None,
    system_buid: str = SYSTEM_BUID,
    label: str = DEFAULT_LABEL,
    autopair: bool = True,
    pair_timeout: Optional[float] = None,
    local_hostname: Optional[str] = None,
    pair_record: Optional[dict[str, Any]] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    port: int = SERVICE_PORT,
    private_key: Optional[RSAPrivateKey] = None,
    **cls_specific_args: Any,
):
    """Build a client around an existing service connection, initialize it and optionally pair.

    Generates a HostID, resolves the pairing-records cache folder, constructs the client, queries the
    device's values, and (when ``autopair`` is set) validates an existing pairing or performs a new one.

    :param service: An already-established lockdownd connection.
    :param identifier: Device identifier (typically its UDID) used to locate the matching pair record.
    :param system_buid: The host's SystemBUID, included when starting a session.
    :param label: User-agent label included in every request sent to lockdownd.
    :param autopair: When True, pair with the device (blocking) if it is not already paired.
    :param pair_timeout: Maximum time in seconds to wait for the user to accept the pairing dialog. A
        value of 0 fails immediately if the dialog is pending; ``None`` waits indefinitely.
    :param local_hostname: Seed used to generate the HostID.
    :param pair_record: A pre-loaded pair record to use instead of looking one up on the host.
    :param pairing_records_cache_folder: Directory used to search for and persist pair records.
    :param port: TCP port of the lockdownd service on the device.
    :param private_key: RSA private key to use when generating the pairing certificate chain; a new key
        is generated if omitted.
    :param cls_specific_args: Extra keyword arguments forwarded to the concrete client's constructor.
    :returns: A connected, initialized client instance.
    :raises IncorrectModeError: The connected daemon is not lockdownd.
    :raises FatalPairingError: Pairing succeeded but the subsequent validation failed.
    """
    host_id = generate_host_id(local_hostname)
    pairing_records_cache_folder = create_pairing_records_cache_folder(pairing_records_cache_folder)

    lockdown_client = cls(
        service,
        host_id=host_id,
        identifier=identifier,
        label=label,
        system_buid=system_buid,
        pair_record=pair_record,
        pairing_records_cache_folder=pairing_records_cache_folder,
        port=port,
        **cls_specific_args,
    )
    await lockdown_client._initialize()
    await lockdown_client._handle_autopair(autopair, pair_timeout, private_key=private_key)
    return lockdown_client
```

### query_type

```
query_type() -> str
```

Query the type of the daemon at the other end of the connection.

Sends a `QueryType` request; for a real lockdownd connection this returns `"com.apple.mobile.lockdown"`.

Returns:

| Type  | Description                      |
| ----- | -------------------------------- |
| `str` | The reported daemon type string. |

Source code in `pymobiledevice3/lockdown.py`

```
async def query_type(self) -> str:
    """Query the type of the daemon at the other end of the connection.

    Sends a ``QueryType`` request; for a real lockdownd connection this returns
    ``"com.apple.mobile.lockdown"``.

    :returns: The reported daemon type string.
    """
    return (await self._request("QueryType")).get("Type", "")
```

### set_uses24hClock

```
set_uses24hClock(value: bool) -> None
```

Alias of `set_uses24h_clock`.

Parameters:

| Name    | Type   | Description                                        | Default    |
| ------- | ------ | -------------------------------------------------- | ---------- |
| `value` | `bool` | True for 24-hour format, False for 12-hour format. | *required* |

Source code in `pymobiledevice3/lockdown.py`

```
async def set_uses24hClock(self, value: bool) -> None:
    """Alias of `set_uses24h_clock`.

    :param value: True for 24-hour format, False for 12-hour format.
    """
    await self.set_uses24h_clock(value)
```

### enter_recovery

```
enter_recovery()
```

Request that the device reboot into recovery mode.

Sends an `EnterRecovery` request to lockdownd.

Returns:

| Type | Description                            |
| ---- | -------------------------------------- |
|      | The lockdownd response to the request. |

Source code in `pymobiledevice3/lockdown.py`

```
async def enter_recovery(self):
    """Request that the device reboot into recovery mode.

    Sends an ``EnterRecovery`` request to lockdownd.

    :returns: The lockdownd response to the request.
    """
    return await self._request("EnterRecovery")
```

### stop_session

```
stop_session() -> dict[str, Any]
```

Stop the current lockdownd session.

Sends a `StopSession` request for the active session and clears the local session id.

Returns:

| Type             | Description                            |
| ---------------- | -------------------------------------- |
| `dict[str, Any]` | The lockdownd response to the request. |

Raises:

| Type                     | Description                                                      |
| ------------------------ | ---------------------------------------------------------------- |
| `CannotStopSessionError` | There is no active session, or lockdownd did not report success. |

Source code in `pymobiledevice3/lockdown.py`

```
async def stop_session(self) -> dict[str, Any]:
    """Stop the current lockdownd session.

    Sends a ``StopSession`` request for the active session and clears the local session id.

    :returns: The lockdownd response to the request.
    :raises CannotStopSessionError: There is no active session, or lockdownd did not report success.
    """
    if self.session_id and self.service:
        response = await self._request("StopSession", {"SessionID": self.session_id})
        self.session_id = None
        if not response or response.get("Result") != "Success":
            raise CannotStopSessionError()
        return response
    raise CannotStopSessionError("Cannot stop the lockdown session: no session is active.")
```

### validate_pairing

```
validate_pairing() -> bool
```

Validate the existing pairing and establish a session with the device.

Loads a pair record if one is not already set, validates it (using the legacy `ValidatePair` request for devices older than iOS 7), starts a session and, when the device requests it, upgrades the connection to SSL. On success, marks the client paired and reloads the device's values. If the pair record turns out to be missing or rejected on-device, the connection is re-established and the method returns False.

Returns:

| Type   | Description                                                                                                                                                   |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bool` | True if pairing was validated and a session established; False otherwise (e.g. no pair record, an invalid host id, or an on-device pairing that was removed). |

Source code in `pymobiledevice3/lockdown.py`

```
async def validate_pairing(self) -> bool:
    """Validate the existing pairing and establish a session with the device.

    Loads a pair record if one is not already set, validates it (using the legacy ``ValidatePair``
    request for devices older than iOS 7), starts a session and, when the device requests it, upgrades
    the connection to SSL. On success, marks the client paired and reloads the device's values. If the
    pair record turns out to be missing or rejected on-device, the connection is re-established and the
    method returns False.

    :returns: True if pairing was validated and a session established; False otherwise (e.g. no pair
        record, an invalid host id, or an on-device pairing that was removed).
    """
    if self.pair_record is None:
        await self.fetch_pair_record()

    if self.pair_record is None:
        return False

    if (Version(self.product_version) < Version("7.0")) and (self.device_class != DeviceClass.WATCH):
        try:
            await self._request("ValidatePair", {"PairRecord": self.pair_record})
        except PairingError:
            return False

    self.host_id = self.pair_record.get("HostID", self.host_id)
    self.system_buid = self.pair_record.get("SystemBUID", self.system_buid)

    try:
        start_session = await self._request(
            "StartSession", {"HostID": self.host_id, "SystemBUID": self.system_buid}
        )
    except (InvalidHostIDError, InvalidConnectionError):
        # no host id means there is no such pairing record
        return False

    self.session_id = start_session.get("SessionID")
    if start_session.get("EnableSessionSSL"):
        minimum_version, maximum_version = TLSVersion.TLSv1_2, TLSVersion.TLSv1_3
        if (Version(self.product_version) < Version("5.0")) and (self.device_class != DeviceClass.WATCH):
            # TLS v1 is the protocol required for versions prior to iOS 5
            minimum_version, maximum_version = TLSVersion.SSLv3, TLSVersion.TLSv1

        with self.ssl_file() as f:
            try:
                await self.service.start_tls(
                    create_ssl_context(f, minimum_version=minimum_version, maximum_version=maximum_version)
                )
            except (SSLZeroReturnError, ConnectionTerminatedError):
                # possible when we have a pair record, but it was removed on-device
                self.pair_record = None
                await self.areestablish_connection()
                return False

    self.paired = True

    # reload data after pairing
    self.all_values = await self.get_value()
    self.udid = self.all_values.get("UniqueDeviceID")

    return True
```

### pair

```
pair(timeout: Optional[float] = None, private_key: Optional[RSAPrivateKey] = None) -> None
```

Pair this host with the device.

Retrieves the device's public key, generates a host key and certificate chain, builds a pair record and sends a `Pair` request. On success the pair record (including any returned escrow bag) is saved to the cache folder and the client is marked paired. Pairing requires the user to accept the on-device trust dialog.

Parameters:

| Name          | Type                      | Description                                                                                                                                                  | Default |
| ------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- |
| `timeout`     | `Optional[float]`         | Maximum time in seconds to wait for the user to accept the pairing dialog. A value of 0 fails immediately if the dialog is pending; None waits indefinitely. | `None`  |
| `private_key` | `Optional[RSAPrivateKey]` | RSA private key to use when generating the pairing certificate chain; a new key is generated if omitted.                                                     | `None`  |

Raises:

| Type                                | Description                                         |
| ----------------------------------- | --------------------------------------------------- |
| `PairingError`                      | The device public key could not be retrieved.       |
| `PairingDialogResponsePendingError` | The user did not accept the pairing dialog in time. |
| `UserDeniedPairingError`            | The user declined the pairing request.              |

Source code in `pymobiledevice3/lockdown.py`

```
async def pair(self, timeout: Optional[float] = None, private_key: Optional[RSAPrivateKey] = None) -> None:
    """Pair this host with the device.

    Retrieves the device's public key, generates a host key and certificate chain, builds a pair record
    and sends a ``Pair`` request. On success the pair record (including any returned escrow bag) is saved
    to the cache folder and the client is marked paired. Pairing requires the user to accept the on-device
    trust dialog.

    :param timeout: Maximum time in seconds to wait for the user to accept the pairing dialog. A value of
        0 fails immediately if the dialog is pending; ``None`` waits indefinitely.
    :param private_key: RSA private key to use when generating the pairing certificate chain; a new key
        is generated if omitted.
    :raises PairingError: The device public key could not be retrieved.
    :raises PairingDialogResponsePendingError: The user did not accept the pairing dialog in time.
    :raises UserDeniedPairingError: The user declined the pairing request.
    """
    self.device_public_key = await self.get_value("", "DevicePublicKey")
    if not self.device_public_key:
        self.logger.error("Unable to retrieve DevicePublicKey")
        await self.service.close()
        raise PairingError()

    self.logger.info("Creating host key & certificate")
    host_cert_pem, host_key_pem, device_cert_pem, root_cert_pem, root_key_pem = generate_pairing_cert_chain(
        self.device_public_key,
        private_key=private_key,
        # TODO: consider parsing product_version to support iOS < 4
    )

    pair_record: dict[str, Any] = {
        "DeviceCertificate": device_cert_pem,
        "HostCertificate": host_cert_pem,
        "HostID": self.host_id,
        "RootCertificate": root_cert_pem,
        "RootPrivateKey": root_key_pem,
        "WiFiMACAddress": self.wifi_mac_address,
        "SystemBUID": self.system_buid,
    }

    pair_options: dict[str, Any] = {
        "HostName": socket.gethostname(),
        "PairRecord": pair_record,
        "ProtocolVersion": "2",
        "PairingOptions": {"ExtendedPairingErrors": True},
    }

    pair = await self._request_pair(pair_options, timeout=timeout)

    pair_record["HostPrivateKey"] = host_key_pem
    escrow_bag = pair.get("EscrowBag")

    if escrow_bag is not None:
        pair_record["EscrowBag"] = pair.get("EscrowBag")

    self.pair_record = pair_record
    await self.save_pair_record()
    self.paired = True
```

### pair_supervised

```
pair_supervised(keybag_file: Path, timeout: Optional[float] = None) -> None
```

Pair this host with a supervised device using a supervision identity.

Loads the supervisor private key and certificate from `keybag_file` and performs the supervised pairing flow: it sends an initial `Pair` request carrying the supervisor certificate and, if the device responds with an `MCChallengeRequired` challenge, signs the challenge (PKCS#7) and sends a second request with the challenge response. On success the pair record (including any returned escrow bag) is saved and the client is marked paired. Because supervision authorizes the host, this does not require the user to accept an on-device dialog.

Parameters:

| Name          | Type              | Description                                                                        | Default    |
| ------------- | ----------------- | ---------------------------------------------------------------------------------- | ---------- |
| `keybag_file` | `Path`            | Path to a PEM file containing both the supervisor private key and certificate.     | *required* |
| `timeout`     | `Optional[float]` | Maximum time in seconds to wait for each pairing request; None waits indefinitely. | `None`     |

Raises:

| Type           | Description                                   |
| -------------- | --------------------------------------------- |
| `PairingError` | The device public key could not be retrieved. |

Source code in `pymobiledevice3/lockdown.py`

```
async def pair_supervised(self, keybag_file: Path, timeout: Optional[float] = None) -> None:
    """Pair this host with a supervised device using a supervision identity.

    Loads the supervisor private key and certificate from ``keybag_file`` and performs the supervised
    pairing flow: it sends an initial ``Pair`` request carrying the supervisor certificate and, if the
    device responds with an ``MCChallengeRequired`` challenge, signs the challenge (PKCS#7) and sends a
    second request with the challenge response. On success the pair record (including any returned escrow
    bag) is saved and the client is marked paired. Because supervision authorizes the host, this does not
    require the user to accept an on-device dialog.

    :param keybag_file: Path to a PEM file containing both the supervisor private key and certificate.
    :param timeout: Maximum time in seconds to wait for each pairing request; ``None`` waits indefinitely.
    :raises PairingError: The device public key could not be retrieved.
    """
    keybag_data = Path(keybag_file).read_bytes()
    private_key = serialization.load_pem_private_key(keybag_data, password=None)
    if not isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey)):
        raise PairingError(
            f"The supervisor keybag must hold an RSA or EC private key, not {type(private_key).__name__}."
        )
    cer = x509.load_pem_x509_certificate(keybag_data)
    public_key = cer.public_bytes(Encoding.DER)

    self.device_public_key = await self.get_value("", "DevicePublicKey")
    if not self.device_public_key:
        self.logger.error("Unable to retrieve DevicePublicKey")
        await self.service.close()
        raise PairingError()

    self.logger.info("Creating host key & certificate")
    host_cert_pem, host_key_pem, device_cert_pem, root_cert_pem, root_key_pem = generate_pairing_cert_chain(
        self.device_public_key
        # TODO: consider parsing product_version to support iOS < 4
    )

    pair_record: dict[str, Any] = {
        "DeviceCertificate": device_cert_pem,
        "HostCertificate": host_cert_pem,
        "HostID": self.host_id,
        "RootCertificate": root_cert_pem,
        "RootPrivateKey": root_key_pem,
        "WiFiMACAddress": self.wifi_mac_address,
        "SystemBUID": self.system_buid,
    }

    pair_options: dict[str, Any] = {
        "PairRecord": pair_record,
        "ProtocolVersion": "2",
        "PairingOptions": {"SupervisorCertificate": public_key, "ExtendedPairingErrors": True},
    }

    # first pair with SupervisorCertificate as PairingOptions to get PairingChallenge
    pair = await self._request_pair(pair_options, timeout=timeout)
    if pair.get("Error") == "MCChallengeRequired":
        extended_response = pair.get("ExtendedResponse")
        if extended_response is not None:
            pairing_challenge = extended_response.get("PairingChallenge")
            signed_response = (
                PKCS7SignatureBuilder()
                .set_data(pairing_challenge)
                .add_signer(cer, private_key, hashes.SHA256())
                .sign(Encoding.DER, [PKCS7Options.Binary])
            )
            pair_options = {
                "PairRecord": pair_record,
                "ProtocolVersion": "2",
                "PairingOptions": {"ChallengeResponse": signed_response, "ExtendedPairingErrors": True},
            }
            # second pair with Response to Challenge
            pair = await self._request_pair(pair_options, timeout=timeout)

    pair_record["HostPrivateKey"] = host_key_pem
    escrow_bag = pair.get("EscrowBag")

    if escrow_bag is not None:
        pair_record["EscrowBag"] = pair.get("EscrowBag")

    self.pair_record = pair_record
    await self.save_pair_record()
    self.paired = True
```

### unpair

```
unpair(host_id: Optional[str] = None) -> None
```

Remove a pairing from the device.

Sends an `Unpair` request. With no `host_id` the current pair record is unpaired; otherwise the pairing identified by `host_id` is removed.

Parameters:

| Name      | Type            | Description                                                           | Default |
| --------- | --------------- | --------------------------------------------------------------------- | ------- |
| `host_id` | `Optional[str]` | HostID of the pairing to remove; defaults to the current pair record. | `None`  |

Source code in `pymobiledevice3/lockdown.py`

```
async def unpair(self, host_id: Optional[str] = None) -> None:
    """Remove a pairing from the device.

    Sends an ``Unpair`` request. With no ``host_id`` the current pair record is unpaired; otherwise the
    pairing identified by ``host_id`` is removed.

    :param host_id: HostID of the pairing to remove; defaults to the current pair record.
    """
    pair_record = self.pair_record if host_id is None else {"HostID": host_id}
    await self._request("Unpair", {"PairRecord": pair_record, "ProtocolVersion": "2"}, verify_request=False)
    unpaired_host_id = pair_record.get("HostID") if pair_record is not None else None
    if unpaired_host_id is not None:
        await self._forget_pair_record(unpaired_host_id)
```

### get_value

```
get_value(domain: Optional[str] = None, key: Optional[str] = None) -> Any
```

Read a value from the device via a `GetValue` request.

With neither `domain` nor `key` given, returns the full values dict and also refreshes the cached `all_values`. Otherwise narrows the lookup to the given domain and/or key. Binary blobs are returned as their raw bytes.

Parameters:

| Name     | Type            | Description                                             | Default |
| -------- | --------------- | ------------------------------------------------------- | ------- |
| `domain` | `Optional[str]` | Domain to read from, or None for the default domain.    | `None`  |
| `key`    | `Optional[str]` | Specific key to read, or None to read the whole domain. | `None`  |

Returns:

| Type  | Description                                           |
| ----- | ----------------------------------------------------- |
| `Any` | The requested value, or None if nothing was returned. |

Source code in `pymobiledevice3/lockdown.py`

```
async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
    """Read a value from the device via a ``GetValue`` request.

    With neither ``domain`` nor ``key`` given, returns the full values dict and also refreshes the cached
    `all_values`. Otherwise narrows the lookup to the given domain and/or key. Binary blobs are
    returned as their raw bytes.

    :param domain: Domain to read from, or ``None`` for the default domain.
    :param key: Specific key to read, or ``None`` to read the whole domain.
    :returns: The requested value, or ``None`` if nothing was returned.
    """
    options: dict[str, Any] = {}
    if domain:
        options["Domain"] = domain
    if key:
        options["Key"] = key
    result = await self._request("GetValue", options)
    if not result:
        return None
    r = result.get("Value")
    if r is None:
        return None
    if hasattr(r, "data"):
        return r.data
    if domain is None and key is None and isinstance(r, dict):
        self.all_values = r
    return cast(Any, r)
```

### remove_value

```
remove_value(domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]
```

Remove a value on the device via a `RemoveValue` request.

Parameters:

| Name     | Type            | Description                                            | Default |
| -------- | --------------- | ------------------------------------------------------ | ------- |
| `domain` | `Optional[str]` | Domain to remove from, or None for the default domain. | `None`  |
| `key`    | `Optional[str]` | Specific key to remove, or None.                       | `None`  |

Returns:

| Type             | Description                            |
| ---------------- | -------------------------------------- |
| `dict[str, Any]` | The lockdownd response to the request. |

Source code in `pymobiledevice3/lockdown.py`

```
async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
    """Remove a value on the device via a ``RemoveValue`` request.

    :param domain: Domain to remove from, or ``None`` for the default domain.
    :param key: Specific key to remove, or ``None``.
    :returns: The lockdownd response to the request.
    """
    options: dict[str, Any] = {}
    if domain:
        options["Domain"] = domain
    if key:
        options["Key"] = key
    return await self._request("RemoveValue", options)
```

### set_value

```
set_value(value: Any, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]
```

Write a value to the device via a `SetValue` request.

Parameters:

| Name     | Type            | Description                                         | Default    |
| -------- | --------------- | --------------------------------------------------- | ---------- |
| `value`  | `Any`           | The value to write.                                 | *required* |
| `domain` | `Optional[str]` | Domain to write to, or None for the default domain. | `None`     |
| `key`    | `Optional[str]` | Specific key to write, or None.                     | `None`     |

Returns:

| Type             | Description                            |
| ---------------- | -------------------------------------- |
| `dict[str, Any]` | The lockdownd response to the request. |

Source code in `pymobiledevice3/lockdown.py`

```
async def set_value(self, value: Any, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
    """Write a value to the device via a ``SetValue`` request.

    :param value: The value to write.
    :param domain: Domain to write to, or ``None`` for the default domain.
    :param key: Specific key to write, or ``None``.
    :returns: The lockdownd response to the request.
    """
    options: dict[str, Any] = {}
    if domain:
        options["Domain"] = domain
    if key:
        options["Key"] = key
    options["Value"] = value
    return await self._request("SetValue", options)
```

### get_service_connection_attributes

```
get_service_connection_attributes(name: str, include_escrow_bag: bool = False) -> dict[str, Any]
```

Ask lockdownd to start a named service and return its connection attributes.

Sends a `StartService` request for the given service. The returned dict includes the `Port` to connect on and whether SSL must be enabled (`EnableServiceSSL`). Use `start_lockdown_service` to also open the connection.

Parameters:

| Name                 | Type   | Description                                                                                                                       | Default    |
| -------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `name`               | `str`  | The lockdownd service name to start (e.g. "com.apple.afc").                                                                       | *required* |
| `include_escrow_bag` | `bool` | When True, include the pair record's escrow bag in the request (required by some services to operate while the device is locked). | `False`    |

Returns:

| Type             | Description                                                                       |
| ---------------- | --------------------------------------------------------------------------------- |
| `dict[str, Any]` | The service connection attributes (including Port and possibly EnableServiceSSL). |

Raises:

| Type                    | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| `NotPairedError`        | The client is not paired with the device.                    |
| `PasswordRequiredError` | The device is passcode-protected and must be unlocked first. |
| `StartServiceError`     | lockdownd refused to start the service.                      |

Source code in `pymobiledevice3/lockdown.py`

```
async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
    """Ask lockdownd to start a named service and return its connection attributes.

    Sends a ``StartService`` request for the given service. The returned dict includes the ``Port`` to
    connect on and whether SSL must be enabled (``EnableServiceSSL``). Use `start_lockdown_service`
    to also open the connection.

    :param name: The lockdownd service name to start (e.g. ``"com.apple.afc"``).
    :param include_escrow_bag: When True, include the pair record's escrow bag in the request (required by
        some services to operate while the device is locked).
    :returns: The service connection attributes (including ``Port`` and possibly ``EnableServiceSSL``).
    :raises NotPairedError: The client is not paired with the device.
    :raises PasswordRequiredError: The device is passcode-protected and must be unlocked first.
    :raises StartServiceError: lockdownd refused to start the service.
    """
    if not self.paired:
        raise NotPairedError()

    options = {"Service": name}
    if include_escrow_bag:
        if self.pair_record is None:
            raise NotPairedError()
        options["EscrowBag"] = self.pair_record["EscrowBag"]

    response = await self._request("StartService", options)
    if not response or response.get("Error"):
        if response.get("Error", "") == "PasswordProtected":
            raise PasswordRequiredError("The device is protected with a passcode. Unlock it and try again.")
        raise StartServiceError(name, response.get("Error", ""))
    return response
```

### start_lockdown_service

```
start_lockdown_service(name: str, include_escrow_bag: bool = False) -> ServiceConnection
```

Start a named lockdownd service and open a connection to it.

Asks lockdownd to start the service (see `get_service_connection_attributes`), opens a new connection to the reported port, and upgrades it to SSL when the service requires it.

Parameters:

| Name                 | Type   | Description                                                                                                                             | Default    |
| -------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `name`               | `str`  | The lockdownd service name to start (e.g. "com.apple.afc").                                                                             | *required* |
| `include_escrow_bag` | `bool` | When True, include the pair record's escrow bag in the start request (required by some services to operate while the device is locked). | `False`    |

Returns:

| Type                | Description                                            |
| ------------------- | ------------------------------------------------------ |
| `ServiceConnection` | A connected ServiceConnection for the started service. |

Raises:

| Type                    | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| `NotPairedError`        | The client is not paired with the device.                    |
| `PasswordRequiredError` | The device is passcode-protected and must be unlocked first. |
| `StartServiceError`     | lockdownd refused to start the service.                      |

Source code in `pymobiledevice3/lockdown.py`

```
async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
    """Start a named lockdownd service and open a connection to it.

    Asks lockdownd to start the service (see `get_service_connection_attributes`), opens a new
    connection to the reported port, and upgrades it to SSL when the service requires it.

    :param name: The lockdownd service name to start (e.g. ``"com.apple.afc"``).
    :param include_escrow_bag: When True, include the pair record's escrow bag in the start request
        (required by some services to operate while the device is locked).
    :returns: A connected `ServiceConnection` for the started service.
    :raises NotPairedError: The client is not paired with the device.
    :raises PasswordRequiredError: The device is passcode-protected and must be unlocked first.
    :raises StartServiceError: lockdownd refused to start the service.
    """
    attr = await self.get_service_connection_attributes(name, include_escrow_bag=include_escrow_bag)
    ssl_context = None
    if attr.get("EnableServiceSSL", False):
        with self.ssl_file() as f:
            ssl_context = create_ssl_context(f)
    return await self.create_service_connection(attr["Port"], ssl_context=ssl_context)
```

### close

```
close() -> None
```

Close the underlying lockdownd connection.

Called automatically when the client is used as an async context manager.

Source code in `pymobiledevice3/lockdown.py`

```
async def close(self) -> None:
    """Close the underlying lockdownd connection.

    Called automatically when the client is used as an async context manager.
    """
    await self.service.close()
```

### ssl_file

```
ssl_file() -> Generator[str, Any, None]
```

Yield a temporary file holding the host certificate and private key for SSL handshakes.

Writes the pair record's host certificate and private key (PEM) to a temporary file for the duration of the `with` block and deletes it on exit, even if an exception is raised.

:yield: Path to the temporary PEM file containing the host certificate followed by its private key.

Source code in `pymobiledevice3/lockdown.py`

```
@contextmanager
def ssl_file(self) -> Generator[str, Any, None]:
    """Yield a temporary file holding the host certificate and private key for SSL handshakes.

    Writes the pair record's host certificate and private key (PEM) to a temporary file for the duration
    of the ``with`` block and deletes it on exit, even if an exception is raised.

    :yield: Path to the temporary PEM file containing the host certificate followed by its private key.
    """
    if self.pair_record is None:
        raise NotPairedError()
    cert_pem = self.pair_record["HostCertificate"]
    private_key_pem = self.pair_record["HostPrivateKey"]

    # use delete=False and manage the deletion ourselves because Windows
    # cannot use in-use files
    with tempfile.NamedTemporaryFile("w+b", delete=False) as f:
        f.write(cert_pem + b"\n" + private_key_pem)
        filename = f.name

    try:
        yield filename
    finally:
        os.unlink(filename)
```

### create_service_connection

```
create_service_connection(port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False) -> ServiceConnection
```

Open a new connection to the device on the given port.

Abstract: each concrete client implements this for its transport (usbmux, TCP, ...). Used to open service connections and to re-establish the lockdownd connection after it drops.

Parameters:

| Name          | Type                   | Description                                                      | Default    |
| ------------- | ---------------------- | ---------------------------------------------------------------- | ---------- |
| `port`        | `int`                  | The device-side port to connect to.                              | *required* |
| `ssl_context` | `Optional[SSLContext]` | Negotiate TLS with this context before any service traffic.      | `None`     |
| `strip_ssl`   | `bool`                 | Carry the traffic in plaintext once the TLS handshake completes. | `False`    |

Returns:

| Type                | Description                    |
| ------------------- | ------------------------------ |
| `ServiceConnection` | A connected ServiceConnection. |

Source code in `pymobiledevice3/lockdown.py`

```
@abstractmethod
async def create_service_connection(
    self, port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False
) -> ServiceConnection:
    """Open a new connection to the device on the given port.

    Abstract: each concrete client implements this for its transport (usbmux, TCP, ...). Used to open
    service connections and to re-establish the lockdownd connection after it drops.

    :param port: The device-side port to connect to.
    :param ssl_context: Negotiate TLS with this context before any service traffic.
    :param strip_ssl: Carry the traffic in plaintext once the TLS handshake completes.
    :returns: A connected `ServiceConnection`.
    """
    pass
```

### fetch_pair_record

```
fetch_pair_record() -> None
```

Load the preferred pair record for this device into `pair_record`.

Looks up the record matching `identifier` in the cache folder (and other known locations). Does nothing if `identifier` is not set.

Source code in `pymobiledevice3/lockdown.py`

```
async def fetch_pair_record(self) -> None:
    """Load the preferred pair record for this device into `pair_record`.

    Looks up the record matching `identifier` in the cache folder (and other known locations). Does
    nothing if `identifier` is not set.
    """
    if self.identifier is not None and self.pairing_records_cache_folder is not None:
        self.pair_record = await get_preferred_pair_record(self.identifier, self.pairing_records_cache_folder)
```

### save_pair_record

```
save_pair_record() -> None
```

Persist the current pair record to the cache folder.

Writes `pair_record` as a plist named `<identifier>.plist` in the pairing-records cache folder. When running under sudo, the file's ownership is handed back to the invoking user so a later unprivileged run can rewrite it.

Source code in `pymobiledevice3/lockdown.py`

```
async def save_pair_record(self) -> None:
    """Persist the current pair record to the cache folder.

    Writes `pair_record` as a plist named ``<identifier>.plist`` in the pairing-records cache folder.
    When running under sudo, the file's ownership is handed back to the invoking user so a later
    unprivileged run can rewrite it.
    """
    assert self.pairing_records_cache_folder is not None and self.pair_record is not None
    if self.identifier is None:
        raise ValueError("Cannot save a pairing record without a device identifier")
    pair_record_file = device_file_path(self.pairing_records_cache_folder, self.identifier, ".plist")
    pair_record_file.write_bytes(plistlib.dumps(self.pair_record))
    # When pairing under sudo, hand the record back to the invoking user (no-op otherwise),
    # so a later unprivileged run can still rewrite it. Without this, a sudo run leaves a
    # root-owned plist that breaks subsequent non-root pairing with EPERM.
    OSUTIL.chown_to_non_sudo_if_needed(pair_record_file)
```

### areestablish_connection

```
areestablish_connection() -> None
```

Re-establish the lockdownd connection after it has dropped.

Closes the current connection, clears the session, opens a fresh connection on `port`, and re-validates pairing if a pair record is present. Called internally to recover from connection errors mid-request.

Source code in `pymobiledevice3/lockdown.py`

```
async def areestablish_connection(self) -> None:
    """Re-establish the lockdownd connection after it has dropped.

    Closes the current connection, clears the session, opens a fresh connection on `port`, and
    re-validates pairing if a pair record is present. Called internally to recover from connection
    errors mid-request.
    """
    await self.close()
    self.session_id = None
    self.service = await self.create_service_connection(self.port)
    self.paired = False
    if self.pair_record is not None:
        # A failure in the pairing requests below must propagate instead of reconnecting again;
        # otherwise a device that drops every request recurses until RecursionError.
        self._reestablishing_connection = True
        try:
            await self.validate_pairing()
        finally:
            self._reestablishing_connection = False
```

## pymobiledevice3.lockdown.UsbmuxLockdownClient

Bases: `LockdownClient`

Lockdown client that reaches the device through a usbmuxd connection (USB or network).

Obtain an instance from `create_using_usbmux`. Service connections are opened through usbmuxd via `create_using_usbmux`.

Source code in `pymobiledevice3/lockdown.py`

```
class UsbmuxLockdownClient(LockdownClient):
    """Lockdown client that reaches the device through a usbmuxd connection (USB or network).

    Obtain an instance from `create_using_usbmux`. Service connections are opened through usbmuxd via
    `create_using_usbmux`.
    """

    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict[str, Any]] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
        usbmux_address: Optional[str] = None,
    ):
        """Initialize a new UsbmuxLockdownClient instance.

        Normally constructed by `create_using_usbmux` rather than directly.

        :param service: An already-established lockdownd connection (opened over usbmuxd).
        :param host_id: The HostID identifying this host to the device.
        :param identifier: Device identifier (typically its UDID) used to locate the matching pair record.
        :param label: User-agent label included in every request sent to lockdownd.
        :param system_buid: The host's SystemBUID, included when starting a session.
        :param pair_record: A pre-loaded pair record to use instead of looking one up.
        :param pairing_records_cache_folder: Directory used to search for and persist pair records.
        :param port: TCP port of the lockdownd service on the device.
        :param usbmux_address: Address of the usbmuxd socket to use, or ``None`` for the default.
        """
        self.usbmux_address = usbmux_address
        super().__init__(
            service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder, port
        )

    @property
    def short_info(self) -> dict[str, Any]:
        """A compact subset of the device's values, plus the usbmux connection type.

        :returns: The base `short_info` dict with an added ``ConnectionType`` key
            (e.g. ``"USB"`` or ``"Network"``).
        """
        short_info = super().short_info
        if self.service.mux_device is not None:
            short_info["ConnectionType"] = self.service.mux_device.connection_type
        return short_info

    async def fetch_pair_record(self) -> None:
        """Load the preferred pair record for this device into `pair_record`.

        Like `fetch_pair_record`, but also consults usbmuxd (at
        `usbmux_address`) as a source of pair records. Does nothing if `identifier` is not set.
        """
        if self.identifier is not None and self.pairing_records_cache_folder is not None:
            self.pair_record = await get_preferred_pair_record(
                self.identifier, self.pairing_records_cache_folder, usbmux_address=self.usbmux_address
            )

    async def create_service_connection(
        self, port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False
    ) -> ServiceConnection:
        """Open a new connection to the device on the given port through usbmuxd.

        :param port: The device-side port to connect to.
        :param ssl_context: Negotiate TLS with this context before any service traffic.
        :param strip_ssl: Carry the traffic in plaintext once the TLS handshake completes.
        :returns: A connected `ServiceConnection` opened over usbmuxd, reusing this client's
            connection type and usbmux address.
        """
        connection_type = self.service.mux_device.connection_type if self.service.mux_device is not None else None
        return await ServiceConnection.create_using_usbmux(
            self.identifier,
            port,
            connection_type,
            usbmux_address=self.usbmux_address,
            ssl_context=ssl_context,
            strip_ssl=strip_ssl,
        )
```

### short_info

```
short_info: dict[str, Any]
```

A compact subset of the device's values, plus the usbmux connection type.

Returns:

| Type             | Description                                                                          |
| ---------------- | ------------------------------------------------------------------------------------ |
| `dict[str, Any]` | The base short_info dict with an added ConnectionType key (e.g. "USB" or "Network"). |

### fetch_pair_record

```
fetch_pair_record() -> None
```

Load the preferred pair record for this device into `pair_record`.

Like `fetch_pair_record`, but also consults usbmuxd (at `usbmux_address`) as a source of pair records. Does nothing if `identifier` is not set.

Source code in `pymobiledevice3/lockdown.py`

```
async def fetch_pair_record(self) -> None:
    """Load the preferred pair record for this device into `pair_record`.

    Like `fetch_pair_record`, but also consults usbmuxd (at
    `usbmux_address`) as a source of pair records. Does nothing if `identifier` is not set.
    """
    if self.identifier is not None and self.pairing_records_cache_folder is not None:
        self.pair_record = await get_preferred_pair_record(
            self.identifier, self.pairing_records_cache_folder, usbmux_address=self.usbmux_address
        )
```

### create_service_connection

```
create_service_connection(port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False) -> ServiceConnection
```

Open a new connection to the device on the given port through usbmuxd.

Parameters:

| Name          | Type                   | Description                                                      | Default    |
| ------------- | ---------------------- | ---------------------------------------------------------------- | ---------- |
| `port`        | `int`                  | The device-side port to connect to.                              | *required* |
| `ssl_context` | `Optional[SSLContext]` | Negotiate TLS with this context before any service traffic.      | `None`     |
| `strip_ssl`   | `bool`                 | Carry the traffic in plaintext once the TLS handshake completes. | `False`    |

Returns:

| Type                | Description                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------ |
| `ServiceConnection` | A connected ServiceConnection opened over usbmuxd, reusing this client's connection type and usbmux address. |

Source code in `pymobiledevice3/lockdown.py`

```
async def create_service_connection(
    self, port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False
) -> ServiceConnection:
    """Open a new connection to the device on the given port through usbmuxd.

    :param port: The device-side port to connect to.
    :param ssl_context: Negotiate TLS with this context before any service traffic.
    :param strip_ssl: Carry the traffic in plaintext once the TLS handshake completes.
    :returns: A connected `ServiceConnection` opened over usbmuxd, reusing this client's
        connection type and usbmux address.
    """
    connection_type = self.service.mux_device.connection_type if self.service.mux_device is not None else None
    return await ServiceConnection.create_using_usbmux(
        self.identifier,
        port,
        connection_type,
        usbmux_address=self.usbmux_address,
        ssl_context=ssl_context,
        strip_ssl=strip_ssl,
    )
```

## RemoteServiceDiscovery (iOS 17+ tunnel)

## pymobiledevice3.remote.remote_service_discovery.RemoteServiceDiscoveryService

Bases: `LockdownServiceProvider`

Service provider for the iOS 17+ RemoteServiceDiscovery (RSD) endpoint exposed over a tunnel.

On modern devices, services are no longer started through lockdownd's StartService RPC. Instead a RemoteXPC handshake against the RSD port yields `peer_info` describing every available service and the TCP port it listens on. This class connects to that endpoint, discovers those services, and acts as a `LockdownServiceProvider`, letting callers open both RemoteXPC and lockdown-style service connections.

The RSD address is only reachable over an active tunnel (a kernel-routable interface or an in-process userspace tunnel; see `is_in_process_tunnel`). Instances may be used as async context managers, which connect on entry and close on exit.

Attributes:

| Name        | Type                       | Description                                                                                                                                         |
| ----------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `service`   |                            | the underlying RemoteXPC connection to the RSD endpoint.                                                                                            |
| `peer_info` | `Optional[dict[str, Any]]` | handshake response describing device properties and available services; populated by connect.                                                       |
| `lockdown`  | `Optional[LockdownClient]` | lockdown client created over the remote endpoint, or None if the device does not offer the remote lockdown service (e.g. a virtual macOS instance). |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
class RemoteServiceDiscoveryService(LockdownServiceProvider):
    """
    Service provider for the iOS 17+ RemoteServiceDiscovery (RSD) endpoint exposed over a tunnel.

    On modern devices, services are no longer started through lockdownd's StartService RPC.
    Instead a RemoteXPC handshake against the RSD port yields ``peer_info`` describing every
    available service and the TCP port it listens on. This class connects to that endpoint,
    discovers those services, and acts as a
    `LockdownServiceProvider`, letting callers
    open both RemoteXPC and lockdown-style service connections.

    The RSD address is only reachable over an active tunnel (a kernel-routable interface or an
    in-process userspace tunnel; see `is_in_process_tunnel`). Instances may be used as async
    context managers, which connect on entry and close on exit.

    :ivar service: the underlying RemoteXPC connection to the RSD endpoint.
    :ivar peer_info: handshake response describing device properties and available services;
        populated by `connect`.
    :ivar lockdown: lockdown client created over the remote endpoint, or ``None`` if the device
        does not offer the remote lockdown service (e.g. a virtual macOS instance).
    """

    def __init__(
        self,
        address: tuple[str, int],
        name: Optional[str] = None,
        open_connection: Optional[Callable[..., Any]] = None,
        auxiliary_metadata: Optional[dict[str, dict[str, Any]]] = None,
        handshake_uuid: Optional[uuid.UUID] = None,
    ) -> None:
        """
        :param address: ``(host, port)`` of the RSD endpoint to connect to.
        :param name: optional human-readable name for this RSD (e.g. the tunnel interface name).
        :param open_connection: optional ``asyncio.open_connection``-compatible dialer used for the
            RemoteXPC handshake and every service connection opened through this RSD. ``None`` uses
            the stdlib dialer; the userspace tunnel injects a relay dialer so device-bound
            connections route through its in-process stack.
        :param auxiliary_metadata: decoded device ``deviceKVSData`` (``{domain: {key: value}}``), when
            the transport that built this RSD had it. The pairing handshake carries it, but the RSD
            handshake does not, so paths without a pairing handshake leave it empty. See
            `parse_device_kvs_data` and `auxiliary_metadata`.
        :param handshake_uuid: peer UUID to send in the RSD handshake; ``None`` sends the host-wide
            ``remotexpc.default_handshake_uuid``, which every connection to a tunnel has to share. On a
            link the host ``remoted`` also uses, pass ``remotexpc.remoted_handshake_uuid`` instead.
        """
        super().__init__()
        self.name = name
        self.handshake_uuid = handshake_uuid
        # Device-advertised auxiliary metadata keyed by preference domain, e.g.
        # ``{"com.apple.WebInspector": {"EnableRemoteInspection": False}}``. Only the pairing
        # handshake (native ``remotepairingd`` / userspace / tunneld) supplies this; the plain RSD
        # handshake does not, so it is ``{}`` on those paths. See `is_remote_web_inspector_enabled`.
        self.auxiliary_metadata: dict[str, dict[str, Any]] = (
            auxiliary_metadata if auxiliary_metadata is not None else {}
        )
        # ``asyncio.open_connection``-compatible dialer used for the RemoteXPC handshake and every
        # service connection opened through this RSD (read by callers such as FileServiceService).
        # ``None`` => stdlib ``asyncio.open_connection``; the userspace tunnel injects a relay dialer
        # so device-bound connections route through its in-process stack without a global monkeypatch.
        self.open_connection = open_connection
        self.service = RemoteXPCConnection(address, open_connection=open_connection)
        self.peer_info: Optional[dict[str, Any]] = None
        self.lockdown: Optional[LockdownClient] = None
        self.all_values: dict[str, Any] = {}

    @property
    def is_in_process_tunnel(self) -> bool:
        """True when this RSD reaches the device through an in-process dialer (the userspace
        tunnel) rather than a kernel-routable interface. The device address (``self.service.address``)
        is then only reachable from THIS process, so it must not be handed to external tools such as
        lldb as a connect endpoint."""
        return self.open_connection is not None

    def get_auxiliary_metadata(self, domain: str) -> dict[str, Any]:
        """Return the device-advertised auxiliary metadata for ``domain`` (empty dict if absent).

        See `auxiliary_metadata` for how this is populated and why it may be empty.
        """
        return self.auxiliary_metadata.get(domain, {})

    def is_remote_web_inspector_enabled(self) -> Optional[bool]:
        """Whether Safari/WebKit remote inspection ("Web Inspector") is enabled on the device.

        Read from the device-advertised auxiliary metadata (no service is opened). Returns ``None``
        when the device did not advertise the ``com.apple.WebInspector`` domain: reliably present on
        the native (macOS ``remotepairingd``) path, but a fresh userspace/tunneld handshake omits it,
        in which case the state is unknown here.
        """
        value = self.get_auxiliary_metadata(WEBINSPECTOR_METADATA_DOMAIN).get(WEBINSPECTOR_ENABLE_REMOTE_INSPECTION_KEY)
        return None if value is None else bool(value)

    def _require_peer_info(self) -> dict[str, Any]:
        """Return the handshake ``peer_info``, raising if the RSD has not been connected yet."""
        if self.peer_info is None:
            raise NotConnectedError("The RSD connection is not open; call connect() first.")
        return self.peer_info

    @property
    def product_version(self) -> str:
        """Device OS version, taken from the RSD handshake ``peer_info`` (``"1.0"`` if absent).

        Tolerates a missing ``OSVersion`` (mirrors ``LockdownClient.product_version``) so building an
        ``InvalidServiceError`` never raises ``KeyError`` on the ``suppress(InvalidServiceError)``
        checkin path (e.g. a device that offers no lockdown service, such as a VirtualMac)."""
        return self._require_peer_info()["Properties"].get("OSVersion") or "1.0"

    @property
    def product_build_version(self) -> str:
        """Device OS build string, taken from the RSD handshake ``peer_info``."""
        return self._require_peer_info()["Properties"]["BuildVersion"]

    @property
    def ecid(self) -> int:
        """Device ECID (unique chip identifier), taken from the RSD handshake ``peer_info``."""
        return self._require_peer_info()["Properties"]["UniqueChipID"]

    @property
    def _lockdown(self) -> LockdownClient:
        """Return the remote lockdown client, raising if the device offers no lockdown service."""
        if self.lockdown is None:
            raise InvalidServiceError("The device does not offer a lockdown service.", self.udid, self.product_version)
        return self.lockdown

    async def connect(self) -> None:
        """
        Connect to the RSD endpoint and perform the RemoteXPC handshake.

        Populates ``peer_info``, `udid`, and `product_type` from the handshake, then
        attempts to open a remote lockdown connection (preferring the trusted variant, falling back
        to the untrusted one). If neither is available the device is treated as offering no lockdown
        service and `lockdown` is left ``None``. On any failure the connection is closed.

        :raises Exception: re-raises after closing if the handshake or connection fails.
        """
        await self.service.connect()
        try:
            await self.service.send_device_handshake(self.handshake_uuid)
            try:
                self.peer_info = await asyncio.wait_for(self.service.receive_response(), PEER_INFO_TIMEOUT)
            except asyncio.TimeoutError as e:
                address = self.service.address
                raise RemoteXPCHandshakeTimeoutError(
                    f"The RSD service at {address[0]}:{address[1]} did not send its peer info during the handshake."
                ) from e
            self.udid = self.peer_info["Properties"]["UniqueDeviceID"]
            self.product_type = self.peer_info["Properties"]["ProductType"]

            # Attempt to initialize a lockdown connection (May fail if RemoteXPC device does not offer this service,
            # such as VirtualMac (virtual macOS instance)
            self.lockdown = None

            with suppress(InvalidServiceError):
                self.lockdown = await create_using_remote(
                    await self.start_lockdown_service("com.apple.mobile.lockdown.remote.trusted"),
                    identifier=self.udid,
                )

            if self.lockdown is None:
                # Reattempt with the untrusted service variant
                with suppress(InvalidServiceError):
                    self.lockdown = await create_using_remote(
                        await self.start_lockdown_service("com.apple.mobile.lockdown.remote.untrusted"),
                        identifier=self.udid,
                    )

            self.all_values = self.lockdown.all_values if self.lockdown is not None else {}
        except Exception:
            await self.close()
            raise

    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        """Read a value from the device, via the remote lockdown service (see ``LockdownClient.get_value``).

        :param domain: Domain to read from, or ``None`` for the default domain.
        :param key: Key to read, or ``None`` for all keys in the domain.
        :return: The requested value.
        """
        return await self._lockdown.get_value(domain, key)

    async def set_value(self, value: Any, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        """Write a value to the device, via the remote lockdown service (see ``LockdownClient.set_value``).

        :param value: The value to write.
        :param domain: Domain to write to, or ``None`` for the default domain.
        :param key: Key to write, or ``None`` for the domain root.
        :return: The device's response plist.
        """
        return await self._lockdown.set_value(value, domain=domain, key=key)

    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        """Remove a value on the device, via the remote lockdown service (see ``LockdownClient.remove_value``).

        :param domain: Domain to remove from, or ``None`` for the default domain.
        :param key: Key to remove, or ``None`` for the domain root.
        :return: The device's response plist.
        """
        return await self._lockdown.remove_value(domain=domain, key=key)

    async def start_lockdown_service_without_checkin(self, name: str) -> ServiceConnection:
        """
        Open a raw connection to a service's port without performing the RSD check-in handshake.

        :param name: name of the service to connect to.
        :returns: an unstarted connection to the service's port.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        return await self.create_service_connection(self.get_service_port(name))

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
        """
        Return the connection attributes for a service.

        Unlike lockdownd, RSD services are discovered from ``peer_info`` and need no StartService
        RPC, so this resolves the port locally and reports SSL as disabled.

        :param name: name of the service.
        :param include_escrow_bag: accepted for interface compatibility; ignored.
        :returns: a dict with the service ``Port`` and ``EnableServiceSSL`` set to ``False``.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        # RSD services are discovered from peer_info and do not require a separate StartService RPC.
        _ = include_escrow_bag
        return {"Port": self.get_service_port(name), "EnableServiceSSL": False}

    async def create_service_connection(
        self, port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False
    ) -> ServiceConnection:
        """
        Create a TCP service connection to a port on the device through this RSD.

        :param port: device-side TCP port to connect to.
        :param ssl_context: unsupported; RSD services are reached in plaintext over the tunnel.
        :param strip_ssl: unsupported, as ``ssl_context``.
        :returns: a connection routed through this RSD's dialer.
        """
        if ssl_context is not None or strip_ssl:
            raise ValueError("RSD service connections do not negotiate TLS")
        return await ServiceConnection.create_using_tcp(
            self.service.address[0], port, open_connection=self.open_connection
        )

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """
        Open a service connection and complete the RSD check-in handshake.

        Connects to the service port, performs the ``RSDCheckin`` exchange (optionally attaching the
        host escrow bag for unlock), and returns the started connection.

        :param name: name of the service to start.
        :param include_escrow_bag: when True, attach the local pairing record's escrow bag to the
            check-in, allowing the connection to unlock the device.
        :returns: a started, checked-in service connection.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        :raises StartServiceError: if the device reports an error starting the service.
        :raises PyMobileDevice3Exception: if the check-in handshake returns an unexpected response.
        """
        service = await self.start_lockdown_service_without_checkin(name)
        try:
            checkin: dict[str, Any] = {"Label": "pymobiledevice3", "ProtocolVersion": "2", "Request": "RSDCheckin"}
            if include_escrow_bag:
                if self.udid is None:
                    raise NotConnectedError("The RSD connection is not open; call connect() first.")
                pairing_record = get_local_pairing_record(
                    get_remote_pairing_record_filename(self.udid), get_home_folder()
                )
                if pairing_record is None:
                    raise NotPairedError(
                        f"No local remote pairing record found for {self.udid}; pair the device first."
                    )
                checkin["EscrowBag"] = base64.b64decode(pairing_record["remote_unlock_host_key"])
            response = await service.send_recv_plist(checkin)
            if response["Request"] != "RSDCheckin":
                raise ProtocolError(f"The device sent an unexpected reply to the {name} check-in: {response}")
            response = await service.recv_plist()
            if response["Request"] != "StartService":
                raise ProtocolError(f"The device sent an unexpected reply while starting {name}: {response}")
            error = response.get("Error")
            if error is not None:
                raise StartServiceError(name, cast(str, error))
        except Exception:
            await service.close()
            raise
        return service

    async def start_lockdown_developer_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """
        Open a connection to a developer service (without RSD check-in).

        :param name: name of the developer service.
        :param include_escrow_bag: accepted for interface compatibility; ignored.
        :returns: an unstarted connection to the service's port.
        :raises StartServiceError: if the service cannot be reached; logs a hint that the
            DeveloperDiskImage may need to be mounted.
        """
        try:
            return await self.start_lockdown_service_without_checkin(name)
        except StartServiceError:
            logging.getLogger(self.__module__).exception(
                "Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. "
                "You can do so using: pymobiledevice3 mounter auto-mount"
            )
            raise

    def start_remote_service(self, name: str) -> RemoteXPCConnection:
        """
        Create (but do not connect) a RemoteXPC connection to a service.

        :param name: name of the service.
        :returns: an unconnected RemoteXPC connection to the service's port.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        service = RemoteXPCConnection(
            (self.service.address[0], self.get_service_port(name)), open_connection=self.open_connection
        )
        return service

    async def start_service(self, name: str) -> Union[RemoteXPCConnection, ServiceConnection]:
        """
        Start a service using the transport it advertises in ``peer_info``.

        Services flagged with ``UsesRemoteXPC`` are opened as RemoteXPC connections via
        `start_remote_service`; all others are opened as lockdown-style connections via
        `start_lockdown_service`.

        :param name: name of the service to start.
        :returns: a RemoteXPC connection or a started lockdown service connection, per the
            service's advertised transport.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        service = self._require_peer_info()["Services"][name]
        service_properties = service.get("Properties", {})
        use_remote_xpc = service_properties.get("UsesRemoteXPC", False)
        return self.start_remote_service(name) if use_remote_xpc else await self.start_lockdown_service(name)

    def get_service_port(self, name: str) -> int:
        """
        Resolve the TCP port a service listens on from the RSD handshake ``peer_info``.

        :param name: name of the service.
        :returns: the device-side TCP port for the service.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        return int(self._get_service_entry(name)["Port"])

    def get_service_features(self, name: str) -> frozenset[str]:
        """
        Return the features a service advertises in the RSD handshake ``peer_info``.

        For CoreDevice services these are the ``com.apple.coredevice.feature.*`` identifiers the
        service accepts in ``CoreDevice.featureIdentifier``; other services advertise plain
        capability tags (e.g. cryptexd's ``CryptexInstall``).

        :param name: name of the service.
        :returns: the advertised features, empty if the service advertises none.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        return frozenset(self._get_service_entry(name).get("Properties", {}).get("Features") or ())

    def require_feature(self, service_name: str, feature: str) -> None:
        """
        Verify a service advertises a feature in the RSD handshake, raising if it does not.

        A service entry with no ``Features`` list (or an empty one) is never used to deny an
        operation: absence of capability advertisement is not evidence of a missing capability,
        so the check is skipped and the device stays the final authority.

        :param service_name: name of the service the feature belongs to.
        :param feature: the feature identifier to verify.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        :raises DeviceFeatureNotSupportedError: if the service advertises a feature list that does
            not contain ``feature``.
        """
        features = self._get_service_entry(service_name).get("Properties", {}).get("Features")
        if features and feature not in features:
            raise DeviceFeatureNotSupportedError(service_name, feature, self.udid, self.product_version)

    def _get_service_entry(self, name: str) -> dict[str, Any]:
        """Return a service's ``peer_info`` entry, raising `InvalidServiceError` if absent."""
        service = self._require_peer_info()["Services"].get(name)
        if service is None:
            raise InvalidServiceError(f"The device does not offer the {name} service.", self.udid, self.product_version)
        return service

    async def close(self) -> None:
        """Close the lockdown client (if any) and the underlying RemoteXPC connection."""
        if self.lockdown is not None:
            await self.lockdown.close()
        await self.service.close()

    async def __aenter__(self) -> "RemoteServiceDiscoveryService":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def __repr__(self) -> str:
        name_str = ""
        if self.name:
            name_str = f" NAME:{self.name}"
        return (
            f"<{self.__class__.__name__} PRODUCT:{self.product_type} VERSION:{self.product_version} "
            f"UDID:{self.udid}{name_str}>"
        )
```

### is_in_process_tunnel

```
is_in_process_tunnel: bool
```

True when this RSD reaches the device through an in-process dialer (the userspace tunnel) rather than a kernel-routable interface. The device address (`self.service.address`) is then only reachable from THIS process, so it must not be handed to external tools such as lldb as a connect endpoint.

### product_version

```
product_version: str
```

Device OS version, taken from the RSD handshake `peer_info` (`"1.0"` if absent).

Tolerates a missing `OSVersion` (mirrors `LockdownClient.product_version`) so building an `InvalidServiceError` never raises `KeyError` on the `suppress(InvalidServiceError)` checkin path (e.g. a device that offers no lockdown service, such as a VirtualMac).

### product_build_version

```
product_build_version: str
```

Device OS build string, taken from the RSD handshake `peer_info`.

### ecid

```
ecid: int
```

Device ECID (unique chip identifier), taken from the RSD handshake `peer_info`.

### get_auxiliary_metadata

```
get_auxiliary_metadata(domain: str) -> dict[str, Any]
```

Return the device-advertised auxiliary metadata for `domain` (empty dict if absent).

See `auxiliary_metadata` for how this is populated and why it may be empty.

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
def get_auxiliary_metadata(self, domain: str) -> dict[str, Any]:
    """Return the device-advertised auxiliary metadata for ``domain`` (empty dict if absent).

    See `auxiliary_metadata` for how this is populated and why it may be empty.
    """
    return self.auxiliary_metadata.get(domain, {})
```

### is_remote_web_inspector_enabled

```
is_remote_web_inspector_enabled() -> Optional[bool]
```

Whether Safari/WebKit remote inspection ("Web Inspector") is enabled on the device.

Read from the device-advertised auxiliary metadata (no service is opened). Returns `None` when the device did not advertise the `com.apple.WebInspector` domain: reliably present on the native (macOS `remotepairingd`) path, but a fresh userspace/tunneld handshake omits it, in which case the state is unknown here.

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
def is_remote_web_inspector_enabled(self) -> Optional[bool]:
    """Whether Safari/WebKit remote inspection ("Web Inspector") is enabled on the device.

    Read from the device-advertised auxiliary metadata (no service is opened). Returns ``None``
    when the device did not advertise the ``com.apple.WebInspector`` domain: reliably present on
    the native (macOS ``remotepairingd``) path, but a fresh userspace/tunneld handshake omits it,
    in which case the state is unknown here.
    """
    value = self.get_auxiliary_metadata(WEBINSPECTOR_METADATA_DOMAIN).get(WEBINSPECTOR_ENABLE_REMOTE_INSPECTION_KEY)
    return None if value is None else bool(value)
```

### connect

```
connect() -> None
```

Connect to the RSD endpoint and perform the RemoteXPC handshake.

Populates `peer_info`, `udid`, and `product_type` from the handshake, then attempts to open a remote lockdown connection (preferring the trusted variant, falling back to the untrusted one). If neither is available the device is treated as offering no lockdown service and `lockdown` is left `None`. On any failure the connection is closed.

Raises:

| Type        | Description                                                   |
| ----------- | ------------------------------------------------------------- |
| `Exception` | re-raises after closing if the handshake or connection fails. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def connect(self) -> None:
    """
    Connect to the RSD endpoint and perform the RemoteXPC handshake.

    Populates ``peer_info``, `udid`, and `product_type` from the handshake, then
    attempts to open a remote lockdown connection (preferring the trusted variant, falling back
    to the untrusted one). If neither is available the device is treated as offering no lockdown
    service and `lockdown` is left ``None``. On any failure the connection is closed.

    :raises Exception: re-raises after closing if the handshake or connection fails.
    """
    await self.service.connect()
    try:
        await self.service.send_device_handshake(self.handshake_uuid)
        try:
            self.peer_info = await asyncio.wait_for(self.service.receive_response(), PEER_INFO_TIMEOUT)
        except asyncio.TimeoutError as e:
            address = self.service.address
            raise RemoteXPCHandshakeTimeoutError(
                f"The RSD service at {address[0]}:{address[1]} did not send its peer info during the handshake."
            ) from e
        self.udid = self.peer_info["Properties"]["UniqueDeviceID"]
        self.product_type = self.peer_info["Properties"]["ProductType"]

        # Attempt to initialize a lockdown connection (May fail if RemoteXPC device does not offer this service,
        # such as VirtualMac (virtual macOS instance)
        self.lockdown = None

        with suppress(InvalidServiceError):
            self.lockdown = await create_using_remote(
                await self.start_lockdown_service("com.apple.mobile.lockdown.remote.trusted"),
                identifier=self.udid,
            )

        if self.lockdown is None:
            # Reattempt with the untrusted service variant
            with suppress(InvalidServiceError):
                self.lockdown = await create_using_remote(
                    await self.start_lockdown_service("com.apple.mobile.lockdown.remote.untrusted"),
                    identifier=self.udid,
                )

        self.all_values = self.lockdown.all_values if self.lockdown is not None else {}
    except Exception:
        await self.close()
        raise
```

### get_value

```
get_value(domain: Optional[str] = None, key: Optional[str] = None) -> Any
```

Read a value from the device, via the remote lockdown service (see `LockdownClient.get_value`).

Parameters:

| Name     | Type            | Description                                          | Default |
| -------- | --------------- | ---------------------------------------------------- | ------- |
| `domain` | `Optional[str]` | Domain to read from, or None for the default domain. | `None`  |
| `key`    | `Optional[str]` | Key to read, or None for all keys in the domain.     | `None`  |

Returns:

| Type  | Description          |
| ----- | -------------------- |
| `Any` | The requested value. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
    """Read a value from the device, via the remote lockdown service (see ``LockdownClient.get_value``).

    :param domain: Domain to read from, or ``None`` for the default domain.
    :param key: Key to read, or ``None`` for all keys in the domain.
    :return: The requested value.
    """
    return await self._lockdown.get_value(domain, key)
```

### set_value

```
set_value(value: Any, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]
```

Write a value to the device, via the remote lockdown service (see `LockdownClient.set_value`).

Parameters:

| Name     | Type            | Description                                         | Default    |
| -------- | --------------- | --------------------------------------------------- | ---------- |
| `value`  | `Any`           | The value to write.                                 | *required* |
| `domain` | `Optional[str]` | Domain to write to, or None for the default domain. | `None`     |
| `key`    | `Optional[str]` | Key to write, or None for the domain root.          | `None`     |

Returns:

| Type             | Description                  |
| ---------------- | ---------------------------- |
| `dict[str, Any]` | The device's response plist. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def set_value(self, value: Any, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
    """Write a value to the device, via the remote lockdown service (see ``LockdownClient.set_value``).

    :param value: The value to write.
    :param domain: Domain to write to, or ``None`` for the default domain.
    :param key: Key to write, or ``None`` for the domain root.
    :return: The device's response plist.
    """
    return await self._lockdown.set_value(value, domain=domain, key=key)
```

### remove_value

```
remove_value(domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]
```

Remove a value on the device, via the remote lockdown service (see `LockdownClient.remove_value`).

Parameters:

| Name     | Type            | Description                                            | Default |
| -------- | --------------- | ------------------------------------------------------ | ------- |
| `domain` | `Optional[str]` | Domain to remove from, or None for the default domain. | `None`  |
| `key`    | `Optional[str]` | Key to remove, or None for the domain root.            | `None`  |

Returns:

| Type             | Description                  |
| ---------------- | ---------------------------- |
| `dict[str, Any]` | The device's response plist. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
    """Remove a value on the device, via the remote lockdown service (see ``LockdownClient.remove_value``).

    :param domain: Domain to remove from, or ``None`` for the default domain.
    :param key: Key to remove, or ``None`` for the domain root.
    :return: The device's response plist.
    """
    return await self._lockdown.remove_value(domain=domain, key=key)
```

### start_lockdown_service_without_checkin

```
start_lockdown_service_without_checkin(name: str) -> ServiceConnection
```

Open a raw connection to a service's port without performing the RSD check-in handshake.

Parameters:

| Name   | Type  | Description                        | Default    |
| ------ | ----- | ---------------------------------- | ---------- |
| `name` | `str` | name of the service to connect to. | *required* |

Returns:

| Type                | Description                                    |
| ------------------- | ---------------------------------------------- |
| `ServiceConnection` | an unstarted connection to the service's port. |

Raises:

| Type                  | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `InvalidServiceError` | if the device does not offer a service with this name. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def start_lockdown_service_without_checkin(self, name: str) -> ServiceConnection:
    """
    Open a raw connection to a service's port without performing the RSD check-in handshake.

    :param name: name of the service to connect to.
    :returns: an unstarted connection to the service's port.
    :raises InvalidServiceError: if the device does not offer a service with this name.
    """
    return await self.create_service_connection(self.get_service_port(name))
```

### get_service_connection_attributes

```
get_service_connection_attributes(name: str, include_escrow_bag: bool = False) -> dict[str, Any]
```

Return the connection attributes for a service.

Unlike lockdownd, RSD services are discovered from `peer_info` and need no StartService RPC, so this resolves the port locally and reports SSL as disabled.

Parameters:

| Name                 | Type   | Description                                    | Default    |
| -------------------- | ------ | ---------------------------------------------- | ---------- |
| `name`               | `str`  | name of the service.                           | *required* |
| `include_escrow_bag` | `bool` | accepted for interface compatibility; ignored. | `False`    |

Returns:

| Type             | Description                                                     |
| ---------------- | --------------------------------------------------------------- |
| `dict[str, Any]` | a dict with the service Port and EnableServiceSSL set to False. |

Raises:

| Type                  | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `InvalidServiceError` | if the device does not offer a service with this name. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
    """
    Return the connection attributes for a service.

    Unlike lockdownd, RSD services are discovered from ``peer_info`` and need no StartService
    RPC, so this resolves the port locally and reports SSL as disabled.

    :param name: name of the service.
    :param include_escrow_bag: accepted for interface compatibility; ignored.
    :returns: a dict with the service ``Port`` and ``EnableServiceSSL`` set to ``False``.
    :raises InvalidServiceError: if the device does not offer a service with this name.
    """
    # RSD services are discovered from peer_info and do not require a separate StartService RPC.
    _ = include_escrow_bag
    return {"Port": self.get_service_port(name), "EnableServiceSSL": False}
```

### create_service_connection

```
create_service_connection(port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False) -> ServiceConnection
```

Create a TCP service connection to a port on the device through this RSD.

Parameters:

| Name          | Type                   | Description                                                         | Default    |
| ------------- | ---------------------- | ------------------------------------------------------------------- | ---------- |
| `port`        | `int`                  | device-side TCP port to connect to.                                 | *required* |
| `ssl_context` | `Optional[SSLContext]` | unsupported; RSD services are reached in plaintext over the tunnel. | `None`     |
| `strip_ssl`   | `bool`                 | unsupported, as ssl_context.                                        | `False`    |

Returns:

| Type                | Description                                    |
| ------------------- | ---------------------------------------------- |
| `ServiceConnection` | a connection routed through this RSD's dialer. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def create_service_connection(
    self, port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False
) -> ServiceConnection:
    """
    Create a TCP service connection to a port on the device through this RSD.

    :param port: device-side TCP port to connect to.
    :param ssl_context: unsupported; RSD services are reached in plaintext over the tunnel.
    :param strip_ssl: unsupported, as ``ssl_context``.
    :returns: a connection routed through this RSD's dialer.
    """
    if ssl_context is not None or strip_ssl:
        raise ValueError("RSD service connections do not negotiate TLS")
    return await ServiceConnection.create_using_tcp(
        self.service.address[0], port, open_connection=self.open_connection
    )
```

### start_lockdown_service

```
start_lockdown_service(name: str, include_escrow_bag: bool = False) -> ServiceConnection
```

Open a service connection and complete the RSD check-in handshake.

Connects to the service port, performs the `RSDCheckin` exchange (optionally attaching the host escrow bag for unlock), and returns the started connection.

Parameters:

| Name                 | Type   | Description                                                                                                            | Default    |
| -------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------- | ---------- |
| `name`               | `str`  | name of the service to start.                                                                                          | *required* |
| `include_escrow_bag` | `bool` | when True, attach the local pairing record's escrow bag to the check-in, allowing the connection to unlock the device. | `False`    |

Returns:

| Type                | Description                               |
| ------------------- | ----------------------------------------- |
| `ServiceConnection` | a started, checked-in service connection. |

Raises:

| Type                       | Description                                               |
| -------------------------- | --------------------------------------------------------- |
| `InvalidServiceError`      | if the device does not offer a service with this name.    |
| `StartServiceError`        | if the device reports an error starting the service.      |
| `PyMobileDevice3Exception` | if the check-in handshake returns an unexpected response. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
    """
    Open a service connection and complete the RSD check-in handshake.

    Connects to the service port, performs the ``RSDCheckin`` exchange (optionally attaching the
    host escrow bag for unlock), and returns the started connection.

    :param name: name of the service to start.
    :param include_escrow_bag: when True, attach the local pairing record's escrow bag to the
        check-in, allowing the connection to unlock the device.
    :returns: a started, checked-in service connection.
    :raises InvalidServiceError: if the device does not offer a service with this name.
    :raises StartServiceError: if the device reports an error starting the service.
    :raises PyMobileDevice3Exception: if the check-in handshake returns an unexpected response.
    """
    service = await self.start_lockdown_service_without_checkin(name)
    try:
        checkin: dict[str, Any] = {"Label": "pymobiledevice3", "ProtocolVersion": "2", "Request": "RSDCheckin"}
        if include_escrow_bag:
            if self.udid is None:
                raise NotConnectedError("The RSD connection is not open; call connect() first.")
            pairing_record = get_local_pairing_record(
                get_remote_pairing_record_filename(self.udid), get_home_folder()
            )
            if pairing_record is None:
                raise NotPairedError(
                    f"No local remote pairing record found for {self.udid}; pair the device first."
                )
            checkin["EscrowBag"] = base64.b64decode(pairing_record["remote_unlock_host_key"])
        response = await service.send_recv_plist(checkin)
        if response["Request"] != "RSDCheckin":
            raise ProtocolError(f"The device sent an unexpected reply to the {name} check-in: {response}")
        response = await service.recv_plist()
        if response["Request"] != "StartService":
            raise ProtocolError(f"The device sent an unexpected reply while starting {name}: {response}")
        error = response.get("Error")
        if error is not None:
            raise StartServiceError(name, cast(str, error))
    except Exception:
        await service.close()
        raise
    return service
```

### start_lockdown_developer_service

```
start_lockdown_developer_service(name: str, include_escrow_bag: bool = False) -> ServiceConnection
```

Open a connection to a developer service (without RSD check-in).

Parameters:

| Name                 | Type   | Description                                    | Default    |
| -------------------- | ------ | ---------------------------------------------- | ---------- |
| `name`               | `str`  | name of the developer service.                 | *required* |
| `include_escrow_bag` | `bool` | accepted for interface compatibility; ignored. | `False`    |

Returns:

| Type                | Description                                    |
| ------------------- | ---------------------------------------------- |
| `ServiceConnection` | an unstarted connection to the service's port. |

Raises:

| Type                | Description                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------- |
| `StartServiceError` | if the service cannot be reached; logs a hint that the DeveloperDiskImage may need to be mounted. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def start_lockdown_developer_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
    """
    Open a connection to a developer service (without RSD check-in).

    :param name: name of the developer service.
    :param include_escrow_bag: accepted for interface compatibility; ignored.
    :returns: an unstarted connection to the service's port.
    :raises StartServiceError: if the service cannot be reached; logs a hint that the
        DeveloperDiskImage may need to be mounted.
    """
    try:
        return await self.start_lockdown_service_without_checkin(name)
    except StartServiceError:
        logging.getLogger(self.__module__).exception(
            "Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. "
            "You can do so using: pymobiledevice3 mounter auto-mount"
        )
        raise
```

### start_remote_service

```
start_remote_service(name: str) -> RemoteXPCConnection
```

Create (but do not connect) a RemoteXPC connection to a service.

Parameters:

| Name   | Type  | Description          | Default    |
| ------ | ----- | -------------------- | ---------- |
| `name` | `str` | name of the service. | *required* |

Returns:

| Type                  | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| `RemoteXPCConnection` | an unconnected RemoteXPC connection to the service's port. |

Raises:

| Type                  | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `InvalidServiceError` | if the device does not offer a service with this name. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
def start_remote_service(self, name: str) -> RemoteXPCConnection:
    """
    Create (but do not connect) a RemoteXPC connection to a service.

    :param name: name of the service.
    :returns: an unconnected RemoteXPC connection to the service's port.
    :raises InvalidServiceError: if the device does not offer a service with this name.
    """
    service = RemoteXPCConnection(
        (self.service.address[0], self.get_service_port(name)), open_connection=self.open_connection
    )
    return service
```

### start_service

```
start_service(name: str) -> Union[RemoteXPCConnection, ServiceConnection]
```

Start a service using the transport it advertises in `peer_info`.

Services flagged with `UsesRemoteXPC` are opened as RemoteXPC connections via `start_remote_service`; all others are opened as lockdown-style connections via `start_lockdown_service`.

Parameters:

| Name   | Type  | Description                   | Default    |
| ------ | ----- | ----------------------------- | ---------- |
| `name` | `str` | name of the service to start. | *required* |

Returns:

| Type                                            | Description                                                                                              |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `Union[RemoteXPCConnection, ServiceConnection]` | a RemoteXPC connection or a started lockdown service connection, per the service's advertised transport. |

Raises:

| Type                  | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `InvalidServiceError` | if the device does not offer a service with this name. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def start_service(self, name: str) -> Union[RemoteXPCConnection, ServiceConnection]:
    """
    Start a service using the transport it advertises in ``peer_info``.

    Services flagged with ``UsesRemoteXPC`` are opened as RemoteXPC connections via
    `start_remote_service`; all others are opened as lockdown-style connections via
    `start_lockdown_service`.

    :param name: name of the service to start.
    :returns: a RemoteXPC connection or a started lockdown service connection, per the
        service's advertised transport.
    :raises InvalidServiceError: if the device does not offer a service with this name.
    """
    service = self._require_peer_info()["Services"][name]
    service_properties = service.get("Properties", {})
    use_remote_xpc = service_properties.get("UsesRemoteXPC", False)
    return self.start_remote_service(name) if use_remote_xpc else await self.start_lockdown_service(name)
```

### get_service_port

```
get_service_port(name: str) -> int
```

Resolve the TCP port a service listens on from the RSD handshake `peer_info`.

Parameters:

| Name   | Type  | Description          | Default    |
| ------ | ----- | -------------------- | ---------- |
| `name` | `str` | name of the service. | *required* |

Returns:

| Type  | Description                               |
| ----- | ----------------------------------------- |
| `int` | the device-side TCP port for the service. |

Raises:

| Type                  | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `InvalidServiceError` | if the device does not offer a service with this name. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
def get_service_port(self, name: str) -> int:
    """
    Resolve the TCP port a service listens on from the RSD handshake ``peer_info``.

    :param name: name of the service.
    :returns: the device-side TCP port for the service.
    :raises InvalidServiceError: if the device does not offer a service with this name.
    """
    return int(self._get_service_entry(name)["Port"])
```

### get_service_features

```
get_service_features(name: str) -> frozenset[str]
```

Return the features a service advertises in the RSD handshake `peer_info`.

For CoreDevice services these are the `com.apple.coredevice.feature.*` identifiers the service accepts in `CoreDevice.featureIdentifier`; other services advertise plain capability tags (e.g. cryptexd's `CryptexInstall`).

Parameters:

| Name   | Type  | Description          | Default    |
| ------ | ----- | -------------------- | ---------- |
| `name` | `str` | name of the service. | *required* |

Returns:

| Type             | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| `frozenset[str]` | the advertised features, empty if the service advertises none. |

Raises:

| Type                  | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `InvalidServiceError` | if the device does not offer a service with this name. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
def get_service_features(self, name: str) -> frozenset[str]:
    """
    Return the features a service advertises in the RSD handshake ``peer_info``.

    For CoreDevice services these are the ``com.apple.coredevice.feature.*`` identifiers the
    service accepts in ``CoreDevice.featureIdentifier``; other services advertise plain
    capability tags (e.g. cryptexd's ``CryptexInstall``).

    :param name: name of the service.
    :returns: the advertised features, empty if the service advertises none.
    :raises InvalidServiceError: if the device does not offer a service with this name.
    """
    return frozenset(self._get_service_entry(name).get("Properties", {}).get("Features") or ())
```

### require_feature

```
require_feature(service_name: str, feature: str) -> None
```

Verify a service advertises a feature in the RSD handshake, raising if it does not.

A service entry with no `Features` list (or an empty one) is never used to deny an operation: absence of capability advertisement is not evidence of a missing capability, so the check is skipped and the device stays the final authority.

Parameters:

| Name           | Type  | Description                                 | Default    |
| -------------- | ----- | ------------------------------------------- | ---------- |
| `service_name` | `str` | name of the service the feature belongs to. | *required* |
| `feature`      | `str` | the feature identifier to verify.           | *required* |

Raises:

| Type                             | Description                                                             |
| -------------------------------- | ----------------------------------------------------------------------- |
| `InvalidServiceError`            | if the device does not offer a service with this name.                  |
| `DeviceFeatureNotSupportedError` | if the service advertises a feature list that does not contain feature. |

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
def require_feature(self, service_name: str, feature: str) -> None:
    """
    Verify a service advertises a feature in the RSD handshake, raising if it does not.

    A service entry with no ``Features`` list (or an empty one) is never used to deny an
    operation: absence of capability advertisement is not evidence of a missing capability,
    so the check is skipped and the device stays the final authority.

    :param service_name: name of the service the feature belongs to.
    :param feature: the feature identifier to verify.
    :raises InvalidServiceError: if the device does not offer a service with this name.
    :raises DeviceFeatureNotSupportedError: if the service advertises a feature list that does
        not contain ``feature``.
    """
    features = self._get_service_entry(service_name).get("Properties", {}).get("Features")
    if features and feature not in features:
        raise DeviceFeatureNotSupportedError(service_name, feature, self.udid, self.product_version)
```

### close

```
close() -> None
```

Close the lockdown client (if any) and the underlying RemoteXPC connection.

Source code in `pymobiledevice3/remote/remote_service_discovery.py`

```
async def close(self) -> None:
    """Close the lockdown client (if any) and the underlying RemoteXPC connection."""
    if self.lockdown is not None:
        await self.lockdown.close()
    await self.service.close()
```

## No-root tunnels (iOS 17+)

The preferred way to obtain an iOS 17+ RSD from your own code: in-process tunnels that need no root and no separate `tunneld` daemon. `PreferredRsdTunnel` picks the transport for you; the other two select one explicitly.

## pymobiledevice3.remote.rsd_tunnel.PreferredRsdTunnel

A no-root iOS 17+ RSD tunnel that selects the best available transport for the host.

Async context manager (closes automatically)::

```
async with PreferredRsdTunnel(serial=udid) as rsd:
    ...  # rsd is a connected RemoteServiceDiscoveryService
```

Or open/close explicitly with :meth:`aopen` / :meth:`aclose`. `serial` selects the device (`None` => first/only device). The userspace tunnel is used, falling back on macOS to the native tunnel when the userspace tunnel cannot serve the device. `prefer_native=True` tries the native tunnel first on macOS instead, falling back to the userspace tunnel when it is unavailable.

Source code in `pymobiledevice3/remote/rsd_tunnel.py`

```
class PreferredRsdTunnel:
    """A no-root iOS 17+ RSD tunnel that selects the best available transport for the host.

    Async context manager (closes automatically)::

        async with PreferredRsdTunnel(serial=udid) as rsd:
            ...  # rsd is a connected RemoteServiceDiscoveryService

    Or open/close explicitly with :meth:`aopen` / :meth:`aclose`. ``serial`` selects the device
    (``None`` => first/only device). The userspace tunnel is used, falling back on macOS to the native
    tunnel when the userspace tunnel cannot serve the device. ``prefer_native=True`` tries the
    native tunnel first on macOS instead, falling back to the userspace tunnel when it is
    unavailable.
    """

    def __init__(self, serial: Optional[str] = None, autopair: bool = True, prefer_native: bool = False) -> None:
        self.serial = serial
        self.autopair = autopair
        self.prefer_native = prefer_native
        self.rsd: Optional[RemoteServiceDiscoveryService] = None
        self._handle: Optional[Union[NativeRemotedTunnel, UserspaceRsdTunnel]] = None

    async def aopen(self) -> RemoteServiceDiscoveryService:
        if self.rsd is not None:
            return self.rsd
        if _IS_DARWIN and self.prefer_native:
            try:
                return await self._open_native()
            except Exception:
                # Any native-path failure (unavailable, or an unexpected ctypes/libxpc error) falls
                # back to the userspace tunnel rather than propagating.
                pass
            return await self._open_userspace()

        try:
            return await self._open_userspace()
        except UserspaceTunnelUnavailableError:
            if not _IS_DARWIN:
                raise
        # iOS 17.0-17.3 has no CoreDeviceProxy; remoted still reaches it, with no root.
        return await self._open_native()

    async def _open_native(self) -> RemoteServiceDiscoveryService:
        # Imported here so non-macOS callers never touch the ctypes/libxpc layer.
        from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel

        native = NativeRemotedTunnel(serial=self.serial)
        try:
            rsd = await native.aopen()
        except BaseException:
            await native.aclose()  # release anything half-acquired
            raise
        self.rsd = rsd
        self._handle = native
        return rsd

    async def _open_userspace(self) -> RemoteServiceDiscoveryService:
        # Imported lazily: the userspace stack (pmd-pytcp) import is expensive.
        from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel

        userspace = UserspaceRsdTunnel(serial=self.serial, autopair=self.autopair)
        rsd = await userspace.aopen()
        self.rsd = rsd
        self._handle = userspace
        return rsd

    async def aclose(self) -> None:
        if self._handle is not None:
            await self._handle.aclose()
            self._handle = None
            self.rsd = None

    async def __aenter__(self) -> RemoteServiceDiscoveryService:
        return await self.aopen()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()
```

## pymobiledevice3.remote.userspace_tunnel.UserspaceRsdTunnel

A no-root, in-process iOS 17+ RSD tunnel and its connected RSD, as one closeable handle.

Replaces the kernel `utun` (which needs root/admin) with a pure-Python PyTCP stack, so the tunnel and every host-initiated developer service run as a normal user. Use it either way:

Async context manager (closes automatically)::

```
async with UserspaceRsdTunnel(serial=udid) as rsd:
    ...  # rsd is a connected RemoteServiceDiscoveryService
```

Open / close handle::

```
tunnel = UserspaceRsdTunnel(serial=udid)
rsd = await tunnel.aopen()
try:
    ...
finally:
    await tunnel.aclose()
```

`serial` selects the target device (`None` => first USB device); `autopair` sets up the pairing on the fly if the device is not yet paired. Device selection (e.g. the CLI `--udid` / `PYMOBILEDEVICE3_UDID` resolution) and the usbmux socket location (incl. a remote usbmuxd) are resolved by the caller / usbmux layer, not here.

Constraints:

- **One tunnel per process.** PyTCP's stack is a process-global singleton; :meth:`aopen` raises if a userspace tunnel is already active. Not re-entrant or thread-safe.
- **The device address is in-process only**, reachable only from this process's userspace stack — never by an external tool. The RSD reports this via :attr:`RemoteServiceDiscoveryService.is_in_process_tunnel`; don't hand its address to lldb.

Host-initiated developer services all work. Device-initiated inbound UDP (the AV media streams behind `display serve-web`) also works: the receiver is bound on the PyTCP stack via :class:`UserspaceUdp` and the stack address is advertised to the device, so its RTP terminates on the userspace stack instead of an unreachable host kernel socket.

The tunnel provider is selected like `remote start-tunnel` but restricted to the root-free paths (see :func:`_create_no_root_tunnel_provider`): CoreDeviceTunnelProxy over lockdown on iOS 17.4+, falling back to RemotePairing over bonjour on iOS 17.0-17.3 / Wi-Fi.

Source code in `pymobiledevice3/remote/userspace_tunnel.py`

```
class UserspaceRsdTunnel:
    """A no-root, in-process iOS 17+ RSD tunnel and its connected RSD, as one closeable handle.

    Replaces the kernel ``utun`` (which needs root/admin) with a pure-Python PyTCP stack, so the
    tunnel and every host-initiated developer service run as a normal user. Use it either way:

    Async context manager (closes automatically)::

        async with UserspaceRsdTunnel(serial=udid) as rsd:
            ...  # rsd is a connected RemoteServiceDiscoveryService

    Open / close handle::

        tunnel = UserspaceRsdTunnel(serial=udid)
        rsd = await tunnel.aopen()
        try:
            ...
        finally:
            await tunnel.aclose()

    ``serial`` selects the target device (``None`` => first USB device); ``autopair`` sets up the
    pairing on the fly if the device is not yet paired. Device selection (e.g. the CLI ``--udid`` /
    ``PYMOBILEDEVICE3_UDID`` resolution) and the usbmux socket location (incl. a remote usbmuxd)
    are resolved by the caller / usbmux layer, not here.

    Constraints:

    * **One tunnel per process.** PyTCP's stack is a process-global singleton; :meth:`aopen`
      raises if a userspace tunnel is already active. Not re-entrant or thread-safe.
    * **The device address is in-process only**, reachable only from this process's userspace
      stack — never by an external tool. The RSD reports this via
      :attr:`RemoteServiceDiscoveryService.is_in_process_tunnel`; don't hand its address to lldb.

    Host-initiated developer services all work. Device-initiated inbound UDP (the AV media streams
    behind ``display serve-web``) also works: the receiver is bound on the PyTCP stack via
    :class:`UserspaceUdp` and the stack address is advertised to the device, so its RTP terminates
    on the userspace stack instead of an unreachable host kernel socket.

    The tunnel provider is selected like ``remote start-tunnel`` but restricted to the root-free
    paths (see :func:`_create_no_root_tunnel_provider`): CoreDeviceTunnelProxy over lockdown on
    iOS 17.4+, falling back to RemotePairing over bonjour on iOS 17.0-17.3 / Wi-Fi.
    """

    def __init__(
        self, serial: Optional[str] = None, autopair: bool = True, remotepairing_fallback: bool = True
    ) -> None:
        self.serial = serial
        self.autopair = autopair
        self.remotepairing_fallback = remotepairing_fallback
        self.rsd: Optional[RemoteServiceDiscoveryService] = None
        self.tun: Optional[UserspaceTun] = None
        self._exit_stack: Optional[AsyncExitStack] = None
        self._transport_watcher: Optional[asyncio.Task[None]] = None

    async def aopen(self) -> RemoteServiceDiscoveryService:
        """Establish the tunnel and return the connected RSD. Idempotent on this handle; raises
        :class:`PyMobileDevice3Exception` if another userspace tunnel is already active."""
        global _active_tunnel, USERSPACE_ACTIVE
        if self.rsd is not None:
            return self.rsd
        async with _lifecycle_lock():
            return await self._aopen_locked()

    async def _aopen_locked(self) -> RemoteServiceDiscoveryService:
        global _active_tunnel, USERSPACE_ACTIVE
        if _active_tunnel is not None:
            raise PyMobileDevice3Exception(
                "A userspace tunnel is already active in this process; only one userspace tunnel per "
                "process is supported."
            )
        # pmd-pytcp presence was proven at import time (this module imports it at module level;
        # cli_common imports us inside a try/except that falls back to the kernel tunnel when that
        # fails). Select the userspace tun via the factory flag — no class is monkeypatched;
        # RemotePairingTunnel.start_tunnel() consults create_tun_device().
        tunnel_service.USE_USERSPACE_TUNNEL = True
        # Every resource is registered on one AsyncExitStack so aclose() unwinds them in LIFO
        # order; a failure mid-setup unwinds whatever was already acquired.
        stack = AsyncExitStack()
        try:
            provider, lockdown = await _create_no_root_tunnel_provider(
                self.serial, self.autopair, self.remotepairing_fallback
            )
            stack.push_async_callback(provider.close)
            if lockdown is not None:
                stack.push_async_callback(lockdown.close)
            tunnel_result = await stack.enter_async_context(provider.start_tcp_tunnel())
            # In the userspace path create_tun_device() always builds a UserspaceTun (the factory
            # flag is set above), so the loosely-typed client.tun is narrowed here.
            self.tun = cast(UserspaceTun, tunnel_result.client.tun)
            self.tun.set_peer(tunnel_result.address)
            dial_plane = await stack.enter_async_context(UserspaceDialPlane(self.tun, tunnel_result.address))
            # Inject the relay dialer into THIS rsd only (no global asyncio.open_connection patch),
            # so a library consumer's other connections in the same process stay on the stdlib default.
            rsd = RemoteServiceDiscoveryService(
                (tunnel_result.address, tunnel_result.port),
                open_connection=dial_plane.dial,
                auxiliary_metadata=tunnel_result.auxiliary_metadata,
            )
            stack.push_async_callback(rsd.close)
            await rsd.connect()
        except BaseException:
            await stack.aclose()
            tunnel_service.USE_USERSPACE_TUNNEL = False
            self.tun = None
            raise

        self._exit_stack = stack
        self.rsd = rsd
        _active_tunnel = self
        USERSPACE_ACTIVE = True
        self._transport_watcher = asyncio.create_task(
            self._watch_transport_closed(tunnel_result.client),
            name=f"userspace-tunnel-transport-watcher-{tunnel_result.address}",
        )
        logger.debug("userspace RSD established (no root): %s rsd_port=%s", tunnel_result.address, tunnel_result.port)
        return rsd

    async def _watch_transport_closed(self, client: tunnel_service.RemotePairingTunnel) -> None:
        """Tear the tunnel down when its outer transport dies (e.g. the USB cable is pulled:
        usbmuxd closes the CoreDeviceProxy connection and the transport read task just ends).

        Without this nothing wakes the pytcp sessions or the relay handlers — every in-flight
        service read parks forever. Keep-alive cannot cover it: a relay's peer is this very
        process, so loopback probes are always answered no matter what happened to the device.
        Closing the dial plane cancels the relay handlers, which surfaces EOF/connection errors
        to all blocked callers.

        Cancellation of this task is an orderly shutdown, never a disconnect: aclose() cancels
        it, and so does asyncio.run() tearing down the loop when an embedder returns with the
        tunnel still open. wait_closed() suppresses the read task's CancelledError, which would
        also swallow ours, so it runs in its own task and a cancellation of this one is caught
        here instead of being mistaken for a dead transport."""
        closed = asyncio.create_task(client.wait_closed())
        try:
            await asyncio.wait({closed})
        except asyncio.CancelledError:
            closed.cancel()
            if self._exit_stack is not None:
                # Loop shutdown with the tunnel still open: release it quietly, as aclose() would.
                with suppress(Exception):
                    await self.aclose()
            raise
        if not closed.cancelled() and closed.exception() is not None:
            logger.debug("transport wait_closed() failed", exc_info=closed.exception())
        if self._exit_stack is None:
            return  # normal aclose() already ran
        logger.warning("userspace tunnel transport closed (device disconnected?); tearing down")
        try:
            await self.aclose()
        except Exception:
            # This task is fire-and-forget and it runs exactly when unwinding is most likely
            # to raise (the transport just died under the RSD); an unhandled exception here
            # would only surface as "Task exception was never retrieved" at GC.
            logger.warning("userspace tunnel teardown after transport death failed", exc_info=True)

    async def aclose(self) -> None:
        """Tear down the tunnel and its RSD, releasing every resource in LIFO order and restoring
        the kernel-tunnel factory default. Idempotent.

        After this returns, no background thread remains blocked (closing the tun wakes the parked
        reader), so the process can exit normally.

        Serialized with the transport watcher's teardown: an explicit aclose() during the
        watcher's unwind (device just disconnected) waits for that unwind instead of
        returning while resources are still being released — so aclose() returning means the
        process-global pytcp stack is really stopped and a new tunnel may be opened."""
        global _active_tunnel, USERSPACE_ACTIVE
        async with _lifecycle_lock():
            if self._exit_stack is None:
                return
            stack, self._exit_stack = self._exit_stack, None
            watcher, self._transport_watcher = self._transport_watcher, None
            if watcher is not None and watcher is not asyncio.current_task():
                # The watcher is parked in wait_closed() (it cannot be mid-aclose: that path
                # holds this lock) — safe to cancel.
                watcher.cancel()
            self.rsd = None
            self.tun = None
            if _active_tunnel is self:
                _active_tunnel = None
                USERSPACE_ACTIVE = False
                tunnel_service.USE_USERSPACE_TUNNEL = False
            await stack.aclose()

    #: ``open``/``close`` are aliases for :meth:`aopen`/:meth:`aclose` (still awaitable).
    open = aopen
    close = aclose

    async def __aenter__(self) -> RemoteServiceDiscoveryService:
        return await self.aopen()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()
```

### aopen

```
aopen() -> RemoteServiceDiscoveryService
```

Establish the tunnel and return the connected RSD. Idempotent on this handle; raises :class:`PyMobileDevice3Exception` if another userspace tunnel is already active.

Source code in `pymobiledevice3/remote/userspace_tunnel.py`

```
async def aopen(self) -> RemoteServiceDiscoveryService:
    """Establish the tunnel and return the connected RSD. Idempotent on this handle; raises
    :class:`PyMobileDevice3Exception` if another userspace tunnel is already active."""
    global _active_tunnel, USERSPACE_ACTIVE
    if self.rsd is not None:
        return self.rsd
    async with _lifecycle_lock():
        return await self._aopen_locked()
```

### aclose

```
aclose() -> None
```

Tear down the tunnel and its RSD, releasing every resource in LIFO order and restoring the kernel-tunnel factory default. Idempotent.

After this returns, no background thread remains blocked (closing the tun wakes the parked reader), so the process can exit normally.

Serialized with the transport watcher's teardown: an explicit aclose() during the watcher's unwind (device just disconnected) waits for that unwind instead of returning while resources are still being released — so aclose() returning means the process-global pytcp stack is really stopped and a new tunnel may be opened.

Source code in `pymobiledevice3/remote/userspace_tunnel.py`

```
async def aclose(self) -> None:
    """Tear down the tunnel and its RSD, releasing every resource in LIFO order and restoring
    the kernel-tunnel factory default. Idempotent.

    After this returns, no background thread remains blocked (closing the tun wakes the parked
    reader), so the process can exit normally.

    Serialized with the transport watcher's teardown: an explicit aclose() during the
    watcher's unwind (device just disconnected) waits for that unwind instead of
    returning while resources are still being released — so aclose() returning means the
    process-global pytcp stack is really stopped and a new tunnel may be opened."""
    global _active_tunnel, USERSPACE_ACTIVE
    async with _lifecycle_lock():
        if self._exit_stack is None:
            return
        stack, self._exit_stack = self._exit_stack, None
        watcher, self._transport_watcher = self._transport_watcher, None
        if watcher is not None and watcher is not asyncio.current_task():
            # The watcher is parked in wait_closed() (it cannot be mid-aclose: that path
            # holds this lock) — safe to cancel.
            watcher.cancel()
        self.rsd = None
        self.tun = None
        if _active_tunnel is self:
            _active_tunnel = None
            USERSPACE_ACTIVE = False
            tunnel_service.USE_USERSPACE_TUNNEL = False
        await stack.aclose()
```

## pymobiledevice3.remote.userspace_tunnel.establish_userspace_rsd

```
establish_userspace_rsd(serial: Optional[str] = None, autopair: bool = True, remotepairing_fallback: bool = True) -> RemoteServiceDiscoveryService
```

CLI convenience: establish a userspace tunnel, keep it alive, and return its connected RSD.

Embedders should use :class:`UserspaceRsdTunnel` directly — it is a closeable handle / async context manager. This wrapper exists for the CLI, which has no teardown hook: it stashes the tunnel for the process lifetime and closes it at interpreter exit (a few ms).

`remotepairing_fallback=False` makes a pre-17.4 device (no CoreDeviceProxy) raise :class:`UserspaceTunnelUnavailableError` instead of attempting RemotePairing, so the caller can route such devices elsewhere (the CLI uses this to fall back to `tunneld`).

Source code in `pymobiledevice3/remote/userspace_tunnel.py`

```
async def establish_userspace_rsd(
    serial: Optional[str] = None, autopair: bool = True, remotepairing_fallback: bool = True
) -> RemoteServiceDiscoveryService:
    """CLI convenience: establish a userspace tunnel, keep it alive, and return its connected RSD.

    Embedders should use :class:`UserspaceRsdTunnel` directly — it is a closeable handle / async
    context manager. This wrapper exists for the CLI, which has no teardown hook: it stashes the
    tunnel for the process lifetime and closes it at interpreter exit (a few ms).

    ``remotepairing_fallback=False`` makes a pre-17.4 device (no CoreDeviceProxy) raise
    :class:`UserspaceTunnelUnavailableError` instead of attempting RemotePairing, so the caller can
    route such devices elsewhere (the CLI uses this to fall back to ``tunneld``).
    """
    global _cli_tunnel
    # In-process retry (the CLI re-runs main() with the userspace env var set after an
    # InvalidServiceError): reuse the live tunnel — PyTCP's stack is a process-global
    # singleton, so a second establishment can only fail.
    if (
        _cli_tunnel is not None
        and _cli_tunnel.rsd is not None
        and (serial is None or serial in (_cli_tunnel.serial, _cli_tunnel.rsd.udid))
    ):
        return _cli_tunnel.rsd
    tunnel = UserspaceRsdTunnel(serial=serial, autopair=autopair, remotepairing_fallback=remotepairing_fallback)
    try:
        rsd = await tunnel.aopen()
    except PyMobileDevice3Exception:
        # Lost an establishment race (aopen serializes on the lifecycle lock, so by now the
        # winner has published): share its tunnel when it serves the requested device.
        # Binary parse errors are deliberately not caught: a malformed reply means this attempt
        # talked to the device and failed, not that another tunnel was already active.
        winner = _cli_tunnel or _active_tunnel
        if (
            winner is not None
            and winner.rsd is not None
            and (serial is None or serial in (winner.serial, winner.rsd.udid))
        ):
            return winner.rsd
        raise
    _cli_tunnel = tunnel
    atexit.register(_close_cli_tunnel_at_exit)
    return rsd
```

## pymobiledevice3.remote.native_tunnel.NativeRemotedTunnel

A no-root macOS RSD obtained by piggybacking `remoted`'s tunnel via `remotepairingd`.

Async context manager (closes automatically)::

```
async with NativeRemotedTunnel(serial=udid) as rsd:
    ...  # rsd is a connected RemoteServiceDiscoveryService
```

Or open/close explicitly with :meth:`aopen` / :meth:`aclose`. `serial` selects the device by UDID (`None` -> the single device `remotepairingd` reports). The RSD address is kernel-routable (Apple's tunnel), so unlike the userspace tunnel it is reachable by other tools; the tunnel lives only while this handle (its assertion) is held open.

Source code in `pymobiledevice3/remote/native_tunnel.py`

```
class NativeRemotedTunnel:
    """A no-root macOS RSD obtained by piggybacking ``remoted``'s tunnel via ``remotepairingd``.

    Async context manager (closes automatically)::

        async with NativeRemotedTunnel(serial=udid) as rsd:
            ...  # rsd is a connected RemoteServiceDiscoveryService

    Or open/close explicitly with :meth:`aopen` / :meth:`aclose`. ``serial`` selects the device by
    UDID (``None`` -> the single device ``remotepairingd`` reports). The RSD address is
    kernel-routable (Apple's tunnel), so unlike the userspace tunnel it is reachable by other tools;
    the tunnel lives only while this handle (its assertion) is held open.
    """

    def __init__(self, serial: Optional[str] = None) -> None:
        self.serial = serial
        self.rsd: Optional[RemoteServiceDiscoveryService] = None
        self._session: Optional[_RemotePairingSession] = None

    async def aopen(self) -> RemoteServiceDiscoveryService:
        if self.rsd is not None:
            return self.rsd
        xpc = _libxpc()
        session = _RemotePairingSession(xpc)
        try:
            tunnel_ip = await asyncio.to_thread(self._establish, session)
            rsd = await self._connect_rsd(xpc, tunnel_ip, session.auxiliary_metadata)
        except BaseException:
            await asyncio.to_thread(session.close)
            raise
        self._session = session
        self.rsd = rsd
        return rsd

    def _establish(self, session: _RemotePairingSession) -> str:
        session.browse(self.serial)
        return session.open_tunnel()

    async def _connect_rsd(
        self, xpc: _LibXpc, tunnel_ip: str, auxiliary_metadata: Optional[dict[str, dict[str, Any]]] = None
    ) -> RemoteServiceDiscoveryService:
        # Right after the tunnel comes up the device may reset the just-established RSD connection
        # ("Device must renegotiate TLS" in remoted's log) and remoted transparently redials -- onto
        # a NEW device port. Apple's own client treats that reset as routine, so retry here too, and
        # re-scan the socket table on every attempt: a cached candidate list goes stale the moment
        # remoted redials (the scan may also simply run before remoted has connected at all).
        last_error: Optional[Exception] = None
        # Identify as remoted, whose connection this one replaces on its own tunnel: a different peer
        # UUID makes the device (iOS 27.2+) tear down the services it has just advertised (see
        # remotexpc.remoted_handshake_uuid). The device still evicts remoted's connection for ours,
        # and remoted redials and evicts ours back (#1994), which is why this transport is opt-in.
        handshake_uuid = await asyncio.to_thread(remoted_handshake_uuid)
        for attempt in range(_RSD_CONNECT_ATTEMPTS):
            if attempt:
                await asyncio.sleep(_RSD_CONNECT_RETRY_DELAY)
            for port in await asyncio.to_thread(find_rsd_port, xpc, tunnel_ip):
                rsd = RemoteServiceDiscoveryService(
                    (tunnel_ip, port), auxiliary_metadata=auxiliary_metadata, handshake_uuid=handshake_uuid
                )
                try:
                    await rsd.connect()
                except Exception as e:  # try the next candidate port
                    last_error = e
                    await rsd.close()
                else:
                    return rsd
        if last_error is None:
            raise _RemotePairingError(f"Could not find remoted's RSD connection on the native tunnel to {tunnel_ip}.")
        raise _RemotePairingError(
            f"Failed to complete the RSD handshake over the native tunnel [{tunnel_ip}]: {last_error!r}"
        )

    async def aclose(self) -> None:
        if self.rsd is not None:
            await self.rsd.close()
            self.rsd = None
        if self._session is not None:
            await asyncio.to_thread(self._close_session)

    def _close_session(self) -> None:
        """Release the assertion and cancel the XPC connections; blocking (waits on replies)."""
        session, self._session = self._session, None
        if session is not None:
            session.close()

    async def __aenter__(self) -> RemoteServiceDiscoveryService:
        return await self.aopen()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()
```

## tunneld discovery

## pymobiledevice3.tunneld.api.get_tunneld_devices

```
get_tunneld_devices(tunneld_address: TunneldAddress = TUNNELD_DEFAULT_ADDRESS, bridge: Optional[bool] = None) -> list[RemoteServiceDiscoveryService]
```

Query a running `tunneld` instance over HTTP for all active tunnels and connect to each.

Parameters:

| Name              | Type             | Description                                                                                                                                                                                                                                                                                                                                        | Default                   |
| ----------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `tunneld_address` | `TunneldAddress` | (host, port) of the tunneld HTTP server.                                                                                                                                                                                                                                                                                                           | `TUNNELD_DEFAULT_ADDRESS` |
| `bridge`          | `Optional[bool]` | bridge connections through tunneld's WS /connect endpoint instead of dialing the tunnel interface directly — required when that interface is unreachable from this process (tunneld on another host, a different docker network stack, or behind an SSH port-forward). None bridges automatically when tunneld_address is a non-loopback TCP host. | `None`                    |

Returns:

| Type                                  | Description                                                                                                                 |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `list[RemoteServiceDiscoveryService]` | a connected RemoteServiceDiscoveryService for every tunnel that could be reached; tunnels that fail to connect are skipped. |

Raises:

| Type                     | Description                                |
| ------------------------ | ------------------------------------------ |
| `TunneldConnectionError` | if the tunneld instance cannot be reached. |

Source code in `pymobiledevice3/tunneld/api.py`

```
async def get_tunneld_devices(
    tunneld_address: TunneldAddress = TUNNELD_DEFAULT_ADDRESS, bridge: Optional[bool] = None
) -> list[RemoteServiceDiscoveryService]:
    """
    Query a running ``tunneld`` instance over HTTP for all active tunnels and connect to each.

    :param tunneld_address: ``(host, port)`` of the ``tunneld`` HTTP server.
    :param bridge: bridge connections through tunneld's ``WS /connect`` endpoint instead of dialing
        the tunnel interface directly — required when that interface is unreachable from this
        process (tunneld on another host, a different docker network stack, or behind an SSH
        port-forward). ``None`` bridges automatically when ``tunneld_address`` is a non-loopback
        TCP host.
    :returns: a connected `RemoteServiceDiscoveryService`
        for every tunnel that could be reached; tunnels that fail to connect are skipped.
    :raises TunneldConnectionError: if the ``tunneld`` instance cannot be reached.
    """
    tunnels = _list_tunnels(tunneld_address)
    return await _create_rsds_from_tunnels(tunnels, tunneld_address, bridge)
```
