import datetime
import logging
from abc import abstractmethod
from ssl import SSLContext
from typing import Any, Optional

from packaging.version import Version

from pymobiledevice3.exceptions import MissingValueError, StartServiceError
from pymobiledevice3.service_connection import ServiceConnection

# Developer mode arrived in iOS 16; before that there is nothing to enable or to query.
DEVELOPER_MODE_MIN_VERSION = Version("16.0")


class LockdownServiceProvider:
    """Abstract interface for lockdown-capable service providers."""

    def __init__(self) -> None:
        # Populated by concrete implementations after successful connection/initialization.
        self.udid: Optional[str] = None
        self.product_type: Optional[str] = None
        self.all_values: dict[str, Any] = {}

    @property
    @abstractmethod
    def product_version(self) -> str:
        """Return the device OS version."""
        pass

    @property
    def has_developer_mode(self) -> bool:
        """Whether this device's OS has a developer mode at all.

        The single place this cutoff is decided. Anything that gates on developer mode -- refusing
        to mount without it, or merely reporting its state -- asks here, so the rule cannot be
        restated somewhere that then drifts.
        """
        return Version(self.product_version) >= DEVELOPER_MODE_MIN_VERSION

    @property
    @abstractmethod
    def product_build_version(self) -> Optional[str]:
        """Return the device OS build string."""
        pass

    @property
    @abstractmethod
    def ecid(self) -> int:
        """Return the device ECID (unique chip identifier)."""
        pass

    async def set_language(self, language: str) -> None:
        """Set the device's language (``Language`` key in the ``com.apple.international`` domain).

        :param language: The language code to set (e.g. ``"en"``).
        """
        await self.set_value(language, key="Language", domain="com.apple.international")

    async def get_language(self) -> str:
        """Get the device's language (``Language`` key in the ``com.apple.international`` domain).

        :returns: The language code, or an empty string when the value is missing or not a string.
        """
        value = await self.get_value(domain="com.apple.international", key="Language")
        return value if isinstance(value, str) else ""

    async def set_locale(self, locale: str) -> None:
        """Set the device's locale (``Locale`` key in the ``com.apple.international`` domain).

        :param locale: The locale string to set (e.g. ``"en_US"``).
        """
        await self.set_value(locale, key="Locale", domain="com.apple.international")

    async def get_locale(self) -> str:
        """Get the device's locale (``Locale`` key in the ``com.apple.international`` domain).

        :returns: The locale string, or an empty string when the value is missing or not a string.
        """
        value = await self.get_value(domain="com.apple.international", key="Locale")
        return value if isinstance(value, str) else ""

    async def set_timezone(self, timezone: str) -> None:
        """Set the device's time zone (``TimeZone`` key, default domain).

        :param timezone: The time zone identifier to set (e.g. ``"America/New_York"``).
        """
        await self.set_value(timezone, key="TimeZone")

    async def set_uses24h_clock(self, value: bool) -> None:
        """Set whether the device uses the 24-hour clock format (``Uses24HourClock`` key, default domain).

        :param value: True for 24-hour format, False for 12-hour format.
        """
        await self.set_value(value, key="Uses24HourClock")

    async def set_assistive_touch(self, value: bool) -> None:
        """Enable or disable AssistiveTouch (``AssistiveTouchEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :param value: True to enable AssistiveTouch, False to disable it.
        """
        await self.set_value(int(value), "com.apple.Accessibility", "AssistiveTouchEnabledByiTunes")

    async def get_assistive_touch(self) -> bool:
        """Get whether AssistiveTouch is enabled (``AssistiveTouchEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :returns: True if AssistiveTouch is enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="AssistiveTouchEnabledByiTunes")
        return bool(value)

    async def set_voice_over(self, value: bool) -> None:
        """Enable or disable VoiceOver (``VoiceOverTouchEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :param value: True to enable VoiceOver, False to disable it.
        """
        await self.set_value(int(value), "com.apple.Accessibility", "VoiceOverTouchEnabledByiTunes")

    async def get_voice_over(self) -> bool:
        """Get whether VoiceOver is enabled (``VoiceOverTouchEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :returns: True if VoiceOver is enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="VoiceOverTouchEnabledByiTunes")
        return bool(value)

    async def set_invert_display(self, value: bool) -> None:
        """Enable or disable display color inversion (``InvertDisplayEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :param value: True to enable display inversion, False to disable it.
        """
        await self.set_value(int(value), "com.apple.Accessibility", "InvertDisplayEnabledByiTunes")

    async def get_invert_display(self) -> bool:
        """Get whether display color inversion is enabled (``InvertDisplayEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :returns: True if display inversion is enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="InvertDisplayEnabledByiTunes")
        return bool(value)

    async def set_enable_wifi_connections(self, value: bool) -> None:
        """Enable or disable Wi-Fi (wireless) lockdown connections to the device
        (``EnableWifiConnections`` key in the ``com.apple.mobile.wireless_lockdown`` domain).

        :param value: True to allow connecting to the device over Wi-Fi, False to disallow it.
        """
        await self.set_value(value, "com.apple.mobile.wireless_lockdown", "EnableWifiConnections")

    async def get_enable_wifi_connections(self) -> bool:
        """Get whether Wi-Fi (wireless) lockdown connections are enabled (``EnableWifiConnections`` key in the
        ``com.apple.mobile.wireless_lockdown`` domain).

        :returns: True if Wi-Fi connections are enabled, False otherwise.
        """
        try:
            value = await self.get_value(domain="com.apple.mobile.wireless_lockdown", key="EnableWifiConnections")
        except MissingValueError:
            # never set on this device: Wi-Fi connections are off
            return False
        return bool(value)

    async def get_developer_mode_status(self) -> bool:
        """Get whether Developer Mode is enabled on the device (``DeveloperModeStatus`` key in the
        ``com.apple.security.mac.amfi`` domain).

        :returns: True if Developer Mode is enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.security.mac.amfi", key="DeveloperModeStatus")
        return bool(value)

    async def get_date(self) -> datetime.datetime:
        """Get the device's current date and time.

        Reads the device's ``TimeIntervalSince1970`` value and converts it to a local
        `datetime`. Falls back to the Unix epoch when the value is missing.

        :returns: The device's current date and time.
        """
        timestamp = await self.get_value(key="TimeIntervalSince1970")
        return datetime.datetime.fromtimestamp(timestamp or 0)

    @abstractmethod
    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """Start a lockdown service and return its active connection."""
        pass

    @abstractmethod
    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
        """Return the service metadata returned by StartService (port, SSL flags, etc.)."""
        pass

    @abstractmethod
    async def create_service_connection(
        self, port: int, ssl_context: Optional[SSLContext] = None, strip_ssl: bool = False
    ) -> ServiceConnection:
        """Create a low-level connection object to a service port, negotiating TLS when given ``ssl_context``
        (``strip_ssl`` drops back to plaintext after the handshake)."""
        pass

    @abstractmethod
    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        """Read a lockdownd value (optionally scoped by domain/key)."""
        pass

    @abstractmethod
    async def set_value(self, value: Any, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        """Write a lockdownd value (optionally scoped by domain/key)."""
        pass

    @abstractmethod
    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        """Remove a lockdownd value (optionally scoped by domain/key)."""
        pass

    async def start_lockdown_developer_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """Start a developer service with a helpful log message on common mount failures."""
        try:
            return await self.start_lockdown_service(name, include_escrow_bag=include_escrow_bag)
        except StartServiceError:
            logging.getLogger(self.__module__).exception(
                "Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. "
                "You can do so using: pymobiledevice3 mounter mount"
            )
            raise
