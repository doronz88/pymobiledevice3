import datetime
import logging
from abc import abstractmethod
from typing import Any, Optional

from pymobiledevice3.exceptions import StartServiceError
from pymobiledevice3.service_connection import ServiceConnection


class LockdownServiceProvider:
    """Abstract interface for lockdown-capable service providers."""

    def __init__(self) -> None:
        # Populated by concrete implementations after successful connection/initialization.
        self.udid: Optional[str] = None
        self.product_type: Optional[str] = None

    @property
    @abstractmethod
    def product_version(self) -> str:
        """Return the device OS version."""
        pass

    @property
    @abstractmethod
    def product_build_version(self) -> str:
        """Return the device OS build string."""
        pass

    @property
    @abstractmethod
    def ecid(self) -> int:
        """Return the device ECID (unique chip identifier)."""
        pass

    @abstractmethod
    async def get_developer_mode_status(self) -> bool:
        """Return whether Developer Mode is enabled."""
        pass

    @abstractmethod
    async def get_date(self) -> datetime.datetime:
        """Return the current device date/time."""
        pass

    @abstractmethod
    async def set_language(self, language: str) -> None:
        """Set the device language."""
        pass

    @abstractmethod
    async def get_language(self) -> str:
        """Get the device language."""
        pass

    @abstractmethod
    async def set_locale(self, locale: str) -> None:
        """Set the device locale."""
        pass

    @abstractmethod
    async def get_locale(self) -> str:
        """Get the device locale."""
        pass

    @abstractmethod
    async def set_assistive_touch(self, value: bool) -> None:
        """Enable or disable AssistiveTouch."""
        pass

    @abstractmethod
    async def get_assistive_touch(self) -> bool:
        """Return whether AssistiveTouch is enabled."""
        pass

    @abstractmethod
    async def set_voice_over(self, value: bool) -> None:
        """Enable or disable VoiceOver."""
        pass

    @abstractmethod
    async def get_voice_over(self) -> bool:
        """Return whether VoiceOver is enabled."""
        pass

    @abstractmethod
    async def set_invert_display(self, value: bool) -> None:
        """Enable or disable inverted display colors."""
        pass

    @abstractmethod
    async def get_invert_display(self) -> bool:
        """Return whether inverted display colors are enabled."""
        pass

    @abstractmethod
    async def set_enable_wifi_connections(self, value: bool) -> None:
        """Enable or disable Wi-Fi-based host connectivity."""
        pass

    @abstractmethod
    async def get_enable_wifi_connections(self) -> bool:
        """Return whether Wi-Fi-based host connectivity is enabled."""
        pass

    @abstractmethod
    async def set_timezone(self, timezone: str) -> None:
        """Set the device timezone identifier."""
        pass

    @abstractmethod
    async def set_uses24h_clock(self, value: bool) -> None:
        """Enable or disable 24-hour time display."""
        pass

    @abstractmethod
    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """Start a lockdown service and return its active connection."""
        pass

    @abstractmethod
    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict:
        """Return the service metadata returned by StartService (port, SSL flags, etc.)."""
        pass

    @abstractmethod
    async def create_service_connection(self, port: int) -> ServiceConnection:
        """Create a low-level connection object to a service port."""
        pass

    @abstractmethod
    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        """Read a lockdownd value (optionally scoped by domain/key)."""
        pass

    @abstractmethod
    async def set_value(self, value, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        """Write a lockdownd value (optionally scoped by domain/key)."""
        pass

    @abstractmethod
    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
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
