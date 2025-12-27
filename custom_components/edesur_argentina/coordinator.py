"""Data coordinators for Edesur integration."""
from datetime import timedelta
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api_client import (
    EdesurApiClient,
    EdesurApiError,
    EdesurAuthError,
    EdesurConnectionError,
    EdesurTimeoutError,
)
from .const import (
    DEFAULT_OUTAGE_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class EdesurSupplyCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator for managing supply-specific data updates."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: EdesurApiClient,
        supply_id: str,
        supply_data: dict[str, Any],
    ) -> None:
        """Initialize the supply coordinator.

        Args:
            hass: Home Assistant instance
            client: Edesur API client
            supply_id: Supply identifier
            supply_data: Initial supply data
        """
        self.client = client
        self.supply_id = supply_id
        self.supply_data = supply_data

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_supply_{supply_id}",
            update_interval=DEFAULT_SCAN_INTERVAL,
        )

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Edesur API.

        Returns:
            Combined data from all supply-specific endpoints

        Raises:
            UpdateFailed: If update fails
        """
        try:
            _LOGGER.debug("Updating data for supply %s", self.supply_id)

            # Fetch all supply-specific data in parallel
            client_details_task = self.client.get_client_details(self.supply_id)
            account_summary_task = self.client.get_account_summary(self.supply_id)
            debt_task = self.client.get_debt(self.supply_id)
            outage_task = self.client.get_outage_by_client(self.supply_id)
            service_cut_task = self.client.validate_service_cut(self.supply_id)

            # Wait for all requests to complete
            client_details, account_summary, debt, outage, service_cut = await asyncio.gather(
                client_details_task,
                account_summary_task,
                debt_task,
                outage_task,
                service_cut_task,
                return_exceptions=True,
            )

            # Build combined data dictionary, preserving last known values on failure
            # Get previous data to preserve last known good values
            previous_data = self.data or {}

            data = {
                "supply_id": self.supply_id,
                "supply_info": self.supply_data,
                "client_details": (
                    previous_data.get("client_details", {})
                    if isinstance(client_details, Exception)
                    else client_details
                ),
                "account_summary": (
                    previous_data.get("account_summary", {})
                    if isinstance(account_summary, Exception)
                    else account_summary
                ),
                "debt": (
                    previous_data.get("debt", {})
                    if isinstance(debt, Exception)
                    else debt
                ),
                "outage": (
                    previous_data.get("outage", {})
                    if isinstance(outage, Exception)
                    else outage
                ),
                "service_cut": (
                    previous_data.get("service_cut", {})
                    if isinstance(service_cut, Exception)
                    else service_cut
                ),
            }

            # Debug logging for client details
            if not isinstance(client_details, Exception) and client_details:
                _LOGGER.info(
                    "Client details fetched for supply %s: Nombre=%s, MarcaMedidor=%s",
                    self.supply_id,
                    client_details.get("Nombre"),
                    client_details.get("MarcaMedidor"),
                )
            elif isinstance(client_details, Exception):
                _LOGGER.warning(
                    "Client details fetch failed for supply %s, preserving last known data",
                    self.supply_id,
                )

            # Log any errors but don't fail the entire update
            for key, value in [
                ("client_details", client_details),
                ("account_summary", account_summary),
                ("debt", debt),
                ("outage", outage),
                ("service_cut", service_cut),
            ]:
                if isinstance(value, Exception):
                    _LOGGER.warning(
                        "Failed to fetch %s for supply %s: %s - preserving last known data",
                        key,
                        self.supply_id,
                        value,
                    )

            _LOGGER.debug("Successfully updated data for supply %s", self.supply_id)
            return data

        except asyncio.CancelledError:
            # Handle cancellation gracefully during shutdown or timeout
            _LOGGER.debug("Supply %s update was cancelled", self.supply_id)
            # Return minimal data with supply info
            return {
                "supply_id": self.supply_id,
                "supply_info": self.supply_data,
                "client_details": {},
                "account_summary": {},
                "debt": {},
                "outage": {},
                "service_cut": {},
            }

        except EdesurAuthError as err:
            _LOGGER.warning(
                "Authentication error for supply %s: %s - keeping last known data",
                self.supply_id,
                err,
            )
            # Return last known data instead of failing to prevent graph gaps
            # The reauthentication happens automatically in the API client
            if self.data:
                return self.data
            # If no previous data, return minimal structure
            return {
                "supply_id": self.supply_id,
                "supply_info": self.supply_data,
                "client_details": {},
                "account_summary": {},
                "debt": {},
                "outage": {},
                "service_cut": {},
            }

        except EdesurConnectionError as err:
            _LOGGER.warning(
                "Connection error for supply %s: %s - keeping last known data",
                self.supply_id,
                err,
            )
            # Return last known data for transient connection issues
            if self.data:
                return self.data
            return {
                "supply_id": self.supply_id,
                "supply_info": self.supply_data,
                "client_details": {},
                "account_summary": {},
                "debt": {},
                "outage": {},
                "service_cut": {},
            }

        except EdesurTimeoutError as err:
            _LOGGER.warning(
                "Timeout error for supply %s: %s - keeping last known data",
                self.supply_id,
                err,
            )
            # Return last known data for transient timeout issues
            if self.data:
                return self.data
            return {
                "supply_id": self.supply_id,
                "supply_info": self.supply_data,
                "client_details": {},
                "account_summary": {},
                "debt": {},
                "outage": {},
                "service_cut": {},
            }

        except EdesurApiError as err:
            _LOGGER.error("API error for supply %s: %s", self.supply_id, err)
            raise UpdateFailed(f"API error: {err}") from err

        except Exception as err:
            _LOGGER.exception("Unexpected error updating supply %s", self.supply_id)
            raise UpdateFailed(f"Unexpected error: {err}") from err


class EdesurGlobalOutageCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator for managing global outage data updates."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: EdesurApiClient,
    ) -> None:
        """Initialize the global outage coordinator.

        Args:
            hass: Home Assistant instance
            client: Edesur API client
        """
        self.client = client

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_global_outages",
            update_interval=DEFAULT_OUTAGE_SCAN_INTERVAL,
        )

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch global outage data from public endpoints.

        Returns:
            Combined global outage data

        Raises:
            UpdateFailed: If update fails
        """
        try:
            _LOGGER.debug("Updating global outage data")

            # Fetch current outages only (scheduled outages endpoint is unreliable)
            try:
                current = await self.client.get_current_outages()
            except Exception as err:
                _LOGGER.warning("Failed to fetch current outages: %s", err)
                current = ""

            data = {
                "current_outages": current,
            }

            _LOGGER.debug("Successfully updated global outage data")
            return data

        except asyncio.CancelledError:
            # Handle cancellation gracefully during shutdown or timeout
            _LOGGER.debug("Global outage update was cancelled")
            # Return empty data instead of failing
            return {
                "current_outages": "",
            }

        except Exception as err:
            _LOGGER.exception("Unexpected error updating global outages")
            raise UpdateFailed(f"Unexpected error: {err}") from err


# Import asyncio for gather
import asyncio
