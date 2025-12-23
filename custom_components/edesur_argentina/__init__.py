"""Edesur Argentina integration."""
from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import aiohttp_client

from .api_client import (
    EdesurApiClient,
    EdesurAuthError,
    EdesurConnectionError,
)
from .const import (
    CONF_SELECTED_SUPPLIES,
    DEFAULT_OUTAGE_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .coordinator import EdesurGlobalOutageCoordinator, EdesurSupplyCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Edesur Argentina from a config entry.

    Args:
        hass: Home Assistant instance
        entry: Config entry

    Returns:
        True if setup was successful

    Raises:
        ConfigEntryAuthFailed: If authentication fails
        ConfigEntryNotReady: If setup should be retried
    """
    _LOGGER.debug("Setting up Edesur integration")

    # Get configuration
    email = entry.data[CONF_EMAIL]
    password = entry.data[CONF_PASSWORD]
    selected_supplies = entry.data.get(CONF_SELECTED_SUPPLIES, [])

    # Get scan intervals from options
    scan_interval = entry.options.get("scan_interval", 30)
    outage_scan_interval = entry.options.get("outage_scan_interval", 5)

    # Create aiohttp session
    session = aiohttp_client.async_get_clientsession(hass)

    # Create API client (DNI will be auto-fetched from profile)
    client = EdesurApiClient(
        email=email,
        password=password,
        session=session,
    )

    # Test authentication
    try:
        await client.authenticate()
    except EdesurAuthError as err:
        _LOGGER.error("Authentication failed: %s", err)
        raise ConfigEntryAuthFailed from err
    except EdesurConnectionError as err:
        _LOGGER.error("Connection failed: %s", err)
        raise ConfigEntryNotReady from err
    except Exception as err:
        _LOGGER.exception("Unexpected error during setup: %s", err)
        raise ConfigEntryNotReady from err

    # Fetch supplies
    try:
        all_supplies = await client.get_supplies()
    except Exception as err:
        _LOGGER.error("Failed to fetch supplies: %s", err)
        raise ConfigEntryNotReady from err

    # Filter to selected supplies
    supplies = [
        supply
        for supply in all_supplies
        if (
            supply.get("CuentaContrato") in selected_supplies
            or supply.get("nroSuministro") in selected_supplies
            or supply.get("supplyId") in selected_supplies
            or supply.get("id") in selected_supplies
        )
    ]

    if not supplies:
        _LOGGER.warning("No matching supplies found for selection")
        supplies = all_supplies  # Fall back to all supplies

    _LOGGER.info("Setting up %d supplies", len(supplies))

    # Create coordinators for each supply
    supply_coordinators = []
    for supply in supplies:
        supply_id = (
            supply.get("CuentaContrato")
            or supply.get("nroSuministro")
            or supply.get("supplyId")
            or supply.get("id")
        )

        coordinator = EdesurSupplyCoordinator(
            hass=hass,
            client=client,
            supply_id=supply_id,
            supply_data=supply,
        )

        # Update interval from options
        coordinator.update_interval = timedelta(minutes=scan_interval)

        # Perform initial data fetch
        await coordinator.async_config_entry_first_refresh()

        supply_coordinators.append(coordinator)

    # Create global outage coordinator
    outage_coordinator = EdesurGlobalOutageCoordinator(
        hass=hass,
        client=client,
    )

    # Update interval from options
    outage_coordinator.update_interval = timedelta(minutes=outage_scan_interval)

    # Schedule initial data fetch in background to avoid blocking setup
    # The coordinator will handle retries and errors gracefully
    hass.async_create_task(
        outage_coordinator.async_config_entry_first_refresh(),
        f"{DOMAIN}_outage_coordinator_first_refresh",
    )

    # Store coordinators and client in hass.data
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "supply_coordinators": supply_coordinators,
        "outage_coordinator": outage_coordinator,
    }

    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register update listener for options
    entry.async_on_unload(entry.add_update_listener(async_update_options))

    _LOGGER.info("Edesur integration setup complete")

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry.

    Args:
        hass: Home Assistant instance
        entry: Config entry

    Returns:
        True if unload was successful
    """
    _LOGGER.debug("Unloading Edesur integration")

    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        # Clean up
        data = hass.data[DOMAIN].pop(entry.entry_id)
        client = data["client"]

        # Close API client session
        await client.close()

        _LOGGER.info("Edesur integration unloaded")

    return unload_ok


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Update options.

    Args:
        hass: Home Assistant instance
        entry: Config entry
    """
    _LOGGER.debug("Updating Edesur integration options")

    # Reload the integration to apply new options
    await hass.config_entries.async_reload(entry.entry_id)


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate old entry.

    Args:
        hass: Home Assistant instance
        entry: Config entry

    Returns:
        True if migration was successful
    """
    _LOGGER.debug("Migrating Edesur entry from version %s", entry.version)

    if entry.version == 1:
        # No migration needed yet
        pass

    _LOGGER.info("Migration to version %s successful", entry.version)

    return True
