"""Config flow for Edesur Argentina integration."""
import logging
from typing import Any, Optional

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv

from .api_client import (
    EdesurApiClient,
    EdesurApiError,
    EdesurAuthError,
    EdesurConnectionError,
)
from .const import (
    CONF_SELECTED_SUPPLIES,
    DOMAIN,
    ERROR_AUTH_FAILED,
    ERROR_CANNOT_CONNECT,
    ERROR_UNKNOWN,
)

_LOGGER = logging.getLogger(__name__)


class EdesurConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Edesur Argentina."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._email: Optional[str] = None
        self._password: Optional[str] = None
        self._client: Optional[EdesurApiClient] = None
        self._supplies: list[dict[str, Any]] = []

    async def async_step_user(
        self, user_input: Optional[dict[str, Any]] = None
    ) -> FlowResult:
        """Handle the initial step - collect credentials.

        Args:
            user_input: User provided configuration

        Returns:
            Flow result
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            self._email = user_input[CONF_EMAIL]
            self._password = user_input[CONF_PASSWORD]

            # Validate credentials
            try:
                # Create API client (DNI will be auto-fetched from profile)
                async with EdesurApiClient(
                    email=self._email,
                    password=self._password,
                ) as client:
                    self._client = client

                    # Test authentication
                    await client.authenticate()

                    # Fetch supplies (will auto-fetch DNI from profile)
                    self._supplies = await client.get_supplies()

                if not self._supplies:
                    errors["base"] = "no_supplies"
                else:
                    # Move to supply selection step
                    return await self.async_step_select_supplies()

            except EdesurAuthError:
                errors["base"] = ERROR_AUTH_FAILED

            except EdesurConnectionError:
                errors["base"] = ERROR_CANNOT_CONNECT

            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected error during setup: %s", err)
                errors["base"] = ERROR_UNKNOWN

        # Show user form (only email and password needed)
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): cv.string,
                    vol.Required(CONF_PASSWORD): cv.string,
                }
            ),
            errors=errors,
        )

    async def async_step_select_supplies(
        self, user_input: Optional[dict[str, Any]] = None
    ) -> FlowResult:
        """Handle supply selection step.

        Args:
            user_input: User selected supplies

        Returns:
            Flow result
        """
        if user_input is not None:
            selected = user_input.get(CONF_SELECTED_SUPPLIES, [])

            if not selected:
                return self.async_show_form(
                    step_id="select_supplies",
                    data_schema=self._get_supply_schema(),
                    errors={"base": "no_supplies_selected"},
                )

            # Create the config entry
            return self.async_create_entry(
                title=f"Edesur - {self._email}",
                data={
                    CONF_EMAIL: self._email,
                    CONF_PASSWORD: self._password,
                    CONF_SELECTED_SUPPLIES: selected,
                },
            )

        # Show supply selection form
        return self.async_show_form(
            step_id="select_supplies",
            data_schema=self._get_supply_schema(),
        )

    def _get_supply_schema(self) -> vol.Schema:
        """Generate schema for supply selection.

        Returns:
            Voluptuous schema for supply selection
        """
        # Create options for each supply
        supply_options = {}
        for supply in self._supplies:
            # Extract supply ID from actual API response structure
            supply_id = (
                supply.get("CuentaContrato")
                or supply.get("nroSuministro")
                or supply.get("supplyId")
                or supply.get("id")
                or str(supply)
            )

            # Create readable label with status
            status = supply.get("LiteralEstadoCuentaContrato") or supply.get("estado") or ""
            label = f"{supply_id} ({status})" if status else supply_id

            supply_options[supply_id] = label

        return vol.Schema(
            {
                vol.Required(CONF_SELECTED_SUPPLIES): cv.multi_select(supply_options),
            }
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "EdesurOptionsFlow":
        """Get the options flow for this handler.

        Args:
            config_entry: Config entry instance

        Returns:
            Options flow handler
        """
        return EdesurOptionsFlow(config_entry)


class EdesurOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for Edesur integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow.

        Args:
            config_entry: Config entry instance
        """
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: Optional[dict[str, Any]] = None
    ) -> FlowResult:
        """Manage the options.

        Args:
            user_input: User input

        Returns:
            Flow result
        """
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        # Get current supplies
        current_supplies = self.config_entry.data.get(CONF_SELECTED_SUPPLIES, [])

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        "scan_interval",
                        default=self.config_entry.options.get("scan_interval", 30),
                    ): vol.All(vol.Coerce(int), vol.Range(min=5, max=1440)),
                    vol.Optional(
                        "outage_scan_interval",
                        default=self.config_entry.options.get(
                            "outage_scan_interval", 5
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=60)),
                }
            ),
        )
