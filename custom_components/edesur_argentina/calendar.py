"""Support for Edesur Argentina calendar items."""
from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from homeassistant.components.calendar import CalendarEntity, CalendarEvent
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EdesurSupplyCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Edesur Argentina calendar entities."""
    coordinators = hass.data[DOMAIN][entry.entry_id]["supply_coordinators"]

    entities = []
    for coordinator in coordinators:
        entities.append(EdesurDueDateCalendar(coordinator))

    async_add_entities(entities)


class EdesurDueDateCalendar(CalendarEntity):
    """Calendar entity for Edesur bill due dates."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: EdesurSupplyCoordinator) -> None:
        """Initialize the calendar entity."""
        self.coordinator = coordinator
        self._attr_name = f"Edesur Argentina {coordinator.supply_id} Bill Due Dates"
        self._attr_unique_id = f"edesur_{coordinator.supply_id}_calendar"
        self._attr_icon = "mdi:calendar-clock"

    @property
    def device_info(self) -> dict[str, Any]:
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self.coordinator.supply_id)},
            "name": f"Edesur Argentina {self.coordinator.supply_id}",
            "manufacturer": "Edesur",
            "model": "Supply",
            "entry_type": "service",
        }

    @property
    def event(self) -> CalendarEvent | None:
        """Return the next upcoming event."""
        events = self._get_events(dt.datetime.now(), dt.datetime.now() + dt.timedelta(days=365))
        if events:
            return events[0]
        return None

    async def async_get_events(
        self,
        hass: HomeAssistant,
        start_date: dt.datetime,
        end_date: dt.datetime,
    ) -> list[CalendarEvent]:
        """Get all events in a specific time frame."""
        return self._get_events(start_date, end_date)

    def _get_events(
        self,
        start_date: dt.datetime,
        end_date: dt.datetime,
    ) -> list[CalendarEvent]:
        """Get all bill due date events."""
        if not self.coordinator.data:
            return []

        debt_data = self.coordinator.data.get("debt", {})
        client_details = self.coordinator.data.get("client_details", {})

        # Extract customer name for event summary
        customer_name = (
            client_details.get("Nombre")
            or client_details.get("nombre")
            or client_details.get("customerName")
            or f"Supply {self.coordinator.supply_id}"
        )

        # Get all debts
        debts = (
            debt_data.get("deuda")  # From GetDeudaAsync response
            or debt_data.get("deudas")
            or debt_data.get("debts")
            or debt_data.get("facturas")
            or []
        )

        events = []

        if isinstance(debts, list):
            for debt in debts:
                due_date_str = (
                    debt.get("fecha_vencimiento")
                    or debt.get("vencimiento")
                    or debt.get("dueDate")
                )

                if not due_date_str:
                    continue

                # Parse due date
                try:
                    # Try DD/MM/YYYY format first (from GetDeudaAsync)
                    due_date = dt.datetime.strptime(due_date_str, "%d/%m/%Y").date()
                except (ValueError, TypeError):
                    try:
                        # Try ISO format YYYY-MM-DD
                        due_date = dt.datetime.strptime(due_date_str, "%Y-%m-%d").date()
                    except (ValueError, TypeError):
                        _LOGGER.warning("Could not parse due date: %s", due_date_str)
                        continue

                # Filter events within date range
                if due_date < start_date.date() or due_date > end_date.date():
                    continue

                # Extract debt details
                amount = debt.get("monto_deuda") or debt.get("monto") or debt.get("amount")
                debt_type = debt.get("tipo_deuda") or debt.get("tipo") or "Bill"
                period = debt.get("periodo") or debt.get("period")

                # Format amount
                amount_str = f"${amount:,.2f}" if amount else "Amount unknown"

                # Build summary and description
                summary = f"Edesur Bill Due - {customer_name}"
                description_parts = [
                    f"Amount: {amount_str}",
                    f"Type: {debt_type}",
                ]

                if period:
                    description_parts.append(f"Period: {period}")

                description = "\n".join(description_parts)

                # Create calendar event (all-day event)
                event = CalendarEvent(
                    summary=summary,
                    start=due_date,
                    end=due_date,
                    description=description,
                )

                events.append(event)

        # Sort events by start date
        events.sort(key=lambda x: x.start)

        return events

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        self.async_on_remove(
            self.coordinator.async_add_listener(self.async_write_ha_state)
        )

    async def async_update(self) -> None:
        """Update the entity."""
        await self.coordinator.async_request_refresh()

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success
