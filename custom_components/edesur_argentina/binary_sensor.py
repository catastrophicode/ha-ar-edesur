"""Binary sensor platform for Edesur Argentina integration."""
from datetime import datetime
import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTR_ADDRESS,
    ATTR_CUSTOMER_NAME,
    ATTR_LAST_UPDATE,
    ATTR_OUTAGE_END,
    ATTR_OUTAGE_REASON,
    ATTR_OUTAGE_START,
    ATTR_SUPPLY_ID,
    BINARY_SENSOR_OUTAGE_AFFECTING,
    BINARY_SENSOR_SERVICE_CUT,
    DOMAIN,
)
from .coordinator import EdesurSupplyCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Edesur binary sensors from a config entry.

    Args:
        hass: Home Assistant instance
        entry: Config entry
        async_add_entities: Callback to add entities
    """
    data = hass.data[DOMAIN][entry.entry_id]
    supply_coordinators: list[EdesurSupplyCoordinator] = data["supply_coordinators"]

    entities = []

    # Create binary sensors for each supply
    for coordinator in supply_coordinators:
        entities.extend(
            [
                EdesurServiceCutBinarySensor(coordinator),
                EdesurOutageAffectingBinarySensor(coordinator),
            ]
        )

    async_add_entities(entities)


class EdesurSupplyBinarySensorBase(
    CoordinatorEntity[EdesurSupplyCoordinator], BinarySensorEntity
):
    """Base class for Edesur supply binary sensors."""

    def __init__(
        self,
        coordinator: EdesurSupplyCoordinator,
        sensor_type: str,
    ) -> None:
        """Initialize the binary sensor.

        Args:
            coordinator: Data coordinator
            sensor_type: Type of sensor
        """
        super().__init__(coordinator)
        self._sensor_type = sensor_type
        self._supply_id = coordinator.supply_id
        self._attr_unique_id = f"{DOMAIN}_{self._supply_id}_{sensor_type}"

    @property
    def device_info(self) -> dict[str, Any]:
        """Return device information.

        Returns:
            Device information dictionary
        """
        supply_data = self.coordinator.supply_data
        client_details = self.coordinator.data.get("client_details", {}) if self.coordinator.data else {}

        # Get customer name and account number
        customer_name = (
            client_details.get("Nombre")
            or supply_data.get("titular")
            or supply_data.get("customerName")
            or "Unknown Customer"
        )

        account_number = (
            client_details.get("CuentaContrato")
            or supply_data.get("CuentaContrato")
            or self._supply_id
        )

        device_name = f"Edesur Argentina {account_number}"

        device_model = "Electricity Supply"

        # Get address information: Dirección: {Calle} {Numero}, {Localidad}
        direccion_cliente = client_details.get("DireccionCliente", {})
        if isinstance(direccion_cliente, dict):
            calle = direccion_cliente.get("Calle", "")
            numero = direccion_cliente.get("Numero", "")
            localidad = direccion_cliente.get("Localidad", "")

            address_parts = []
            if calle and numero:
                address_parts.append(f"{calle} {numero}")
            elif calle:
                address_parts.append(calle)
            if localidad:
                address_parts.append(localidad)

            suggested_area = ", ".join(address_parts) if address_parts else None
        else:
            suggested_area = (
                supply_data.get("direccion")
                or supply_data.get("address")
            )

        return {
            "identifiers": {(DOMAIN, self._supply_id)},
            "name": device_name,
            "manufacturer": "Edesur",
            "model": device_model,
            "suggested_area": suggested_area,
            "configuration_url": "https://ov.edesur.com.ar",
        }

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes.

        Returns:
            Dictionary of extra attributes
        """
        supply_data = self.coordinator.supply_data
        return {
            ATTR_SUPPLY_ID: self._supply_id,
            ATTR_ADDRESS: supply_data.get("direccion") or supply_data.get("address"),
            ATTR_CUSTOMER_NAME: supply_data.get("titular")
            or supply_data.get("customerName"),
            ATTR_LAST_UPDATE: datetime.now().isoformat(),
        }


class EdesurServiceCutBinarySensor(EdesurSupplyBinarySensorBase):
    """Binary sensor for service cut status."""

    def __init__(self, coordinator: EdesurSupplyCoordinator) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator, BINARY_SENSOR_SERVICE_CUT)
        self._attr_name = "Service Status"
        self._attr_device_class = BinarySensorDeviceClass.PROBLEM
        self._attr_icon = "mdi:power-plug-off"

    @property
    def is_on(self) -> bool:
        """Return true if service is cut.

        Returns:
            True if there is a service cut
        """
        if not self.coordinator.data:
            return False

        service_cut_data = self.coordinator.data.get("service_cut", {})

        # Check various possible field names for service cut status
        is_cut = (
            service_cut_data.get("corteProgramado")
            or service_cut_data.get("corteActivo")
            or service_cut_data.get("serviceCut")
            or service_cut_data.get("isCut")
            or service_cut_data.get("hayCorte")
        )

        # Handle different data types
        if isinstance(is_cut, bool):
            return is_cut
        elif isinstance(is_cut, str):
            return is_cut.lower() in ["true", "yes", "si", "1", "active", "activo"]
        elif isinstance(is_cut, (int, float)):
            return bool(is_cut)

        # If we have service cut data at all, check if it indicates a problem
        if service_cut_data:
            # Check for specific status indicators
            status = (
                service_cut_data.get("estado")
                or service_cut_data.get("status")
                or ""
            )

            if isinstance(status, str):
                problem_keywords = [
                    "cortado",
                    "corte",
                    "cut",
                    "interrumpido",
                    "suspended",
                ]
                return any(keyword in status.lower() for keyword in problem_keywords)

        return False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = super().extra_state_attributes

        if self.coordinator.data:
            service_cut_data = self.coordinator.data.get("service_cut", {})

            # Add service cut details
            attrs.update(
                {
                    "cut_type": service_cut_data.get("tipoCorte")
                    or service_cut_data.get("cutType"),
                    "reason": service_cut_data.get("motivo")
                    or service_cut_data.get("reason"),
                    "estimated_restoration": service_cut_data.get(
                        "horaEstimadaRestauracion"
                    )
                    or service_cut_data.get("estimatedRestoration"),
                }
            )

        return attrs


class EdesurOutageAffectingBinarySensor(EdesurSupplyBinarySensorBase):
    """Binary sensor for outage affecting supply."""

    def __init__(self, coordinator: EdesurSupplyCoordinator) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator, BINARY_SENSOR_OUTAGE_AFFECTING)
        self._attr_name = "Supply Status"
        self._attr_device_class = BinarySensorDeviceClass.PROBLEM
        self._attr_icon = "mdi:transmission-tower-export"

    @property
    def is_on(self) -> bool:
        """Return true if an outage is affecting this supply.

        Returns:
            True if outage is affecting the supply
        """
        if not self.coordinator.data:
            return False

        outage_data = self.coordinator.data.get("outage", {})

        # Check if there's an active outage
        has_outage = (
            outage_data.get("corteActivo")
            or outage_data.get("outageActive")
            or outage_data.get("hayCorte")
            or outage_data.get("isActive")
        )

        # Handle different data types
        if isinstance(has_outage, bool):
            return has_outage
        elif isinstance(has_outage, str):
            return has_outage.lower() in ["true", "yes", "si", "1", "active", "activo"]
        elif isinstance(has_outage, (int, float)):
            return bool(has_outage)

        # Check if outage end time is in the future (indicating active outage)
        outage_end = outage_data.get("fechaFin") or outage_data.get("endDate")

        if outage_end:
            try:
                # Try to parse the date and check if it's in the future
                # This is a simplified check - actual parsing would depend on format
                from datetime import datetime

                # If we have an end date, consider the outage active
                return True
            except Exception:
                pass

        # Check for specific outage status
        status = outage_data.get("estado") or outage_data.get("status") or ""

        if isinstance(status, str):
            active_keywords = ["activo", "active", "en_curso", "ongoing", "programado"]
            if any(keyword in status.lower() for keyword in active_keywords):
                return True

        return False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = super().extra_state_attributes

        if self.coordinator.data:
            outage_data = self.coordinator.data.get("outage", {})

            # Add outage details
            attrs.update(
                {
                    ATTR_OUTAGE_START: outage_data.get("fechaInicio")
                    or outage_data.get("startDate"),
                    ATTR_OUTAGE_END: outage_data.get("fechaFin")
                    or outage_data.get("endDate"),
                    ATTR_OUTAGE_REASON: outage_data.get("motivo")
                    or outage_data.get("reason"),
                    "affected_area": outage_data.get("zonaAfectada")
                    or outage_data.get("affectedArea"),
                    "outage_type": outage_data.get("tipoCorte")
                    or outage_data.get("outageType"),
                }
            )

        return attrs
