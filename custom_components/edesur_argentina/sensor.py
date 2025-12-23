"""Sensor platform for Edesur Argentina integration."""
from datetime import datetime
import datetime as dt
import json
import logging
import re
from typing import Any, Optional

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CURRENCY_DOLLAR
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTR_AFFECTED_AREAS,
    ATTR_ADDRESS,
    ATTR_CUSTOMER_NAME,
    ATTR_DEBT_DETAILS,
    ATTR_LAST_UPDATE,
    ATTR_OUTAGE_END,
    ATTR_OUTAGE_REASON,
    ATTR_OUTAGE_START,
    ATTR_SUPPLY_ID,
    DOMAIN,
    SENSOR_ACCOUNT_STATUS,
    SENSOR_CURRENT_OUTAGES,
    SENSOR_CUSTOMER_NAME,
    SENSOR_DUE_DATE,
    SENSOR_LAST_OUTAGE,
    SENSOR_TOTAL_DEBT,
)
from .coordinator import EdesurGlobalOutageCoordinator, EdesurSupplyCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Edesur sensors from a config entry.

    Args:
        hass: Home Assistant instance
        entry: Config entry
        async_add_entities: Callback to add entities
    """
    data = hass.data[DOMAIN][entry.entry_id]
    supply_coordinators: list[EdesurSupplyCoordinator] = data["supply_coordinators"]
    outage_coordinator: EdesurGlobalOutageCoordinator = data["outage_coordinator"]

    entities = []

    # Create sensors for each supply
    for coordinator in supply_coordinators:
        entities.extend(
            [
                EdesurCustomerNameSensor(coordinator),
                EdesurAccountStatusSensor(coordinator),
                EdesurTotalDebtSensor(coordinator),
                EdesurDueDateSensor(coordinator),
                EdesurLastOutageSensor(coordinator),
            ]
        )

    # Create global sensors
    entities.extend(
        [
            EdesurCurrentOutagesSensor(outage_coordinator),
        ]
    )

    async_add_entities(entities)


class EdesurSupplySensorBase(CoordinatorEntity[EdesurSupplyCoordinator], SensorEntity):
    """Base class for Edesur supply sensors."""

    def __init__(
        self,
        coordinator: EdesurSupplyCoordinator,
        sensor_type: str,
    ) -> None:
        """Initialize the sensor.

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

        # Debug logging
        if client_details:
            _LOGGER.debug(
                "Device info for supply %s: client_details keys=%s",
                self._supply_id,
                list(client_details.keys()) if isinstance(client_details, dict) else "not a dict",
            )
        else:
            _LOGGER.warning(
                "Device info for supply %s: No client_details available. coordinator.data=%s",
                self._supply_id,
                "None" if not self.coordinator.data else list(self.coordinator.data.keys()),
            )

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


class EdesurCustomerNameSensor(EdesurSupplySensorBase):
    """Sensor for customer name."""

    def __init__(self, coordinator: EdesurSupplyCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, SENSOR_CUSTOMER_NAME)
        self._attr_name = f"Edesur Argentina {coordinator.supply_id} Customer Name"
        self._attr_icon = "mdi:account"

    @property
    def native_value(self) -> Optional[str]:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            supply_data = self.coordinator.supply_data
            return (
                supply_data.get("titular")
                or supply_data.get("customerName")
                or "Unknown Customer"
            )

        client_details = self.coordinator.data.get("client_details", {})
        supply_data = self.coordinator.supply_data

        # Get customer name from client details or supply data
        customer_name = (
            client_details.get("Nombre")
            or supply_data.get("titular")
            or supply_data.get("customerName")
            or "Unknown Customer"
        )

        return customer_name


class EdesurAccountStatusSensor(EdesurSupplySensorBase):
    """Sensor for account status."""

    def __init__(self, coordinator: EdesurSupplyCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, SENSOR_ACCOUNT_STATUS)
        self._attr_name = f"Edesur Argentina {coordinator.supply_id} Account Status"
        self._attr_icon = "mdi:account-check"

    @property
    def native_value(self) -> Optional[str]:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return None

        account_summary = self.coordinator.data.get("account_summary", {})

        # Try to extract status from various possible fields
        status = (
            account_summary.get("estado")
            or account_summary.get("status")
            or account_summary.get("accountStatus")
        )

        if status:
            return str(status)

        # If no explicit status, check if account is active based on data presence
        if account_summary:
            return "Active"

        return "Unknown"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = super().extra_state_attributes

        if self.coordinator.data:
            account_summary = self.coordinator.data.get("account_summary", {})

            # Add relevant account details
            attrs.update(
                {
                    "balance": account_summary.get("saldo")
                    or account_summary.get("balance"),
                    "last_payment": account_summary.get("ultimoPago")
                    or account_summary.get("lastPayment"),
                    "last_payment_date": account_summary.get("fechaUltimoPago")
                    or account_summary.get("lastPaymentDate"),
                }
            )

        return attrs


class EdesurTotalDebtSensor(EdesurSupplySensorBase):
    """Sensor for total debt."""

    def __init__(self, coordinator: EdesurSupplyCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, SENSOR_TOTAL_DEBT)
        self._attr_name = f"Edesur Argentina {coordinator.supply_id} Total Debt"
        self._attr_icon = "mdi:currency-usd"
        self._attr_device_class = SensorDeviceClass.MONETARY
        self._attr_state_class = SensorStateClass.TOTAL
        self._attr_native_unit_of_measurement = CURRENCY_DOLLAR

    @property
    def native_value(self) -> Optional[float]:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return None

        debt_data = self.coordinator.data.get("debt", {})

        # Try to extract total debt from various possible fields
        total_debt = (
            debt_data.get("totalDeuda")
            or debt_data.get("total")
            or debt_data.get("montoTotal")
            or debt_data.get("totalDebt")
        )

        if total_debt is not None:
            try:
                return float(total_debt)
            except (ValueError, TypeError):
                _LOGGER.warning("Could not convert debt to float: %s", total_debt)

        # If no total field found, try to get monto_deuda from first element of deuda array
        deuda_array = debt_data.get("deuda", [])
        if isinstance(deuda_array, list) and len(deuda_array) > 0:
            first_deuda = deuda_array[0]
            monto_deuda = first_deuda.get("monto_deuda")
            if monto_deuda is not None:
                try:
                    return float(monto_deuda)
                except (ValueError, TypeError):
                    _LOGGER.warning("Could not convert monto_deuda to float: %s", monto_deuda)

        return 0.0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = super().extra_state_attributes

        if self.coordinator.data:
            debt_data = self.coordinator.data.get("debt", {})

            # Add debt details
            debt_details = []

            # Try to extract individual debts - check both possible field names
            debts = (
                debt_data.get("deuda")  # From GetDeudaAsync response
                or debt_data.get("deudas")
                or debt_data.get("debts")
                or debt_data.get("facturas")
                or []
            )

            if isinstance(debts, list):
                for debt in debts:
                    debt_details.append(
                        {
                            "period": debt.get("periodo") or debt.get("period"),
                            "amount": debt.get("monto_deuda") or debt.get("monto") or debt.get("amount"),
                            "due_date": debt.get("fecha_vencimiento") or debt.get("vencimiento") or debt.get("dueDate"),
                            "type": debt.get("tipo_deuda") or debt.get("tipo"),
                        }
                    )

            attrs[ATTR_DEBT_DETAILS] = debt_details

        return attrs


class EdesurDueDateSensor(EdesurSupplySensorBase):
    """Sensor for next due date."""

    def __init__(self, coordinator: EdesurSupplyCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, SENSOR_DUE_DATE)
        self._attr_name = f"Edesur Argentina {coordinator.supply_id} Due Date"
        self._attr_icon = "mdi:calendar-clock"
        self._attr_device_class = SensorDeviceClass.DATE

    @property
    def native_value(self) -> Optional[dt.date]:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return None

        debt_data = self.coordinator.data.get("debt", {})

        # Try to find the nearest due date
        due_dates = []

        debts = (
            debt_data.get("deuda")  # From GetDeudaAsync response
            or debt_data.get("deudas")
            or debt_data.get("debts")
            or debt_data.get("facturas")
            or []
        )

        if isinstance(debts, list):
            for debt in debts:
                due_date = debt.get("fecha_vencimiento") or debt.get("vencimiento") or debt.get("dueDate")
                if due_date:
                    due_dates.append(due_date)

        # Also check account summary
        account_summary = self.coordinator.data.get("account_summary", {})
        next_due = (
            account_summary.get("proximoVencimiento")
            or account_summary.get("nextDueDate")
        )
        if next_due:
            due_dates.append(next_due)

        if due_dates:
            # Parse dates and return the earliest one
            parsed_dates = []
            for date_str in due_dates:
                try:
                    # Try DD/MM/YYYY format first (from GetDeudaAsync)
                    parsed_date = dt.datetime.strptime(date_str, "%d/%m/%Y").date()
                    parsed_dates.append(parsed_date)
                except (ValueError, TypeError):
                    try:
                        # Try ISO format YYYY-MM-DD
                        parsed_date = dt.datetime.strptime(date_str, "%Y-%m-%d").date()
                        parsed_dates.append(parsed_date)
                    except (ValueError, TypeError):
                        _LOGGER.warning("Could not parse due date: %s", date_str)
                        continue

            if parsed_dates:
                return min(parsed_dates)

        return None


class EdesurLastOutageSensor(EdesurSupplySensorBase):
    """Sensor for last outage information."""

    def __init__(self, coordinator: EdesurSupplyCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, SENSOR_LAST_OUTAGE)
        self._attr_name = f"Edesur Argentina {coordinator.supply_id} Last Outage"
        self._attr_icon = "mdi:power-plug-off"

    @property
    def native_value(self) -> Optional[str]:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return None

        outage_data = self.coordinator.data.get("outage", {})

        # Check if there's an active or recent outage
        has_outage = (
            outage_data.get("corteProgramado")
            or outage_data.get("corteActivo")
            or outage_data.get("outage")
        )

        if has_outage:
            return "Active Outage"

        # Try to get last outage date
        last_outage = (
            outage_data.get("ultimoCorte")
            or outage_data.get("lastOutage")
            or outage_data.get("fechaUltimoCorte")
        )

        if last_outage:
            return str(last_outage)

        return "No Recent Outages"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = super().extra_state_attributes

        if self.coordinator.data:
            outage_data = self.coordinator.data.get("outage", {})

            attrs.update(
                {
                    ATTR_OUTAGE_START: outage_data.get("fechaInicio")
                    or outage_data.get("startDate"),
                    ATTR_OUTAGE_END: outage_data.get("fechaFin")
                    or outage_data.get("endDate"),
                    ATTR_OUTAGE_REASON: outage_data.get("motivo")
                    or outage_data.get("reason"),
                }
            )

        return attrs


class EdesurGlobalSensorBase(
    CoordinatorEntity[EdesurGlobalOutageCoordinator], SensorEntity
):
    """Base class for global Edesur sensors."""

    def __init__(
        self,
        coordinator: EdesurGlobalOutageCoordinator,
        sensor_type: str,
    ) -> None:
        """Initialize the sensor.

        Args:
            coordinator: Data coordinator
            sensor_type: Type of sensor
        """
        super().__init__(coordinator)
        self._sensor_type = sensor_type
        self._attr_unique_id = f"{DOMAIN}_global_{sensor_type}"


class EdesurCurrentOutagesSensor(EdesurGlobalSensorBase):
    """Sensor for current outages."""

    def __init__(self, coordinator: EdesurGlobalOutageCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, SENSOR_CURRENT_OUTAGES)
        self._attr_name = "Edesur Current Outages"
        self._attr_icon = "mdi:power-plug-off-outline"

    @property
    def native_value(self) -> int:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return 0

        current_outages = self.coordinator.data.get("current_outages", "")

        # Parse JavaScript data to count outages
        # The data is in JavaScript format, so we need to extract it
        try:
            # Try to find array pattern
            if isinstance(current_outages, str):
                # Look for array-like structure
                matches = re.findall(r"\{[^}]+\}", current_outages)
                return len(matches)
        except Exception as err:
            _LOGGER.warning("Failed to parse current outages: %s", err)

        return 0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = {}

        if self.coordinator.data:
            current_outages = self.coordinator.data.get("current_outages", "")

            # Try to extract affected areas
            try:
                if isinstance(current_outages, str):
                    # Basic parsing - this may need adjustment based on actual format
                    attrs[ATTR_AFFECTED_AREAS] = current_outages[:500]
            except Exception:
                pass

            attrs[ATTR_LAST_UPDATE] = datetime.now().isoformat()

        return attrs


