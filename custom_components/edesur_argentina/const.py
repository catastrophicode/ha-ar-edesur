"""Constants for the Edesur Argentina integration."""
from datetime import timedelta
from typing import Final

DOMAIN: Final = "edesur_argentina"

# Configuration
CONF_DNI: Final = "dni"
CONF_DOCUMENT_TYPE: Final = "document_type"
CONF_SELECTED_SUPPLIES: Final = "selected_supplies"

# Default values
DEFAULT_SCAN_INTERVAL: Final = timedelta(hours=24)  # Daily updates for account data
DEFAULT_OUTAGE_SCAN_INTERVAL: Final = timedelta(minutes=5)  # Frequent updates for outages
DEFAULT_TIMEOUT: Final = 30
REQUEST_DELAY: Final = 0.5  # Delay between API requests to avoid rate limiting (seconds)

# API Endpoints
API_BASE_URL: Final = "https://ed.edesur.com.ar/api"
API_LOGIN: Final = f"{API_BASE_URL}/Usuario/LoginAsync"
API_SUPPLY_RETRIEVE: Final = f"{API_BASE_URL}/Cliente/SupplyRetrieveAsync"
API_RETRIEVE_CLIENT: Final = f"{API_BASE_URL}/Cliente/RetrieveClienteAsync"
API_ACCOUNT_SUMMARY: Final = f"{API_BASE_URL}/Cliente/ResumenCuentaAsync"
API_DEBT: Final = f"{API_BASE_URL}/PlanPagos/GetDeudaAsync"
API_OUTAGE_BY_CLIENT: Final = f"{API_BASE_URL}/utils/outage-by-client"
API_OUTAGE_VALIDATE: Final = f"{API_BASE_URL}/Cliente/ValidarCorteSuministroAsync"
API_SCHEDULED_OUTAGES: Final = f"{API_BASE_URL}/utils/outage-report"
API_GET_PROFILE: Final = f"{API_BASE_URL}/Usuario/GetProfileAsync"

# Public endpoints
API_CURRENT_OUTAGES: Final = "https://www.enre.gov.ar/paginacorte/js/data_EDS.js"

# Document types
DOCUMENT_TYPES: Final = ["DNI", "CUIL", "CUIT", "Pasaporte"]

# Encryption methods
ENCRYPTION_NONE: Final = "none"
ENCRYPTION_BASE64: Final = "base64"
ENCRYPTION_AES: Final = "aes"
ENCRYPTION_RSA: Final = "rsa"

# Sensor types
SENSOR_ACCOUNT_STATUS: Final = "account_status"
SENSOR_TOTAL_DEBT: Final = "total_debt"
SENSOR_DUE_DATE: Final = "due_date"
SENSOR_LAST_OUTAGE: Final = "last_outage"
SENSOR_CUSTOMER_NAME: Final = "customer_name"
SENSOR_CURRENT_OUTAGES: Final = "current_outages"
SENSOR_SCHEDULED_OUTAGES: Final = "scheduled_outages"

# Binary sensor types
BINARY_SENSOR_SERVICE_CUT: Final = "service_cut"
BINARY_SENSOR_OUTAGE_AFFECTING: Final = "outage_affecting_supply"

# Attributes
ATTR_SUPPLY_ID: Final = "supply_id"
ATTR_ADDRESS: Final = "address"
ATTR_CUSTOMER_NAME: Final = "customer_name"
ATTR_LAST_UPDATE: Final = "last_update"
ATTR_DEBT_DETAILS: Final = "debt_details"
ATTR_OUTAGE_START: Final = "outage_start"
ATTR_OUTAGE_END: Final = "outage_end"
ATTR_OUTAGE_REASON: Final = "outage_reason"
ATTR_AFFECTED_AREAS: Final = "affected_areas"

# Error messages
ERROR_AUTH_FAILED: Final = "authentication_failed"
ERROR_CANNOT_CONNECT: Final = "cannot_connect"
ERROR_INVALID_CREDENTIALS: Final = "invalid_credentials"
ERROR_TIMEOUT: Final = "timeout"
ERROR_UNKNOWN: Final = "unknown_error"

# Retry configuration
MAX_RETRIES: Final = 3
RETRY_DELAY: Final = 5  # seconds
