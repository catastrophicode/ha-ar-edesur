# Edesur Argentina - Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/custom-components/hacs)
[![GitHub Release](https://img.shields.io/github/release/catastrophicode/ha-ar-edesur-integration.svg)](https://github.com/catastrophicode/ha-ar-edesur-integration/releases)
[![License](https://img.shields.io/github/license/catastrophicode/ha-ar-edesur-integration.svg)](LICENSE)

Home Assistant custom integration for monitoring Edesur Argentina electricity supplies. Track your account status, debt, outages, and service cuts directly from Home Assistant.

## Features

- **Multi-Supply Support**: Monitor multiple electricity supplies from a single account
- **Reconfigurable Supply Selection**: Add or remove supplies after initial setup
- **Account Monitoring**: Track account status, debt, and payment due dates
- **Outage Detection**: Real-time monitoring of service cuts and outages
- **Global Outage Information**: View current and scheduled outages across the network
- **Automatic Reauthentication**: Seamlessly handles token expiration
- **Configurable Update Intervals**: Customize polling frequency for supplies and outages
- **Multi-Language Support**: Available in English and Spanish
- **Robust Error Handling**: Automatic retries and graceful degradation

## Sensors

### Per Supply

Each electricity supply creates a device named "Edesur Argentina [account_number]" with the following sensors:

#### Regular Sensors
- **Customer Name** (`sensor.edesur_argentina_[supply_id]_customer_name`)
  - State: Customer name from account
  - Icon: mdi:account

- **Account Status** (`sensor.edesur_argentina_[supply_id]_account_status`)
  - State: Account status (Active, Suspended, etc.)
  - Attributes: Balance, last payment, last payment date
  - Icon: mdi:account-check

- **Total Debt** (`sensor.edesur_argentina_[supply_id]_total_debt`)
  - State: Total debt amount in USD ($)
  - Device Class: Monetary
  - Attributes: Detailed breakdown of individual debts
  - Icon: mdi:currency-usd

- **Due Date** (`sensor.edesur_argentina_[supply_id]_due_date`)
  - State: Next payment due date
  - Device Class: Date
  - Attributes: Supply and customer information
  - Icon: mdi:calendar-clock

- **Last Outage** (`sensor.edesur_argentina_[supply_id]_last_outage`)
  - State: Last outage information
  - Attributes: Outage start, end, and reason
  - Icon: mdi:power-plug-off

#### Binary Sensors
- **Service Status** (`binary_sensor.edesur_argentina_[supply_id]_service_cut`)
  - State: On if service is cut, Off otherwise
  - Device Class: Problem
  - Attributes: Cut type, reason, estimated restoration time
  - Icon: mdi:power-plug-off

- **Supply Status** (`binary_sensor.edesur_argentina_[supply_id]_outage_affecting_supply`)
  - State: On if an outage is affecting this supply
  - Device Class: Problem
  - Attributes: Outage details, affected area, outage type
  - Icon: mdi:transmission-tower-export

### Global Sensors

- **Edesur Current Outages** (`sensor.edesur_argentina_global_current_outages`)
  - State: Number of current outages
  - Attributes: List of affected areas
  - Icon: mdi:power-plug-off-outline

## Installation

### HACS (Recommended)

1. Ensure [HACS](https://hacs.xyz/) is installed
2. Add this repository as a custom repository in HACS:
   - Open HACS
   - Go to "Integrations"
   - Click the three dots in the top right
   - Select "Custom repositories"
   - Add URL: `https://github.com/catastrophicode/ha-ar-edesur-integration`
   - Category: Integration
3. Click "Install"
4. Restart Home Assistant

### Manual Installation

1. Download the latest release from [GitHub](https://github.com/catastrophicode/ha-ar-edesur-integration/releases)
2. Extract the `custom_components/edesur_argentina` directory to your Home Assistant `config/custom_components/` directory
3. Restart Home Assistant

## Configuration

### UI Configuration Flow

1. Navigate to **Settings** → **Devices & Services**
2. Click **+ Add Integration**
3. Search for "Edesur Argentina"
4. Enter your Edesur Oficina Virtual credentials
5. Select which supplies you want to monitor
6. Click **Submit** to complete setup

### Reconfiguring Supply Selection

You can add or remove supplies after initial setup:

1. Go to **Settings** → **Devices & Services**
2. Find the Edesur Argentina integration
3. Click the three dots menu (⋮)
4. Select **Reconfigure**
5. Update your supply selection
6. Click **Submit** - the integration will reload with your new selection

### Options

After setup, you can configure polling intervals:

- **Scan Interval**: How often to update supply data (default: 30 minutes)
- **Outage Scan Interval**: How often to check for outages (default: 5 minutes)

To configure options:
1. Go to **Settings** → **Devices & Services**
2. Find the Edesur Argentina integration
3. Click **Configure**

## API Endpoints Used

### Authenticated Endpoints

- `POST /api/Usuario/LoginAsync` - Authentication
- `POST /api/Usuario/GetProfileAsync` - User profile (includes DNI)
- `POST /api/Cliente/SupplyRetrieveAsync` - Retrieve supplies
- `GET /api/Cliente/ResumenCuentaAsync/{supplyId}` - Account summary
- `POST /api/PlanPagos/GetDeudaAsync` - Debt information
- `POST /api/utils/outage-by-client` - Outage status
- `GET /api/Cliente/ValidarCorteSuministroAsync/{supplyId}` - Service cut validation

### Public Endpoints

- `GET https://www.enre.gov.ar/paginacorte/js/data_EDS.js` - Current outages

## Security

This integration handles authentication with Edesur's API using their required encryption method. Your credentials are stored securely in Home Assistant's configuration and are never exposed in logs or the UI.

**Recommendation**: Use a strong, unique password for your Edesur account.

## Troubleshooting

### Authentication Failed

**Problem**: "Authentication failed" error during setup

**Solutions**:
- Verify your email and password are correct
- Check that you can log in to [Oficina Virtual](https://ov.edesur.com.ar)
- Ensure your account is active
- Check Home Assistant logs for detailed error messages

### No Supplies Found

**Problem**: "No supplies found" error

**Solutions**:
- Ensure your account has registered supplies
- Verify you can see your supplies in the Oficina Virtual web portal
- Check Home Assistant logs for detailed error messages

### Connection Errors

**Problem**: "Cannot connect" errors

**Solutions**:
- Check your internet connection
- Verify Home Assistant can reach ed.edesur.com.ar
- Check if Edesur's API is down (temporary outages)
- Review Home Assistant logs for detailed error messages

### Data Not Updating

**Problem**: Sensors show stale data

**Solutions**:
- Check the update interval in integration options
- Review logs for API errors
- Verify your authentication token hasn't expired
- Restart the integration

### Enabling Debug Logging

Add to `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.edesur_argentina: debug
```

Then restart Home Assistant and check the logs at **Settings** → **System** → **Logs**.

## API Limitations

- **Rate Limiting**: Edesur may rate-limit API requests. Default intervals are conservative to avoid issues.
- **Authentication Token Expiry**: Tokens expire after a period. The integration handles reauthentication automatically.
- **Data Freshness**: Account and debt data may not be real-time; it reflects Edesur's internal systems.
- **Outage Information**: Global outage data depends on third-party sources (ENRE) and may have delays.

## Development

### Project Structure

```
custom_components/edesur_argentina/
├── __init__.py           # Integration setup and entry points
├── manifest.json         # Integration metadata
├── const.py             # Constants and configuration
├── config_flow.py       # UI configuration flow
├── edesur_encryption.py # Encryption implementation
├── encryption.py        # Encryption utilities
├── api_client.py        # Edesur API client
├── coordinator.py       # Data update coordinators
├── sensor.py           # Sensor platform
├── binary_sensor.py    # Binary sensor platform
└── translations/        # UI translations
    ├── en.json          # English translations
    └── es.json          # Spanish translations
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This is an unofficial integration and is not affiliated with, endorsed by, or connected to Edesur or any of its subsidiaries or affiliates. This integration is provided "as is" without warranty of any kind.

Use at your own risk. The authors are not responsible for any issues arising from the use of this integration, including but not limited to service disruptions, data inaccuracies, or account access issues.

## Acknowledgments

- Home Assistant community for documentation and examples
- Edesur Argentina for providing the Oficina Virtual service
- ENRE (Ente Nacional Regulador de la Electricidad) for public outage data

## Support

- **Issues**: [GitHub Issues](https://github.com/catastrophicode/ha-ar-edesur-integration/issues)
- **Discussions**: [GitHub Discussions](https://github.com/catastrophicode/ha-ar-edesur-integration/discussions)
- **Home Assistant Community**: [Community Forum](https://community.home-assistant.io/)

## Changelog

### Version 1.1.0
- ✅ Reconfigure flow to add/remove supplies after initial setup
- ✅ Spanish translations for UI elements
- ✅ Pre-populated supply selection during reconfiguration
- ✅ Fixed encryptor attribute inconsistency in API client
- ✅ Automatic token refresh on 401 authentication errors
- ✅ Removed unreliable scheduled outages endpoint
- ✅ Increased timeout for slow outage endpoints (60s)

### Version 1.0.0 (Initial Release)
- ✅ Multi-supply monitoring
- ✅ Customer name sensor
- ✅ Account status and debt tracking
- ✅ Outage detection (per-supply and global)
- ✅ Service cut monitoring
- ✅ Configurable update intervals
- ✅ Automatic reauthentication
- ✅ Comprehensive error handling and retry logic
- ✅ Async-first architecture with non-blocking setup
- ✅ Graceful handling of timeouts and cancellations
