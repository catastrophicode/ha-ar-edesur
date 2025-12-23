"""API client for Edesur Argentina."""
import asyncio
import logging
import ssl
from typing import Any, Optional

import aiohttp
from aiohttp import ClientError, ClientTimeout

from .const import (
    API_ACCOUNT_SUMMARY,
    API_CURRENT_OUTAGES,
    API_DEBT,
    API_GET_PROFILE,
    API_LOGIN,
    API_OUTAGE_BY_CLIENT,
    API_OUTAGE_VALIDATE,
    API_RETRIEVE_CLIENT,
    API_SCHEDULED_OUTAGES,
    API_SUPPLY_RETRIEVE,
    DEFAULT_TIMEOUT,
    ERROR_AUTH_FAILED,
    ERROR_CANNOT_CONNECT,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
    MAX_RETRIES,
    RETRY_DELAY,
)
from .edesur_encryption import EdesurEncryption

_LOGGER = logging.getLogger(__name__)

# Create SSL context at module level to avoid blocking calls in event loop
_SSL_CONTEXT_INSECURE = ssl.create_default_context()
_SSL_CONTEXT_INSECURE.check_hostname = False
_SSL_CONTEXT_INSECURE.verify_mode = ssl.CERT_NONE


class EdesurApiError(Exception):
    """Base exception for Edesur API errors."""


class EdesurAuthError(EdesurApiError):
    """Exception for authentication errors."""


class EdesurConnectionError(EdesurApiError):
    """Exception for connection errors."""


class EdesurTimeoutError(EdesurApiError):
    """Exception for timeout errors."""


class EdesurApiClient:
    """Client for interacting with Edesur API."""

    def __init__(
        self,
        email: str,
        password: str,
        dni: Optional[str] = None,
        document_type: str = "DNI",
        session: Optional[aiohttp.ClientSession] = None,
        encryptor: Optional[EdesurEncryption] = None,
    ) -> None:
        """Initialize the API client.

        Args:
            email: User email
            password: User password
            dni: Document number (optional, only needed for supply retrieval)
            document_type: Type of document (DNI, CUIL, CUIT, Pasaporte)
            session: Optional aiohttp session
            encryptor: Optional credential encryptor

        Note:
            Authentication (login) only requires email and password.
            DNI is only needed when calling get_supplies().
        """
        self.email = email
        self.password = password
        self.dni = dni
        self.document_type = document_type
        self._session = session
        self._own_session = session is None
        self._token: Optional[str] = None
        self._user_data: Optional[dict[str, Any]] = None
        self.encryptor = encryptor or EdesurEncryption()

    async def __aenter__(self) -> "EdesurApiClient":
        """Async context manager entry."""
        if self._own_session:
            self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close the API client session."""
        if self._own_session and self._session:
            await self._session.close()
            self._session = None

    async def _request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        json_data: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, str]] = None,
        retry_count: int = 0,
        timeout_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Make an HTTP request with retry logic.

        Args:
            method: HTTP method
            url: Request URL
            headers: Optional headers
            json_data: Optional JSON payload
            params: Optional query parameters
            retry_count: Current retry attempt
            timeout_seconds: Optional custom timeout in seconds

        Returns:
            JSON response data

        Raises:
            EdesurAuthError: For authentication failures
            EdesurConnectionError: For connection issues
            EdesurTimeoutError: For timeout errors
            EdesurApiError: For other API errors
        """
        if not self._session:
            raise EdesurConnectionError("Session not initialized")

        request_headers = headers or {}
        if self._token and "Authorization" not in request_headers:
            request_headers["Authorization"] = f"Bearer {self._token}"

        timeout = ClientTimeout(total=timeout_seconds or DEFAULT_TIMEOUT)

        try:
            # Log full request details
            _LOGGER.info("=" * 80)
            _LOGGER.info("REQUEST: %s %s", method, url)
            _LOGGER.info("Headers: %s", request_headers)
            _LOGGER.info("Payload: %s", json_data)
            _LOGGER.info("Params: %s", params)
            _LOGGER.info("Cookies: %s", self._session.cookie_jar if self._session else "None")

            async with self._session.request(
                method,
                url,
                headers=request_headers,
                json=json_data,
                params=params,
                timeout=timeout,
            ) as response:
                # Log response
                response_text = await response.text()
                _LOGGER.info("RESPONSE: Status %d", response.status)
                _LOGGER.info("Response headers: %s", dict(response.headers))
                _LOGGER.info("Response body: %s", response_text[:1000])
                _LOGGER.info("=" * 80)
                # Handle authentication errors
                if response.status == 401:
                    # Only retry authentication once to avoid infinite loops
                    if retry_count == 0 and self._token:
                        _LOGGER.warning("Token expired (401), attempting reauthentication")
                        try:
                            # Re-authenticate to get a fresh token
                            await self.authenticate()
                            _LOGGER.info("Reauthentication successful, retrying request")
                            # Retry the request with the new token
                            return await self._request(
                                method, url, headers, json_data, params, retry_count + 1, timeout_seconds
                            )
                        except Exception as auth_err:
                            _LOGGER.error("Reauthentication failed: %s", auth_err)
                            raise EdesurAuthError(ERROR_AUTH_FAILED) from auth_err
                    else:
                        _LOGGER.warning("Authentication failed (401)")
                        raise EdesurAuthError(ERROR_AUTH_FAILED)

                # Handle server errors with retry
                if response.status >= 500:
                    if retry_count < MAX_RETRIES:
                        _LOGGER.warning(
                            "Server error %d, retrying in %d seconds (attempt %d/%d)",
                            response.status,
                            RETRY_DELAY,
                            retry_count + 1,
                            MAX_RETRIES,
                        )
                        await asyncio.sleep(RETRY_DELAY)
                        return await self._request(
                            method,
                            url,
                            headers,
                            json_data,
                            params,
                            retry_count + 1,
                        )
                    else:
                        raise EdesurApiError(
                            f"Server error {response.status} after {MAX_RETRIES} retries"
                        )

                # Handle other client errors
                if response.status >= 400:
                    _LOGGER.error(
                        "API error %d: %s", response.status, response_text[:200]
                    )
                    raise EdesurApiError(
                        f"API error {response.status}: {response_text[:100]}"
                    )

                # Try to parse JSON response
                try:
                    import json
                    data = json.loads(response_text) if response_text else {}
                    return data
                except Exception as err:
                    # Some endpoints might return plain text
                    _LOGGER.debug("Non-JSON response: %s", response_text[:200])
                    return {"data": response_text}

        except asyncio.TimeoutError as err:
            if retry_count < MAX_RETRIES:
                _LOGGER.warning(
                    "Request timeout, retrying (attempt %d/%d)",
                    retry_count + 1,
                    MAX_RETRIES,
                )
                await asyncio.sleep(RETRY_DELAY)
                return await self._request(
                    method, url, headers, json_data, params, retry_count + 1, timeout_seconds
                )
            raise EdesurTimeoutError(ERROR_TIMEOUT) from err

        except ClientError as err:
            _LOGGER.error("Connection error: %s", err)
            raise EdesurConnectionError(ERROR_CANNOT_CONNECT) from err

        except Exception as err:
            _LOGGER.error("Unexpected error: %s", err)
            raise EdesurApiError(f"{ERROR_UNKNOWN}: {err}") from err

    async def authenticate(self) -> dict[str, Any]:
        """Authenticate with Edesur API.

        Returns:
            User data from authentication response

        Raises:
            EdesurAuthError: If authentication fails
        """
        _LOGGER.info("Authenticating with Edesur API")

        # Encrypt credentials
        encrypted_email = self.encryptor.encrypt(self.email)
        encrypted_password = self.encryptor.encrypt(self.password)

        payload = {
            "email": encrypted_email,
            "password": encrypted_password,
        }

        try:
            response = await self._request("POST", API_LOGIN, json_data=payload)

            # Extract token and user data
            # The exact response structure may vary - adjust based on actual API
            if isinstance(response, dict):
                self._token = response.get("token") or response.get("access_token")
                self._user_data = response.get("user") or response

                if not self._token:
                    _LOGGER.warning(
                        "No token in response, trying to use full response as user data"
                    )
                    # Some APIs return the token in a different field or structure
                    # Log the response structure for debugging
                    _LOGGER.debug("Login response structure: %s", list(response.keys()))

                _LOGGER.info("Authentication successful")
                return self._user_data or response

            raise EdesurAuthError("Invalid authentication response format")

        except EdesurAuthError:
            raise
        except Exception as err:
            _LOGGER.error("Authentication failed: %s", err)
            raise EdesurAuthError(f"Authentication failed: {err}") from err

    async def get_profile(self, use_cache: bool = False) -> dict[str, Any]:
        """Get user profile information including DNI.

        Args:
            use_cache: Whether to use cached profile data

        Returns:
            User profile data including DNI and document type

        Raises:
            EdesurApiError: If profile retrieval fails
        """
        if not self._token:
            await self.authenticate()

        encrypted_username = self.encryptor.encrypt(self.email)

        payload = {
            "username": encrypted_username,
            "origen": "ONEHUB",
            "tipoCliente": "PERSONA",
        }

        params = {"useCache": "false" if not use_cache else "true"}

        _LOGGER.debug("Retrieving user profile (useCache=%s)", use_cache)

        response = await self._request(
            "POST", API_GET_PROFILE, json_data=payload, params=params
        )

        # Extract and store DNI if not already set
        # Profile data is nested under "body" key
        if isinstance(response, dict):
            body = response.get("body", response)  # Handle both nested and direct format

            if not self.dni:
                self.dni = (
                    body.get("numeroDocumentoIdentidad")
                    or body.get("nroDocumento")
                    or body.get("dni")
                )
                if self.dni:
                    _LOGGER.info("Retrieved DNI from profile: %s", self.dni)

            if not self.document_type or self.document_type == "DNI":
                doc_type = (
                    body.get("tipoDocumentoIdentidad")
                    or body.get("tipoDocumento")
                )
                if doc_type:
                    self.document_type = doc_type

        return response

    async def get_supplies(self) -> list[dict[str, Any]]:
        """Retrieve all supplies for the authenticated user.

        Returns:
            List of supply data dictionaries

        Raises:
            EdesurApiError: If supply retrieval fails

        Note:
            If DNI is not provided during initialization, this method will
            automatically fetch it from the user profile.
        """
        if not self._token:
            await self.authenticate()

        # If DNI not provided, fetch from profile
        if not self.dni:
            _LOGGER.info("DNI not provided, fetching from user profile")
            await self.get_profile()

            if not self.dni:
                raise EdesurApiError(
                    "Could not retrieve DNI from profile. "
                    "Please provide DNI during initialization."
                )

        encrypted_username = self.encryptor.encrypt(self.email)

        payload = {
            "nroDocumento": self.dni,
            "tipoDocumento": self.document_type,
            "username": encrypted_username,
        }

        _LOGGER.info("Retrieving supplies for document %s", self.dni)

        response = await self._request("POST", API_SUPPLY_RETRIEVE, json_data=payload)

        # Extract supplies from response
        # Actual API structure: {"ListadoClientes": [...], "CodigoResultado": "0", ...}
        if isinstance(response, dict):
            supplies = response.get("ListadoClientes", [])

            if isinstance(supplies, list):
                _LOGGER.info("Found %d supplies", len(supplies))
                return supplies

            # Fallback to other possible formats
            supplies = (
                response.get("supplies")
                or response.get("data")
                or response.get("suministros")
                or []
            )

            if isinstance(supplies, list):
                return supplies

            # If response is a single supply, wrap it in a list
            if "CuentaContrato" in response or "nroSuministro" in response or "supplyId" in response:
                return [response]

        _LOGGER.warning("Unexpected supplies response format: %s", type(response))
        return []

    async def get_client_details(self, supply_id: str) -> dict[str, Any]:
        """Retrieve detailed client information for a specific supply.

        Args:
            supply_id: Supply ID (plain text, will be encrypted)

        Returns:
            Client details data including address, meter info, etc.
        """
        if not self._token:
            await self.authenticate()

        # Encrypt supply ID
        encrypted_supply_id = self.encryptor.encrypt(supply_id, double_tilde=False)

        url = f"{API_RETRIEVE_CLIENT}/{encrypted_supply_id}"
        _LOGGER.debug("Getting client details for supply %s", supply_id)

        # Add custom headers
        headers = {
            "requestkey": "cuentaContrato",
            "tipovalidacion": "route-hash-cliente",
            "tipologueo": "interno",
            "x-origin-channel": self.encryptor.encrypt("CAN001", double_tilde=False),
        }

        response = await self._request("GET", url, headers=headers)

        # Extract client from response
        # Response structure: {"ListadoCliente": [...], "CodigoResultado": "0", ...}
        if isinstance(response, dict):
            clients = response.get("ListadoCliente", [])
            if isinstance(clients, list) and len(clients) > 0:
                return clients[0]

        return response

    async def get_account_summary(self, supply_id: str) -> dict[str, Any]:
        """Get account summary for a specific supply.

        Args:
            supply_id: Supply ID (plain text, will be encrypted)

        Returns:
            Account summary data
        """
        if not self._token:
            await self.authenticate()

        # Encrypt supply ID
        encrypted_supply_id = self.encryptor.encrypt(supply_id, double_tilde=False)

        url = f"{API_ACCOUNT_SUMMARY}/{encrypted_supply_id}"
        _LOGGER.debug("Getting account summary for supply %s", supply_id)

        # Add custom headers
        headers = {
            "requestkey": "cuentaContrato",
            "tipovalidacion": "route-hash-cliente",
            "tipologueo": "interno",
            "x-origin-channel": self.encryptor.encrypt("CAN001", double_tilde=False),
        }

        return await self._request("GET", url, headers=headers)

    async def get_debt(self, supply_id: str) -> dict[str, Any]:
        """Get debt information for a specific supply.

        Args:
            supply_id: Supply ID (plain text, will be encrypted)

        Returns:
            Debt data
        """
        if not self._token:
            await self.authenticate()

        # Encrypt supply ID
        encrypted_supply_id = self.encryptor.encrypt(supply_id, double_tilde=False)

        payload = {
            "nroSuministro": encrypted_supply_id,
            "tipoBusqueda": "nro_suministro",
            "valorBusqueda": encrypted_supply_id,
        }

        # Add custom headers
        headers = {
            "requestkey": "nroSuministro",
            "tipovalidacion": "body-hash-cliente",
            "tipologueo": "interno",
            "x-origin-channel": self.encryptor.encrypt("CAN001", double_tilde=False),
        }

        _LOGGER.debug("Getting debt for supply %s", supply_id)

        return await self._request("POST", API_DEBT, json_data=payload, headers=headers)

    async def get_outage_by_client(self, supply_id: str) -> dict[str, Any]:
        """Get outage status for a specific supply.

        Args:
            supply_id: Supply ID

        Returns:
            Outage data
        """
        if not self._token:
            await self.authenticate()

        payload = {"nroSuministro": supply_id}

        _LOGGER.debug("Getting outage status for supply %s", supply_id)

        return await self._request("POST", API_OUTAGE_BY_CLIENT, json_data=payload)

    async def validate_service_cut(self, supply_id: str) -> dict[str, Any]:
        """Validate if there's a service cut for a specific supply.

        Args:
            supply_id: Supply ID (plain text, will be encrypted)

        Returns:
            Service cut validation data
        """
        if not self._token:
            await self.authenticate()

        # Encrypt supply ID
        encrypted_supply_id = self.encryptor.encrypt(supply_id, double_tilde=False)

        url = f"{API_OUTAGE_VALIDATE}/{encrypted_supply_id}"
        _LOGGER.debug("Validating service cut for supply %s", supply_id)

        # Add custom headers
        headers = {
            "requestkey": "nroSuministro",
            "tipovalidacion": "route-hash-cliente",
            "tipologueo": "interno",
            "x-origin-channel": self.encryptor.encrypt("CAN001", double_tilde=False),
        }

        return await self._request("GET", url, headers=headers)

    async def get_scheduled_outages(self) -> dict[str, Any]:
        """Get scheduled outages (public endpoint).

        Returns:
            Scheduled outages data
        """
        _LOGGER.debug("Getting scheduled outages")

        # Use longer timeout (60s) for this endpoint as it can be slow
        return await self._request("GET", API_SCHEDULED_OUTAGES, timeout_seconds=60)

    async def get_current_outages(self) -> str:
        """Get current outages from ENRE (public endpoint).

        Returns:
            JavaScript data containing current outages

        Note:
            This endpoint has SSL issues, so we skip it gracefully
        """
        _LOGGER.debug("Getting current outages from ENRE")

        try:
            # The ENRE endpoint has SSL/TLS issues
            # Use the module-level SSL context to avoid blocking calls
            # Use longer timeout (60s) as this is an external endpoint
            timeout = ClientTimeout(total=60)

            async with aiohttp.ClientSession() as temp_session:
                async with temp_session.request(
                    "GET",
                    API_CURRENT_OUTAGES,
                    timeout=timeout,
                    ssl=_SSL_CONTEXT_INSECURE,
                ) as response:
                    response_text = await response.text()

                    if response.status == 200:
                        return response_text
                    else:
                        _LOGGER.warning("ENRE endpoint returned status %d", response.status)
                        return ""

        except Exception as err:
            _LOGGER.debug("Could not fetch current outages from ENRE: %s", err)
            # Return empty string instead of raising - this is a non-critical endpoint
            return ""
