"""API client for Edesur Argentina."""
import asyncio
import logging
import ssl
import time
import uuid
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
        self._auth_lock = asyncio.Lock()
        self._last_auth_attempt: float = 0
        self._last_auth_success: float = 0
        self._auth_failure_count: int = 0
        self._auth_in_progress: bool = False

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
        skip_reauth: bool = False,
        request_id: Optional[str] = None,
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
            skip_reauth: Skip reauthentication on 401 (used for login endpoint)

        Returns:
            JSON response data

        Raises:
            EdesurAuthError: For authentication failures
            EdesurConnectionError: For connection issues
            EdesurTimeoutError: For timeout errors
            EdesurApiError: For other API errors
        """
        # Generate request ID if not provided
        if request_id is None:
            request_id = str(uuid.uuid4())[:8]

        if not self._session:
            raise EdesurConnectionError("Session not initialized")

        request_headers = headers or {}
        if self._token and "Authorization" not in request_headers:
            request_headers["Authorization"] = f"Bearer {self._token}"

        timeout = ClientTimeout(total=timeout_seconds or DEFAULT_TIMEOUT)

        try:
            # Log full request details
            _LOGGER.info("=" * 80)
            _LOGGER.info("[%s] REQUEST: %s %s (retry: %d)", request_id, method, url, retry_count)
            _LOGGER.info("[%s] Has token: %s", request_id, "Yes" if self._token else "No")
            _LOGGER.info("[%s] Token (first 20 chars): %s", request_id, self._token[:20] + "..." if self._token else "None")
            _LOGGER.info("[%s] Skip reauth: %s", request_id, skip_reauth)
            _LOGGER.info("[%s] Auth in progress: %s", request_id, self._auth_in_progress)
            _LOGGER.info("[%s] Auth failure count: %d", request_id, self._auth_failure_count)
            _LOGGER.info("[%s] Seconds since last auth attempt: %.1f", request_id, time.time() - self._last_auth_attempt if self._last_auth_attempt else 0)
            _LOGGER.info("[%s] Headers: %s", request_id, {k: v for k, v in request_headers.items() if k != "Authorization"})
            _LOGGER.debug("[%s] Payload: %s", request_id, json_data)
            _LOGGER.debug("[%s] Params: %s", request_id, params)

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
                _LOGGER.info("[%s] RESPONSE: Status %d", request_id, response.status)
                _LOGGER.info("[%s] Response headers: %s", request_id, dict(response.headers))
                _LOGGER.info("[%s] Response body (first 1000 chars): %s", request_id, response_text[:1000])
                _LOGGER.info("=" * 80)
                # Handle authentication errors
                if response.status == 401:
                    # Only retry authentication once to avoid infinite loops
                    # Skip reauthentication for login endpoint itself
                    if not skip_reauth and retry_count == 0:
                        _LOGGER.warning("[%s] Token expired (401), attempting reauthentication", request_id)

                        # Save the current token before attempting to acquire the lock
                        token_before_lock = self._token

                        # Check if authentication is already failing repeatedly
                        if self._auth_failure_count >= 3:
                            time_since_last_attempt = time.time() - self._last_auth_attempt
                            if time_since_last_attempt < 60:  # Less than 1 minute
                                _LOGGER.error(
                                    "[%s] Authentication has failed %d times in the last %.1f seconds. "
                                    "Refusing to retry to prevent lockout. Please check your credentials.",
                                    request_id,
                                    self._auth_failure_count,
                                    time_since_last_attempt,
                                )
                                raise EdesurAuthError("Authentication failing repeatedly, please check credentials")

                        _LOGGER.info("[%s] Waiting to acquire auth lock...", request_id)
                        lock_acquired_at = time.time()

                        # Use lock to prevent multiple concurrent reauthentication attempts
                        async with self._auth_lock:
                            wait_time = time.time() - lock_acquired_at
                            _LOGGER.info("[%s] Auth lock acquired after %.2f seconds", request_id, wait_time)

                            # Check if token was refreshed while we were waiting for the lock
                            if self._token and self._token != token_before_lock:
                                _LOGGER.info(
                                    "[%s] Token was refreshed by another request while waiting (old: %s..., new: %s...), retrying request",
                                    request_id,
                                    token_before_lock[:20] if token_before_lock else "None",
                                    self._token[:20] if self._token else "None",
                                )
                                return await self._request(
                                    method, url, headers, json_data, params, retry_count + 1, timeout_seconds, skip_reauth, request_id
                                )

                            # Check if authentication just failed for another request
                            if self._auth_in_progress:
                                _LOGGER.warning(
                                    "[%s] Another authentication is in progress, waiting...",
                                    request_id,
                                )
                                await asyncio.sleep(1)
                                if self._token and self._token != token_before_lock:
                                    _LOGGER.info("[%s] Token refreshed during wait, retrying", request_id)
                                    return await self._request(
                                        method, url, headers, json_data, params, retry_count + 1, timeout_seconds, skip_reauth, request_id
                                    )

                            try:
                                _LOGGER.info("[%s] Starting reauthentication (lock acquired, auth_in_progress: %s)", request_id, self._auth_in_progress)
                                self._auth_in_progress = True

                                # Clear the old token before reauthenticating
                                old_token = self._token
                                _LOGGER.info("[%s] Clearing old token: %s...", request_id, old_token[:20] if old_token else "None")
                                self._token = None

                                # Re-authenticate to get a fresh token
                                _LOGGER.info("[%s] Calling authenticate()...", request_id)
                                await self.authenticate()

                                if self._token and self._token != old_token:
                                    _LOGGER.info(
                                        "[%s] Reauthentication successful with new token (old: %s..., new: %s...), retrying request",
                                        request_id,
                                        old_token[:20] if old_token else "None",
                                        self._token[:20] if self._token else "None",
                                    )
                                    self._auth_failure_count = 0  # Reset failure count on success
                                elif self._token == old_token:
                                    _LOGGER.warning("[%s] Reauthentication returned the same token, this may indicate an issue", request_id)
                                else:
                                    _LOGGER.error("[%s] Reauthentication failed: no token received", request_id)
                                    raise EdesurAuthError("No token received after reauthentication")

                                # Retry the request with the new token
                                return await self._request(
                                    method, url, headers, json_data, params, retry_count + 1, timeout_seconds, skip_reauth, request_id
                                )
                            except Exception as auth_err:
                                _LOGGER.error(
                                    "[%s] Reauthentication failed: %s (type: %s)",
                                    request_id,
                                    auth_err,
                                    type(auth_err).__name__,
                                )
                                self._auth_failure_count += 1
                                raise EdesurAuthError(ERROR_AUTH_FAILED) from auth_err
                            finally:
                                self._auth_in_progress = False
                                _LOGGER.info("[%s] Auth lock will be released, auth_in_progress set to False", request_id)
                    else:
                        if skip_reauth:
                            _LOGGER.error(
                                "[%s] Authentication failed (401) on login endpoint - credentials may be incorrect. Response: %s",
                                request_id,
                                response_text[:500],
                            )
                        elif retry_count > 0:
                            _LOGGER.error(
                                "[%s] Authentication failed (401) after reauthentication attempt (retry_count=%d). Response: %s",
                                request_id,
                                retry_count,
                                response_text[:500],
                            )
                        else:
                            _LOGGER.warning("[%s] Authentication failed (401)", request_id)
                        raise EdesurAuthError(ERROR_AUTH_FAILED)

                # Handle server errors with retry
                if response.status >= 500:
                    if retry_count < MAX_RETRIES:
                        _LOGGER.warning(
                            "[%s] Server error %d, retrying in %d seconds (attempt %d/%d)",
                            request_id,
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
                            timeout_seconds,
                            skip_reauth,
                            request_id,
                        )
                    else:
                        raise EdesurApiError(
                            f"Server error {response.status} after {MAX_RETRIES} retries"
                        )

                # Handle other client errors
                if response.status >= 400:
                    _LOGGER.error(
                        "[%s] API error %d: %s", request_id, response.status, response_text[:200]
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
                    "[%s] Request timeout, retrying (attempt %d/%d)",
                    request_id,
                    retry_count + 1,
                    MAX_RETRIES,
                )
                await asyncio.sleep(RETRY_DELAY)
                return await self._request(
                    method, url, headers, json_data, params, retry_count + 1, timeout_seconds, skip_reauth, request_id
                )
            _LOGGER.error("[%s] Request timeout after %d retries", request_id, MAX_RETRIES)
            raise EdesurTimeoutError(ERROR_TIMEOUT) from err

        except ClientError as err:
            _LOGGER.error("[%s] Connection error: %s", request_id, err)
            raise EdesurConnectionError(ERROR_CANNOT_CONNECT) from err

        except EdesurAuthError:
            # Re-raise auth errors without wrapping them
            raise

        except EdesurApiError:
            # Re-raise API errors without wrapping them
            raise

        except Exception as err:
            _LOGGER.error("[%s] Unexpected error in _request: %s (type: %s)", request_id, err, type(err).__name__)
            raise EdesurApiError(f"{ERROR_UNKNOWN}: {err}") from err

    async def authenticate(self) -> dict[str, Any]:
        """Authenticate with Edesur API.

        Returns:
            User data from authentication response

        Raises:
            EdesurAuthError: If authentication fails
        """
        self._last_auth_attempt = time.time()
        _LOGGER.info("=" * 80)
        _LOGGER.info("AUTHENTICATE: Starting authentication with Edesur API")
        _LOGGER.info("AUTHENTICATE: Email: %s", self.email)
        _LOGGER.info("AUTHENTICATE: Current token before auth: %s", self._token[:20] + "..." if self._token else "None")
        _LOGGER.info("AUTHENTICATE: Auth failure count: %d", self._auth_failure_count)
        _LOGGER.info("AUTHENTICATE: Seconds since last success: %.1f", time.time() - self._last_auth_success if self._last_auth_success else 0)

        # Encrypt credentials
        try:
            encrypted_email = self.encryptor.encrypt(self.email)
            encrypted_password = self.encryptor.encrypt(self.password)
            _LOGGER.info("AUTHENTICATE: Credentials encrypted successfully")
            _LOGGER.info("AUTHENTICATE: Encrypted email (first 50 chars): %s", encrypted_email[:50])
            _LOGGER.info("AUTHENTICATE: Encrypted password length: %d", len(encrypted_password))
        except Exception as err:
            _LOGGER.error("AUTHENTICATE: Failed to encrypt credentials: %s", err)
            raise EdesurAuthError(f"Credential encryption failed: {err}") from err

        payload = {
            "email": encrypted_email,
            "password": encrypted_password,
        }

        try:
            # Use skip_reauth=True to prevent reauthentication loops on login endpoint
            _LOGGER.info("AUTHENTICATE: Sending authentication request to %s", API_LOGIN)
            response = await self._request("POST", API_LOGIN, json_data=payload, skip_reauth=True)

            # Extract token and user data
            # The exact response structure may vary - adjust based on actual API
            if isinstance(response, dict):
                _LOGGER.info("AUTHENTICATE: Authentication response received")
                _LOGGER.info("AUTHENTICATE: Response keys: %s", list(response.keys()))
                _LOGGER.info("AUTHENTICATE: Full response: %s", response)

                self._token = response.get("token") or response.get("access_token")
                self._user_data = response.get("user") or response

                if not self._token:
                    _LOGGER.error(
                        "AUTHENTICATE: No token in response! Response structure: %s",
                        list(response.keys())
                    )
                    _LOGGER.error("AUTHENTICATE: Full response for debugging: %s", response)
                    raise EdesurAuthError("No token received in authentication response")
                else:
                    _LOGGER.info("AUTHENTICATE: ✓ Authentication successful!")
                    _LOGGER.info("AUTHENTICATE: Token received (first 20 chars): %s...", self._token[:20])
                    _LOGGER.info("AUTHENTICATE: Token length: %d", len(self._token))
                    self._last_auth_success = time.time()
                    self._auth_failure_count = 0

                _LOGGER.info("=" * 80)
                return self._user_data or response

            _LOGGER.error("AUTHENTICATE: Invalid authentication response format: %s", type(response))
            raise EdesurAuthError("Invalid authentication response format")

        except EdesurAuthError:
            _LOGGER.error("AUTHENTICATE: Authentication failed with EdesurAuthError")
            self._auth_failure_count += 1
            _LOGGER.info("=" * 80)
            raise
        except Exception as err:
            _LOGGER.error("AUTHENTICATE: Authentication failed with unexpected error: %s (type: %s)", err, type(err).__name__)
            self._auth_failure_count += 1
            _LOGGER.info("=" * 80)
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
