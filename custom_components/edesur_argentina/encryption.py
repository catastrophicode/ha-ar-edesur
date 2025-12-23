"""Encryption module for Edesur API credentials.

This module provides pluggable encryption methods for email and password.
Since Edesur's exact encryption method is not publicly documented, this
implementation supports multiple encryption strategies that can be easily
switched or extended.

Supported methods:
- none: No encryption (plain text) - for testing or if API accepts plain credentials
- base64: Simple Base64 encoding - common for basic obfuscation
- aes: AES-256 encryption with a known key - if API uses symmetric encryption
- rsa: RSA public key encryption - if API provides a public key

The default implementation uses Base64 encoding as a starting point.
Users can contribute the correct method once discovered through reverse engineering.
"""

import base64
import hashlib
import logging
from typing import Optional

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .const import (
    ENCRYPTION_AES,
    ENCRYPTION_BASE64,
    ENCRYPTION_NONE,
    ENCRYPTION_RSA,
)

_LOGGER = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Exception raised for encryption errors."""


class CredentialEncryptor:
    """Handle credential encryption for Edesur API.

    This class provides a pluggable interface for different encryption methods.
    The actual encryption method used by Edesur may need to be determined through
    reverse engineering of their mobile app or web application.
    """

    def __init__(
        self,
        method: str = ENCRYPTION_BASE64,
        key: Optional[bytes] = None,
        public_key: Optional[str] = None,
    ) -> None:
        """Initialize the encryptor.

        Args:
            method: Encryption method to use
            key: Encryption key for AES (32 bytes for AES-256)
            public_key: RSA public key in PEM format
        """
        self.method = method
        self.key = key
        self.public_key = public_key

        if method == ENCRYPTION_AES and not key:
            # Generate a default key if none provided
            # In production, this should come from API documentation or reverse engineering
            self.key = hashlib.sha256(b"edesur_default_key").digest()
            _LOGGER.warning(
                "Using default AES key. This may not match Edesur's actual encryption."
            )

        if method == ENCRYPTION_RSA and not public_key:
            raise EncryptionError("RSA encryption requires a public key")

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string using the configured method.

        Args:
            plaintext: The plain text string to encrypt

        Returns:
            The encrypted string (usually base64 encoded)

        Raises:
            EncryptionError: If encryption fails
        """
        try:
            if self.method == ENCRYPTION_NONE:
                return plaintext

            elif self.method == ENCRYPTION_BASE64:
                return self._encrypt_base64(plaintext)

            elif self.method == ENCRYPTION_AES:
                return self._encrypt_aes(plaintext)

            elif self.method == ENCRYPTION_RSA:
                return self._encrypt_rsa(plaintext)

            else:
                raise EncryptionError(f"Unknown encryption method: {self.method}")

        except Exception as err:
            _LOGGER.error("Encryption failed: %s", err)
            raise EncryptionError(f"Encryption failed: {err}") from err

    def _encrypt_base64(self, plaintext: str) -> str:
        """Simple Base64 encoding.

        This is the default implementation. Many APIs use Base64 as a simple
        obfuscation method (though it's not true encryption).
        """
        encoded = base64.b64encode(plaintext.encode("utf-8"))
        return encoded.decode("utf-8")

    def _encrypt_aes(self, plaintext: str) -> str:
        """AES-256 encryption in CBC mode.

        This implementation uses AES-256 in CBC mode with PKCS7 padding.
        The IV is prepended to the ciphertext.
        """
        if not self.key:
            raise EncryptionError("AES key not configured")

        # Generate random IV
        iv = get_random_bytes(AES.block_size)

        # Create cipher
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Pad and encrypt
        padded_data = pad(plaintext.encode("utf-8"), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        # Return IV + ciphertext, base64 encoded
        encrypted_data = iv + ciphertext
        return base64.b64encode(encrypted_data).decode("utf-8")

    def _encrypt_rsa(self, plaintext: str) -> str:
        """RSA encryption using public key.

        This implementation uses RSA-OAEP encryption scheme.
        Useful if Edesur provides a public key for credential encryption.
        """
        if not self.public_key:
            raise EncryptionError("RSA public key not configured")

        # Import the public key
        key = RSA.import_key(self.public_key)

        # Create cipher
        cipher = PKCS1_OAEP.new(key)

        # Encrypt (RSA can only encrypt small amounts of data)
        ciphertext = cipher.encrypt(plaintext.encode("utf-8"))

        # Return base64 encoded
        return base64.b64encode(ciphertext).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a string (for testing purposes).

        Args:
            ciphertext: The encrypted string

        Returns:
            The decrypted plain text

        Note:
            This is mainly for testing. The API doesn't require decryption.
        """
        try:
            if self.method == ENCRYPTION_NONE:
                return ciphertext

            elif self.method == ENCRYPTION_BASE64:
                decoded = base64.b64decode(ciphertext.encode("utf-8"))
                return decoded.decode("utf-8")

            elif self.method == ENCRYPTION_AES:
                if not self.key:
                    raise EncryptionError("AES key not configured")

                # Decode base64
                encrypted_data = base64.b64decode(ciphertext.encode("utf-8"))

                # Extract IV and ciphertext
                iv = encrypted_data[: AES.block_size]
                actual_ciphertext = encrypted_data[AES.block_size :]

                # Create cipher and decrypt
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                padded_data = cipher.decrypt(actual_ciphertext)

                # Unpad and return
                plaintext = unpad(padded_data, AES.block_size)
                return plaintext.decode("utf-8")

            else:
                raise EncryptionError(
                    f"Decryption not implemented for method: {self.method}"
                )

        except Exception as err:
            _LOGGER.error("Decryption failed: %s", err)
            raise EncryptionError(f"Decryption failed: {err}") from err


def get_default_encryptor() -> CredentialEncryptor:
    """Get the default credential encryptor.

    This function returns an encryptor with the method most likely to work
    with Edesur's API based on common patterns. Users can modify this once
    the actual encryption method is discovered.

    Returns:
        A configured CredentialEncryptor instance
    """
    # Start with Base64 as it's the most common simple encoding
    # This can be updated once the actual method is reverse engineered
    return CredentialEncryptor(method=ENCRYPTION_BASE64)
