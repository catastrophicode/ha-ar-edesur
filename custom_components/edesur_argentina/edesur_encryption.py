"""Edesur encryption implementation - TripleDES with MD5 key hash.

After reverse engineering the Edesur Oficina Virtual web application,
we discovered the actual encryption method:

Algorithm: TripleDES (NOT AES!)
Mode: ECB
Key: MD5("*Enel2022!")
IV: First 8 bytes of MD5("*Enel2022!") (sigBytes: 8)
Output: URL-safe base64 with ~~ suffix (double tilde)

The JavaScript implementation:
- Uses CryptoJS.TripleDES.encrypt()
- MD5 hashes the key "*Enel2022!"
- Uses ECB mode with 8-byte IV
- Converts to base64 and makes it URL-safe
- Adds ~~ suffix (double tilde)
"""

import base64
import hashlib
import logging

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

_LOGGER = logging.getLogger(__name__)

# The actual key discovered from the web application
EDESUR_KEY_PLAIN = "*Enel2022!"


class EdesurEncryption:
    """Handle Edesur credential encryption using TripleDES."""

    def __init__(self, key_string: str = EDESUR_KEY_PLAIN):
        """Initialize the encryptor.

        Args:
            key_string: The plain key string (default: discovered key)
        """
        self.key_string = key_string

        # Generate MD5 hash of the key (as done in JavaScript)
        md5_hash = hashlib.md5(key_string.encode('utf-8')).digest()

        # TripleDES key is the full MD5 hash (16 bytes)
        self.key = md5_hash

        # IV is first 8 bytes of the MD5 hash
        self.iv = md5_hash[:8]

        _LOGGER.debug("Encryption initialized with key hash: %s", md5_hash.hex())

    def encrypt(self, plaintext: str, double_tilde: bool = True) -> str:
        """Encrypt a string using Edesur's method.

        This matches the JavaScript implementation:
        1. Hash the key with MD5
        2. Encrypt with TripleDES in ECB mode
        3. Convert to base64
        4. Make URL-safe
        5. Add ~ suffix

        Args:
            plaintext: The text to encrypt
            double_tilde: If True, use ~~ suffix (for credentials). If False, use ~ (for route params)

        Returns:
            Encrypted string in Edesur format (URL-safe base64 + ~)
        """
        if not plaintext:
            plaintext = ""

        try:
            # Create TripleDES cipher in ECB mode
            # Note: CryptoJS uses ECB by default, and the IV is used differently
            cipher = DES3.new(self.key, DES3.MODE_ECB)

            # Pad to 8-byte blocks (DES block size)
            padded = pad(plaintext.encode('utf-8'), DES3.block_size)

            # Encrypt
            ciphertext = cipher.encrypt(padded)

            # Convert to base64
            b64 = base64.b64encode(ciphertext).decode('utf-8')

            # Make URL-safe (replace + with -, / with _)
            url_safe = b64.replace('+', '-').replace('/', '_')

            # Remove padding and add tilde suffix
            # Credentials use ~~, route parameters use single ~
            suffix = '~~' if double_tilde else '~'
            url_safe = url_safe.rstrip('=') + suffix

            _LOGGER.debug("Encrypted '%s' to '%s'", plaintext[:10] + "...", url_safe[:20] + "...")

            return url_safe

        except Exception as err:
            _LOGGER.error("Encryption failed: %s", err)
            raise

    def decrypt(self, encrypted: str) -> str:
        """Decrypt Edesur encrypted string (for testing).

        Args:
            encrypted: The encrypted string (with ~ suffix)

        Returns:
            Decrypted plaintext
        """
        try:
            # Remove ~ suffix
            encrypted = encrypted.rstrip('~')

            # Convert from URL-safe base64
            standard_b64 = encrypted.replace('-', '+').replace('_', '/')

            # Add padding back
            padding_needed = (4 - len(standard_b64) % 4) % 4
            standard_b64 += '=' * padding_needed

            # Decode base64
            ciphertext = base64.b64decode(standard_b64)

            # Create cipher
            cipher = DES3.new(self.key, DES3.MODE_ECB)

            # Decrypt and unpad
            padded = cipher.decrypt(ciphertext)
            plaintext = unpad(padded, DES3.block_size)

            return plaintext.decode('utf-8')

        except Exception as err:
            _LOGGER.error("Decryption failed: %s", err)
            raise


def encrypt_credential(plaintext: str) -> str:
    """Encrypt a credential using Edesur's method.

    Convenience function for encrypting email/password.

    Args:
        plaintext: The credential to encrypt

    Returns:
        Encrypted credential
    """
    encryptor = EdesurEncryption()
    return encryptor.encrypt(plaintext)


def decrypt_credential(encrypted: str) -> str:
    """Decrypt a credential (for testing).

    Args:
        encrypted: The encrypted credential

    Returns:
        Decrypted credential
    """
    encryptor = EdesurEncryption()
    return encryptor.decrypt(encrypted)
