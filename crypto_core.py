"""Password-based authenticated encryption for text and small files.

Public API:
    encrypt_bytes / decrypt_bytes  - convenient for Streamlit uploads
    encrypt_text / decrypt_text    - Base64 text representation
    encrypt_file / decrypt_file    - .kripto files on disk

Format v1: 8-byte magic, 1-byte algorithm ID, 16-byte salt, 12-byte nonce,
then ciphertext with its 16-byte authentication tag. The whole header is
authenticated as associated data. Scrypt parameters are fixed for v1.
"""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"KRIPTO1\0"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE

# Parameters are part of format v1. Changing them requires a new format version.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

AES_256_GCM = "AES-256-GCM"
CHACHA20_POLY1305 = "ChaCha20-Poly1305"
_ALGORITHM_IDS = {AES_256_GCM: 1, CHACHA20_POLY1305: 2}
_ID_ALGORITHMS = {value: key for key, value in _ALGORITHM_IDS.items()}


class InvalidEncryptedData(ValueError):
    """The encrypted package has an invalid or unsupported format."""


class DecryptionFailed(ValueError):
    """The password is wrong or the encrypted package was modified."""


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        raise ValueError("password must not be empty")
    return password.encode("utf-8")


def _key(password: str, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(_password_bytes(password))


def _cipher(algorithm: str, key: bytes) -> AESGCM | ChaCha20Poly1305:
    if algorithm == AES_256_GCM:
        return AESGCM(key)
    if algorithm == CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    raise ValueError(f"unsupported algorithm: {algorithm}")


def encrypt_bytes(
    data: bytes, password: str, algorithm: str = AES_256_GCM
) -> bytes:
    """Encrypt bytes into a self-contained, authenticated .kripto package."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if algorithm not in _ALGORITHM_IDS:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    _password_bytes(password)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = MAGIC + bytes([_ALGORITHM_IDS[algorithm]]) + salt + nonce
    key = _key(password, salt)
    ciphertext = _cipher(algorithm, key).encrypt(nonce, data, header)
    return header + ciphertext


def decrypt_bytes(encrypted: bytes, password: str) -> bytes:
    """Decrypt a package, raising DecryptionFailed if authentication fails."""
    if not isinstance(encrypted, bytes):
        raise TypeError("encrypted must be bytes")
    _password_bytes(password)
    if len(encrypted) < HEADER_SIZE + TAG_SIZE or not encrypted.startswith(MAGIC):
        raise InvalidEncryptedData("invalid or incomplete .kripto data")
    algorithm_id = encrypted[len(MAGIC)]
    if algorithm_id not in _ID_ALGORITHMS:
        raise InvalidEncryptedData("unsupported encryption algorithm")
    algorithm = _ID_ALGORITHMS[algorithm_id]
    header = encrypted[:HEADER_SIZE]
    salt_start = len(MAGIC) + 1
    salt = encrypted[salt_start : salt_start + SALT_SIZE]
    nonce = encrypted[salt_start + SALT_SIZE : HEADER_SIZE]
    key = _key(password, salt)
    try:
        return _cipher(algorithm, key).decrypt(
            nonce, encrypted[HEADER_SIZE:], header
        )
    except InvalidTag as exc:
        raise DecryptionFailed("wrong password or modified encrypted data") from exc


def encrypt_text(
    text: str, password: str, algorithm: str = AES_256_GCM
) -> str:
    """Encrypt UTF-8 text and return a copyable Base64 string."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return base64.b64encode(encrypt_bytes(text.encode("utf-8"), password, algorithm)).decode(
        "ascii"
    )


def decrypt_text(encrypted_base64: str, password: str) -> str:
    """Decode Base64 and decrypt a UTF-8 text message."""
    if not isinstance(encrypted_base64, str):
        raise TypeError("encrypted_base64 must be a string")
    try:
        encrypted = base64.b64decode(encrypted_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidEncryptedData("invalid Base64 text") from exc
    return decrypt_bytes(encrypted, password).decode("utf-8")


def encrypt_file(
    source: str | Path,
    password: str,
    algorithm: str = AES_256_GCM,
    destination: str | Path | None = None,
) -> Path:
    """Encrypt a file to source-name.kripto without overwriting existing files."""
    source_path = Path(source)
    target = Path(destination) if destination is not None else source_path.with_name(
        source_path.name + ".kripto"
    )
    encrypted = encrypt_bytes(source_path.read_bytes(), password, algorithm)
    with target.open("xb") as output:
        output.write(encrypted)
    return target


def decrypt_file(
    source: str | Path, password: str, destination: str | Path | None = None
) -> Path:
    """Verify and decrypt a .kripto file before creating its output file."""
    source_path = Path(source)
    if destination is None:
        if source_path.suffix != ".kripto":
            raise ValueError("source filename must end in .kripto")
        target = source_path.with_suffix("")
    else:
        target = Path(destination)
    plaintext = decrypt_bytes(source_path.read_bytes(), password)
    with target.open("xb") as output:
        output.write(plaintext)
    return target
