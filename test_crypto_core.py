"""Run with: python -m unittest -v"""

import base64
import tempfile
import unittest
from pathlib import Path

from crypto_core import (
    AES_256_GCM,
    CHACHA20_POLY1305,
    HEADER_SIZE,
    DecryptionFailed,
    InvalidEncryptedData,
    decrypt_bytes,
    decrypt_file,
    decrypt_text,
    encrypt_bytes,
    encrypt_file,
    encrypt_text,
)


class CryptoCoreTests(unittest.TestCase):
    def test_text_round_trip_for_both_algorithms(self):
        for algorithm in (AES_256_GCM, CHACHA20_POLY1305):
            with self.subTest(algorithm=algorithm):
                encoded = encrypt_text("Pesan rahasia 🔐", "kata sandi panjang", algorithm)
                self.assertEqual(decrypt_text(encoded, "kata sandi panjang"), "Pesan rahasia 🔐")

    def test_binary_round_trip_for_both_algorithms(self):
        original = b"%PDF-1.7\x00\xff\x80" * 100
        for algorithm in (AES_256_GCM, CHACHA20_POLY1305):
            with self.subTest(algorithm=algorithm):
                self.assertEqual(
                    decrypt_bytes(encrypt_bytes(original, "benar", algorithm), "benar"),
                    original,
                )

    def test_wrong_password_is_rejected(self):
        encrypted = encrypt_bytes(b"private", "benar")
        with self.assertRaises(DecryptionFailed):
            decrypt_bytes(encrypted, "salah")

    def test_changed_ciphertext_is_rejected(self):
        encrypted = bytearray(encrypt_bytes(b"private", "benar"))
        encrypted[HEADER_SIZE] ^= 1
        with self.assertRaises(DecryptionFailed):
            decrypt_bytes(bytes(encrypted), "benar")

    def test_changed_header_is_rejected(self):
        encrypted = bytearray(encrypt_bytes(b"private", "benar"))
        encrypted[10] ^= 1  # Salt is authenticated with the rest of the header.
        with self.assertRaises(DecryptionFailed):
            decrypt_bytes(bytes(encrypted), "benar")

    def test_repeated_encryption_has_fresh_randomness(self):
        first = encrypt_bytes(b"same message", "same password")
        second = encrypt_bytes(b"same message", "same password")
        self.assertNotEqual(first, second)
        self.assertEqual(decrypt_bytes(first, "same password"), b"same message")
        self.assertEqual(decrypt_bytes(second, "same password"), b"same message")

    def test_invalid_format_and_base64_are_rejected(self):
        with self.assertRaises(InvalidEncryptedData):
            decrypt_bytes(b"not a package", "benar")
        with self.assertRaises(InvalidEncryptedData):
            decrypt_text("%%%", "benar")
        with self.assertRaises(InvalidEncryptedData):
            decrypt_text(base64.b64encode(b"short").decode(), "benar")

    def test_file_round_trip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "contoh.pdf"
            original.write_bytes(b"%PDF-1.7\n" + bytes(range(256)))
            encrypted_path = encrypt_file(original, "benar")
            self.assertEqual(encrypted_path.name, "contoh.pdf.kripto")
            with self.assertRaises(FileExistsError):
                encrypt_file(original, "benar")
            original.unlink()
            restored_path = decrypt_file(encrypted_path, "benar")
            self.assertEqual(restored_path.read_bytes(), b"%PDF-1.7\n" + bytes(range(256)))
            with self.assertRaises(FileExistsError):
                decrypt_file(encrypted_path, "benar")

    def test_failed_file_decryption_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "test.txt"
            original.write_text("rahasia", encoding="utf-8")
            encrypted_path = encrypt_file(original, "benar")
            original.unlink()
            with self.assertRaises(DecryptionFailed):
                decrypt_file(encrypted_path, "salah")
            self.assertFalse(original.exists())

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_bytes(b"secret", "", AES_256_GCM)
        with self.assertRaises(ValueError):
            encrypt_bytes(b"secret", "benar", "AES-ECB")
        with self.assertRaises(TypeError):
            encrypt_bytes("not bytes", "benar")


if __name__ == "__main__":
    unittest.main()
