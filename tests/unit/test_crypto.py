"""Tests for multi-key Fernet helpers."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from cryptography.fernet import Fernet, InvalidToken

from recon_operator.crypto import build_fernet_cipher, load_fernet_key_material


class CryptoRotationTests(unittest.TestCase):
    def test_multi_key_encrypts_with_primary_and_decrypts_with_previous(self):
        old_key = Fernet.generate_key().decode()
        new_key = Fernet.generate_key().decode()
        legacy = Fernet(old_key.encode()).encrypt(b'{"legacy":true}')
        cipher = build_fernet_cipher([new_key, old_key])
        self.assertEqual(cipher.decrypt(legacy), b'{"legacy":true}')
        fresh = cipher.encrypt(b'{"fresh":true}')
        # New tokens decrypt with primary alone.
        self.assertEqual(Fernet(new_key.encode()).decrypt(fresh), b'{"fresh":true}')
        with self.assertRaises(InvalidToken):
            Fernet(old_key.encode()).decrypt(fresh)

    def test_load_fernet_key_material_from_env(self):
        primary = Fernet.generate_key().decode()
        previous = Fernet.generate_key().decode()
        with mock.patch.dict(
            os.environ,
            {"FERNET_KEY": primary, "FERNET_PREVIOUS_KEYS": f"{previous},{primary}"},
            clear=False,
        ):
            keys = load_fernet_key_material()
        self.assertEqual(keys[0], primary)
        self.assertEqual(keys, [primary, previous])

    def test_load_rejects_missing_primary(self):
        with mock.patch.dict(
            os.environ, {"FERNET_KEY": "", "FERNET_PREVIOUS_KEYS": ""}, clear=False
        ):
            with self.assertRaisesRegex(RuntimeError, "FERNET_KEY"):
                load_fernet_key_material()


if __name__ == "__main__":
    unittest.main()
