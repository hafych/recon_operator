import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

import decrypt


class DecryptTests(unittest.TestCase):
    def test_main_decrypts_to_output_file(self):
        key = Fernet.generate_key()
        plaintext = '{"status": "ok"}\n'

        with tempfile.TemporaryDirectory() as tmp:
            encrypted_path = Path(tmp) / "scan.enc"
            output_path = Path(tmp) / "scan.json"
            encrypted_path.write_bytes(Fernet(key).encrypt(plaintext.encode()))

            original_argv = sys.argv
            original_key = os.environ.get("FERNET_KEY")
            sys.argv = ["decrypt.py", str(encrypted_path), "-o", str(output_path)]
            os.environ["FERNET_KEY"] = key.decode()
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    decrypt.main()
            finally:
                sys.argv = original_argv
                if original_key is None:
                    os.environ.pop("FERNET_KEY", None)
                else:
                    os.environ["FERNET_KEY"] = original_key

            self.assertEqual(output_path.read_text(encoding="utf-8"), plaintext)
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)

    def test_main_requires_key(self):
        original_argv = sys.argv
        original_key = os.environ.pop("FERNET_KEY", None)
        sys.argv = ["decrypt.py", "unused.enc"]
        try:
            with self.assertRaisesRegex(RuntimeError, "FERNET_KEY"):
                decrypt.main()
        finally:
            sys.argv = original_argv
            if original_key is not None:
                os.environ["FERNET_KEY"] = original_key

    def test_cli_reports_wrong_key_without_traceback(self):
        correct_key = Fernet.generate_key()
        wrong_key = Fernet.generate_key()

        with tempfile.TemporaryDirectory() as tmp:
            encrypted_path = Path(tmp) / "scan.enc"
            encrypted_path.write_bytes(Fernet(correct_key).encrypt(b"{}"))

            original_argv = sys.argv
            original_key = os.environ.get("FERNET_KEY")
            original_prev = os.environ.pop("FERNET_PREVIOUS_KEYS", None)
            sys.argv = ["decrypt.py", str(encrypted_path)]
            os.environ["FERNET_KEY"] = wrong_key.decode()
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(stderr):
                    exit_code = decrypt.cli()
            finally:
                sys.argv = original_argv
                if original_key is None:
                    os.environ.pop("FERNET_KEY", None)
                else:
                    os.environ["FERNET_KEY"] = original_key
                if original_prev is None:
                    os.environ.pop("FERNET_PREVIOUS_KEYS", None)
                else:
                    os.environ["FERNET_PREVIOUS_KEYS"] = original_prev

            self.assertEqual(exit_code, 1)
            self.assertIn("wrong FERNET_KEY", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_decrypts_with_previous_key(self):
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()
        plaintext = '{"rotated": true}\n'

        with tempfile.TemporaryDirectory() as tmp:
            encrypted_path = Path(tmp) / "legacy.enc"
            encrypted_path.write_bytes(Fernet(old_key).encrypt(plaintext.encode()))

            original_argv = sys.argv
            original_key = os.environ.get("FERNET_KEY")
            original_prev = os.environ.get("FERNET_PREVIOUS_KEYS")
            sys.argv = ["decrypt.py", str(encrypted_path)]
            os.environ["FERNET_KEY"] = new_key.decode()
            os.environ["FERNET_PREVIOUS_KEYS"] = old_key.decode()
            stdout = io.StringIO()
            try:
                with contextlib.redirect_stdout(stdout):
                    exit_code = decrypt.cli()
            finally:
                sys.argv = original_argv
                if original_key is None:
                    os.environ.pop("FERNET_KEY", None)
                else:
                    os.environ["FERNET_KEY"] = original_key
                if original_prev is None:
                    os.environ.pop("FERNET_PREVIOUS_KEYS", None)
                else:
                    os.environ["FERNET_PREVIOUS_KEYS"] = original_prev

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue().rstrip("\n"), plaintext.rstrip("\n"))
