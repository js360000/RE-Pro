from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _path_setup  # noqa: F401

from re_pro.symbol_acquisition import acquire_pdbs_from_symbol_servers


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class SymbolAcquisitionTests(unittest.TestCase):
    def test_acquire_pdbs_from_symbol_servers_downloads_matching_pdb(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            records = [
                {
                    "format": "RSDS",
                    "pdb_path": r"C:\build\sample.pdb",
                    "guid": "12345678-1234-ABCD-9876-001122334455",
                    "age": 1,
                }
            ]
            captured_urls: list[str] = []

            def fake_urlopen(request, timeout=0):
                captured_urls.append(request.full_url)
                return _FakeResponse(b"Microsoft C/C++ MSF 7.00\r\n")

            with patch("re_pro.symbol_acquisition.urlopen", side_effect=fake_urlopen):
                downloads = acquire_pdbs_from_symbol_servers(records, root, symbol_servers=["https://symbols.example.test"])

            self.assertEqual(len(downloads), 1)
            self.assertTrue((root / "sample.pdb").exists())
            self.assertIn("sample.pdb/123456781234ABCD98760011223344551/sample.pdb", captured_urls[0])


if __name__ == "__main__":
    unittest.main()
