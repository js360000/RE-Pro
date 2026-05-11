from __future__ import annotations

import unittest

from re_pro.pe_resources import _build_ico_from_group
from tests import _path_setup  # noqa: F401


class PEResourceTests(unittest.TestCase):
    def test_build_ico_from_group_reconstructs_valid_ico(self) -> None:
        png_payload = b"\x89PNG\r\n\x1a\n" + b"x" * 16
        group = bytearray()
        group.extend((0).to_bytes(2, "little"))
        group.extend((1).to_bytes(2, "little"))
        group.extend((1).to_bytes(2, "little"))
        group.extend(bytes([16, 16, 0, 0]))
        group.extend((1).to_bytes(2, "little"))
        group.extend((32).to_bytes(2, "little"))
        group.extend(len(png_payload).to_bytes(4, "little"))
        group.extend((7).to_bytes(2, "little"))

        ico = _build_ico_from_group(bytes(group), 1033, {("ID_7", 1033): png_payload}, {})

        self.assertIsNotNone(ico)
        assert ico is not None
        self.assertEqual(ico[:4], b"\x00\x00\x01\x00")
        self.assertIn(png_payload, ico)


if __name__ == "__main__":
    unittest.main()
