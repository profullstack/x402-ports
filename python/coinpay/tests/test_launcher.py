import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import coinpay  # noqa: E402


class Launcher(unittest.TestCase):
    def test_env_bin_wins(self):
        with mock.patch.dict(os.environ, {"COINPAY_BIN": "/opt/coinpay"}):
            self.assertEqual(coinpay.command(["x402", "pay", "u"]), ["/opt/coinpay", "x402", "pay", "u"])

    def test_npx_with_pinned_version(self):
        with mock.patch.dict(os.environ, {"COINPAY_VERSION": "0.8.0"}, clear=True), mock.patch("shutil.which", lambda n: "/usr/bin/npx" if n == "npx" else None):
            self.assertEqual(coinpay.command(["--help"]), ["npx", "--yes", "@profullstack/coinpay@0.8.0", "--help"])

    def test_nothing_found(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", lambda n: None):
            self.assertIsNone(coinpay.command([]))
            self.assertEqual(coinpay.main([]), 127)


if __name__ == "__main__":
    unittest.main()
