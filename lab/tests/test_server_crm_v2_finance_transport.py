# -*- coding: utf-8 -*-
"""Static transport surface for server-authoritative finance endpoints."""
import os
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class FinanceTransportSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "host", "public", "index.php"),
                  "r", encoding="utf-8") as handle:
            cls.index = handle.read()
        with open(os.path.join(ROOT, "cloud_sync", "client.py"),
                  "r", encoding="utf-8") as handle:
            cls.client = handle.read()

    def test_append_and_void_routes_are_explicit(self):
        self.assertIn("'/finance/transactions/append' => ['POST']", self.index)
        self.assertIn("'/finance/transactions/void' => ['POST']", self.index)
        self.assertIn("$finance->append($body, $context, $requestId)", self.index)
        self.assertIn("$finance->void($body, $context, $requestId)", self.index)

    def test_client_has_distinct_finance_methods(self):
        self.assertIn("def append_ledger_transaction", self.client)
        self.assertIn("def void_ledger_transaction", self.client)
        self.assertIn('route = "/finance/transactions/void"', self.client)
        self.assertIn('"transaction_id": transaction_id', self.client)
        self.assertIn('"reason": reason.strip()', self.client)


if __name__ == "__main__":
    unittest.main()
