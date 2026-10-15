#!/usr/bin/env python3
"""Phase 7: apply reconciliation coverage and fix deterministic legacy ledger order."""
from __future__ import annotations

from pathlib import Path

import patch_phase7_migration_reconciliation_v2 as reconciliation

ROOT = Path(__file__).resolve().parents[2]
APPLY = ROOT / "host" / "src" / "LegacyApply.php"


def patch_apply_order() -> None:
    text = APPLY.read_text(encoding="utf-8")
    marker = """            foreach ($staged as $row) {\n                $byEntity[(string) $row['entity']][] = $row;\n            }\n\n            /** @var array<string, string> $sourceMap */\n"""
    replacement = """            foreach ($staged as $row) {\n                $byEntity[(string) $row['entity']][] = $row;\n            }\n            // customer_transactions receive a new server sequence while the\n            // customer ledger is locked. Preserve the legacy per-customer\n            // array order before allocating those new sequence numbers; SQL\n            // row order is otherwise undefined and can silently swap entries.\n            if (isset($byEntity['customer_transactions'])) {\n                usort($byEntity['customer_transactions'],\n                    static function (array $left, array $right): int {\n                        $leftRecord = json_decode((string) $left['record_json'], true);\n                        $rightRecord = json_decode((string) $right['record_json'], true);\n                        $leftCustomer = is_array($leftRecord)\n                            && is_string($leftRecord['customer_id'] ?? null)\n                            ? $leftRecord['customer_id'] : '';\n                        $rightCustomer = is_array($rightRecord)\n                            && is_string($rightRecord['customer_id'] ?? null)\n                            ? $rightRecord['customer_id'] : '';\n                        $customerOrder = strcmp($leftCustomer, $rightCustomer);\n                        if ($customerOrder !== 0) {\n                            return $customerOrder;\n                        }\n                        $leftSeq = is_array($leftRecord)\n                            && is_int($leftRecord['seq'] ?? null)\n                            ? $leftRecord['seq'] : PHP_INT_MAX;\n                        $rightSeq = is_array($rightRecord)\n                            && is_int($rightRecord['seq'] ?? null)\n                            ? $rightRecord['seq'] : PHP_INT_MAX;\n                        if ($leftSeq !== $rightSeq) {\n                            return $leftSeq <=> $rightSeq;\n                        }\n                        return strcmp((string) $left['source_key'],\n                            (string) $right['source_key']);\n                    }\n                );\n            }\n\n            /** @var array<string, string> $sourceMap */\n"""
    if text.count(marker) != 1:
        raise RuntimeError("LegacyApply staged grouping anchor drifted")
    APPLY.write_text(text.replace(marker, replacement), encoding="utf-8", newline="\n")


def main() -> None:
    reconciliation.base.main()
    patch_apply_order()
    print("phase7 reconciliation + transaction ordering patch applied")


if __name__ == "__main__":
    main()
