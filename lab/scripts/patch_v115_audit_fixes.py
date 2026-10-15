#!/usr/bin/env python3
"""Apply audited v1.15 fixes for config kill-switch parsing and DB-independent ranges."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def patch_config() -> None:
    path = ROOT / "host" / "src" / "Config.php"
    old = r'''    public static function freshBoolean(string $key, bool $default = false): bool
    {
        $file = self::$path !== '' ? self::$path : self::locate();
        $source = @file_get_contents($file);
        if (!is_string($source) || $source === '') {
            return $default;
        }
        $quoted = preg_quote($key, '/');
        $pattern = '/[\'\"]' . $quoted . '[\'\"]\s*=>\s*(true|false)\b/i';
        $matched = preg_match($pattern, $source, $match);
        if ($matched !== 1 || !isset($match[1])) {
            return $default;
        }
        return strtolower((string) $match[1]) === 'true';
    }
'''
    new = r'''    public static function freshBoolean(string $key, bool $default = false): bool
    {
        $file = self::$path !== '' ? self::$path : self::locate();
        $source = @file_get_contents($file);
        if (!is_string($source) || $source === '') {
            return $default;
        }

        // Parse PHP tokens rather than raw text. A commented-out "true" must
        // never enable a security kill switch, and duplicate assignments are
        // ambiguous, so they fail closed to the caller-supplied default.
        $tokens = token_get_all($source);
        $values = [];
        $count = count($tokens);
        $singleQuoted = "'" . $key . "'";
        $doubleQuoted = '"' . $key . '"';
        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING
                || ($token[1] !== $singleQuoted && $token[1] !== $doubleQuoted)) {
                continue;
            }

            $j = $i + 1;
            while ($j < $count && is_array($tokens[$j])
                && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                $j++;
            }
            if ($j >= $count || !is_array($tokens[$j])
                || $tokens[$j][0] !== T_DOUBLE_ARROW) {
                continue;
            }
            $j++;
            while ($j < $count && is_array($tokens[$j])
                && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                $j++;
            }
            if ($j >= $count || !is_array($tokens[$j]) || $tokens[$j][0] !== T_STRING) {
                continue;
            }
            $literal = strtolower((string) $tokens[$j][1]);
            if ($literal === 'true' || $literal === 'false') {
                $values[] = $literal === 'true';
            }
        }
        return count($values) === 1 ? $values[0] : $default;
    }
'''
    replace_once(path, old, new, "Config::freshBoolean")


def patch_schema() -> None:
    path = ROOT / "host" / "src" / "Schema.php"
    replace_once(
        path,
        "    public const E_EMPTY_REFERENCE = 'EMPTY_REFERENCE';\n",
        "    public const E_EMPTY_REFERENCE = 'EMPTY_REFERENCE';\n"
        "    public const E_OUT_OF_RANGE    = 'OUT_OF_RANGE';\n",
        "range error code",
    )
    replace_once(
        path,
        "                    'watch_interval_hours'      => ['sql' => 'int', 'type' => 'int',\n"
        "                                                    'nullable' => false, 'default' => 2],\n",
        "                    'watch_interval_hours'      => ['sql' => 'int', 'type' => 'int',\n"
        "                                                    'nullable' => false, 'default' => 2,\n"
        "                                                    'min' => 1, 'max' => 72],\n",
        "watch interval range",
    )
    replace_once(
        path,
        "                if ($check['enum'] !== null && !in_array($value, $check['enum'], true)) {\n"
        "                    return [self::failure(self::E_ENUM_MISMATCH, $table, $column)];\n"
        "                }\n"
        "                return [];\n\n"
        "            case 'datetime':\n",
        "                if ($check['enum'] !== null && !in_array($value, $check['enum'], true)) {\n"
        "                    return [self::failure(self::E_ENUM_MISMATCH, $table, $column)];\n"
        "                }\n"
        "                if (($check['min'] !== null && $value < $check['min'])\n"
        "                    || ($check['max'] !== null && $value > $check['max'])) {\n"
        "                    return [self::failure(self::E_OUT_OF_RANGE, $table, $column)];\n"
        "                }\n"
        "                return [];\n\n"
        "            case 'datetime':\n",
        "integer range validation",
    )
    replace_once(
        path,
        "            'enum' => null, 'format' => null, 'ref' => null, 'auto' => false,\n",
        "            'enum' => null, 'format' => null, 'ref' => null, 'auto' => false,\n"
        "            'min' => null, 'max' => null,\n",
        "range defaults",
    )


def main() -> None:
    patch_config()
    patch_schema()
    print("v1.15 audited production fixes applied")


if __name__ == "__main__":
    main()
