from __future__ import annotations

import random
import re

SQL_ERROR_PATTERNS = [
    # MySQL / MariaDB
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s*mysql_", re.IGNORECASE),
    re.compile(r"valid mysql result", re.IGNORECASE),
    re.compile(r"mySqlClient\.", re.IGNORECASE),
    re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),
    # PostgreSQL
    re.compile(r"postgresql.*error", re.IGNORECASE),
    re.compile(r"warning:\s*pg_", re.IGNORECASE),
    re.compile(r"valid postgresql result", re.IGNORECASE),
    re.compile(r"Npgsql\.", re.IGNORECASE),
    re.compile(r"org\.postgresql\.", re.IGNORECASE),
    # SQLite
    re.compile(r"sqlite3::", re.IGNORECASE),
    re.compile(r"sqlite_error", re.IGNORECASE),
    re.compile(r"unrecognized token:", re.IGNORECASE),
    # Generic SQL errors / Joomla database driver
    re.compile(r"JDatabaseDriver.*error", re.IGNORECASE),
    re.compile(r"joomla\.database\.", re.IGNORECASE),
    re.compile(r"syntax error.*SQL statement", re.IGNORECASE),
]


def generate_php_math_payload() -> tuple[str, str]:
    """
    Generates a secure, benign PHP execution payload where the expected result
    is computed at runtime by PHP and NEVER appears literally in the uploaded file.
    Returns: (payload_code, expected_result_str)
    """
    n1 = random.randint(10000, 99999)
    n2 = random.randint(10000, 99999)
    expected = str(n1 * n2)
    payload = (
        "// proofcms authorized audit proof. Delete after testing.\n"
        f"<?php $a={n1};$b={n2};echo 'JVH_MATH_'.($a*$b).'_END'; ?>"
    )
    return payload, expected


def verify_php_execution(body: str, expected_product: str) -> tuple[bool, bool]:
    """
    Verifies execution proof in HTTP response body.
    Returns: (is_executed, is_source_leaked).
    - If raw PHP tags (<?php, <?=, <?) remain, execution is strictly rejected.
    - If the dynamic calculation marker is found and matches expected_product, execution is confirmed.
    """
    if not body:
        return False, False

    # Check for unparsed/leaked PHP source code
    has_php_source = bool(re.search(r"<\?(?:php|=|\s)", body, re.IGNORECASE))
    if has_php_source:
        return False, True

    # Search for calculated token
    match = re.search(r"JVH_MATH_(\d+)_END", body)
    if match and match.group(1) == str(expected_product):
        return True, False

    return False, False


def find_sql_errors(body: str) -> list[str]:
    """Returns any matched SQL error strings found in the given response body."""
    matches = []
    if not body:
        return matches
    for pattern in SQL_ERROR_PATTERNS:
        m = pattern.search(body)
        if m:
            matches.append(m.group(0))
    return matches
