#!/usr/bin/env python3
"""Checks that every upstream core endpoint is either mounted or deferred with a reason.

Reads docs/parity/ENDPOINTS.md (the measured inventory) and docs/parity/DEFERRED.md
(the reasons). Exits 1 when a missing endpoint has no reason, when a deferred
endpoint is now mounted or unknown upstream, or when a reason is empty.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENDPOINTS = ROOT / "docs" / "parity" / "ENDPOINTS.md"
DEFERRED = ROOT / "docs" / "parity" / "DEFERRED.md"

ROW = re.compile(r"^\| ([^|]+?) \| (GET|POST|PUT|PATCH|DELETE) \| `([^`]+)` \| (mounted|missing|declared only) \|$")
DEFERRED_ROW = re.compile(r"^\| ([^|]+?) \| (GET|POST|PUT|PATCH|DELETE) \| `([^`]+)` \| (.+?) \|$")


def inventory():
    rows = {}
    for line in ENDPOINTS.read_text(encoding="utf8").splitlines():
        match = ROW.match(line)
        if match:
            plugin, method, path, status = match.groups()
            rows[(method, path)] = (plugin.strip(), status)
    return rows


def deferred():
    reasons = {}
    for line in DEFERRED.read_text(encoding="utf8").splitlines():
        match = DEFERRED_ROW.match(line)
        if match and match.group(1).strip() != "Plugin":
            plugin, method, path, reason = match.groups()
            reasons[(method, path)] = reason.strip()
    return reasons


def main():
    rows = inventory()
    reasons = deferred()
    problems = []
    for key, (plugin, status) in sorted(rows.items()):
        if status == "missing" and key not in reasons:
            problems.append(f"missing and not deferred: {key[0]} {key[1]} ({plugin})")
    for key, reason in sorted(reasons.items()):
        if not reason:
            problems.append(f"empty reason: {key[0]} {key[1]}")
        if key not in rows:
            problems.append(f"deferred but not in the upstream inventory: {key[0]} {key[1]}")
        elif rows[key][1] != "missing":
            problems.append(f"deferred but now {rows[key][1]}: {key[0]} {key[1]}; remove it from DEFERRED.md")
    if problems:
        print("\n".join(problems))
        print(f"{len(problems)} problem(s)")
        return 1
    mounted = sum(1 for _, status in rows.values() if status == "mounted")
    print(f"ok: {mounted} mounted, {len(reasons)} deferred with reasons, {len(rows)} upstream endpoints")
    return 0


if __name__ == "__main__":
    sys.exit(main())
