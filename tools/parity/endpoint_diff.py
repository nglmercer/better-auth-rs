#!/usr/bin/env python3
"""Compares upstream Better Auth endpoints with the routes this crate mounts.

Usage:
    endpoint_diff.py UPSTREAM_DIST_DIR [--router PATH] [--plugins-dir PATH]

UPSTREAM_DIST_DIR is the `dist/` directory of an installed `better-auth` package
at the pinned version. The files are read as text and never executed.

Statuses:
    mounted   the router dispatches this method and path
    declared  a Rust plugin declares it, but no handler is mounted
    missing   neither exists
"""

import argparse
import collections
import os
import re
import sys

ROUTE_RE = re.compile(r'\(Method::(GET|POST|PUT|PATCH|DELETE), "([^"]+)"\)')
PREFIX_RE = re.compile(r'\(Method::(GET|POST), path\) if path\.starts_with\("([^"]+)"\)')
DECLARED_RE = re.compile(r'(?:endpoint\(|Endpoint::new\()\s*Method::(GET|POST|PUT|PATCH|DELETE),\s*"([^"]+)"')
DECLARED_SHORT_RE = re.compile(r'endpoint\(\s*Method::(GET|POST|PUT|PATCH|DELETE),\s*"([^"]+)"')
UPSTREAM_RE = re.compile(r'createAuthEndpoint\(\s*"([^"]+)"\s*,\s*\{')
METHOD_RE = re.compile(r'method:\s*(\[[^\]]*\]|"[A-Z]+")')


def upstream_endpoints(dist):
    found = {}
    for root, _, files in os.walk(dist):
        for name in files:
            if not name.endswith((".mjs", ".js", ".cjs")):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf8", errors="ignore") as handle:
                text = handle.read()
            parts = os.path.relpath(path, dist).split(os.sep)
            plugin = parts[1] if parts[0] == "plugins" and len(parts) > 2 else "core"
            for match in UPSTREAM_RE.finditer(text):
                window = text[match.end(): match.end() + 1500]
                method_match = METHOD_RE.search(window)
                methods = ["?"]
                if method_match:
                    raw = method_match.group(1).strip("[]")
                    methods = [m.strip().strip('"') for m in raw.split(",") if m.strip()]
                for method in methods:
                    key = (method, match.group(1))
                    found.setdefault(key, plugin)
    return found


def rust_routes(router_text, plugin_texts):
    mounted = set()
    for method, path in ROUTE_RE.findall(router_text):
        mounted.add((method, path))
    prefixes = [(method, prefix) for method, prefix in PREFIX_RE.findall(router_text)]
    declared = set()
    for text in plugin_texts:
        for method, path in DECLARED_RE.findall(text) + DECLARED_SHORT_RE.findall(text):
            declared.add((method, path))
    return mounted, prefixes, declared


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dist")
    parser.add_argument("--router", default="crates/better-auth/src/router.rs")
    parser.add_argument("--plugins-dir", default="crates/better-auth/src/plugins")
    args = parser.parse_args()

    with open(args.router, encoding="utf8") as handle:
        router_text = handle.read()
    plugin_texts = []
    for root, _, files in os.walk(args.plugins_dir):
        for name in files:
            if name.endswith(".rs"):
                with open(os.path.join(root, name), encoding="utf8") as handle:
                    plugin_texts.append(handle.read())
    mounted, prefixes, declared = rust_routes(router_text, plugin_texts)
    upstream = upstream_endpoints(args.dist)

    def status(method, path):
        if (method, path) in mounted:
            return "mounted"
        if any(method == m and path.startswith(p) for m, p in prefixes):
            return "mounted"
        if (method, path) in declared:
            return "declared"
        return "missing"

    counts = collections.Counter()
    rows = []
    for (method, path), plugin in sorted(upstream.items(), key=lambda item: (item[1], item[0][1], item[0][0])):
        state = status(method, path)
        counts[state] += 1
        rows.append((plugin, method, path, state))

    print("# Upstream endpoint diff")
    print()
    print(f"Upstream endpoints: {len(upstream)}. Mounted: {counts['mounted']}. "
          f"Declared only: {counts['declared']}. Missing: {counts['missing']}.")
    print()
    print("| Plugin | Method | Path | Status |")
    print("|---|---|---|---|")
    for plugin, method, path, state in rows:
        print(f"| {plugin} | {method} | `{path}` | {state} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
