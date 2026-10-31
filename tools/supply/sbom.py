#!/usr/bin/env python3
"""Writes a CycloneDX 1.5 SBOM for the workspace from `cargo metadata`.

Usage:
    cargo metadata --format-version 1 --locked | tools/supply/sbom.py > sbom.cdx.json

Only the resolved dependency graph is read. Components come from crates.io or
path crates in this workspace. Each record carries the license reported by the
package metadata, and a missing license is left out instead of guessed.
"""

import hashlib
import json
import sys
import uuid


def component(package, workspace_ids):
    name = package["name"]
    version = package["version"]
    purl = f"pkg:cargo/{name}@{version}"
    entry = {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
        "scope": "required",
    }
    if package.get("license"):
        entry["licenses"] = [{"expression": package["license"]}]
    if package["id"] in workspace_ids:
        entry["properties"] = [{"name": "cargo:workspace", "value": "true"}]
    elif package.get("source"):
        entry["externalReferences"] = [
            {"type": "distribution", "url": package["source"]}
        ]
    return entry


def main():
    metadata = json.load(sys.stdin)
    workspace_ids = set(metadata["workspace_members"])
    components = [
        component(package, workspace_ids)
        for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"]))
    ]
    seed = json.dumps([c["bom-ref"] for c in components]).encode()
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.UUID(bytes=hashlib.sha256(seed).digest()[:16])}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "better-auth-rs",
                "bom-ref": "better-auth-rs",
            },
            "tools": [{"name": "tools/supply/sbom.py"}],
        },
        "components": components,
    }
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    sys.exit(main())
