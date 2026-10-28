#!/usr/bin/env python3
"""Write a deterministic SPDX 2.3 inventory from a Go binary's build info."""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path
from urllib.parse import quote


def build_info(binary):
    output = subprocess.run(
        ["go", "version", "-m", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    go_version = ""
    modules = {}
    previous = None
    for line in output.splitlines():
        fields = line.strip().split()
        if len(fields) == 2 and fields[0] == "go":
            go_version = fields[1]
        elif len(fields) >= 3 and fields[0] == "dep":
            path, version = fields[1:3]
            checksum = fields[3] if len(fields) > 3 else ""
            modules[path] = {"path": path, "version": version, "checksum": checksum}
            previous = path
        elif len(fields) >= 3 and fields[0] == "=>" and previous:
            path, version = fields[1:3]
            checksum = fields[3] if len(fields) > 3 else ""
            modules.pop(previous, None)
            modules[path] = {"path": path, "version": version, "checksum": checksum}
            previous = None
    return go_version, sorted(modules.values(), key=lambda item: item["path"])


def spdx_id(prefix, value):
    digest = hashlib.sha256(value.encode()).hexdigest()[:20].upper()
    return f"SPDXRef-{prefix}-{digest}"


def module_package(module):
    path = module["path"]
    version = module["version"]
    purl = f"pkg:golang/{quote(path, safe='/.-_~')}@{quote(version, safe='.-_~+') }"
    package = {
        "name": path,
        "SPDXID": spdx_id("MODULE", purl),
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "LIBRARY",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        }],
    }
    if module["checksum"]:
        package["sourceInfo"] = f"Go module authentication checksum: {module['checksum']}"
    return package


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    go_version, modules = build_info(Path(args.binary))
    app_id = "SPDXRef-MITNICK"
    packages = [{
        "name": "Mitnick",
        "SPDXID": app_id,
        "versionInfo": args.version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "comment": f"Binary target: {args.target}; Go build: {go_version}",
    }]
    packages.extend(module_package(module) for module in modules)
    relationships = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": app_id,
    }]
    relationships.extend({
        "spdxElementId": app_id,
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": package["SPDXID"],
    } for package in packages[1:])

    created = datetime.datetime.fromtimestamp(
        int(os.environ.get("SOURCE_DATE_EPOCH", "0")), datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    identity = json.dumps(
        {"version": args.version, "target": args.target, "packages": packages},
        sort_keys=True,
        separators=(",", ":"),
    )
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "urn:mitnick:spdx:" + hashlib.sha256(identity.encode()).hexdigest())
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"Mitnick {args.version} {args.target}",
        "documentNamespace": f"urn:uuid:{namespace}",
        "documentDescribes": [app_id],
        "creationInfo": {
            "creators": [f"Tool: Mitnick SPDX generator {args.version}"],
            "created": created,
        },
        "packages": packages,
        "relationships": relationships,
    }
    destination = Path(args.output)
    destination.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
