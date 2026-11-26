#!/usr/bin/env python3
"""Normalize the published static asset manifest for reproducible releases."""

import json
import sys
from email.utils import formatdate
from pathlib import Path


manifest_path = Path(sys.argv[1])
last_modified = formatdate(int(sys.argv[2]), usegmt=True)
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

# Endpoint routing uses the route and encoding metadata, including server quality.
# The SDK can emit the same identity and compressed representations in different
# orders. Keep each descriptor's metadata intact when ordering the endpoints.
manifest["Endpoints"].sort(key=lambda endpoint: (endpoint["Route"], endpoint["AssetFile"]))
for endpoint in manifest["Endpoints"]:
    for header in endpoint["ResponseHeaders"]:
        if header["Name"] == "Last-Modified":
            header["Value"] = last_modified

manifest_path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
