#!/usr/bin/env bash
# Real same-UID agent control regression; separate-UID authorization remains a different fixture.
set -euo pipefail
cd "$(dirname "$0")/../../.."
unshare --user --map-root-user --net python3 -B tests/integration/enrollment/bundle_control_check.py \
    "$(realpath src/Nergal.Agent/bin/Release/net10.0/nergal-agent.dll)" \
    "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
