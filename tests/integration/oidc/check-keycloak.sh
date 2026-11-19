#!/usr/bin/env bash
# Only launch a fresh, digest-checked upstream distribution in new namespaces.
set -euo pipefail
[[ $# == 1 ]] || { echo "Supply the Keycloak 26.8.2 release tar.gz" >&2; exit 2; }
archive=$(realpath "$1")
cd "$(dirname "$0")/../../.."
unshare --user --map-root-user --net python3 -B tests/integration/oidc/keycloak.py "$archive" \
    "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
