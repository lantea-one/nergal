#!/usr/bin/env bash
# Rebuild the unprivileged UI sandbox, preserving its private disposable state.
set -euo pipefail
cd "$(dirname "$0")/../.."
# Serialize manual and watched refreshes of this disposable stack.
mkdir -p artifacts/dev-stack
exec 9>artifacts/dev-stack/build.lock
flock 9
export MSBUILDDISABLENODEREUSE=1
export NERGAL_DEV_UID=$(id -u) NERGAL_DEV_GID=$(id -g)
dotnet restore Nergal.slnx --locked-mode
# A persistent compiler server would inherit descriptor 9 and retain this lock.
dotnet build Nergal.slnx -c Release --no-restore -m:2 -nr:false -p:UseSharedCompilation=false
dotnet publish src/Nergal.Web -c Release --no-build --no-restore -o artifacts/dev-stack/web
dotnet publish src/Nergal.Admin -c Release --no-build --no-restore -o artifacts/dev-stack/admin
# This disposable stack owns its private database. Stop its writer before the explicit offline upgrade.
if docker container inspect nergal-dev-web-1 >/dev/null 2>&1; then docker stop nergal-dev-web-1 >/dev/null; fi
python3 tools/dev-stack/provision.py "$@"
export BUILDX_CONFIG="$PWD/artifacts/dev-stack/buildx"
mkdir -p "$BUILDX_CONFIG"
if find artifacts/dev-stack/sources -name '*.conf' -print -quit | read -r _; then
    docker build -f tools/dev-stack/Validator.Dockerfile -t nergal-source-validator:local tools/dev-stack
fi
docker compose -p nergal-dev -f tools/dev-stack/compose.yaml -f artifacts/dev-stack/sources.compose.yaml up -d --no-build --force-recreate
curl --fail --silent --show-error --cacert artifacts/dev-stack/private/tls.crt --retry 15 --retry-all-errors --retry-delay 1 https://127.0.0.1:5443/healthz
printf '\nLocal sandbox: https://127.0.0.1:5443/manage\nCredentials: artifacts/dev-stack/private/access.txt\n'
