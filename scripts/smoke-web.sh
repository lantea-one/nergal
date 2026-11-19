#!/usr/bin/env bash
# Exercise the real, unprivileged development host. Never contact a firewall agent.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts
dotnet publish src/Nergal.Web --configuration Release --no-build --no-restore \
  --output "$PWD/artifacts/web" >/dev/null
dotnet artifacts/web/Nergal.Web.dll --contentRoot "$PWD/artifacts/web" \
  --urls http://127.0.0.1:5191 >artifacts/web-smoke.log 2>&1 &
app_pid=$!
trap 'kill "$app_pid" 2>/dev/null || true; wait "$app_pid" 2>/dev/null || true' EXIT
curl --fail --silent --show-error --retry 20 --retry-delay 1 --retry-connrefused \
  http://127.0.0.1:5191/healthz >/dev/null
curl --fail --silent http://127.0.0.1:5191/ | grep -q '<h1>nergal</h1>'
curl --fail --silent http://127.0.0.1:5191/backend-decision | grep -q 'Native nftables first'
curl --fail --silent http://127.0.0.1:5191/_framework/blazor.web.js >artifacts/blazor.web.js
[[ -s artifacts/blazor.web.js ]]
write_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -X POST http://127.0.0.1:5191/api/policies/apply)
case "$write_status" in 404|405) ;; *) exit 1 ;; esac
for path in login session logout; do
    [[ $(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:5191/$path") == 404 ]]
done
printf 'MVC, Blazor, health and absence of a firewall-write endpoint passed.\n'
