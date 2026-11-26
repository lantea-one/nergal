#!/bin/sh
# Build and load a timestamp-normalized role image with Docker Buildx.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
case "${NERGAL_COMPONENT:-controller}" in
    controller) dockerfile=Dockerfile; default_image=nergal-controller:local ;;
    agent) dockerfile=agent.Dockerfile; default_image=nergal-agent:local ;;
    *) echo 'NERGAL_COMPONENT must be controller or agent' >&2; exit 2 ;;
esac
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}
case "$epoch" in
    ''|*[!0-9]*) echo 'SOURCE_DATE_EPOCH must be a non-negative integer' >&2; exit 2 ;;
esac
exec docker buildx build \
    --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    --output=type=docker,rewrite-timestamp=true \
    --provenance=false \
    --file "$root/deploy/container/$dockerfile" \
    --tag "${NERGAL_IMAGE:-$default_image}" \
    "$@" "$root"
