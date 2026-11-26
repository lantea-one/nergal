#!/bin/sh
# Build and load a timestamp-normalized controller image with Docker Buildx.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}
case "$epoch" in
    ''|*[!0-9]*) echo 'SOURCE_DATE_EPOCH must be a non-negative integer' >&2; exit 2 ;;
esac
exec docker buildx build \
    --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    --output=type=docker,rewrite-timestamp=true \
    --provenance=false \
    --file "$root/deploy/container/Dockerfile" \
    --tag "${NERGAL_IMAGE:-nergal-controller:local}" \
    "$@" "$root"
