#!/usr/bin/env bash
# Assemble reproducible Linux release archives (.tar.gz, .deb when dpkg-deb is present, and SHA256SUMS).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERIFY=0
OUT_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verify) VERIFY=1; shift ;;
        --output-dir) OUT_DIR="$2"; shift 2 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

VERSION=$(sed -n 's:.*<Version>\([^<]*\)</Version>.*:\1:p' Directory.Build.props | head -n 1)
if [[ -z "$VERSION" ]]; then
    printf 'Could not read <Version> from Directory.Build.props\n' >&2
    exit 1
fi

if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="artifacts/packages/${VERSION}"
fi
mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

ROOT="$STAGE/root"
mkdir -p \
    "$ROOT/opt/nergal/agent" \
    "$ROOT/opt/nergal/web" \
    "$ROOT/opt/nergal/admin" \
    "$ROOT/usr/local/sbin" \
    "$ROOT/etc/systemd/system" \
    "$ROOT/usr/lib/sysusers.d" \
    "$ROOT/usr/lib/tmpfiles.d"

dotnet publish src/Nergal.Agent/Nergal.Agent.csproj --configuration Release --no-restore --output "$ROOT/opt/nergal/agent" >/dev/null
dotnet publish src/Nergal.Web/Nergal.Web.csproj --configuration Release --no-restore --output "$ROOT/opt/nergal/web" >/dev/null
dotnet publish src/Nergal.Admin/Nergal.Admin.csproj --configuration Release --no-restore --output "$ROOT/opt/nergal/admin" >/dev/null

cat > "$ROOT/usr/local/sbin/nergal-agent" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/dotnet /opt/nergal/agent/nergal-agent.dll "$@"
EOF
chmod 0755 "$ROOT/usr/local/sbin/nergal-agent"

cat > "$ROOT/usr/local/sbin/nergal-admin" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/dotnet /opt/nergal/admin/nergal-admin.dll "$@"
EOF
chmod 0755 "$ROOT/usr/local/sbin/nergal-admin"

install -m 0644 deploy/systemd/nergal-agent.service "$ROOT/etc/systemd/system/nergal-agent.service"
install -m 0644 deploy/systemd/nergal-web.service "$ROOT/etc/systemd/system/nergal-web.service"
install -m 0644 deploy/systemd/nergal.sysusers "$ROOT/usr/lib/sysusers.d/nergal.conf"
install -m 0644 deploy/systemd/nergal.tmpfiles "$ROOT/usr/lib/tmpfiles.d/nergal.conf"

TAR_NAME="nergal_${VERSION}_linux-x64.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner -czf "$OUT_DIR/$TAR_NAME" -C "$ROOT" .

DEB_NAME="nergal_${VERSION}_amd64.deb"
BUILT_DEB=0
if command -v dpkg-deb >/dev/null 2>&1; then
    DEB_STAGE="$STAGE/deb"
    cp -a "$ROOT" "$DEB_STAGE"
    mkdir -p "$DEB_STAGE/DEBIAN"
    cat > "$DEB_STAGE/DEBIAN/control" <<EOF
Package: nergal
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: nergal maintainers <noreply@lantea.one>
Depends: nftables
Description: Self-hosted native nftables firewall controller and privileged host agent
 nergal separates an unprivileged ASP.NET Core MVC/Blazor controller from a
 privileged nftables host agent with explicit table ownership, atomic
 candidate validation, and independent local timed rollback.
EOF
    cat > "$DEB_STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if command -v systemd-sysusers >/dev/null 2>&1; then
        systemd-sysusers /usr/lib/sysusers.d/nergal.conf || true
    fi
    if command -v systemd-tmpfiles >/dev/null 2>&1; then
        systemd-tmpfiles --create /usr/lib/tmpfiles.d/nergal.conf || true
    fi
fi
exit 0
EOF
    chmod 0755 "$DEB_STAGE/DEBIAN/postinst"
    dpkg-deb --root-owner-group --build "$DEB_STAGE" "$OUT_DIR/$DEB_NAME" >/dev/null
    BUILT_DEB=1
fi

(
    cd "$OUT_DIR"
    if [[ "$BUILT_DEB" -eq 1 ]]; then
        sha256sum "$TAR_NAME" "$DEB_NAME" > SHA256SUMS
    else
        sha256sum "$TAR_NAME" > SHA256SUMS
    fi
)

if [[ "$VERIFY" -eq 1 ]]; then
    (cd "$OUT_DIR" && sha256sum -c SHA256SUMS >/dev/null)
    TAR_LIST=$(tar -tzf "$OUT_DIR/$TAR_NAME")
    for expected in \
        "./opt/nergal/agent/nergal-agent.dll" \
        "./opt/nergal/web/Nergal.Web.dll" \
        "./opt/nergal/admin/nergal-admin.dll" \
        "./usr/local/sbin/nergal-agent" \
        "./usr/local/sbin/nergal-admin" \
        "./etc/systemd/system/nergal-agent.service" \
        "./etc/systemd/system/nergal-web.service" \
        "./usr/lib/sysusers.d/nergal.conf" \
        "./usr/lib/tmpfiles.d/nergal.conf"; do
        grep -qxF "$expected" <<< "$TAR_LIST" || {
            printf 'Missing expected entry in tarball: %s\n' "$expected" >&2
            exit 1
        }
    done
    if [[ "$BUILT_DEB" -eq 1 ]]; then
        DEB_INFO=$(dpkg-deb --info "$OUT_DIR/$DEB_NAME")
        DEB_LIST=$(dpkg-deb --contents "$OUT_DIR/$DEB_NAME")
        grep -q "Version: ${VERSION}" <<< "$DEB_INFO"
        grep -q "./opt/nergal/agent/nergal-agent.dll" <<< "$DEB_LIST"
        grep -q "./usr/lib/sysusers.d/nergal.conf" <<< "$DEB_LIST"
    fi
fi

printf 'PACKAGED version=%s dir=%s deb=%s\n' "$VERSION" "$OUT_DIR" "$BUILT_DEB"
