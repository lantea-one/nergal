#!/usr/bin/env bash
# Build the Linux release payload and requested package formats.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERIFY=0
ALLOW_MISSING=0
FORMAT=all
OUT_DIR=""
while (($#)); do
    case "$1" in
        --verify) VERIFY=1; shift ;;
        --allow-missing-tools) ALLOW_MISSING=1; shift ;;
        --output-dir) (($# >= 2)) || { echo '--output-dir requires a value' >&2; exit 2; }; OUT_DIR=$2; shift 2 ;;
        --format) (($# >= 2)) || { echo '--format requires a value' >&2; exit 2; }; FORMAT=$2; shift 2 ;;
        -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
case "$FORMAT" in all|tar|deb|rpm|arch) ;; *) echo 'Format must be all, tar, deb, rpm, or arch' >&2; exit 2 ;; esac

VERSION=$(sed -n 's:.*<Version>\([^<]*\)</Version>.*:\1:p' Directory.Build.props | head -n 1)
[[ -n "$VERSION" ]] || { echo 'Could not read <Version> from Directory.Build.props' >&2; exit 1; }
[[ "$VERSION" =~ ^[A-Za-z0-9.+:~_-]+$ ]] || { echo 'Version contains unsupported package characters' >&2; exit 1; }
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || { echo 'SOURCE_DATE_EPOCH must be a non-negative integer' >&2; exit 2; }
export SOURCE_DATE_EPOCH
[[ -n "$OUT_DIR" ]] || OUT_DIR="artifacts/packages/${VERSION}"
mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/root"
mkdir -p "$ROOT/opt/nergal/agent" "$ROOT/opt/nergal/web" "$ROOT/opt/nergal/admin" \
    "$ROOT/usr/bin" "$ROOT/usr/lib/systemd/system" "$ROOT/usr/lib/sysusers.d" "$ROOT/usr/lib/tmpfiles.d"

# Keep framework-dependent binaries on the pinned .NET 10 target. Runtime packages
# declare the shared runtime; no network-dependent package scripts are used.
dotnet publish src/Nergal.Agent/Nergal.Agent.csproj -c Release --no-restore -o "$ROOT/opt/nergal/agent" >/dev/null
dotnet publish src/Nergal.Web/Nergal.Web.csproj -c Release --no-restore -o "$ROOT/opt/nergal/web" >/dev/null
dotnet publish src/Nergal.Admin/Nergal.Admin.csproj -c Release --no-restore -o "$ROOT/opt/nergal/admin" >/dev/null
for app in agent admin; do
    cat > "$ROOT/usr/bin/nergal-$app" <<EOF
#!/bin/sh
exec /usr/bin/dotnet /opt/nergal/$app/nergal-$app.dll "\$@"
EOF
    chmod 0755 "$ROOT/usr/bin/nergal-$app"
done
install -m 0644 deploy/systemd/nergal-agent.service "$ROOT/usr/lib/systemd/system/nergal-agent.service"
install -m 0644 deploy/systemd/nergal-web.service "$ROOT/usr/lib/systemd/system/nergal-web.service"
install -m 0644 deploy/systemd/nergal.sysusers "$ROOT/usr/lib/sysusers.d/nergal.conf"
install -m 0644 deploy/systemd/nergal.tmpfiles "$ROOT/usr/lib/tmpfiles.d/nergal.conf"
install -D -m 0755 deploy/systemd/nergal-local-agent "$ROOT/usr/lib/nergal/nergal-local-agent"
install -m 0644 deploy/systemd/nergal-agent-enroll.service "$ROOT/usr/lib/systemd/system/nergal-agent-enroll.service"
install -D -m 0644 LICENSE "$ROOT/usr/share/licenses/nergal/LICENSE"
web_endpoints="$ROOT/opt/nergal/web/Nergal.Web.staticwebassets.endpoints.json"
if [[ -f "$web_endpoints" ]]; then
    modified=$(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" '+%a, %d %b %Y %T GMT')
    sed -i "s/\"Name\":\"Last-Modified\",\"Value\":\"[^\"]*\"/\"Name\":\"Last-Modified\",\"Value\":\"$modified\"/g" "$web_endpoints"
fi
find "$ROOT" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner \
    -czf "$OUT_DIR/nergal_${VERSION}_linux-x64.tar.gz" -C "$ROOT" .

need_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        if ((ALLOW_MISSING)); then printf 'SKIPPED format=%s missing-tool=%s\n' "$2" "$1" >&2; return 1; fi
        printf 'Cannot build %s package: required tool %s is unavailable (use --format for a different format or --allow-missing-tools)\n' "$2" "$1" >&2
        exit 1
    fi
}

BUILT=()
if [[ "$FORMAT" == all || "$FORMAT" == deb ]]; then
    if need_tool dpkg-deb deb; then
        p="$STAGE/deb"; cp -a "$ROOT" "$p"; mkdir -p "$p/DEBIAN"
        cat > "$p/DEBIAN/control" <<EOF
Package: nergal
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: nergal maintainers <noreply@lantea.one>
Depends: dotnet-runtime-10.0, aspnetcore-runtime-10.0, nftables, systemd
Description: Self-hosted native nftables firewall controller and host agent
 Nergal separates its unprivileged ASP.NET Core controller from the privileged
 host agent. Package installation does not enable or start either service.
EOF
        cat > "$p/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    systemd-sysusers /usr/lib/sysusers.d/nergal.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/nergal.conf
fi
exit 0
EOF
        chmod 0755 "$p/DEBIAN/postinst"
        dpkg-deb --root-owner-group --build "$p" "$OUT_DIR/nergal_${VERSION}_amd64.deb" >/dev/null
        BUILT+=("nergal_${VERSION}_amd64.deb")
    fi
fi

if [[ "$FORMAT" == all || "$FORMAT" == rpm ]]; then
    if need_tool rpmbuild rpm; then
        mkdir -p "$STAGE/rpm"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
        cat > "$STAGE/rpm/SPECS/nergal.spec" <<EOF
%global debug_package %{nil}
%global __os_install_post %{nil}
Name: nergal
Version: ${VERSION}
Release: 1
Summary: Self-hosted native nftables firewall controller and host agent
License: MIT
BuildArch: x86_64
AutoReqProv: no
Requires: dotnet-runtime-10.0
Requires: aspnetcore-runtime-10.0
Requires: nftables
Requires: systemd
%description
Nergal firewall controller and host agent. Installation does not enable or start services.
%install
mkdir -p %{buildroot}
cp -a "$ROOT/." %{buildroot}/
%post
systemd-sysusers /usr/lib/sysusers.d/nergal.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/nergal.conf
%files
/opt/nergal
/usr/bin/nergal-agent
/usr/bin/nergal-admin
/usr/lib/nergal
/usr/lib/systemd/system/nergal-agent.service
/usr/lib/systemd/system/nergal-agent-enroll.service
/usr/lib/systemd/system/nergal-web.service
/usr/lib/sysusers.d/nergal.conf
/usr/lib/tmpfiles.d/nergal.conf
%license /usr/share/licenses/nergal/LICENSE
EOF
        rpmbuild --define "_topdir $STAGE/rpm" -bb "$STAGE/rpm/SPECS/nergal.spec" >/dev/null
        cp "$STAGE/rpm/RPMS/x86_64/nergal-${VERSION}-1.x86_64.rpm" "$OUT_DIR/"
        BUILT+=("nergal-${VERSION}-1.x86_64.rpm")
    fi
fi

if [[ "$FORMAT" == all || "$FORMAT" == arch ]]; then
    if need_tool makepkg arch; then
        p="$STAGE/arch"; mkdir -p "$p"
        cp "$OUT_DIR/nergal_${VERSION}_linux-x64.tar.gz" "$p/payload.tar.gz"
        payload_hash=$(sha256sum "$p/payload.tar.gz" | cut -d' ' -f1)
        cat > "$p/PKGBUILD" <<EOF
pkgname=nergal
pkgver=$VERSION
pkgrel=1
pkgdesc='Self-hosted native nftables firewall controller and host agent'
arch=('x86_64')
url='https://git.lantea.one/lantea-one/nergal'
license=('MIT')
options=('!strip' '!debug')
depends=('dotnet-runtime-10.0' 'aspnet-runtime-10.0' 'nftables' 'systemd')
source=('payload.tar.gz')
sha256sums=('${payload_hash}')
package() { tar --no-same-owner -xzf "\$srcdir/payload.tar.gz" -C "\$pkgdir"; }
EOF
        if (( EUID == 0 )); then
            : "${NERGAL_PACKAGE_USER:?Set NERGAL_PACKAGE_USER to an unprivileged Arch package builder}"
            [[ $(id -u "$NERGAL_PACKAGE_USER") != 0 ]] || { echo 'Arch package builder must be unprivileged' >&2; exit 1; }
            chmod o+x "$STAGE"
            chown -R "$NERGAL_PACKAGE_USER" "$p"
            (cd "$p" && runuser -u "$NERGAL_PACKAGE_USER" -- makepkg --nodeps --noconfirm)
        else
            (cd "$p" && makepkg --nodeps --noconfirm)
        fi
        pkg=$(find "$p" -maxdepth 1 -name 'nergal-*.pkg.tar.*' -print -quit)
        [[ -n "$pkg" ]] || { echo 'makepkg did not produce an Arch package' >&2; exit 1; }
        cp "$pkg" "$OUT_DIR/"
        BUILT+=("$(basename "$pkg")")
    fi
fi

(cd "$OUT_DIR" && sha256sum "nergal_${VERSION}_linux-x64.tar.gz" "${BUILT[@]}" > SHA256SUMS)

if ((VERIFY)); then
    (cd "$OUT_DIR" && sha256sum -c SHA256SUMS)
    archive_contents=$(tar -tzf "$OUT_DIR/nergal_${VERSION}_linux-x64.tar.gz")
    grep -qx './usr/lib/systemd/system/nergal-agent-enroll.service' <<< "$archive_contents"
    grep -qx './usr/lib/nergal/nergal-local-agent' <<< "$archive_contents"
    for f in "${BUILT[@]}"; do
        case "$f" in
            *.deb)
                deps=$(dpkg-deb --field "$OUT_DIR/$f" Depends)
                contents=$(dpkg-deb --contents "$OUT_DIR/$f")
                grep -q 'aspnetcore-runtime-10.0' <<< "$deps"
                grep -q '/usr/lib/systemd/system/nergal-agent.service' <<< "$contents"
                ;;
            *.rpm)
                deps=$(rpm -qp --requires "$OUT_DIR/$f")
                grep -qx 'aspnetcore-runtime-10.0' <<< "$deps"
                ;;
            *.pkg.tar.*)
                metadata=$(tar -xOf "$OUT_DIR/$f" .PKGINFO)
                grep -qx 'depend = aspnet-runtime-10.0' <<< "$metadata"
                ;;
        esac
    done
fi
printf 'PACKAGED version=%s dir=%s formats=%s\n' "$VERSION" "$OUT_DIR" "${BUILT[*]:-tar}"
