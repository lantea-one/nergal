#!/usr/bin/env bash
# Exercise package layout/metadata with a synthetic publish payload and real dpkg-deb.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
command -v dpkg-deb >/dev/null || { echo 'SKIP: dpkg-deb unavailable' >&2; exit 0; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/dotnet" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=''
project=''
while (($#)); do
    case "$1" in
        --output|-o) out=$2; shift 2 ;;
        *.csproj) project=$1; shift ;;
        *) shift ;;
    esac
done
mkdir -p "$out"
case "$project" in
    */Nergal.Agent.csproj) touch "$out/nergal-agent.dll" ;;
    */Nergal.Web.csproj) touch "$out/Nergal.Web.dll"; chmod 0666 "$out/Nergal.Web.dll" ;;
    */Nergal.Admin.csproj) touch "$out/nergal-admin.dll" ;;
    *) exit 3 ;;
esac
EOF
chmod +x "$tmp/bin/dotnet"
(umask 000; PATH="$tmp/bin:$PATH" "$repo/scripts/package-release.sh" --format deb --verify --output-dir "$tmp/out")
version=$(sed -n 's:.*<Version>\([^<]*\)</Version>.*:\1:p' "$repo/Directory.Build.props" | head -n 1)
deb="$tmp/out/nergal_${version}_amd64.deb"
test -f "$deb"
depends=$(dpkg-deb --field "$deb" Depends)
for dep in dotnet-runtime-10.0 aspnetcore-runtime-10.0 nftables systemd; do
    [[ ", ${depends}, " == *", $dep, "* ]]
done
contents=$(dpkg-deb --contents "$deb")
grep -q '/usr/lib/systemd/system/nergal-agent.service' <<< "$contents"
grep -q '/usr/lib/systemd/system/nergal-agent-reconcile.service' <<< "$contents"
grep -q '/usr/bin/nergal-agent' <<< "$contents"
dpkg-deb --extract "$deb" "$tmp/extracted"
[[ $(stat -c '%a' "$tmp/extracted/opt/nergal/web") == 755 ]]
[[ $(stat -c '%a' "$tmp/extracted/opt/nergal/web/Nergal.Web.dll") == 644 ]]
web_unit=$(dpkg-deb --fsys-tarfile "$deb" | tar -xOf - ./usr/lib/systemd/system/nergal-web.service)
grep -Fxq 'Environment=ASPNETCORE_WEBROOT=/opt/nergal/web/wwwroot' <<< "$web_unit"
postinst=$(dpkg-deb --ctrl-tarfile "$deb" | tar -xOf - ./postinst)
if grep -Eq 'systemctl|deb-systemd-invoke' <<< "$postinst"; then
    echo 'Debian postinst must leave service activation to the operator' >&2
    exit 1
fi
grep -q 'systemd-sysusers' <<< "$postinst"
(cd "$tmp/out" && sha256sum -c SHA256SUMS)
PATH="$tmp/bin:$PATH" "$repo/scripts/package-release.sh" --format tar --verify --output-dir "$tmp/tar"
echo 'PASS: synthetic Debian package layout, dependencies, offline setup, and checksums'
