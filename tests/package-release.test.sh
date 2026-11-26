#!/usr/bin/env bash
# Exercise package layout with a synthetic publish payload, or use --reproducibility
# to compare real packages built under different source paths.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [[ ${1:-} == --reproducibility && $# -le 2 ]]; then
    format=${2:-tar}
    case "$format" in
        tar|deb|rpm|arch) ;;
        *) echo 'Reproducibility format must be tar, deb, rpm, or arch' >&2; exit 2 ;;
    esac
    if [[ "$format" == arch ]]; then
        # makepkg includes the build directory in .BUILDINFO. Use the same
        # path for both builds while varying the source and staging paths.
        export NERGAL_ARCH_BUILD_DIRECTORY=${NERGAL_ARCH_BUILD_DIRECTORY:-"$tmp/arch-build"}
    fi
    commit=$(git -C "$repo" rev-parse HEAD)
    export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo" show -s --format=%ct "$commit")}
    mkdir "$tmp/build-inputs"
    cp "$repo/scripts/package-release.sh" "$repo/scripts/collect-nuget-notices.py" \
        "$repo/scripts/normalize-static-asset-endpoints.py" "$repo/deploy/LinuxRelease.targets" "$tmp/build-inputs/"
    cp -R "$repo/scripts/nuget-license-texts" "$tmp/build-inputs/"
    for build in first 'second checkout'; do
        checkout="$tmp/$build"
        git clone --quiet --no-local --no-checkout "$repo" "$checkout"
        git -C "$checkout" -c advice.detachedHead=false checkout --quiet "$commit"
        # Test the packaging script under review against the exact tracked build inputs.
        cp "$tmp/build-inputs/package-release.sh" "$tmp/build-inputs/collect-nuget-notices.py" \
            "$tmp/build-inputs/normalize-static-asset-endpoints.py" "$checkout/scripts/"
        cp -R "$tmp/build-inputs/nuget-license-texts" "$checkout/scripts/"
        cp "$tmp/build-inputs/LinuxRelease.targets" "$checkout/deploy/"
        (
            cd "$checkout"
            dotnet restore Nergal.slnx --locked-mode
            bash scripts/package-release.sh --format "$format" --verify --output-dir "$tmp/$build.packages"
        )
    done
    while read -r _ filename; do
        first="$tmp/first.packages/$filename"
        second="$tmp/second checkout.packages/$filename"
        if ! cmp -s "$first" "$second"; then
            printf 'Package bytes differ: %s\n' "$filename" >&2
            if [[ "$filename" == *.tar.gz ]]; then
                python3 -B - "$first" "$second" <<'PY'
import hashlib
import sys
import tarfile


def members(path):
    with tarfile.open(path, "r:gz") as archive:
        return {
            item.name: (item.mode, item.uid, item.gid, item.mtime, item.type,
                        item.linkname, item.pax_headers,
                        hashlib.file_digest(archive.extractfile(item), "sha256").hexdigest()
                        if item.isfile() else None)
            for item in archive
        }


first, second = (members(path) for path in sys.argv[1:])
for name in sorted(first.keys() | second.keys()):
    if first.get(name) != second.get(name):
        print(f"Archive member differs: {name}", file=sys.stderr)
        print(f"  first:  {first.get(name)}", file=sys.stderr)
        print(f"  second: {second.get(name)}", file=sys.stderr)
PY
            fi
            exit 1
        fi
    done < "$tmp/first.packages/SHA256SUMS"
    cmp "$tmp/first.packages/SHA256SUMS" "$tmp/second checkout.packages/SHA256SUMS"
    cat "$tmp/first.packages/SHA256SUMS"
    printf 'PASS: %s output is byte-identical across independent source paths\n' "$format"
    exit 0
fi
if (($#)); then
    echo 'Usage: package-release.test.sh [--reproducibility [tar|deb|rpm|arch]]' >&2
    exit 2
fi

command -v dpkg-deb >/dev/null || { echo 'SKIP: dpkg-deb unavailable' >&2; exit 0; }
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
    */Nergal.Web.csproj)
        touch "$out/Nergal.Web.dll"
        chmod 0666 "$out/Nergal.Web.dll"
        cat > "$out/Nergal.Web.staticwebassets.endpoints.json" <<'JSON'
{
  "Version": 1,
  "Endpoints": [
    {
      "Route": "editor.js",
      "AssetFile": "editor.js.gz",
      "Selectors": [{"Name": "Content-Encoding", "Value": "gzip", "Quality": "0.02"}],
      "ResponseHeaders": [{"Name": "Content-Encoding", "Value": "gzip"}, {"Value": "Tue, 01 Jan 2030 00:00:00 GMT", "Name": "Last-Modified"}]
    },
    {
      "Route": "editor.js",
      "AssetFile": "editor.js",
      "Selectors": [],
      "ResponseHeaders": [{"Name": "Last-Modified", "Value": "Tue, 01 Jan 2030 00:00:00 GMT"}]
    }
  ]
}
JSON
        ;;
    */Nergal.Admin.csproj) touch "$out/nergal-admin.dll" ;;
    *) exit 3 ;;
esac
EOF
chmod +x "$tmp/bin/dotnet"
(umask 000; SOURCE_DATE_EPOCH=0 PATH="$tmp/bin:$PATH" "$repo/scripts/package-release.sh" --format deb --verify --output-dir "$tmp/out")
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
test -s "$tmp/extracted/usr/share/licenses/nergal/THIRD-PARTY-NOTICES.txt"
python3 -B - "$tmp/extracted/opt/nergal/web/Nergal.Web.staticwebassets.endpoints.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
identity, gzip = manifest["Endpoints"]
assert identity["AssetFile"] == "editor.js" and identity["Selectors"] == []
assert gzip["AssetFile"] == "editor.js.gz"
assert gzip["Selectors"] == [{"Name": "Content-Encoding", "Value": "gzip", "Quality": "0.02"}]
assert gzip["ResponseHeaders"][0] == {"Name": "Content-Encoding", "Value": "gzip"}
for endpoint in (identity, gzip):
    assert endpoint["ResponseHeaders"][-1]["Value"] == "Thu, 01 Jan 1970 00:00:00 GMT"
PY
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
