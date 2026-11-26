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
    cp "$repo/scripts/package-release.sh" "$repo/scripts/collect-nuget-notices.py" "$repo/deploy/LinuxRelease.targets" "$tmp/build-inputs/"
    cp -R "$repo/scripts/nuget-license-texts" "$tmp/build-inputs/"
    for build in first 'second checkout'; do
        checkout="$tmp/$build"
        git clone --quiet --no-local --no-checkout "$repo" "$checkout"
        git -C "$checkout" -c advice.detachedHead=false checkout --quiet "$commit"
        # Test the packaging script under review against the exact tracked build inputs.
        cp "$tmp/build-inputs/package-release.sh" "$tmp/build-inputs/collect-nuget-notices.py" "$checkout/scripts/"
        cp -R "$tmp/build-inputs/nuget-license-texts" "$checkout/scripts/"
        cp "$tmp/build-inputs/LinuxRelease.targets" "$checkout/deploy/"
        (
            cd "$checkout"
            dotnet restore Nergal.slnx --locked-mode
            bash scripts/package-release.sh --format "$format" --verify --output-dir "$tmp/$build.packages"
        )
    done
    cmp "$tmp/first.packages/SHA256SUMS" "$tmp/second checkout.packages/SHA256SUMS"
    while read -r _ filename; do
        cmp "$tmp/first.packages/$filename" "$tmp/second checkout.packages/$filename"
    done < "$tmp/first.packages/SHA256SUMS"
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
test -s "$tmp/extracted/usr/share/licenses/nergal/THIRD-PARTY-NOTICES.txt"
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
