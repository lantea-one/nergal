#!/usr/bin/env bash
# Attach verified files to the stable Forgejo release that triggered the job.
set -euo pipefail

[[ "$#" -gt 0 ]]
[[ "${AUR_RELEASE_ID:?Missing release ID}" =~ ^[1-9][0-9]*$ ]]
[[ "${AUR_RELEASE_TAG:?Missing release tag}" =~ ^v?[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]+)?$ ]]
: "${RELEASE_TOKEN:?Missing Forgejo token}"
url="${GITHUB_API_URL:?Missing Forgejo API URL}/repos/${GITHUB_REPOSITORY:?Missing repository}/releases/$AUR_RELEASE_ID"
headers=(--header "Authorization: token $RELEASE_TOKEN")

files=()
for file in "$@"; do
    test -s "$file"
    name=${file##*/}
    case "$name" in
        "nergal_${AUR_RELEASE_TAG#v}_linux-x64.tar.gz"|SHA256SUMS|nergal-aur-recipes.zip) files+=("$name") ;;
        *) printf 'Unexpected release asset %s\n' "$name" >&2; exit 1 ;;
    esac
done

release=$(curl --fail-with-body --silent --show-error "${headers[@]}" "$url")
existing=$(python3 -c '
from collections import Counter
import json
import sys

tag, *names = sys.argv[1:]
release = json.load(sys.stdin)
if release["tag_name"] != tag or release["draft"] or release["prerelease"]:
    sys.exit(f"Release changed or is no longer stable: {tag}")
counts = Counter(asset["name"] for asset in release["assets"])
for name in names:
    if counts[name] > 1:
        sys.exit(f"Release {tag} has duplicate attachments named {name}")
    if counts[name] == 1:
        print(name)
' "$AUR_RELEASE_TAG" "${files[@]}" <<< "$release")

declare -A attached=()
while IFS= read -r name; do
    if [[ -n "$name" ]]; then
        attached["$name"]=1
    fi
done <<< "$existing"

if (( ${#attached[@]} == $# )); then
    printf 'Requested files are already attached to %s\n' "$AUR_RELEASE_TAG"
    exit 0
fi

# Resume an interrupted upload only if every already-published file matches
# this build. Publish no new file until the whole partial set has been checked.
for file in "$@"; do
    name=${file##*/}
    if [[ -v attached["$name"] ]]; then
        download="${GITHUB_SERVER_URL:?Missing Forgejo server URL}/$GITHUB_REPOSITORY/releases/download/$AUR_RELEASE_TAG/$name"
        if ! curl --fail --silent --show-error --location "$download" | cmp -s -- "$file" -; then
            printf 'Existing asset %s differs from this build or could not be downloaded\n' "$name" >&2
            exit 1
        fi
    fi
done

for file in "$@"; do
    name=${file##*/}
    if [[ ! -v attached["$name"] ]]; then
        curl --fail-with-body --silent --show-error "${headers[@]}" \
            --form "attachment=@$file" "$url/assets?name=$name" >/dev/null
        printf 'Attached %s to %s\n' "$name" "$AUR_RELEASE_TAG"
    fi
done
