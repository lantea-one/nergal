#!/usr/bin/env bash
# Attach one verified AUR bundle to the stable release that triggered the job.
set -euo pipefail

bundle=${1:?Supply the verified AUR recipe archive}
name=nergal-aur-recipes.zip
test -s "$bundle"
[[ "${AUR_RELEASE_ID:?Missing release ID}" =~ ^[1-9][0-9]*$ ]]
: "${AUR_RELEASE_TAG:?Missing release tag}" "${RELEASE_TOKEN:?Missing Forgejo token}"
url="${GITHUB_API_URL:?Missing Forgejo API URL}/repos/${GITHUB_REPOSITORY:?Missing repository}/releases/$AUR_RELEASE_ID"
headers=(--header "Authorization: token $RELEASE_TOKEN")

release=$(curl --fail-with-body --silent --show-error "${headers[@]}" "$url")
existing=$(python3 -c '
import json
import sys

tag, name = sys.argv[1:]
release = json.load(sys.stdin)
if release["tag_name"] != tag or release["draft"] or release["prerelease"]:
    sys.exit(f"Release changed or is no longer stable: {tag}")
print(sum(asset["name"] == name for asset in release["assets"]))
' "$AUR_RELEASE_TAG" "$name" <<< "$release")
case "$existing" in
    0) ;;
    1) printf 'AUR recipe archive is already attached to %s\n' "$AUR_RELEASE_TAG"; exit 0 ;;
    *) printf 'Release %s has duplicate AUR recipe archives\n' "$AUR_RELEASE_TAG" >&2; exit 1 ;;
esac

curl --fail-with-body --silent --show-error "${headers[@]}" \
    --form "attachment=@$bundle;type=application/zip" "$url/assets?name=$name" >/dev/null
printf 'Attached AUR recipe archive to %s\n' "$AUR_RELEASE_TAG"
