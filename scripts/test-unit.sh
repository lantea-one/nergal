#!/usr/bin/env bash
# Collect coverage in a private writable runtime directory, including rootless CI.
# Check the report as well as the test exit code: VSTest can pass while failing
# to save its artifacts if the inherited XDG_RUNTIME_DIR is missing/read-only.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p artifacts/test-results
result_directory=$(mktemp -d "$PWD/artifacts/test-results/run.XXXXXXXX")
export XDG_RUNTIME_DIR="$result_directory/runtime"
mkdir -m 700 "$XDG_RUNTIME_DIR"
trap 'rmdir "$XDG_RUNTIME_DIR" 2>/dev/null || true' EXIT

# A single MSBuild node avoids cross-invocation worker pipe collisions in isolated runners.
dotnet test Nergal.sln --configuration Release --no-build --no-restore -m:1 -nr:false \
    --collect:"XPlat Code Coverage" --results-directory "$result_directory"
mapfile -t test_projects < <(find tests -name '*.Tests.csproj' -type f)
mapfile -t reports < <(find "$result_directory" -name coverage.cobertura.xml -type f)
if [[ ${#test_projects[@]} -eq 0 || ${#reports[@]} -ne ${#test_projects[@]} ]]; then
    printf 'Coverage collection failed: expected %s reports, found %s.\n' "${#test_projects[@]}" "${#reports[@]}" >&2
    exit 1
fi
for report in "${reports[@]}"; do
    if ! grep -Eq 'lines-covered="[1-9][0-9]*"' "$report"; then
        printf 'Coverage collection failed: no executed lines in %s.\n' "$report" >&2
        exit 1
    fi
    printf 'Coverage report: %s\n' "$report"
done
