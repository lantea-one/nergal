#!/usr/bin/env bash
# Each case receives fresh user/network namespaces, synthetic interfaces and private state.
set -euo pipefail
cd "$(dirname "$0")/../../.."
[[ $# -le 1 ]] || { printf 'Usage: %s [--agent]\n' "$0" >&2; exit 2; }
case ${1:-} in
    '') cases=(native) ;;
    --agent) cases=(lifecycle explicit-drift timeout-recreated missing-table foreign-collision unknown-expression nat-set-drift bridge-set-drift) ;;
    *) printf 'Usage: %s [--agent]\n' "$0" >&2; exit 2 ;;
esac
for scenario in "${cases[@]}"; do
    unshare --user --map-root-user --net python3 -B tests/integration/enrollment/auxiliary_apply_check.py \
        "$(realpath src/Nergal.Agent/bin/Release/net10.0/nergal-agent.dll)" \
        "$(realpath tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)" \
        "$scenario" "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
done
