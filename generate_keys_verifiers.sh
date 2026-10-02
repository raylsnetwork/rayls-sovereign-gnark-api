#!/bin/bash
#
# DEVELOPMENT ONLY: generates keys and verifiers with a single-party
# groth16.Setup. Whoever runs it can forge proofs with the result, so never
# deploy it. Production keys come from ./ceremony.sh
# (docs/trusted-setup-ceremony.md).
#
# Refuses to run while the ceremony has a release, since that would overwrite
# the release's keys in last_build/. --force overrides this for local
# experiments; restore the release afterwards with `git checkout -- last_build`.
#
# SKIP_KEYGEN=1 only converts the verifiers (same as ./convert_verifiers.sh).

set -e
cd "$(dirname "$0")"

force=""
case "${1:-}" in
    --force) force="-force" ;;
    "") ;;
    *) echo "Usage: $0 [--force]" >&2; exit 1 ;;
esac

if [ -z "${SKIP_KEYGEN:-}" ]; then
    go run ./cmd/setup/setup_keys_verifiers $force
fi
exec ./convert_verifiers.sh
