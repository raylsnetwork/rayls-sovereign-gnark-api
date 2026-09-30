#!/usr/bin/env bash
# ceremony.sh - run the perpetual Groth16 trusted-setup ceremony from this
# repository.
#
# Phase 1 is imported from the public Perpetual Powers of Tau. Phase 2 never
# closes: anyone can contribute at any time, and each contribution leads to a
# new release of keys once the public beacon it announced is published. Every
# step is a git commit under ceremony/, signed with the contributor's SSH key.
# See README.md ("Trusted-Setup Ceremony") and docs/trusted-setup-ceremony.md.
#
# Run ./ceremony.sh help for the commands.
set -euo pipefail

# drand quicknet: a public randomness beacon publishing a round every 3 seconds.
DRAND_CHAIN="52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
DRAND_API="${DRAND_API:-https://api.drand.sh}"
# Perpetual Powers of Tau (PSE), 80 contributions, cut to 2^17.
PTAU_URL="${PTAU_URL:-https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_17.ptau}"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/rayls-ceremony"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
NAME_RE='^[a-z0-9][a-z0-9-]{0,39}$'

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

# CEREMONY_DEMO=1 rehearses the flow with two tiny circuits and an insecure
# local phase 1 in ceremony-demo/, leaving ceremony/ and last_build/ untouched.
if [ "${CEREMONY_DEMO:-}" = "1" ]; then
    DEMO=1
    DIR="ceremony-demo"
    OUT="ceremony-demo/last_build"
    DEFAULT_DELAY=1
else
    DEMO=0
    DIR="ceremony"
    OUT="last_build"
    DEFAULT_DELAY=30
fi

TOOL_DIR=""
cleanup() {
    if [ -n "$TOOL_DIR" ]; then rm -rf "$TOOL_DIR"; fi
}
trap cleanup EXIT

die()  { echo "ceremony.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

usage() {
    cat <<EOF
Usage: ./ceremony.sh <command> [options]

  register   --name NAME [--key PUBKEY] [--push]
             Register your SSH public key (once per institution or user).

  contribute --name NAME [--key PUBKEY] [--note TEXT] [--beacon-delay MIN]
             [--skip-verify] [--push]
             Verify the transcript, add your phase 2 contribution, announce a
             drand round MIN minutes ahead (default $DEFAULT_DELAY) for the next
             release, write an attestation and make a signed commit.

  finalize   [--wait] [--key PUBKEY] [--push]
             Once the announced drand round is published, release new keys
             into $OUT/ (--wait waits for it). Anyone can run this.

  verify     [--no-ptau]
             Check everything: phase 1 against the powers-of-tau file, every
             contribution, signatures, attestations, every release's drand
             beacon, and that $OUT/ matches the latest release.

  status     Show phase 1, every contribution and every release.

  init       [--ptau FILE] [--key PUBKEY]
             Start the ceremony (once, for the repository): import phase 1
             from the Perpetual Powers of Tau (downloaded and cached).

  round-at   "YYYY-MM-DD HH:MM UTC"
             The drand round published at (or just after) a time.

Environment:
  CEREMONY_DEMO=1   rehearse with tiny circuits in ceremony-demo/ (keys are useless)
  PTAU_URL          powers-of-tau file to import (default: PPoT 0080, 2^17)
  DEFAULT_BRANCH    branch contributions are based on (default: main)

PUBKEY defaults to the first of ~/.ssh/id_ed25519.pub, id_ecdsa.pub, id_rsa.pub.
EOF
}

# --- tool -----------------------------------------------------------------

# build_tool compiles cmd/ceremony once, in the main shell, so that calls from
# subshells ($(...) and pipelines) reuse it.
build_tool() {
    TOOL_DIR="$(mktemp -d)"
    step "building the ceremony tool at $(git rev-parse --short HEAD)"
    go build -o "$TOOL_DIR/ceremony" ./cmd/ceremony || die "could not build cmd/ceremony"
}

tool() {
    [ -n "$TOOL_DIR" ] || die "internal error: the ceremony tool is not built"
    "$TOOL_DIR/ceremony" "$@"
}

# info KEY prints one value from the tool's machine-readable state.
info() {
    tool info --dir "$DIR" 2>/dev/null | sed -n "s/^$1=//p"
}

require_ceremony() {
    [ -f "$DIR/manifest.json" ] || die "no ceremony in $DIR/ yet (start it with ./ceremony.sh init)"
}

# fetch_ptau prints the path of the cached powers-of-tau file, downloading it
# on first use.
fetch_ptau() {
    local file="$CACHE_DIR/$(basename "$PTAU_URL")"
    if [ ! -f "$file" ]; then
        mkdir -p "$CACHE_DIR"
        step "downloading $(basename "$PTAU_URL") (about 150 MB, once) to $CACHE_DIR"
        curl -fSL --retry 3 -o "$file.part" "$PTAU_URL" || die "could not download $PTAU_URL"
        mv "$file.part" "$file"
    fi
    echo "$file"
}

# --- keys and signing -----------------------------------------------------

default_key() {
    for k in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_ecdsa.pub" "$HOME/.ssh/id_rsa.pub"; do
        [ -f "$k" ] && { echo "$k"; return; }
    done
}

# key_body prints "type base64" of a public key, dropping the comment.
key_body() { awk '{print $1, $2}' "$1"; }

require_key() {
    [ -n "$KEY" ] && [ -f "$KEY" ] || die "SSH public key not found; pass --key ~/.ssh/<key>.pub"
}

# signing_key prints what git should sign with: the public key when ssh-agent
# holds it, otherwise the private key file next to it.
signing_key() {
    if [ -n "${SSH_AUTH_SOCK:-}" ] && ssh-add -L 2>/dev/null | grep -qF "$(key_body "$KEY")"; then
        echo "$KEY"
    elif [ -f "${KEY%.pub}" ]; then
        echo "${KEY%.pub}"
    else
        die "the private key for $KEY is neither in ssh-agent nor at ${KEY%.pub}"
    fi
}

# commit_signed MESSAGE PATH... stages the paths and makes an SSH-signed commit
# containing only them.
commit_signed() {
    local msg="$1"; shift
    git add -- "$@"
    if git diff --cached --quiet -- "$@"; then
        die "nothing to commit in $*"
    fi
    git -c gpg.format=ssh -c user.signingkey="$(signing_key)" commit -S -q -m "$msg" -- "$@" \
        || die "signed commit failed (is the private key for $KEY available?)"
    step "committed: $msg"
}

# regenerate_allowed_signers rebuilds the git allowed-signers file from the
# registered public keys; the principal is the contributor name.
regenerate_allowed_signers() {
    local out="$DIR/contributors/allowed_signers" f
    : > "$out"
    for f in "$DIR"/contributors/*.pub; do
        [ -e "$f" ] || continue
        echo "$(basename "$f" .pub) namespaces=\"git\" $(key_body "$f")" >> "$out"
    done
}

# --- git helpers ----------------------------------------------------------

require_clean_ceremony() {
    [ -z "$(git status --porcelain -- "$DIR")" ] || die "uncommitted changes in $DIR/: commit or discard them first"
}

# require_up_to_date fails if origin/DEFAULT_BRANCH has commits we don't.
require_up_to_date() {
    git remote get-url origin >/dev/null 2>&1 || return 0
    git fetch --quiet origin "$DEFAULT_BRANCH" 2>/dev/null || { step "could not fetch origin/$DEFAULT_BRANCH; continuing with the local copy"; return 0; }
    local behind
    behind="$(git rev-list --count "HEAD..origin/$DEFAULT_BRANCH")"
    [ "$behind" = "0" ] || die "you are $behind commit(s) behind origin/$DEFAULT_BRANCH: pull the latest ceremony state first"
}

# use_branch NAME switches to ceremony/NAME when on the default branch, so the
# commits can go up as a pull request. On any other branch it stays put.
use_branch() {
    local current
    current="$(git branch --show-current)"
    if [ "$current" = "$DEFAULT_BRANCH" ] || [ "$current" = "master" ]; then
        git switch -q -c "ceremony/$1" || die "could not create branch ceremony/$1"
        step "working on branch ceremony/$1"
    fi
}

maybe_push() {
    if [ "$PUSH" = "1" ]; then
        git push -u origin HEAD
        step "pushed $(git branch --show-current); open a pull request into $DEFAULT_BRANCH"
    else
        step "not pushed. When ready: git push -u origin $(git branch --show-current), then open a pull request"
    fi
}

ensure_lfs_rule() {
    local rule="$DIR/**/*.bin filter=lfs diff=lfs merge=lfs -text"
    grep -qxF "$rule" .gitattributes 2>/dev/null || echo "$rule" >> .gitattributes
}

# --- drand ----------------------------------------------------------------

drand_info() {
    curl -sS --max-time 30 "$DRAND_API/$DRAND_CHAIN/info" || die "could not reach drand at $DRAND_API"
}

# round_at_epoch T prints the first round published at or after unix time T.
round_at_epoch() {
    local info period genesis
    info="$(drand_info)"
    period="$(echo "$info" | sed -n 's/.*"period":\([0-9]*\).*/\1/p')"
    genesis="$(echo "$info" | sed -n 's/.*"genesis_time":\([0-9]*\).*/\1/p')"
    [ -n "$period" ] && [ -n "$genesis" ] || die "unexpected drand info: $info"
    # Round r is published at genesis + (r-1)*period.
    echo $(( ($1 - genesis + period - 1) / period + 1 ))
}

# round_time ROUND prints when a round is published, in UTC.
round_time() {
    local info period genesis t
    info="$(drand_info)"
    period="$(echo "$info" | sed -n 's/.*"period":\([0-9]*\).*/\1/p')"
    genesis="$(echo "$info" | sed -n 's/.*"genesis_time":\([0-9]*\).*/\1/p')"
    t=$(( genesis + ($1 - 1) * period ))
    date -u -d "@$t" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -u -r "$t" '+%Y-%m-%d %H:%M:%S UTC'
}

# round_from_source extracts N from "drand quicknet round N".
round_from_source() {
    echo "$1" | sed -n 's/^drand quicknet round \([0-9][0-9]*\)$/\1/p'
}

# drand_try ROUND prints the round's randomness, or returns 1 if it is not
# published yet.
drand_try() {
    local round="$1" body code tmp
    tmp="$(mktemp)"
    code="$(curl -sS --max-time 30 -o "$tmp" -w '%{http_code}' "$DRAND_API/$DRAND_CHAIN/public/$round")" \
        || { rm -f "$tmp"; die "could not reach drand at $DRAND_API"; }
    body="$(cat "$tmp")"; rm -f "$tmp"
    case "$code" in
        200) ;;
        425) return 1 ;;
        *)   die "drand returned HTTP $code for round $round" ;;
    esac
    echo "$body" | grep -q "\"round\":$round," || die "drand answered for a different round than $round"
    echo "$body" | sed -n 's/.*"randomness":"\([0-9a-f]\{64\}\)".*/\1/p'
}

to_epoch() {
    date -u -d "$1" +%s 2>/dev/null \
        || date -u -j -f "%Y-%m-%d %H:%M" "${1% UTC}" +%s 2>/dev/null \
        || die "could not parse date '$1' (use \"YYYY-MM-DD HH:MM UTC\")"
}

# --- commands -------------------------------------------------------------

cmd_round_at() {
    [ $# -eq 1 ] || die 'usage: round-at "YYYY-MM-DD HH:MM UTC"'
    round_at_epoch "$(to_epoch "$1")"
}

cmd_init() {
    local ptau=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --ptau) ptau="$2"; shift 2 ;;
            --key) KEY="$2"; shift 2 ;;
            *) die "init: unknown option $1" ;;
        esac
    done
    [ ! -e "$DIR/manifest.json" ] || die "a ceremony already exists in $DIR/"
    require_key

    if [ "$DEMO" = "1" ] && [ -z "$ptau" ]; then
        step "starting a DEMO ceremony with an insecure local phase 1"
        tool init --dir "$DIR"
    else
        [ -n "$ptau" ] || ptau="$(fetch_ptau)"
        step "starting the ceremony: importing phase 1 from $(basename "$ptau") (compiles every circuit)"
        tool init --dir "$DIR" --ptau "$ptau" --ptau-source "$PTAU_URL"
    fi
    mkdir -p "$DIR/contributors" "$DIR/attestations"
    : > "$DIR/contributors/allowed_signers"
    ensure_lfs_rule
    commit_signed "ceremony: start, phase 1 from $(info phase1_source)" "$DIR" .gitattributes
    step "ceremony started. Next: ./ceremony.sh register --name <you>, then contribute"
}

cmd_register() {
    local name=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --name) name="$2"; shift 2 ;;
            --key) KEY="$2"; shift 2 ;;
            --push) PUSH=1; shift ;;
            *) die "register: unknown option $1" ;;
        esac
    done
    [[ "$name" =~ $NAME_RE ]] || die "--name must be lowercase letters, digits and dashes (e.g. bank-a)"
    require_key
    require_ceremony
    require_clean_ceremony

    local dest="$DIR/contributors/$name.pub"
    if [ -f "$dest" ]; then
        [ "$(key_body "$dest")" = "$(key_body "$KEY")" ] || die "$name is registered with a different key"
        step "$name is already registered with this key"
        return
    fi
    use_branch "register-$name"
    cp "$KEY" "$dest"
    regenerate_allowed_signers
    commit_signed "ceremony: register contributor $name" "$DIR/contributors"
    maybe_push
}

cmd_contribute() {
    local name="" note="" skip_verify=0 delay="$DEFAULT_DELAY"
    while [ $# -gt 0 ]; do
        case "$1" in
            --name) name="$2"; shift 2 ;;
            --key) KEY="$2"; shift 2 ;;
            --note) note="$2"; shift 2 ;;
            --beacon-delay) delay="$2"; shift 2 ;;
            --skip-verify) skip_verify=1; shift ;;
            --push) PUSH=1; shift ;;
            *) die "contribute: unknown option $1" ;;
        esac
    done
    [[ "$name" =~ $NAME_RE ]] || die "--name must be lowercase letters, digits and dashes (e.g. bank-a)"
    [[ "$delay" =~ ^[0-9]+$ ]] && [ "$delay" -ge 1 ] || die "--beacon-delay must be a whole number of minutes"
    require_key
    require_ceremony
    require_clean_ceremony
    require_up_to_date

    local reg="$DIR/contributors/$name.pub"
    [ -f "$reg" ] || die "$name is not registered: run ./ceremony.sh register --name $name first"
    [ "$(key_body "$reg")" = "$(key_body "$KEY")" ] || die "$KEY is not the key registered for $name"

    if [ "$skip_verify" = "0" ]; then
        step "verifying the transcript so far (use --skip-verify only if you just verified it)"
        tool verify --dir "$DIR" >/dev/null
    fi

    local index round
    index="$(info next_index)"
    round="$(round_at_epoch $(( $(date -u +%s) + delay * 60 )))"
    step "contribution #$index; the next release will use drand quicknet round $round ($(round_time "$round"))"
    step "contributing to every circuit. Do not interrupt; this can take a while."
    local hash
    hash="$(tool contribute --dir "$DIR" --name "$name" --beacon-source "drand quicknet round $round" \
        | grep -E '^[0-9a-f]{64}$' | tail -n1)"
    [ -n "$hash" ] || die "the tool did not report a contribution hash"

    # The beacon must still be unknown now that the contribution is fixed.
    if drand_try "$round" >/dev/null; then
        git checkout -q -- "$DIR/manifest.json"
        git clean -fdq -- "$DIR/phase2"
        die "drand round $round was published before the contribution finished; rerun with a larger --beacon-delay"
    fi

    local id attestation
    id="$(printf '%04d-%s' "$index" "$name")"
    attestation="$DIR/attestations/$id.md"
    cat > "$attestation" <<EOF
# Contribution $(printf '%04d' "$index") by $name

- Contribution hash: \`$hash\`
- Date (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')
- Next release beacon: drand quicknet round $round ($(round_time "$round"))
- Repository commit: $(git rev-parse HEAD)
- Tool: $(go version | awk '{print $3}'), $(uname -srm)
- Signing key: $(ssh-keygen -lf "$KEY" | awk '{print $2}')
- Randomness: generated in memory with crypto/rand by \`cmd/ceremony\`, never
  written to disk, and discarded when the process exited.

## Notes

${note:-None.}
EOF

    use_branch "contribution-$id"
    commit_signed "ceremony: contribution $(printf '%04d' "$index") by $name (next release: drand round $round)" "$DIR"
    maybe_push
    cat >&2 <<EOF

==================================================================
 Your contribution hash:

   $hash

 Write it down and publish it. After $(round_time "$round")
 anyone can release keys that include it:

   ./ceremony.sh finalize --wait
==================================================================
EOF
}

cmd_finalize() {
    local wait=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --wait) wait=1; shift ;;
            --key) KEY="$2"; shift 2 ;;
            --push) PUSH=1; shift ;;
            *) die "finalize: unknown option $1" ;;
        esac
    done
    require_key
    require_ceremony
    require_clean_ceremony
    [ "$(info pending)" = "1" ] || die "no contributions since the last release"

    local round value version
    round="$(round_from_source "$(info pending_beacon)")"
    [ -n "$round" ] || die "the announced beacon is not a drand quicknet round"
    while ! value="$(drand_try "$round")"; do
        [ "$wait" = "1" ] || die "drand round $round is published at $(round_time "$round"); try again then, or pass --wait"
        step "waiting for drand round $round ($(round_time "$round"))..."
        sleep 15
    done
    version=$(( $(info latest_release) + 1 ))
    step "releasing v$version with drand quicknet round $round: $value"
    tool finalize --dir "$DIR" --beacon "$value" --out "$OUT"
    if [ "$DEMO" = "0" ]; then
        step "converting the Solidity verifiers"
        SKIP_KEYGEN=1 SKIP_CONTRACTS_COPY=1 ./generate_keys_verifiers.sh >/dev/null
    fi
    tool verify --dir "$DIR" --out "$OUT" >/dev/null
    commit_signed "ceremony: release v$version (contributions 1-$(info contributions), drand round $round)" "$DIR" "$OUT"
    maybe_push
    step "released v$version. Deploy the new verifiers in $OUT/ together with the matching gnark-api build."
}

cmd_verify() {
    local use_ptau=1
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-ptau) use_ptau=0; shift ;;
            *) die "verify: unknown option $1" ;;
        esac
    done
    require_ceremony

    local args=(--dir "$DIR")
    [ "$(info latest_release)" != "0" ] && args+=(--out "$OUT")
    if [ "$use_ptau" = "1" ] && [ "$(info phase1_source)" != "insecure-demo" ]; then
        args+=(--ptau "$(fetch_ptau)")
    fi
    step "replaying the transcript"
    tool verify "${args[@]}"

    step "checking release beacons against drand"
    local version count source value round
    while IFS=$'\t' read -r version count source value; do
        [ -n "$version" ] || continue
        round="$(round_from_source "$source")"
        [ -n "$round" ] || die "release v$version beacon is not a drand quicknet round"
        [ "$(drand_try "$round")" = "$value" ] || die "release v$version beacon does not match drand round $round"
        echo "v$version: drand quicknet round $round matches"
    done < <(tool releases --dir "$DIR" 2>/dev/null | awk -F'\t' 'NF == 4')

    step "checking contribution signatures and attestations"
    local signers="$DIR/contributors/allowed_signers" index name path hash beacon commit att
    while IFS=$'\t' read -r index name path hash beacon; do
        [ -n "$index" ] || continue
        att="$DIR/attestations/$(printf '%04d-%s' "$index" "$name").md"
        [ -f "$att" ] || die "contribution $index by $name has no attestation"
        grep -q "$hash" "$att" || die "attestation for contribution $index does not record hash $hash"
        commit="$(git log --diff-filter=A --format=%H -1 -- "$DIR/$path")"
        if [ -z "$commit" ]; then
            echo "#$index $name: not committed yet"
            continue
        fi
        git -c gpg.ssh.allowedSignersFile="$signers" verify-commit "$commit" 2>&1 \
            | grep -q "Good \"git\" signature for $name with" \
            || die "contribution $index by $name is not signed by $name's registered key (commit $commit)"
        echo "#$index $name: signed by $name, $hash"
    done < <(tool contributions --dir "$DIR" 2>/dev/null | awk -F'\t' 'NF == 5')

    echo "ceremony verifies"
}

# --- main -----------------------------------------------------------------

KEY="$(default_key || true)"
PUSH=0
cmd="${1:-help}"
[ $# -gt 0 ] && shift
case "$cmd" in
    init|register|contribute|finalize|verify|status) build_tool ;;
esac
case "$cmd" in
    round-at)   cmd_round_at "$@" ;;
    init)       cmd_init "$@" ;;
    register)   cmd_register "$@" ;;
    contribute) cmd_contribute "$@" ;;
    finalize)   cmd_finalize "$@" ;;
    verify)     cmd_verify "$@" ;;
    status)     require_ceremony; tool status --dir "$DIR" 2>/dev/null | grep -v '^✓' ;;
    help|-h|--help) usage ;;
    *) usage >&2; exit 1 ;;
esac
