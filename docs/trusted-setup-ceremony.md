# Groth16 trusted-setup ceremony

Status: the tooling is built and tested (`cmd/ceremony`, `ceremony.sh`); no
production release has been made yet. The step-by-step guide for institutions
is in the README ("Trusted-Setup Ceremony"). This document explains the design.

## Why we need it

Groth16 needs a setup per circuit. It picks secret random numbers, derives the
proving and verifying keys from them, and must then throw the numbers away.
Anyone who kept them (the "toxic waste") can forge proofs that the verifier
contracts accept, and nothing on chain would reveal it.

Before the first release, the keys in `last_build/` came from a single-party
`groth16.Setup` in `cmd/setup/setup_keys_verifiers`, so whoever ran it could
forge proofs. That program (`./generate_keys_verifiers.sh`) remains for
development only: it refuses to run while `ceremony/manifest.json` has a
release, since it would overwrite the release's keys, unless given `--force`.
Its one `groth16.Setup` call is suppressed for gnark-safety with that reason,
as is the one in `cmd/setup/generate_h_parameter`, which only self-checks the H
point and never persists its keys. `./convert_verifiers.sh`, which both
`ceremony.sh finalize` and the development script run, only rewrites the
Solidity verifiers and never generates keys.

## The two phases

gnark v0.14.0 implements the multi-party Groth16 setup (BGM17) in
`backend/groth16/bn254/mpcsetup`. It has two phases, each with its own secrets:

| | Phase 1 ("powers of tau") | Phase 2 |
|---|---|---|
| Secrets | τ, α, β | δ |
| Scope | Any circuit up to a size | One per circuit (18) |
| Output | Encrypted powers of τ, α·τ, β·τ | The circuit's proving and verifying keys |

**Both phases need at least one honest contributor.** Knowing τ breaks the keys,
and so does knowing δ alone. gnark's MPC sets the verifying key's γ to the
generator, so with δ a forger takes A = [α]₁ and B = [β]₂ (both public) and
C = −vk_x / δ, which satisfies
`e(A, B) = e(α, β) · e(vk_x, g₂) · e(C, [δ]₂)` for any public inputs.

Phase 2 is computed from the sealed phase 1. Adding a contribution to phase 1
after phase 2 has started would invalidate every phase 2 contribution made so
far.

## Design

### Phase 1: imported from the Perpetual Powers of Tau

Phase 1 comes from the [Perpetual Powers of
Tau](https://github.com/privacy-ethereum/perpetualpowersoftau), a public
ceremony with 80 independent contributors, via its 2^17 file
`ppot_0080_17.ptau` (151 MB). The assumption that one of its contributors was
honest is far stronger than anything we could organise ourselves, and anyone can
add themselves to that ceremony too.

`ceremony init` imports it once (`internal/ceremony/ptau.go`):

- parses the snarkjs `.ptau` sections (τ powers in G1 and G2, α·τ and β·τ in
  G1, β in G2), whose little-endian Montgomery encoding matches gnark-crypto's;
- checks every point is on the curve and in the prime-order subgroup, and that
  the vectors start at the generators;
- checks with random linear combinations and pairings that each vector is
  consecutive powers of the same τ, and that β agrees between G1 and G2;
- records the file's source URL, SHA-256 and BLAKE2b-512 in the manifest.

It does not replay the PPoT ceremony's own contributions; snarkjs
`powersoftau verify` does that for anyone who wants to.

The imported parameters are truncated to each circuit domain size (2^17, 2^16
and 2^13), keeping the first powers of the same τ. Without that, the 2^16 and
2^13 circuits would prove over a larger domain than they need.

### Phase 2: perpetual, with releases

Phase 2 is a single chain of contributions that never closes:

```text
v1:  [you] ─────────────────────────▶ beacon 1 ─▶ keys v1
v2:  [you] ─▶ [bank-b] ─────────────▶ beacon 2 ─▶ keys v2
v3:  [you] ─▶ [bank-b] ─▶ [bank-c] ─▶ beacon 3 ─▶ keys v3
```

- **Contribute.** Anyone registered adds randomness to all 18 circuits on top
  of the latest contribution, verifying every earlier contribution first. The
  contribution announces a future drand quicknet round as the beacon for the
  next release. The script picks the round a configurable delay ahead (default
  45 minutes) and discards the contribution if, by the clock, the round is
  published (or within 2 minutes of it) before the contribution is finished,
  e.g. because the machine slept.
- **Release.** Once that round is published, anyone can finalize: the tool
  replays the chain, applies the beacon to the latest contribution and writes
  the keys. Several contributions can go into one release; the beacon is the
  one announced by the last of them.
- **Trust.** A release rests on the contributors it includes. Every release
  includes every earlier contribution, so a participant who contributed can
  trust every later release without trusting anyone else.

**For full trust and security, phase 2 needs a contribution from someone other
than whoever made the previous releases. Ideally, every institution or user
running this repository contributes once.** The first release, with a single
contributor, rests entirely on that participant.

### Recorded in git

Every step is a commit under `ceremony/`, signed with the contributor's SSH key:

```text
ceremony/
  manifest.json             # circuits and R1CS hashes, phase 1 source and hashes,
                            # every contribution, every release and its output hashes
  contributors/             # one SSH public key per contributor + allowed_signers
  attestations/0001-x.md    # signed statement per contribution
  phase1/srs-17.bin         # imported parameters, truncated per domain size
  phase1/srs-16.bin
  phase1/srs-13.bin
  phase2/0001-x/<Circuit>.bin   # one directory per contribution
```

The `.bin` files are tracked with Git LFS. Each contribution adds about 18
circuit files.

## The tooling

`cmd/ceremony` (logic in `internal/ceremony`) implements the protocol;
`ceremony.sh` wraps it for institutions (git, signing, drand, attestations).

| Command | What it does |
|---|---|
| `join` | For a new participant: `git pull` and `git lfs pull` (and `git pull` in the contracts repository), then `verify`, `register`, `contribute`, `finalize --wait` and (optionally) `copy-verifiers`, in order |
| `init` | Compiles the 18 circuits, records their R1CS hashes, imports phase 1 |
| `register` | Adds the contributor's SSH public key to the allowlist |
| `contribute` | Checks and extends the chain, announces the next beacon, writes an attestation, signed commit |
| `finalize` | Waits for the announced beacon, releases keys into `last_build/`, converts the verifiers |
| `verify` | Checks phase 1 against the `.ptau`, every contribution, every release (re-derived), every beacon against drand, every signature against the registered key, and `last_build/` against the latest release |
| `copy-verifiers` | Copies the latest release's verifiers into the contracts repository and commits them there |
| `status` | Shows phase 1, contributions and releases |
| `clean` | Removes leftovers of an interrupted run |

Properties enforced, all covered by tests:

- **Circuits must match.** Nothing runs if the code compiles to different R1CS
  than the manifest records. Compilation is deterministic: all 18 circuits hash
  identically to the R1CS files in `last_build/` built by a separate process.
- **Every contribution is checked cryptographically** against the previous one,
  and every file against its recorded SHA-256. Edited, reordered or removed
  contributions are rejected.
- **Releases are re-derived.** Every release must use the beacon its last
  contribution announced, cover more contributions than the previous one, and
  reproduce its recorded outputs byte for byte.
- **Phase 1 must match the public file**, and malformed or inconsistent `.ptau`
  files are rejected.
- **Each proving key uses its circuit's own domain size.**
- **Contributions are signed** by the registered key of the institution they
  name, and each has an attestation recording its hash.

`contribute`, `finalize` and `verify` process several circuits in parallel
(`--jobs`; by default half the CPU cores, at most 9, limited to one job per
2.5 GB of available memory); finalizing with any number of jobs gives
byte-identical keys.

Preparing each circuit's phase 2 starting state is the slow part of every
command. gnark's `Phase2.Initialize` does it on one core and recomputes the
Lagrange-form phase 1 parameters for every circuit.
`internal/ceremony/initialize.go` computes those parameters once per domain
size and the per-wire sums in parallel. Its output is byte-identical to
gnark's, which the tests check. Circuits with Groth16 commitments (none here)
fall back to gnark's implementation. An interrupted `contribute` or `finalize`
removes its partial files.

Rehearsals: `CEREMONY_DEMO=1` runs the same flow with two tiny circuits and an
insecure local phase 1 in `ceremony-demo/`.

## Deploying a release

Every release changes the keys. The new verifiers, the gnark-api build and the
relayer must be deployed together, and every institution must upgrade at the
same time: proofs made with one release's keys don't verify against another's.
Batching contributions into releases keeps upgrades rare. Before deploying,
each institution runs `./ceremony.sh verify`.

A release reaches `main` through two pull requests, opened only once both
repositories have all their commits:

- rayls-sovereign-gnark-api: 3 commits (register, contribution, release; 2 if
  the contributor was already registered);
- rayls-sovereign-contracts: 1 commit with the release's verifiers, on a
  branch with the same name as the gnark-api one.

`join --contracts DIR` makes all four. A release whose verifiers never reach
the contracts repository can't be deployed, so if that commit is missing, run
`./ceremony.sh copy-verifiers` before the contributor's machine is destroyed.

## Limitations

- **Beacon timing is only as good as git timestamps.** A contributor could in
  principle wait for the announced round, then craft and backdate a
  contribution. This does not let them learn δ (they still don't know earlier
  contributors' randomness) but it is why the beacon is announced in the signed
  contribution commit and the contribution PR should be pushed before the round.
- **Registration is an allowlist in the repository.** Who may register is a
  review decision on the pull request that adds the key.
- **Phase 1 trust is inherited** from the Perpetual Powers of Tau.

## Next steps

- [x] Time a full run: `verify` of release v1 takes about 20 minutes on a
      20-core, 32 GB laptop (6 circuits at a time), down from over 3 hours.
- [ ] Make the first production release (first contributor) and deploy it.
- [ ] Add a CI check that runs `./ceremony.sh verify` on every contribution pull
      request.
- [ ] Add a startup check in gnark-api that refuses keys whose hashes differ
      from the latest release in `ceremony/manifest.json`.
- [x] Gate `setup_keys_verifiers.go` so single-party keys can't overwrite a
      release: it refuses while the ceremony has one, unless `--force`.
- [ ] Check on-chain history for proofs forged before the circuit fixes.
