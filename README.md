<div align="center">

# Rayls Gnark API

**Groth16 proof generation and verification service for Rayls Enygma — the gnark-based proofs API used by the Privacy Ledgers and the Private Network Hub.**

[![License: Apache 2.0][license-badge]][license-url]
[![Go][go-badge]][go-url]

[![Discord][discord-badge]][discord-url]
[![X][x-badge]][x-url]
[![LinkedIn][linkedin-badge]][linkedin-url]
[![YouTube][youtube-badge]][youtube-url]

[Quick start](#-quick-start) | [Development](#-development-workflows) | [Ceremony](#-trusted-setup-ceremony) | [Git LFS](#-git-lfs-management) | [License](#-license)

</div>

## What is this?

A Go HTTP service, built on [gnark](https://github.com/Consensys/gnark), that generates and
verifies the Groth16 zero-knowledge proofs behind Rayls **Enygma** (confidential transfers and
DVP). The compiled circuits and their proving/verifying keys are stored under `last_build/` and
tracked with Git LFS. See the note on [Proving & Verifying Keys](#-proving--verifying-keys) below
for their trust assumptions.

## 🚀 Quick Start

### Standard Workflow With Docker (No Circuit Changes)

NOTHING, just up the container.

### Standard Workflow Without Docker (No Circuit Changes)
```bash
# 1. Compile and generate executables
./compile_circuits_gen_executables.sh

# 2. Start the server
./run_gnark_server.sh
```

---

## 📝 Development Workflows

### When Circuits Are Modified
If you've changed any circuit logic, you MUST regenerate keys and verifiers.
The steps below use a single-party setup and are for **development only**;
production keys come from the [trusted-setup ceremony](#-trusted-setup-ceremony).
Once the ceremony has a release, `generate_keys_verifiers.sh` refuses to overwrite
its keys; `--force` does it anyway for local experiments, which must not be committed
(restore with `git checkout -- last_build`). A circuit change for production needs a
new ceremony (see [docs/trusted-setup-ceremony.md](docs/trusted-setup-ceremony.md)).

```bash
# A. Generate new development keys and verifiers
./generate_keys_verifiers.sh

# B. Commit artifacts to Git LFS (commits only last_build/; add --push to push)
./update_last_build_lfs.sh --push

# C. Compile executables
./compile_circuits_gen_executables.sh

# D. Start the server
./run_gnark_server.sh
```

### When Only Server Code Changes
For API or server logic updates (no circuit modifications):

```bash
# 1. Recompile executables
./compile_circuits_gen_executables.sh

# 2. Restart the server
./run_gnark_server.sh
```

### Just Running the Server
If no changes were made:

```bash
./run_gnark_server.sh
```

---

## 🧪 Testing

Run the unit and circuit tests (honest and forged witnesses for every circuit):
```bash
go test ./...
```

Run the load test against a running server:
```bash
./tests/stress_test.sh
```

---

## 📦 Git LFS Management

### Essential Commands

**Check what's tracked by LFS:**
```bash
git lfs ls-files        # List all LFS files
git lfs status          # Show pending LFS changes
```

**Save space by removing old versions:**
```bash
git lfs prune --verify-remote
```

### Troubleshooting

**Missing files after clone?**
```bash
git lfs pull
```

**Verify LFS configuration:**
```bash
cat .gitattributes | grep last_build
# Expected: last_build/** filter=lfs diff=lfs merge=lfs -text
```

**Check if files are properly stored as LFS pointers:**
```bash
head -n 3 last_build/*.sol
# Should show: version, oid, size (not actual file content)
```

**Force re-download all LFS files:**
```bash
git lfs fetch --all
git lfs checkout
```

---

## ⚠️ Important Notes

- **Circuit changes = New keys required**: run `generate_keys_verifiers.sh` for development keys; production keys come from the ceremony
- **Large files**: The `last_build/` directory contains large binary files managed by Git LFS
- **Team collaboration**: All team members must have Git LFS installed
- **After generating keys**: Always run `update_last_build_lfs.sh` to commit changes to LFS. It commits only `last_build/`, and pushes only with `--push`
- **Storage optimization**: Periodically run `git lfs prune` to remove old artifact versions

---

## 📊 Workflow Decision Tree

```
Did you modify circuits?
├─ YES → Run: A → B → C → D
│        (generate_keys → update_lfs → compile → server)
├─ NO → Did you modify server code?
│       ├─ YES → Run: 1 → 2
│       │        (compile → server)
│       └─ NO → Run: 2
│                (server only)
```

---

## 🔀 Merging Between Release Branches

When merging changes from one release branch to another (e.g., `release/2.6` → `release/2.6.1`), you must **exclude the `last_build/` folder**. Each release version has its own generated keys and verifiers that should not be overwritten.

### Why?
- Keys and verifiers in `last_build/` are always generated from scripts
- Each release version must maintain its own artifacts
- Merging these files would break the target release

### Merge Procedure

```bash
# 1. Create a temporary branch from the source release
git checkout release/2.6
git checkout -b merge-2.6-to-2.6.1

# 2. Reset the last_build folder to match the target release
git checkout release/2.6.1 -- last_build/

# 3. Commit this change
git commit -m "Exclude last_build changes for merge to 2.6.1"

# 4. Push the branch
git push origin merge-2.6-to-2.6.1

git merge origin/version/2.6.1 

fix conflicts

# 5. Open a PR from branch merge-2.6-to-2.6.1 into your target release branch

should have no conflicts
```

Any error, just  regenerate keys and verifiers (check contracts repo too).

This ensures only code changes are merged while preserving the target branch's generated artifacts.

## 🔑 Proving & Verifying Keys

`last_build/` holds the keys of the latest ceremony release, and `./ceremony.sh verify`
proves they were derived from the transcript in `ceremony/`.

`./generate_keys_verifiers.sh` produces keys from a single-party `groth16.Setup(...)` instead.
They are **development/testing artifacts**: whoever ran that setup could forge proofs, so it
refuses to overwrite a ceremony release unless given `--force`. `./convert_verifiers.sh` only
converts the Solidity verifiers in `last_build/` and never touches keys.

## 🔐 Trusted-Setup Ceremony

Groth16 needs a one-time setup whose secret randomness ("toxic waste") could forge proofs if
anyone kept it. This repository makes that setup **perpetual and verifiable**:

- **Phase 1** (the generic "powers of tau") is imported from the public
  [Perpetual Powers of Tau](https://github.com/privacy-ethereum/perpetualpowersoftau),
  a ceremony with 80 independent contributors. Nobody here has to run it.
- **Phase 2** (specific to our circuits) is where **you** add randomness. It never closes: anyone
  can contribute at any time, on top of everyone before them, and each contribution produces a
  new **release** of keys once a public random beacon ([drand](https://drand.love)) it announced
  is published.

The keys of a release are safe as long as **at least one** of its phase 2 contributors discarded
their randomness. So if you contribute, you can trust every release from then on without
trusting anyone else. Everything is a signed commit under `ceremony/`, and anyone can replay it
and re-derive the keys in `last_build/`.

> [!IMPORTANT]
> **For full trust and security, phase 2 needs a contribution from someone other than whoever
> made the previous releases, and ideally from you.** Until then, a release only rests on the
> contributors it already includes: the first release, with a single contributor, rests
> entirely on that one participant. **Ideally, every institution or user running this
> repository contributes once**, with [`./ceremony.sh join`](#join-the-ceremony-one-command). Your own contribution is the
> only one you don't have to trust.

Background and design: [docs/trusted-setup-ceremony.md](docs/trusted-setup-ceremony.md).

### Prerequisites

- Go (the version in `go.mod`), git 2.34 or newer, Git LFS, and `curl`
- An SSH key for signing, e.g. `~/.ssh/id_ed25519.pub`, loaded in `ssh-agent` or with its
  private key next to it
- About 150 MB of disk for the Perpetual Powers of Tau file (downloaded once to
  `~/.cache/rayls-ceremony`) and about 2.5 GB of memory per parallel job (`--jobs`; by
  default half the CPU cores, at most 9, and no more than available memory allows)
- For contributing: ideally a fresh machine or VM that you destroy afterwards, **kept awake and
  plugged in for the whole contribution** (see [How long it takes](#how-long-it-takes))

### Join the ceremony (one command)

Phase 1 is already imported, so a new institution or user joins with a single command. It runs
every step below in order and stops at the first error:

```bash
git switch main && git pull && git lfs pull
./ceremony.sh join --name bank-b --note "Fresh VM, destroyed afterwards" \
    --contracts ../rayls-sovereign-contracts --push
```

| Step | What `join` does | Time |
|---|---|---|
| 1. verify | Checks everything done so far, so you don't have to trust it (`--skip-verify` skips it; `contribute` still checks every earlier contribution) | ~20 min |
| 2. register | Registers your SSH key under `--name`; skipped if it already is | seconds |
| 3. contribute | Adds your randomness and announces a drand round `--beacon-delay` minutes ahead (default 45) | ~20 min |
| 4. finalize | Waits for that round, then releases keys that include your contribution into `last_build/` | the rest of the delay, then ~20 min |
| 5. copy-verifiers | With `--contracts DIR`, copies the new verifiers there for you to review and commit | seconds |

Everything is committed on a `ceremony/join-NAME` branch (when started from `main`) and pushed at
the end with `--push`; then open a pull request. Keep the machine **awake and plugged in** until
it finishes.

Write down the **contribution hash** it prints and publish it: it is how you (and anyone else)
confirm later that your contribution is in the keys.

Options:

- `--beacon-delay MIN`: how far ahead the beacon is. It must still be in the future when your
  contribution finishes (~20 minutes). The default of 45 is enough on a fast machine; use more
  on a slow or memory-limited one.
- `--no-finalize`: stop after contributing, e.g. to let other institutions contribute before the
  next release. Anyone can release later with `./ceremony.sh finalize --wait`.
- `--key PUBKEY`, `--jobs N`, `--note TEXT`: as for `contribute`.

Each contributor needs **its own SSH key**: `register` refuses a key already registered under
another name.

### Steps, one by one

`join` runs steps 2 to 6 below. Run them separately to control each one, e.g. to batch several
contributions into one release.

Run everything from the repository root, on an up-to-date checkout. Nothing is pushed unless
you pass `--push`.

```bash
git switch main && git pull
```

**1. `init`: first time only, for the whole repository.** Skip this if `ceremony/manifest.json`
already exists. It downloads the Perpetual Powers of Tau, imports it as phase 1 and commits:

```bash
./ceremony.sh init
```

**2. `register`: once per institution or user.** Adds your SSH public key, so every later commit
in your name must be signed by it:

```bash
./ceremony.sh register --name bank-a
```

**3. `contribute`: once per institution or user.** Keep the machine awake until it finishes:

```bash
./ceremony.sh contribute --name bank-a --note "Fresh VM, destroyed afterwards"
```

It:

1. checks you are up to date and verifies every earlier contribution;
2. announces a future drand round (`--beacon-delay`, default 45 minutes ahead) as the beacon for
   the next release, and prints when that is;
3. adds your randomness to every circuit on top of the latest contribution (in memory only,
   never written to disk);
4. writes your attestation and makes a commit signed with your SSH key, on a `ceremony/...`
   branch.

It prints your **contribution hash**. Write it down and publish it: it is how you (and anyone
else) confirm later that your contribution is in the keys.

**4. `finalize`: release the new keys.** Once the announced drand round is published, anyone
(usually you, right after contributing) releases keys that include your contribution:

```bash
./ceremony.sh finalize --wait
```

This writes the new release's keys, R1CS and Solidity verifiers to `last_build/` and commits.
`--wait` waits for the round if it isn't published yet.

**5. `verify`: everyone, at every release.**

```bash
./ceremony.sh verify
./ceremony.sh status   # find your name and the hash you wrote down
```

`verify` checks phase 1 against the Perpetual Powers of Tau file, replays every phase 2
contribution cryptographically, re-derives every release, checks each release's beacon against
drand, checks every contribution is signed by the registered key of the institution it names,
and checks `last_build/` matches the latest release (keys and R1CS byte for byte, Solidity
verifiers by their verifying-key constants).

**6. `copy-verifiers`, push, and deploy.**

```bash
./ceremony.sh copy-verifiers        # into ../rayls-sovereign-contracts (or --contracts DIR)
git push -u origin HEAD             # then open a pull request
```

Every release changes the keys, so the new verifiers, the gnark-api build with the new
`last_build/` and the relayer must be deployed together, and every institution must upgrade at
the same time: proofs made with one release's keys don't verify against another's. Batching
several contributions into one release keeps upgrades rare.

### How long it takes

`contribute`, `finalize` and `verify` work on every circuit; their running time is dominated by
the 2^16 and 2^17 circuits.

| Step | Measured | Notes |
|---|---|---|
| `init` | a few minutes | plus the 150 MB download the first time |
| `verify` | about 20 minutes on a 20-core, 32 GB laptop (6 circuits at a time) | was over 3 hours before the parallel preparation |
| `contribute`, `finalize` | similar to `verify` | they do the same preparation, plus a few seconds per circuit |

The announced beacon round must still be in the future when `contribute` finishes. If it isn't
(for example because the machine slept), the contribution is **discarded automatically** and you
run `contribute` again with a larger `--beacon-delay`. The default of 45 minutes leaves about a
25-minute margin on a machine like the one above; on a much slower or memory-limited machine (fewer
`--jobs`), use more.

### If something goes wrong

| Situation | What to do |
|---|---|
| You pressed Ctrl+C during `contribute` or `finalize` | The script removes the partial files itself. Run the command again. |
| The machine slept or crashed during a run | Run `./ceremony.sh clean`, then the command again. |
| "uncommitted changes in ceremony/ or last_build/" | Leftovers of an interrupted run: `./ceremony.sh clean`. |
| "… was discarded; rerun with a larger --beacon-delay" | The beacon was published before your contribution finished. Run `contribute` again with a larger `--beacon-delay`, and keep the machine awake. |
| "you are N commit(s) behind origin/main" | Someone contributed meanwhile: `git pull`, then contribute on top of them. |
| drand temporarily unreachable | `finalize --wait` keeps retrying; other commands ask you to try again later. |

### Rehearse first (about 10 minutes)

Demo mode runs the same steps with two tiny circuits and an insecure local phase 1 in
`ceremony-demo/`; it never touches `ceremony/` or `last_build/`. Use a scratch clone:

```bash
git clone <this repo> ceremony-rehearsal && cd ceremony-rehearsal
export CEREMONY_DEMO=1
./ceremony.sh init
./ceremony.sh join --name my-bank           # announces a beacon 3 minutes ahead in demo mode
./ceremony.sh verify
```

To rehearse a second participant, create another key (`ssh-keygen -t ed25519 -f /tmp/other`)
and run `./ceremony.sh join --name other-bank --key /tmp/other.pub`.

### Command reference

| # | Command | What it does | What it commits |
|---|---|---|---|
| | `join --name NAME [--contracts DIR] [--beacon-delay MIN] [--no-finalize] [--skip-verify]` | Steps 5, 2, 3, 4 and 6, in that order, for a new participant | everything steps 2–4 commit |
| 1 | `init [--ptau FILE]` | Imports phase 1 (once per repository) | `ceremony/manifest.json`, phase 1 parameters, the Git LFS rule |
| 2 | `register --name NAME [--key PUBKEY]` | Registers your signing key | `ceremony/contributors/NAME.pub`, `allowed_signers` |
| 3 | `contribute --name NAME [--note TEXT] [--beacon-delay MIN] [--jobs N]` | Adds your phase 2 contribution and announces the next beacon | the contribution, its attestation, the manifest |
| 4 | `finalize [--wait] [--jobs N]` | Releases keys once the announced beacon is published | `last_build/`, the release record |
| 5 | `verify [--no-ptau] [--jobs N]` | Checks everything | nothing |
| 6 | `copy-verifiers [--contracts DIR]` | Copies the release's verifiers into the contracts repository | nothing (review and commit them there) |
| | `status` | Shows phase 1, contributions and releases | nothing |
| | `clean` | Removes leftovers of an interrupted run | nothing |
| | `round-at "YYYY-MM-DD HH:MM UTC"` | Prints the drand round for a time | nothing |

`join`, `register`, `contribute` and `finalize` also accept `--push`. Run `./ceremony.sh help` for all
options; `CEREMONY_JOBS` sets the default for `--jobs` (0, the default, picks it automatically).

### Tips for contributors

- **Keep the machine awake and plugged in** for the whole contribution (e.g. set Windows or
  macOS sleep to "never", or use a tool such as PowerToys Awake or `caffeinate`).
- **Use a clean machine** if you can: a fresh VM or live USB, destroyed afterwards. Say what you
  did in `--note`; it goes into your signed attestation.
- **Publish your contribution hash** somewhere outside git (e.g. your institution's announcement
  channel).

## Contributing

We are not accepting external contributions at this time — see [CONTRIBUTING.md](./CONTRIBUTING.md). Please also read our [Code of Conduct](./CODE_OF_CONDUCT.md).

## Security

To report a security vulnerability, see [SECURITY.md](./SECURITY.md) — please do not open a public issue.

## 📄 License

Licensed under the Apache License, Version 2.0 — see [LICENSE](./LICENSE).

Third-party code incorporated in this repository (gnark/gnark-crypto, the generated Groth16
verifier template, and the iden3 Poseidon constants) remains under its own license — see
[NOTICE](./NOTICE).

Copyright 2026 Rayls Core Ltd.

[license-badge]: https://img.shields.io/badge/License-Apache_2.0-blue.svg
[license-url]: ./LICENSE
[go-badge]: https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white
[go-url]: https://go.dev
[discord-badge]: https://img.shields.io/badge/Discord-join%20chat-5865F2?logo=discord&logoColor=white
[discord-url]: https://discord.gg/6THZ96357r
[x-badge]: https://img.shields.io/badge/X-%40RaylsLabs-000000?logo=x&logoColor=white
[x-url]: https://x.com/RaylsLabs
[linkedin-badge]: https://img.shields.io/badge/LinkedIn-Rayls-0A66C2?logo=linkedin&logoColor=white
[linkedin-url]: https://www.linkedin.com/company/rayls/
[youtube-badge]: https://img.shields.io/badge/YouTube-Rayls-FF0000?logo=youtube&logoColor=white
[youtube-url]: https://www.youtube.com/@Rayls_blockchain