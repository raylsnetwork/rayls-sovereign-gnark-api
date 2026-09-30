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

```bash
# A. Generate new keys and verifiers
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

- **Circuit changes = New keys required**: Always run `generate_keys_verifiers.sh` after modifying circuits
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

Until the first ceremony release, the Groth16 proving and verifying keys committed under
`last_build/` (via Git LFS) are produced by a single-party `groth16.Setup(...)`. They are
**development/testing artifacts**: whoever ran that setup could forge proofs, so do not rely on
them for any production trust assumptions.

After a ceremony release, `last_build/` holds that release's keys, and `./ceremony.sh verify`
proves they were derived from the transcript in `ceremony/`.

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
> repository contributes once** (step 2 below takes one command). Your own contribution is the
> only one you don't have to trust.

Background and design: [docs/trusted-setup-ceremony.md](docs/trusted-setup-ceremony.md).

### Prerequisites

- Go (the version in `go.mod`), git 2.34 or newer, Git LFS, and `curl`
- An SSH key for signing, e.g. `~/.ssh/id_ed25519.pub`, loaded in `ssh-agent` or with its
  private key next to it
- About 150 MB for the Perpetual Powers of Tau file, downloaded once to `~/.cache/rayls-ceremony`
- For contributing: ideally a fresh machine or VM that you destroy afterwards

### How it works for you

**1. First time only: start the ceremony.** If `ceremony/manifest.json` already exists, skip
this step. Otherwise, the first user imports phase 1 and becomes contributor #1:

```bash
git switch main && git pull
./ceremony.sh init            # downloads the Perpetual Powers of Tau, imports it, commits
```

**2. Register and contribute.** Every new institution or user does this once:

```bash
git switch main && git pull
./ceremony.sh register --name bank-a
./ceremony.sh contribute --name bank-a --note "Fresh VM, destroyed afterwards"
```

`contribute`:

1. checks you are up to date and verifies the whole transcript so far;
2. adds your randomness to every circuit on top of the latest contribution (in memory only,
   never written to disk);
3. announces a future drand round (30 minutes ahead by default) as the beacon for the next
   release;
4. writes your attestation and makes a commit signed with your SSH key, on a
   `ceremony/...` branch.

It prints your **contribution hash**. Write it down and publish it: it is how you (and anyone
else) confirm later that your contribution is in the keys.

**3. Release the new keys.** Once the announced drand round is published, anyone (usually you,
straight away) can release keys that include your contribution:

```bash
./ceremony.sh finalize --wait --push
```

This writes the new release's keys, R1CS and Solidity verifiers to `last_build/`, checks they
are exactly what the transcript produces, commits, and pushes. Open a pull request with your
branch; once it is reviewed and merged, the next institution contributes on top of yours.

**4. Verify before you deploy (everyone, at every release).**

```bash
git pull
./ceremony.sh verify
./ceremony.sh status   # find your name and the hash you wrote down
```

`verify` checks phase 1 against the Perpetual Powers of Tau file, replays every phase 2
contribution cryptographically, re-derives every release, checks each release's beacon against
drand, checks every contribution is signed by the registered key of the institution it names,
and checks `last_build/` matches the latest release byte for byte.

**Deploying a release.** Every release changes the keys, so the new Solidity verifiers in
`last_build/` must be deployed and every institution must upgrade gnark-api at the same time:
proofs made with one release's keys don't verify against another's. Batching several
contributions into one release keeps upgrades rare.

### Rehearse first (about 5 minutes)

Demo mode runs the same flow with two tiny circuits and an insecure local phase 1 in
`ceremony-demo/`; it never touches `ceremony/` or `last_build/`. Use a scratch clone:

```bash
git clone <this repo> ceremony-rehearsal && cd ceremony-rehearsal
export CEREMONY_DEMO=1
./ceremony.sh init
./ceremony.sh register --name my-bank
./ceremony.sh contribute --name my-bank      # announces a beacon 1 minute ahead in demo mode
./ceremony.sh finalize --wait
./ceremony.sh verify
```

### Command reference

| Command | What it does | What it commits |
|---|---|---|
| `init [--ptau FILE]` | Imports phase 1 (once per repository) | `ceremony/manifest.json`, phase 1 parameters, the Git LFS rule |
| `register --name NAME [--key PUBKEY]` | Registers your signing key | `ceremony/contributors/NAME.pub`, `allowed_signers` |
| `contribute --name NAME [--note TEXT] [--beacon-delay MIN] [--push]` | Adds your phase 2 contribution and announces the next beacon | the contribution, its attestation, the manifest |
| `finalize [--wait] [--push]` | Releases keys once the announced beacon is published | `last_build/`, the release record |
| `verify [--no-ptau]` | Checks everything | nothing |
| `status` | Shows phase 1, contributions and releases | nothing |
| `round-at "YYYY-MM-DD HH:MM UTC"` | Prints the drand round for a time | nothing |

Nothing is pushed unless you pass `--push`. Run `./ceremony.sh help` for all options.

### Tips for contributors

- **Use a clean machine** if you can: a fresh VM or live USB, destroyed afterwards. Say what you
  did in `--note`; it goes into your signed attestation.
- **Don't interrupt** a contribution: it covers all 18 circuits. If it runs past the announced
  beacon round, the script discards it; rerun with a larger `--beacon-delay`.
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