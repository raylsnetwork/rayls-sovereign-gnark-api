<div align="center">

# Rayls Gnark API

**Groth16 proof generation and verification service for Rayls Enygma — the gnark-based proofs API used by the Privacy Ledgers and the Private Network Hub.**

[![License: Apache 2.0][license-badge]][license-url]
[![Go][go-badge]][go-url]

[![Discord][discord-badge]][discord-url]
[![X][x-badge]][x-url]
[![LinkedIn][linkedin-badge]][linkedin-url]
[![YouTube][youtube-badge]][youtube-url]

[Quick start](#-quick-start) | [Development](#-development-workflows) | [Git LFS](#-git-lfs-management) | [License](#-license)

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
If you've changed any circuit logic, you MUST regenerate keys and verifiers:

```bash
# A. Generate new keys and verifiers
./generate_keys_verifiers.sh

# B. Commit artifacts to Git LFS
./update_last_build_lfs.sh

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

Run the test suite:
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
- **After generating keys**: Always run `update_build_artifacts.sh` to commit changes to LFS
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

The Groth16 proving and verifying keys committed under `last_build/` (via Git LFS) are produced
by a single-party `groth16.Setup(...)` — they are **development/testing artifacts, not the output
of a multi-party trusted-setup ceremony**. Do not rely on them for any production trust
assumptions. A production deployment should generate its own keys through an appropriate ceremony.

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