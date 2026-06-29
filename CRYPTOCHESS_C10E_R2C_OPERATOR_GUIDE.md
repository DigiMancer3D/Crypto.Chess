# CryptoChess 2.0.0-rc1 C10E-R2C Operator Guide

**Document type:** GitHub upload guide  
**Format:** Markdown  
**Release line:** CryptoChess `2.0.0-rc1` / `PQC-C10E-R2C`  
**Primary target:** Kubuntu/Linux release package  
**Also covers:** Windows, macOS, Arch Linux, Asset Manager GUI/CLI, PAH handling, and PQC container use

---

## 1. Purpose

This guide explains how to launch and use CryptoChess, how to use the CryptoChess Asset Manager, how to use the PAH/PQC asset-handling workflow, and how to understand the PQC container layout used by this release.

This is **not** a README replacement. It is a detailed operator and maintainer guide for users, testers, and future developers.

---

## 2. Verified C10E-R2C release files

The final public release surface for C10E-R2C contains these files:

```text
PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset
3Dx9_core_4a7ef30be349.pqcasset
3Dx9_readme_1ffba09c2096.pqcasset
3Dx9_assets_6d046160ab99.pqcasset
CryptoChessAssetManager.py
cryptochess.sh
C10E_R2C_GITHUB_UPLOAD_SHA256SUMS.txt
reports/
```

The final promoted outer PQCZIP is:

```text
PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset
```

Its SHA256 is:

```text
c99cc9de85a28201f87f213563b3cdad50d75294a885a01b88cb30065a61a7da
```

Verify the GitHub upload folder with:

```bash
sha256sum -c C10E_R2C_GITHUB_UPLOAD_SHA256SUMS.txt
```

Expected result: every file reports `OK`.

---

## 3. Release container roles

CryptoChess C10E-R2C is organized around three main `3Dx9` PQCAsset containers plus one outer PQCZIP.

| File | Role | Purpose |
|---|---:|---|
| `3Dx9_core_4a7ef30be349.pqcasset` | Core | Restores the Python runtime/game code into `.cryptochess_runtime/core/`. |
| `3Dx9_readme_1ffba09c2096.pqcasset` | Readme/docs | Contains bundled documentation, license/status text, guides, and readable project material. |
| `3Dx9_assets_6d046160ab99.pqcasset` | Assets | Contains sprites, lessons, teaching assets, static assets, legacy converted asset lane, and a public placeholder for local data. |
| `PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset` | Outer PQCZIP | Packages the three role containers plus `CryptoChessAssetManager.py` and `cryptochess.sh` for release transport. |
| `CryptoChessAssetManager.py` | Manager | Safe GUI/CLI manager for inspection, verification, launch, release audits, and package maintenance. |
| `cryptochess.sh` | Launcher | Convenience wrapper for Linux/macOS-style shells. |

The public assets container intentionally contains:

```text
data/README_PUBLIC_STATE.md
```

This keeps the portable runtime `data/` directory present while avoiding shipment of private local state files.

---

## 4. Files that must not be uploaded publicly

Do not upload these as part of the public GitHub release surface:

```text
.cryptochess_runtime/
c9_build/
c10_safety_backups/
export/C10_public_candidates/
old C9/C10D/C10E-R1 PQCZIPs
old C9 metadata files
unwrap_pqczip_outer.py
chess.crypto
state.pah2
CryptoChess.state.pah2
install.key
cryptochess_hnr_install.key
*.kbch
*.kchain
*.anchor
*.bak containing private state
```

Private runtime state should be generated locally on a user device. It should not be shipped inside the public release package.

---

## 5. Launching CryptoChess

### 5.1 Kubuntu / Ubuntu / Debian Linux

From the folder that contains the release files:

```bash
cd /path/to/C10E_R2C_GITHUB_UPLOAD
chmod +x cryptochess.sh CryptoChessAssetManager.py
./cryptochess.sh run
```

Alternative direct manager launch:

```bash
python3 CryptoChessAssetManager.py --launch-game
```

The manager restores the runtime into:

```text
.cryptochess_runtime/
```

and launches the game directly from:

```text
.cryptochess_runtime/core/CryptoChess.py
```

The C10E-R2C manager avoids wrapper recursion. It should show:

```text
Launching CryptoChess from restored runtime checkout.
No automatic return/repack will be performed by this manager.
```

and then a JSON block containing:

```json
"wrapper_recursion": false
```

### 5.2 Arch Linux / Manjaro

Install Python and Tk support if needed:

```bash
sudo pacman -Syu python tk
```

Then run:

```bash
cd /path/to/C10E_R2C_GITHUB_UPLOAD
chmod +x cryptochess.sh CryptoChessAssetManager.py
./cryptochess.sh run
```

Alternative:

```bash
python3 CryptoChessAssetManager.py --launch-game
```

### 5.3 macOS

Install Python 3 if needed. Homebrew users can use:

```bash
brew install python-tk
```

Then run:

```bash
cd /path/to/C10E_R2C_GITHUB_UPLOAD
chmod +x cryptochess.sh CryptoChessAssetManager.py
./cryptochess.sh run
```

Alternative:

```bash
python3 CryptoChessAssetManager.py --launch-game
```

If macOS blocks execution because of local security settings, run from Terminal and confirm the local Python script is trusted. The release is a Python package, not a notarized `.app` bundle.

### 5.4 Windows

The recommended Windows path is **WSL with Ubuntu/Kubuntu**.

Inside WSL:

```bash
cd /mnt/c/path/to/C10E_R2C_GITHUB_UPLOAD
chmod +x cryptochess.sh CryptoChessAssetManager.py
./cryptochess.sh run
```

Native Windows may work if Python and Tkinter are installed, but the shell wrapper is not a native PowerShell script. Use direct Python commands:

```powershell
py -3 CryptoChessAssetManager.py --status
py -3 CryptoChessAssetManager.py --launch-game
```

If `py -3` is not available:

```powershell
python CryptoChessAssetManager.py --status
python CryptoChessAssetManager.py --launch-game
```

For GUI use on Windows, Tkinter must be available in the Python installation.

---

## 6. Device password prompt

During launch, CryptoChess may ask for a local device password or local gate password. This is expected behavior for the runtime environment.

Important distinction:

```text
A local device password prompt is not the same as shipping a private key.
```

The final C10E-R2C public release doctor confirmed:

```text
private root files absent
stale root files absent
release surface clean
public release ready
```

---

## 7. Quick smoke test

Use this test after unpacking or cloning the release package.

```bash
cd /path/to/C10E_R2C_GITHUB_UPLOAD

python3 CryptoChessAssetManager.py --status
python3 CryptoChessAssetManager.py --final-release-doctor
./cryptochess.sh --verify-pqcassets
./cryptochess.sh --verify-assets
./cryptochess.sh --restore-runtime-only
./cryptochess.sh run
```

Expected:

```text
status shows stage PQC-C10E-R2C
verify-pqcassets overall_passed true
verify-assets overall_passed true
restore-runtime passed true
game launches
```

After testing, local runtime output may exist in:

```text
.cryptochess_runtime/
```

That folder is local working state and should not be uploaded as part of the public release.

---

## 8. Asset Manager overview

The Asset Manager is:

```text
CryptoChessAssetManager.py
```

It provides safe GUI and CLI access to CryptoChess PQC assets.

Its design rules are:

```text
bare run does not mutate
device paths are not exported
root release files are protected by explicit promotion steps
privacy audits block private local state from public release
```

Run a basic status check:

```bash
python3 CryptoChessAssetManager.py --status
```

Expected fields include:

```json
{
  "bare_run_mutates": false,
  "device_paths_exported": false,
  "safe_default": true,
  "stage": "PQC-C10E-R2C"
}
```

---

## 9. Asset Manager GUI

Launch the GUI:

```bash
python3 CryptoChessAssetManager.py --gui
```

On Linux/macOS, if the wrapper supports GUI routing:

```bash
./cryptochess.sh gui
```

If the wrapper does not expose `gui` on your platform, use the direct Python command.

### GUI use cases

The GUI is intended for:

```text
viewing available containers
inspecting container metadata
checking file roles
previewing text-like internal files
searching internal paths
verifying containers
launching safe manager workflows
```

### GUI classification markers

| Marker concept | Meaning |
|---|---|
| Green file / normal asset | A readable, structurally valid file entry. |
| Empty asset warning | A `.pqcasset` exists but has no useful entries. |
| PQCZIP outer | An outer package containing other public release payloads. |
| Vanity PQCAsset / vanity PQCZIP | A container with vanity naming or vanity-derived identity properties. |
| Malformed | A container that fails structural parsing or validation. |
| Privacy warning | A file or internal path should be reviewed before public shipment. |
| Privacy blocker | A file or internal path must not ship publicly. |
| Signed/locked asset | A container associated with signature/lock metadata, when present. |
| Returned/closed | A conceptual state for containers that have been closed or returned to package state. |

The exact GUI layout may vary by system, but the manager is intended to support searching, selecting, previewing, and verifying release files.

---

## 10. Asset Manager CLI reference

### 10.1 Status

```bash
python3 CryptoChessAssetManager.py --status
```

Shows safe manager status, release stage, and count of visible `.pqcasset` files.

### 10.2 Scan current folder

```bash
python3 CryptoChessAssetManager.py --scan
```

Scans the current folder and classifies visible assets without exposing device paths.

### 10.3 Verify one container

```bash
python3 CryptoChessAssetManager.py --verify 3Dx9_assets_6d046160ab99.pqcasset
```

Verify the final outer PQCZIP:

```bash
python3 CryptoChessAssetManager.py --verify PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset
```

Expected:

```json
"passed": true
```

### 10.4 List container contents

```bash
python3 CryptoChessAssetManager.py --list-container 3Dx9_assets_6d046160ab99.pqcasset --limit 20
```

Search inside a container:

```bash
python3 CryptoChessAssetManager.py \
  --list-container 3Dx9_assets_6d046160ab99.pqcasset \
  --find "README_PUBLIC_STATE" \
  --limit 20
```

Search the outer PQCZIP:

```bash
python3 CryptoChessAssetManager.py \
  --list-container PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset \
  --limit 20
```

### 10.5 Preview a text-like internal file

```bash
python3 CryptoChessAssetManager.py \
  --preview-container 3Dx9_assets_6d046160ab99.pqcasset \
  --internal-path data/README_PUBLIC_STATE.md
```

### 10.6 Audit one container for privacy

```bash
python3 CryptoChessAssetManager.py \
  --audit-container 3Dx9_assets_6d046160ab99.pqcasset
```

A public-ready assets container should have:

```json
"blocker_count": 0
```

Warnings are allowed when they are review-only and not public-release blockers.

### 10.7 Audit the outer PQCZIP

```bash
python3 CryptoChessAssetManager.py \
  --audit-pqczip PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset
```

Expected:

```json
{
  "passed": true,
  "summary": {
    "blocker_count": 0,
    "public_release_ready": true
  }
}
```

### 10.8 Audit the full release surface

```bash
python3 CryptoChessAssetManager.py --audit-release-surface --write-release-surface-audit
```

Expected:

```json
{
  "summary": {
    "blocker_count": 0,
    "public_release_ready": true,
    "requires_new_pqczip_build": false
  }
}
```

### 10.9 Run the final release doctor

```bash
python3 CryptoChessAssetManager.py --final-release-doctor --write-final-release-report
```

Expected:

```json
{
  "passed": true,
  "summary": {
    "failed_count": 0,
    "public_release_ready": true
  }
}
```

### 10.10 Launch game through manager

```bash
python3 CryptoChessAssetManager.py --launch-game
```

Equivalent compatibility aliases:

```bash
python3 CryptoChessAssetManager.py launch
python3 CryptoChessAssetManager.py run
python3 CryptoChessAssetManager.py launch-game
```

### 10.11 Launch through wrapper

```bash
./cryptochess.sh run
```

The wrapper should route into the manager and then the manager should launch the restored runtime directly.

---

## 11. Wrapper command reference

The Linux/macOS-style wrapper is:

```text
cryptochess.sh
```

Common commands:

```bash
./cryptochess.sh run
./cryptochess.sh --status
./cryptochess.sh --verify-pqcassets
./cryptochess.sh --verify-assets
./cryptochess.sh --restore-runtime-only
```

Expected wrapper checks:

```text
verify-pqcassets: overall_passed true
verify-assets: overall_passed true
restore-runtime-only: passed true
```

---

## 12. Public package maintenance commands

Most users do not need these commands. They are for maintainers.

### 12.1 Build a fresh public PQCZIP

```bash
python3 CryptoChessAssetManager.py --build-public-pqczip --write-pqczip
```

Then locate the new file:

```bash
PQCZIP=$(ls -t export/C10_public_release/PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_*.pqcasset | head -n1)
echo "$PQCZIP"
```

### 12.2 Verify and audit the candidate

```bash
python3 CryptoChessAssetManager.py --verify "$PQCZIP"
python3 CryptoChessAssetManager.py --audit-pqczip "$PQCZIP"
```

### 12.3 Dry-run promotion

```bash
python3 CryptoChessAssetManager.py --promote-public-pqczip "$PQCZIP"
```

### 12.4 Apply promotion

```bash
python3 CryptoChessAssetManager.py \
  --promote-public-pqczip "$PQCZIP" \
  --apply-promote \
  --yes
```

Promotion moves older/stale outer PQCZIPs into a safety backup folder. It does not change the three role containers unless you explicitly rebuild and promote them through separate asset-candidate steps.

---

## 13. Asset Handler / PAH overview

PAH means **Portable Asset Handler** in this project context.

The CryptoChess package uses PAH-style containers to group files into portable binary assets. The user-facing file extension is usually:

```text
.pqcasset
```

The release also uses the term:

```text
PQCZIP
```

for an outer `.pqcasset` that packages other release files.

### PAH concepts

| Concept | Meaning |
|---|---|
| PAH1 | Structural container format used by these release `.pqcasset` files. |
| PAH2 | Older or converted asset lane retained for compatibility in some asset paths. |
| PQCAsset | A `.pqcasset` container with internal entries and a path map. |
| PQCZIP | A `.pqcasset` used as an outer release package containing other containers and scripts. |
| Path map | Metadata mapping encoded payload names back to portable internal paths. |
| Encoded entry | The stored internal payload name inside the container. |
| Portable internal path | A path such as `data/README_PUBLIC_STATE.md`, not a device path. |
| Device path | A local absolute path. These should not be exported in public reports. |
| Digital scarcity extraction | In PAH handler workflows, extraction/export can be treated as removing an item from a container, depending on the handler command used. |
| Return | Putting an opened or extracted item back into its container state. |
| Verify | Checking structure, entries, hashes, path map integrity, and trailing bytes. |
| Split | Dividing large container payloads into smaller transport pieces. |
| Vanity | A variant where the container name or identity is selected to satisfy a desired visible pattern. |
| SPX-QEC | A SPHINCS+/QEC-related variant used by the broader toolchain when available. |
| Falcon/SPHINCS+/Hybrid signatures | Signature modes described by the PAH toolchain when those tools are present. |

---

## 14. PAH tooling note

The C10E-R2C public release is primarily operated through:

```text
CryptoChessAssetManager.py
```

Some development or advanced PAH operations may use separate tools, commonly named like:

```text
pah_wrap_improved.py
pah.c
unified_sphinx_keygen.py
```

Those tools may not be included in the public release folder. When they are present in a development environment, always check their local help first:

```bash
python3 pah_wrap_improved.py --help
```

or:

```bash
./pah --help
```

Exact flags can vary by tool version.

---

## 15. Common PAH-style operations

The following examples show the intended workflow style. Use the exact command supported by your local PAH tool.

### 15.1 Create a container

Generic pattern:

```bash
python3 pah_wrap_improved.py create \
  --output MyContainer.pqcasset \
  --input path/to/folder
```

Possible signature variants may include:

```bash
python3 pah_wrap_improved.py create \
  --output MyContainer.pqcasset \
  --input path/to/folder \
  --signature hybrid
```

or:

```bash
python3 pah_wrap_improved.py create \
  --output MyContainer.pqcasset \
  --input path/to/folder \
  --signature sphincs
```

Check your local PAH tool help before relying on a signature flag.

### 15.2 List a container

With Asset Manager:

```bash
python3 CryptoChessAssetManager.py --list-container MyContainer.pqcasset --limit 50
```

With a PAH tool, if available:

```bash
python3 pah_wrap_improved.py list MyContainer.pqcasset
```

### 15.3 Verify a container

With Asset Manager:

```bash
python3 CryptoChessAssetManager.py --verify MyContainer.pqcasset
```

With a PAH tool, if available:

```bash
python3 pah_wrap_improved.py verify MyContainer.pqcasset
```

### 15.4 Extract or open a container

Asset Manager inspection commands are non-destructive. They list and preview.

For runtime restore:

```bash
./cryptochess.sh --restore-runtime-only
```

For PAH extraction, when using a dedicated PAH handler:

```bash
python3 pah_wrap_improved.py extract \
  MyContainer.pqcasset \
  --output extracted/
```

If the handler implements digital scarcity extraction, extraction may remove the item from the source container. Read the PAH tool help before using destructive extraction.

### 15.5 Return files to a container

Generic PAH handler pattern:

```bash
python3 pah_wrap_improved.py create \
  --output ReturnedContainer.pqcasset \
  --input extracted/
```

or, if the tool supports a direct return command:

```bash
python3 pah_wrap_improved.py return \
  MyContainer.pqcasset \
  --input extracted/some-file
```

Check the local PAH tool help for exact syntax.

### 15.6 Split a large container

Generic pattern:

```bash
python3 pah_wrap_improved.py split \
  MyContainer.pqcasset \
  --parts 4 \
  --output split_parts/
```

or by size:

```bash
python3 pah_wrap_improved.py split \
  MyContainer.pqcasset \
  --size 50M \
  --output split_parts/
```

### 15.7 Retrieve/reassemble split pieces

Generic pattern:

```bash
python3 pah_wrap_improved.py retrieve \
  --input split_parts/ \
  --output MyContainer.rebuilt.pqcasset
```

### 15.8 Resolve vanity container names

Generic pattern:

```bash
python3 pah_wrap_improved.py resolve-vanity \
  --input MyContainer.pqcasset
```

### 15.9 Use SPX-QEC or vanity SPX-QEC variants

When SPX-QEC tools are present, check their local JSON/config and help:

```bash
python3 unified_sphinx_keygen.py --help
python3 pah_wrap_improved.py --help
```

SPX-QEC variants belong to the advanced cryptographic/tooling layer. They are not required to launch CryptoChess C10E-R2C.

---

## 16. PQC container variants used in this version

C10E-R2C uses or preserves the following container concepts.

### 16.1 Standard role PQCAssets

These are the three main role containers:

```text
3Dx9_core_4a7ef30be349.pqcasset
3Dx9_readme_1ffba09c2096.pqcasset
3Dx9_assets_6d046160ab99.pqcasset
```

They are required for normal manager verification and runtime restore.

### 16.2 Outer PQCZIP

This is the transport package:

```text
PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset
```

It contains:

```text
3Dx9_assets_6d046160ab99.pqcasset
3Dx9_core_4a7ef30be349.pqcasset
3Dx9_readme_1ffba09c2096.pqcasset
CryptoChessAssetManager.py
cryptochess.sh
```

### 16.3 Legacy converted PAH2 asset lane

The assets container preserves a legacy converted lane:

```text
_legacy_convert_from_pah2/CryptoChess.assets.pah2
```

The public audit treats this as a warning/review item, not a blocker, because the final assets container has no private state blockers.

### 16.4 Public local-data placeholder

The assets container includes:

```text
data/README_PUBLIC_STATE.md
```

This keeps the `data/` directory present without shipping:

```text
chess.crypto
CryptoChess.state.pah2
install.key
anchors
local backups
```

### 16.5 Vanity and SPX-QEC variants

The broader PAH/PQC toolchain may support vanity assets, vanity PQCZIPs, SPX-QEC features, and Falcon/SPHINCS+/Hybrid signature modes. C10E-R2C does not require those advanced variants to launch the game. They are useful for development, experimentation, identity/signature workflows, and future container hardening.

---

## 17. Handling containers with the Asset Manager

### 17.1 Inspect the outer PQCZIP

```bash
python3 CryptoChessAssetManager.py \
  --list-container PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset \
  --limit 20
```

Expected internal entries include:

```text
3Dx9_assets_6d046160ab99.pqcasset
3Dx9_core_4a7ef30be349.pqcasset
3Dx9_readme_1ffba09c2096.pqcasset
CryptoChessAssetManager.py
cryptochess.sh
```

### 17.2 Inspect the assets container

```bash
python3 CryptoChessAssetManager.py \
  --list-container 3Dx9_assets_6d046160ab99.pqcasset \
  --limit 50
```

Search for the public data placeholder:

```bash
python3 CryptoChessAssetManager.py \
  --list-container 3Dx9_assets_6d046160ab99.pqcasset \
  --find README_PUBLIC_STATE \
  --limit 20
```

### 17.3 Confirm no private state is shipped

```bash
python3 CryptoChessAssetManager.py \
  --list-container 3Dx9_assets_6d046160ab99.pqcasset \
  --find chess.crypto \
  --limit 20

python3 CryptoChessAssetManager.py \
  --list-container 3Dx9_assets_6d046160ab99.pqcasset \
  --find install.key \
  --limit 20

python3 CryptoChessAssetManager.py \
  --list-container 3Dx9_assets_6d046160ab99.pqcasset \
  --find anchor \
  --limit 20
```

Expected:

```text
matching_count: 0
```

The word `state` may match `README_PUBLIC_STATE.md`, which is expected.

---

## 18. Handling containers alone, outside the chess game

You can use the manager to inspect and verify `.pqcasset` containers that are not part of CryptoChess.

Examples:

```bash
python3 CryptoChessAssetManager.py --verify SomeContainer.pqcasset
python3 CryptoChessAssetManager.py --list-container SomeContainer.pqcasset --limit 100
python3 CryptoChessAssetManager.py --audit-container SomeContainer.pqcasset
```

This is useful for:

```text
checking structural validity
checking path-map validity
finding privacy blockers
previewing readable internal files
testing whether a PQCAsset is empty, malformed, or valid
```

For general extraction, splitting, signing, or digital-scarcity workflows, use the dedicated PAH handler if it is present in your development environment.

---

## 19. Suggested GitHub upload structure

A clean upload folder should look like:

```text
C10E_R2C_GITHUB_UPLOAD/
├── 3Dx9_assets_6d046160ab99.pqcasset
├── 3Dx9_core_4a7ef30be349.pqcasset
├── 3Dx9_readme_1ffba09c2096.pqcasset
├── CryptoChessAssetManager.py
├── cryptochess.sh
├── PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset
├── C10E_R2C_GITHUB_UPLOAD_SHA256SUMS.txt
└── reports/
    ├── C10E_R2C_FINAL_PUBLIC_RELEASE_DOCTOR.json
    ├── C10_PACKAGE_MANIFEST.json
    ├── C10_PACKAGE_PATH_MAP.json
    ├── C10_RELEASE_SURFACE_AUDIT.json
    └── PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset.sha256.txt
```

Verify after upload or download:

```bash
cd C10E_R2C_GITHUB_UPLOAD
sha256sum -c C10E_R2C_GITHUB_UPLOAD_SHA256SUMS.txt
```

Expected `OK` for every listed file.

---

## 20. Troubleshooting

### 20.1 Permission denied

```bash
chmod +x cryptochess.sh CryptoChessAssetManager.py
```

Then retry:

```bash
./cryptochess.sh run
```

### 20.2 `python3` not found

Kubuntu/Ubuntu/Debian:

```bash
sudo apt update
sudo apt install python3 python3-tk
```

Arch:

```bash
sudo pacman -Syu python tk
```

macOS with Homebrew:

```bash
brew install python-tk
```

Windows:

```powershell
py -3 --version
```

or install Python 3 from the official Python installer or use WSL.

### 20.3 GUI does not open

Make sure Tkinter is installed.

Kubuntu/Ubuntu/Debian:

```bash
sudo apt install python3-tk
```

Arch:

```bash
sudo pacman -S tk
```

macOS:

```bash
brew install python-tk
```

Then test:

```bash
python3 - <<'PY'
import tkinter
print("tkinter ok")
PY
```

### 20.4 Wrapper recursion or repeated launch messages

C10E-R2C fixes the wrapper recursion issue. The manager should launch the runtime directly and print:

```json
"wrapper_recursion": false
```

If repeated launch messages occur, check that the active manager is C10E-R2C:

```bash
python3 CryptoChessAssetManager.py --status
```

Expected:

```json
"stage": "PQC-C10E-R2C"
```

### 20.5 Game asks for device password

This can be normal. It is a local device gate. Enter the correct local password. This does not mean private state was shipped publicly.

### 20.6 Release audit fails

Run:

```bash
python3 CryptoChessAssetManager.py --audit-release-surface --write-release-surface-audit
python3 CryptoChessAssetManager.py --final-release-doctor --write-final-release-report
```

Review:

```text
export/C10_RELEASE_SURFACE_AUDIT.json
export/C10E_R2C_FINAL_PUBLIC_RELEASE_DOCTOR.json
```

Common causes:

```text
old PQCZIP still in root
old C9 metadata still in root
unwrap_pqczip_outer.py still in root
private state file in root
modified manager not rebuilt into the outer PQCZIP
```

### 20.7 Check whether the manager inside the PQCZIP matches root

```bash
python3 CryptoChessAssetManager.py \
  --audit-pqczip PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_c99cc9de85a2.pqcasset
```

Expected:

```json
"matches_active_root": true
```

for `CryptoChessAssetManager.py`.

---

## 21. Maintainer notes

### 21.1 Rebuild after manager changes

Any time `CryptoChessAssetManager.py` changes, rebuild and promote the outer PQCZIP:

```bash
python3 CryptoChessAssetManager.py --build-public-pqczip --write-pqczip

PQCZIP=$(ls -t export/C10_public_release/PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_*.pqcasset | head -n1)

python3 CryptoChessAssetManager.py --verify "$PQCZIP"
python3 CryptoChessAssetManager.py --audit-pqczip "$PQCZIP"
python3 CryptoChessAssetManager.py --promote-public-pqczip "$PQCZIP" --apply-promote --yes
python3 CryptoChessAssetManager.py --final-release-doctor --write-final-release-report
```

### 21.2 Rebuild after asset changes

When changing public assets, build a public assets candidate first, audit it, then promote it. Do not manually edit root `.pqcasset` files.

General pattern:

```bash
python3 CryptoChessAssetManager.py --build-public-assets-candidate --write-candidate

CAND=$(ls -t export/C10_public_candidates/3Dx9_assets_*.pqcasset | head -n1)

python3 CryptoChessAssetManager.py --verify "$CAND"
python3 CryptoChessAssetManager.py --audit-container "$CAND"
python3 CryptoChessAssetManager.py --promote-public-assets-candidate "$CAND" --apply-promote --yes
```

Then rebuild/promote the outer PQCZIP.

### 21.3 Do not develop in the sealed upload folder

Use a development copy. Keep the GitHub upload folder clean.

---

## 22. Summary

CryptoChess C10E-R2C is operated through:

```text
cryptochess.sh
CryptoChessAssetManager.py
three 3Dx9 role containers
one outer PQCZIP
```

Normal users should launch with:

```bash
./cryptochess.sh run
```

or:

```bash
python3 CryptoChessAssetManager.py --launch-game
```

Maintainers should validate with:

```bash
python3 CryptoChessAssetManager.py --final-release-doctor
sha256sum -c C10E_R2C_GITHUB_UPLOAD_SHA256SUMS.txt
```

The final C10E-R2C public package is considered ready when:

```text
final-release-doctor passed true
public_release_ready true
checksum verification OK
game launches from restored runtime
```
