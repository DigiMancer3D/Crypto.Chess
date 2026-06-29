# ♞♝ Crypto.Chess

<div align="center">

**Where Chess Becomes a Lesson in Post-Quantum Cryptography**

[![Release](https://img.shields.io/badge/Release-2.0.0--rc1-blueviolet)](https://github.com/DigiMancer3D/Crypto.Chess)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Linux-Made%20on%20Kubuntu-brightgreen)](https://github.com/kubuntu-team/kubuntu.org)
[![PQC Native](https://img.shields.io/badge/PQC-Native%20Containers-ff6b6b)](https://github.com/DigiMancer3D/PQC-Containers)

**An educational chess variant that makes the invisible differences between Classical Cryptography and Post-Quantum Cryptography (PQC) tangible, playable, and unforgettable.**

[🚀 Quick Start](#-quick-start) • [🎮 How to Play](#-how-to-play--the-crypto-chess-metaphor) • [🧠 Educational Goals](#-why-this-matters) • [🛠️ Technical Foundation](#-technical-foundation--pqc-containers)

</div>

---

## 🎯 What is Crypto.Chess?

Crypto.Chess is not standard chess. It is a **purpose-built cryptography teaching game** disguised as a chess variant.

You don't just *read* about how lattice-based PQC differs from RSA/ECC, you **play the math**.

Every piece movement, every game mode, and every rule has been deliberately designed to mirror real cryptographic concepts:

- **Input vs Processing phases**
- **Deterministic vs branching/randomized transformations**
- **Exploitable scenerios** in **Classical** *vs* **Hybrid** *vs* **Post-quantum** systems
- **Verifiable randomness & receipts**
- **State recovery & cross-party influence**

The result is an intuitive, visual, and surprisingly deep way to internalize how PQC differs from past methods and how it fundamentally changes the rules of the game for cryptography.

---

## 🕹️ Core Metaphor: Two Pieces. Two Cryptographic Realities.

### ♞ The Knight, Classical Cryptography
- Classic L-shaped move (forced split axis).
- Once you commit to the one axis, **the other axis is fixed**.
- The second half of the move is **deterministic / preset**.
- Represents classical public-key crypto (factoring, discrete log): the output structure is heavily determined by the input once the "direction" is chosen. There is elegance, but also rigidity.

### ♝ The Bishop, Post-Quantum Cryptography (Lattice-based)
- Moves diagonally (evoking the mathematical lattices at the heart of Kyber, Dilithium, Falcon, etc.).
- **Split-Move System** (the heart of the teaching experience):
  1. **First half (Input/Setup phase)**: Choose your diagonal direction.
  2. **Second half (Processing phase)**: You may *continue* in the same direction **or** branch into a new direction.
- This extra choice in the second half models the **additional layers of mathematics** PQC uses to replace classical hardness assumptions. The result feels more "noisy", more flexible, and harder to predict from the outside, similar to real PQC algorithms.

**The Rounds are conceptually split into two halves**:
- **First half** = Your move / input (including the powerful **HODL** option, deliberately do nothing to bank move allowance for later).
- **Second half** = The cryptographic processing / transformation.

This split is not just flavor, it is the pedagogical core of Crypto.Chess.

---

## 🎮 Three Game Modes, Three Ways to Explore the Same Truth

| Mode       | Core Experience                          | New Piece          | Key Teaching Point                                      | Crypto Analogy |
|------------|------------------------------------------|--------------------|---------------------------------------------------------|----------------|
| **PQC**    | Pure Bishop vs Knight split-move chess  | N/A                 | The fundamental split between input & processing       | Core PQC algorithms |
| **Hybrid** | PQC with dynamic role-swapping          | **Rook** (swappable at half-time) | Hybrid systems & transitional schemes                  | Hybrid Key Exchange, PQC + classical fallbacks |
| **Classical** | "More pieces, more complexity"         | **Automated Pawn** (one per player) | Classical crypto has *many* interdependent moving parts | Classical PKI, multi-party protocols, certificate chains |

### PQC Mode (Base Rules)
The purest expression of the Bishop/Knight metaphor. Master the split-move and the HODL economy.

### Hybrid Mode (Unique PQC Variant)
At the **half-time check**, either player may swap their active piece for a **Rook**.

The Rook comes with powerful **built-in automated behaviors**:
- Can execute "PQC-mimic" moves that help the Knight player experience lattice-like randomness.
- Can also attempt high-risk, long-range "long-shot" captures.

This mode teaches hybrid cryptography and the strategic value of having fallback or transitional mechanisms.

### Classical Mode (Different Unique PQC Variant)
Instead of a swappable Rook, the board gains a **permanent automated Pawn for each player**.

**Extraordinary custom rule**: 
> Both pawns are **fully automated** according to rich rule sets **and can be manipulated by either player for either player**.

This is one of the most unusual and powerful teaching tools in the game. It demonstrates how classical cryptography often involves **many more "pieces"** (keys, CAs, handshakes, revocation lists, multiple parties) that can influence each other in complex, sometimes surprising ways, compared to the more streamlined, self-contained nature of many PQC designs.

---

## ✨ Unique, Custom & Unusual Systems

Crypto.Chess contains several genuinely novel mechanics rarely (if ever) seen in other chess variants or educational games:

- **Split-Move Bishop**, Explicit modeling of crypto round phases with player choice in the second phase.
- **HODL / Banked Moves**, Strategic resource management with a crypto-culture name.
- **Half-time Check & Rook Swap (Hybrid)**, Dynamic piece/role negotiation mid-round.
- **Cross-Player Automated Pawn Manipulation (Classical)**, Both players can control *both* pawns. A striking metaphor for shared state and influence in classical systems.
- **Verifiable HNR Randomness & Receipt System**, Custom on-chain-style verifiable randomness, audit receipts, and history verification (HNR = Hash Number Roller / Verifiable Randomness Chain). Includes HNR0–HNR5 components for engine, chaining, verification, receipts, and wallet demos.
- **Signed Teaching Content**, Lessons and assets are cryptographically signed.
- **Encrypted Persistent State + Advanced Recovery**, Full local encrypted state with multiple recovery paths (backup containers, journals, checkpoints, workspace).
- **Startup Recovery & Rollback Detection**, The game actively detects and helps repair generation rollbacks and migration issues.
- **PQC-Native Asset Distribution**, The entire game (code + assets + docs) is shipped inside PAH1/PQCAsset containers with path maps, verification, and privacy audits.

These are not gimmicks. They are deliberate, custom-designed cryptographic teaching instruments.

---

## 🧠 Why This Matters (Educational Goals)

Most people "know" that PQC is coming. Very few *feel* the difference.

Crypto.Chess turns abstract NIST PQC algorithms into muscle memory:

- Why does lattice math feel different from factoring?
- What does "extra math in the second phase" actually look like in practice?
- Why do classical systems often end up with more moving parts and more attack surface?
- What does verifiable randomness and non-repudiation *feel* like when you're the one making (or breaking) the rules?

Play a few games in each mode and these concepts stop being theory. They become intuition.

---

## 🛠️ Technical Foundation, Built on PQC Containers

Crypto.Chess 2.0.0-rc1 (C10E-R2C) is a **practical test and demonstration** of the [PQC-Containers](https://github.com/DigiMancer3D/PQC-Containers) project (the formal build state of the original [PQCAssets](https://github.com/DigiMancer3D/PQCAssets) concept).

### How the Release Works
- Everything is packaged in **PAH1 `.pqcasset` containers** (core, assets, readme).
- An outer **PQCZIP** bundles the release for safe transport.
- The **CryptoChessAssetManager.py** provides a safe GUI + CLI for:
  - Verification & audits
  - Runtime restoration into `.Crypto.Chess_runtime/`
  - Privacy-safe inspection of internal paths only
  - Final release doctor checks
- Local device state (keys, `chess.crypto`, etc.) is **never** included in the public release. It is generated on first launch on your machine. This ensures everyone whom wants a fresh copy can obtain a fresh copy.

This architecture itself is part of the lesson: **secure, verifiable, privacy-respecting software distribution using post-quantum techniques**.

See the full **[Operator Guide](OPERATOR_GUIDE.md)** (included in the release) for every command, verification step, and maintenance workflow.

---

## 🚀 Quick Start

### Recommended: Kubuntu / Ubuntu / Debian

```bash
cd /path/to/C10E_R2C_GITHUB_UPLOAD
chmod +x Crypto.Chess.sh CryptoChessAssetManager.py
./Crypto.Chess.sh run
```

Or launch directly:

```bash
python3 CryptoChessAssetManager.py --launch-game
```

### Other Platforms
- **Arch/Manjaro**: `sudo pacman -Syu python tk`
- **macOS** (Homebrew): `brew install python-tk`
- **Windows**: Use WSL with Ubuntu (recommended) or native Python + Tkinter

More instructions for some platforms, GUI usage, verification commands, and troubleshooting are in the included **Operator Guide**.

After launch you may be prompted for a **local device password**, this is normal for the cryptography parts of the system holding the game and stays on your machine.

---

## 📦 Repository Structure (Release)

```
C10E_R2C_GITHUB_UPLOAD/
├── 3Dx9_assets_*.pqcasset      # Sprites, themes, lessons, public placeholder
├── 3Dx9_core_*.pqcasset        # Python runtime + game engine + HNR systems
├── 3Dx9_readme_*.pqcasset      # Documentation, guides, license status
├── PQCZIP_*.pqcasset           # Outer release container
├── CryptoChessAssetManager.py  # Safe GUI/CLI manager + launcher
├── Crypto.Chess.sh             # Convenient shell wrapper
├── C10E_R2C_GITHUB_UPLOAD_SHA256SUMS.txt
└── reports/                    # Verification & audit artifacts
```

---

## 🔗 Related Projects

- [PQC-Containers](https://github.com/DigiMancer3D/PQC-Containers), The formal tooling and container format powering this release
- [PQCAssets](https://github.com/DigiMancer3D/PQCAssets), Original conceptual project

---

<div align="center">
<br></br>
  
**Play the difference. Understand the difference.**

*Crypto.Chess, Because the best way to learn cryptography is to play it.*

<br></br><br></br>
</div>
