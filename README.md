# QuantaCrypt

Post-quantum file encryption for macOS. Protect files with a password, or split the key across several people so that no one of them can open the file alone.

---

## Features

- **Quantum-resistant encryption** — ML-KEM-768 (FIPS 203) key encapsulation + AES-256-GCM streaming for files of any size (see [Security Overview](#security-overview) for the implementation's status)
- **Password or split-key protection** — encrypt with a single password, or split the key across multiple people so no one person can unlock the file alone (k-of-n threshold)
- **Plain-language interface** — no cryptographic jargon; progress messages, errors, and labels are written for everyday users
- **50-word recovery phrases** — split-key shares encoded as memorable word phrases for safe offline storage
- **Self-opening archives** — optionally embed the decryptor inside the `.qcx` file so recipients need no extra software
- **File inspector** — view encryption details (mode, format version, fingerprint) without needing the password
- **Password strength meter** — real-time feedback while typing, powered by zxcvbn pattern matching
- **Drag-and-drop** — drop files onto any window to encrypt or decrypt them instantly
- **Encrypted virtual drives** — create `.qcv` container files that mount as real volumes via FUSE; drag files in/out through Finder with on-the-fly encryption
- **macOS integration** — double-click `.qcx` or `.qcv` files in Finder, custom document icon, DMG installer
- **Dark native UI** — Tkinter-based interface with keyboard shortcuts and a guided wizard flow
- **Cross-platform foundations** — core crypto works on macOS, Windows, and Linux; the UI is macOS-primary with platform-aware fallbacks

---

## Quick Start

```bash
# Install from source
pip install -e ".[dev]"

# Launch the app
python -m quantacrypt
```

> `tkinterdnd2` is optional — enables drag-and-drop. Everything works without it.
> `zxcvbn` is optional — enables the password strength estimator. A built-in fallback is used without it.
> `fusepy` is optional — enables encrypted volume mounting. Install with `pip install fusepy` plus a FUSE backend (macOS: `brew install --cask fuse-t`, the kext-free option both UIs recommend; `macfuse` also works).

---

## How It Works

**Encrypting a file:**
1. Pick a file (or folder, or multiple files)
2. Choose **Single Password** or **Split Between People**
3. Set your password or configure how many people hold shares
4. Click **Encrypt File →**. The output is a `.qcx` file

**Decrypting a file:**
1. Open a `.qcx` file (or drag it onto the window)
2. Enter your password or paste the required number of shares
3. Click **Decrypt File →**. The original file is restored

**Split-key mode** works like a vault with multiple keys: you give each person a unique share, and only when enough people combine their shares can the file be unlocked. Quick presets (2-of-3, 3-of-5, 3-of-7) make configuration easy.

> **Note on folder encryption:** a folder is archived straight into the encrypted output. No plaintext copy of it is written anywhere, not even briefly, so a synced or removable destination never sees your files, and the only extra disk space needed is the output itself. Members that are already compressed (photos, video, archives) are stored as-is inside the archive rather than deflated again; text and documents are deflated. Symbolic links inside the folder are not packed (a link would point outside the archive); the result screen names the ones that were left out.

---

## Launch Modes

| Command | Result |
|---------|--------|
| `python -m quantacrypt` | Home screen (Encrypt, Decrypt, or Volumes) |
| `python -m quantacrypt myfile.qcx` | Opens that file directly in the decryptor |
| `python -m quantacrypt vault.qcv` | Opens the volume manager in mount mode |
| Double-click `.qcx` or `.qcv` in Finder | Opens in QuantaCrypt (after build + install) |
| `./myfile.qcx` *(after build + embed)* | Self-opening — runs its own decryptor |

---

## Project Structure

```
quantacrypt/
├── pyproject.toml                  # Version, dependencies, pytest + coverage config
├── requirements.txt                # `-e .[dev]` shim; pyproject stays the source of truth
├── requirements-lock.txt           # Hash-pinned export of uv.lock (CI + release builds)
├── uv.lock
├── README.md
├── RELEASING.md                    # Release process and version management
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── ci.yml                  # Push/PR: pytest + coverage gate, pip-audit, macOS shell build
│       ├── codeql.yml              # CodeQL analysis (actions, python, swift)
│       └── release.yml             # v* tags: build 3 DMGs → GitHub Release → version bump
├── docs/
│   └── design/                     # One design doc per feature / architectural decision
├── src/
│   └── quantacrypt/
│       ├── __init__.py             # Package root, version
│       ├── __main__.py             # Entry point — launch mode detection (.qcx / .qcv / home)
│       ├── cli.py                  # `qc-core` entry point — stdin/stdout helper for the Swift shell
│       ├── core/
│       │   ├── __init__.py         # Re-exports key constants
│       │   ├── crypto.py           # Cryptographic primitives (KEM, AES-GCM, Argon2id, Shamir)
│       │   ├── package.py          # UI-agnostic .qcx operations (load, encrypt, decrypt, naming)
│       │   ├── volume.py           # Encrypted volume container (.qcv) crypto + journal
│       │   ├── fuse_ops.py         # FUSE filesystem operations + mount/unmount API
│       │   ├── errors.py           # Shared error vocabulary (friendly_error / classify_error)
│       │   └── service.py          # JSON-lines dispatcher behind `qc-core`
│       ├── ui/                     # Tkinter app
│       │   ├── __init__.py
│       │   ├── shared.py           # Design system and shared widgets
│       │   ├── launcher.py         # Home screen with recent files
│       │   ├── encryptor.py        # Encryption wizard
│       │   ├── decryptor.py        # Decryption wizard with file inspector
│       │   ├── volume_manager.py   # Volume creation wizard + mount panel
│       │   └── updater.py          # Background update check (GitHub Releases API)
│       └── assets/
│           ├── icon.png            # App icon
│           ├── doc_icon.png        # .qcx document icon (Finder)
│           └── vol_icon.png        # .qcv document icon (Finder)
├── macos/                          # SwiftUI shell — xcodegen project.yml → QuantaCrypt.xcodeproj
│   ├── project.yml
│   ├── QuantaCrypt/
│   │   ├── App/                    # App entry, AppState, ContentView, Settings
│   │   ├── Core/                   # qc-core client, transport, wire protocol, helper lookup
│   │   ├── Features/               # Encrypt / Decrypt / Volumes screens and their models
│   │   └── Shared/                 # Share files, credential fields, panels, clipboard
│   └── QuantaCryptTests/           # XCTest suite for the shell
├── tests/
│   ├── conftest.py                 # Shared fixtures and helpers
│   ├── test_crypto.py              # Crypto primitive tests
│   ├── test_volume.py              # Volume crypto + FUSE tests
│   ├── test_gui_logic.py           # GUI validation / logic tests
│   ├── test_integration.py         # Streaming, folder, batch tests
│   └── test_service.py             # qc-core protocol + core/package tests
└── scripts/
    └── build.py                    # PyInstaller build + DMG; --helper / --native for the Swift app
```

---

## Building the App

```bash
# Build for the current machine's architecture
python scripts/build.py

# Build for a specific architecture
python scripts/build.py --arch arm64
python scripts/build.py --arch x86_64

# Skip tests (if already run separately)
python scripts/build.py --arch arm64 --skip-tests
```

The build script runs the full test suite with coverage **before** compiling (unless `--skip-tests` is passed). If any test fails or coverage drops below the threshold in `pyproject.toml` (`fail_under`, currently 95%), the build aborts.

On success it produces two artifacts in `dist/`:

- **`quantacrypt.app`** — a self-contained macOS app bundle with `.qcx` file association and custom document icon
- **`quantacrypt-{arch}.dmg`** — a distributable disk image with drag-to-Applications layout (e.g. `quantacrypt-arm64.dmg`)

> **First launch:** macOS Gatekeeper will block unsigned apps. Right-click the `.app` → **Open**, or run:
> ```bash
> xattr -d com.apple.quarantine dist/tk/quantacrypt.app
> ```

---

## Running Tests

```bash
python -m pytest tests/ -v

# One file without the coverage gate (the whole-package fail_under would fail a passing subset)
python -m pytest --no-cov tests/test_crypto.py
```

Coverage reports are generated automatically: a summary prints to the terminal and a detailed HTML report is written to `htmlcov/`.

```bash
open htmlcov/index.html
```

> Tests that import the Tkinter UI modules require a display environment. On headless systems, crypto and logic tests will still pass while UI-dependent tests are skipped.

---

## Native macOS app (preview)

`macos/` contains a SwiftUI shell that drives the same Python core through a
bundled helper (`qc-core`). `python scripts/build.py --native` produces one
`QuantaCrypt.app` (interface plus core) and its DMG. It is the planned
replacement for the Tkinter windows; see `docs/design/native-macos-ui.md`
for the plan and `RELEASING.md` for the build. The Tkinter app remains the shipped UI
until the native one reaches parity.

The native shell is also the accessible one: its controls are real AppKit
controls with VoiceOver labels. Tk on macOS exposes no accessibility role for
the label-based buttons the Tkinter windows use, so screen-reader users should
prefer the native app.

---

## Keyboard Shortcuts

`⌘` on macOS (`Ctrl` also works there), `Ctrl` on Linux / Windows.

| Shortcut | Action |
|----------|--------|
| `⌘E` | Open Encryptor |
| `⌘D` | Open Decryptor |
| `⌘M` | Open Volume Manager (mount) |
| `⌘I` | Inspect a .qcx file |
| `⌘O` | Browse for a file (in a wizard) |
| `⌘Return` | Start encryption / decryption |
| `Escape` | Close a wizard — asks first if you have typed anything; never quits the app |

---

## .qcx File Format

```
[ optional: embedded decryptor binary     ]  ← only when "self-opening" is ticked
[ encrypted payload chunks (AES-256-GCM)  ]  ← 4 MB chunks, each independently authenticated
[ MAGIC (6 bytes) + length (4 bytes) + JSON metadata tail ]
```

**Public metadata** (viewable via Inspect, no password needed): format version, encryption mode, the key encapsulation used (`kem`), the Argon2id parameters the file was made with (`argon2`), password-hardening salt, KEM ciphertext and the encrypted KEM private key, payload offset, chunk count. Every one of these fields is covered by an HMAC keyed from the derived key, so an edit to any of them is detected before a byte of payload is read.

**Encrypted metadata** (revealed only after decryption): original filename, file size, encryption timestamp.

Files are written as format version 2 (`FORMAT_VERSION` in `core/crypto.py`). Format 1 files, made by earlier releases with the round-3 Kyber-768 class, implicit Argon2id parameters and a whole-file SHA-256 in the encrypted envelope, still open: the reader selects the KEM and parameters the file names, and honours a recorded hash when there is one. Format 2 dropped that hash on purpose: each 4 MB chunk is an AES-GCM unit whose additional data binds its index and a last-chunk flag, and the chunk count is authenticated, so every byte, its order and the length are already proven, and the hash was 75% of encryption time on CPUs without SHA extensions.

---

## .qcv Volume Format

Encrypted virtual drives that mount as real volumes via FUSE. Each file inside the volume is independently encrypted (Cryptomator-style architecture). A volume whose file or folder can't be written (a read-only disk image, a locked share) mounts read-only and says so, rather than failing on the first copy. Keep sync clients away from a mounted vault: if the container file is replaced, overwritten in place, shortened, renamed or removed beneath the mount (a version restored by iCloud Drive or Dropbox, a backup copied over it), the drive flips read-only and keeps serving what it opened instead of writing into the foreign file, and any writes made since the change are copied to a `.stale-` file beside the vault. One FUSE-specific limit to know: a folder holding a file another app still has open can't be removed until that file is closed (`rm -rf` reports "Directory not empty"); see `docs/design/encrypted-volumes.md`.

Containers are format version 3 (`VOLUME_FORMAT_VERSION` in `core/volume.py`): the layout of version 2 plus a cleartext auth-params block that names its key encapsulation (`kem`) and, for password volumes, its Argon2id parameters (`argon2`). Version 1 containers still open and are rewritten as version 2 on their first save. Version 2 containers (Kyber-768, implicit parameters) open unchanged and keep their version through every compaction, so an older release can still mount them. Everything the app tells you about a volume before you unlock it comes from the cleartext block. The key is derived from that block, so an edited salt or parameter set fails at the credential step; because the KEM private key is sealed under the password (or shares), a failure *after* it unseals — the KEM ciphertext, the sealed metadata, the metadata HMAC, a header version that disagrees with the sealed one, or a field edited or removed in the cleartext block — is reported as tampering, never as a wrong password. Only a wrong password or share set produces the wrong-credentials message.

```
[ 512-byte header: magic + version + volume UUID + nonces                ]
[ cleartext auth params: Argon2 salt, KEM ciphertext (for key derivation)]
[ encrypted metadata block (AES-256-GCM)                                 ]
[ encrypted directory index (AES-256-GCM) — file tree with inodes        ]
[ baseline file data — per-file chunked AES-256-GCM (64 KB chunks)       ]
[ append-only journal — every change since the last full rewrite:        ]
      [ record header — AES-GCM JSON, AAD = the record's own offset ]
      [ record body   — the encrypted file blob, for "write" records ]
      ... one record per write / delete / rename / mkdir / rmdir ...
```

**Journal and replay:** a save appends records instead of rewriting the container, so its cost is proportional to the edit rather than to the volume. Opening a volume replays those records in order on top of the baseline directory index. Replay stops at the first record that is not complete and authentic, and the next append resumes from exactly that point, so a crash part-way through a save loses only the records that were never fully written, and the volume opens at its last consistent state. A record that is complete but fails authentication is not the crash shape (corruption or a deliberate rollback), and the volume is flagged as suspicious when it opens. Each record's authentication covers its own byte offset, so records cannot be reordered within the file. Deleting or rewriting a file leaves its old bytes in place; once that dead space exceeds 30% of the live data and an 8 MB floor, or the journal holds more than 10,000 records, the next save compacts instead: it rewrites the container with the journal folded in and starts an empty one. A volume that is filled and then emptied therefore shrinks back to a few kilobytes on the save that empties it.

The container grows dynamically as files are added. No pre-allocation is needed. Key derivation uses the same Argon2id + ML-KEM-768 scheme as `.qcx` files. Both password and split-key (Shamir) authentication modes are supported.

**Requirements:** A FUSE backend is needed to mount volumes. On macOS, install [macFUSE](https://osxfuse.github.io/) or FUSE-T via Homebrew. The Python `fusepy` package provides the bindings.

---

## Security Overview

- **Key encapsulation:** ML-KEM-768 (FIPS 203) for every file and volume written by this release; files and volumes made before format 2 / 3 used the round-3 CRYSTALS-Kyber-768 submission and are read with it
- **Symmetric encryption:** AES-256-GCM with 4 MB streaming chunks
- **Password hardening:** Argon2id — `time_cost=4`, `memory_cost=64 MB`, `parallelism=1`, 32-byte salt, 64-byte output; the parameters are recorded in each container so they can be raised in a later release without stranding existing files (a reader is bounded to 32 passes and 1 GB, so a crafted file cannot ask for more)
- **Split-key scheme:** Shamir secret sharing over the Mersenne prime M521
- **Share encoding:** BIP-39 compatible 50-word mnemonic phrases
- **Clipboard protection:** Auto-clears copied shares after 60 seconds

### What the post-quantum layer is, and what it rests on

The ML-KEM implementation is [`kyber-py`](https://github.com/GiacomoPope/kyber-py)
(1.2.0 in `requirements-lock.txt`), a pure-Python library — its `ML_KEM_768`
class for new containers, its `Kyber768` class to read the older ones. Its own README states:
*"Under no circumstances should this be used for cryptographic applications…
This is an educational resource and has not been designed to be secure against
any form of side-channel attack."* It is not constant-time.

What is post-quantum here is the key *encapsulation*: the AES key for a file is an
ML-KEM-768 shared secret XORed with the key derived from your password, so it is
never the password-derived key alone. That shared secret is not an independent
second factor, though: the KEM private key is itself stored encrypted under the
password-derived key (under the Shamir-recovered master key in split-key mode), so
anyone who can reach decapsulation already holds that key. The KEM is defence in
depth over the password, and a side-channel weakness in decapsulation gains an
attacker nothing they do not already have. The primitives the security actually
rests on — AES-256, SHA-512, HMAC-SHA-256, Argon2id — are symmetric, and
Grover's algorithm halves rather than breaks them.

A file's security therefore rests on Argon2id over the password you chose — or, in
split-key mode, on fewer than `k` shares ever coming together. Nothing in this
project has been independently audited: not the KEM implementation, not the `.qcx`
and `.qcv` container formats, not the code around them.

### Verifying a download

Every release carries a `SHA256SUMS` file and a signed build-provenance
attestation. With the DMGs and `SHA256SUMS` in one folder:

```bash
shasum -a 256 -c SHA256SUMS                      # macOS (sha256sum -c on Linux)
gh attestation verify QuantaCrypt-native-arm64.dmg --owner alexboccard
```

The second command proves, against Sigstore's transparency log, that the exact
bytes you downloaded were produced by this repository's release workflow at a
named commit. The apps themselves are ad-hoc signed: macOS will show the
unidentified-developer prompt on first launch until notarization lands.

---

## License

MIT
