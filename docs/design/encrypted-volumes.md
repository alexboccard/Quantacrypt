# Design Doc: Encrypted Volumes (.qcv)

**Status:** Implemented (Phase 4 complete)
**Date:** 2026-03-17
**Author:** Alex + Claude

## Problem

QuantaCrypt encrypts individual files as `.qcx` containers, but users need a way to work with multiple files transparently — editing, adding, and removing files without manually encrypting/decrypting each one. The goal is a virtual encrypted drive that mounts as a real folder on macOS/Linux.

## Options Considered

### Option A: Monolithic encrypted disk image
Encrypt a single large blob (like a `.dmg` or LUKS volume). Simple, but: no file-level granularity, entire image must be re-encrypted on any change, no partial sync possible.

### Option B: File-level encryption inside a container (Cryptomator-style)
Each file encrypted independently within a structured container. Random-access reads/writes. Only changed files need re-encryption. Directory index tracks the tree structure.

### Option C: Overlay filesystem with encrypted backing store
Use OverlayFS or similar with an encrypted lower layer. Complex kernel dependencies, poor portability.

## Decision

**Option B** — file-level encryption inside a `.qcv` container, mounted via FUSE.

Rationale:
- Per-file encryption means small edits don't re-encrypt the whole volume
- FUSE provides real filesystem semantics without kernel modules (FUSE-T on macOS is kext-free)
- Container format is portable (single file, self-contained)
- Aligns with existing AES-256-GCM + ML-KEM crypto stack

## Container Format

```
[Header — 512 bytes]           MAGIC "QCVOL\x01" + FORMAT_VERSION + VOLUME_ID + nonces
[Auth Params — cleartext JSON] Mode, Argon2 salt, KEM ciphertext (needed to derive key)
[Encrypted Metadata — AES-GCM] Mode, chunk_size, created_at, argon2 params
[Encrypted Directory Index]    JSON tree: { "/path": { inode, size, mode, mtime, nonce, hash } }
[File Data Section]            Per-file chunked AES-GCM (64KB chunks)
```

### Key decisions within the format:
- **Auth params are unencrypted** — they contain only public-key-like fields (Argon2 salt, KEM ciphertext) needed to derive the key. No secrets exposed.
- **64KB chunk size** (vs 4MB for .qcx) — optimized for random-access FUSE reads. Smaller chunks = less wasted I/O for small reads.
- **Per-file nonces** — each file gets a random `base_nonce`; chunks use `nonce XOR chunk_index` to avoid nonce reuse.
- **LRU cache** (default 100MB) for decrypted file data in FUSE layer.

## Architecture

Three new core modules:

| Module | Responsibility |
|--------|---------------|
| `core/volume.py` | Volume container: create, open, read/write files, directory index, metadata, atomic saves |
| `core/fuse_ops.py` | FUSE filesystem operations (`QuantaCryptFUSE`), mount/unmount API, cache management |
| `ui/volume_manager.py` | Volume creation wizard + mount/unmount panel in Tkinter |

### Safety mechanisms:
- **Double-mount prevention** — checks if volume is already mounted before allowing mount
- **Hash verification** — SHA-256 hash per file for integrity checking
- **Corrupt volume handling** — graceful errors instead of crashes on malformed containers
- **Disk-full safe saves** — atomic write to `.tmp` then `os.replace()` for crash safety
- **Graceful shutdown** — `atexit` + signal handlers unmount all volumes on app exit

## Trade-offs

| Trade-off | Decision | Rationale |
|-----------|----------|-----------|
| Chunk size | 64KB (not 4MB like .qcx) | FUSE random-access performance matters more than throughput |
| Cache size | 100MB LRU default | Balance between memory use and read performance |
| FUSE dependency | Required for mount, optional install | Can't avoid external dep for filesystem mounting; app detects and guides user |
| Auth params in cleartext | Yes | Required to derive key without already having key; contains no secrets |

## Testing

- 283 tests passing (volume crypto, FUSE ops, auth params, graceful shutdown, edge cases)
- Coverage: 97% on `core/` modules
- All crypto uses `secrets.token_bytes()` per project convention

## 2026-09-06 addendum — known behaviour on macFUSE / FUSE-T

- **A folder holding a file another app still has open cannot be removed.**
  Unlinking such a file is deferred by libfuse (it renames the file to
  `.fuse_hiddenXXXXXXXXXXXXXXXX` and removes it after the last close), so
  `rm -rf` of the folder ends with "Directory not empty" even though Finder
  shows it empty; close the file and retry. Letting the removal succeed was
  tried (review runs 15–16) and withdrawn: the macFUSE kernel revokes the
  open file's descriptors the moment the directory goes, and the app loses
  its unsaved writes.
- `.fuse_hidden…` names may appear in listings while such a file is open.
  Ones libfuse created in this session are removed at unmount; a leftover
  from a crashed session is an ordinary file — delete it. Renaming such a
  name back to a real file name does not rescue it: libfuse keeps the node
  marked hidden through the rename and unlinks it at its new name after the
  last close (traced on macFUSE 5.1.3, review run 18). The volume persists
  the content at that close and then applies libfuse's delete, so nothing
  is lost by the write-back — the file is simply still deleted.
- `cp -p`/`rsync -a` onto a mounted volume may journal several records per
  file: macOS delivers permission and time changes before the buffered data,
  and macFUSE stores copied extended attributes in `._` sidecar files.

## 2026-09-06 addendum — read-only mounts

`mount_volume()` probes `os.access(W_OK)` on the container *and* its folder
(journal appends need the file, compaction needs a temp file beside it). If
either refuses, the volume is served read-only: `-o ro` to FUSE, every
mutating operation answers `EROFS` before touching state, nothing is ever
saved, no sidecar lock is taken (two readers cannot corrupt a journal), and
the `volume_mount` / `volume_list` results carry `read_only` so both UIs
badge the drive. A vault on a read-only disk image or a locked share
therefore opens instead of failing on the first write. A sync client must
not touch a mounted vault. The mount keys its identity on the *descriptor*
it opened, not the path, and refuses the next save with `ESTALE` when the
file on disk is no longer the one it opened — a version restored over it
(new inode), an in-place `cp` / `> file` (same inode, checked by re-reading
the header through the descriptor), a shortening, a rename or move (the
inode still has a name), or an outright removal. In every case the mount
flips read-only and keeps serving what it opened; nothing is appended into
the foreign file, so a rename-style restore reopens intact. When the inode
was *orphaned* (a replace / overwrite / removal unlinked what the mount
held) the records this session wrote live only in that descriptor, so they
are copied to a `<vault>.qcv.stale-<stamp>` sidecar before the unmount frees
it — reopen that sidecar to recover them (review runs 19–20). The residual
gap is an older copy of the *same* volume that happens to be at least as
long as the live journal: inode, size and header all match, and only the
deferred format work (a length trailer + header-as-AAD) closes it. The
decision is made
once: fixing the permissions requires a remount, and a mount that *loses*
writability afterwards flips itself to read-only on the first failed save
(the write that hit the failure is reported to the caller and lost). A
read-only reader pins the container inode at open, so a writer elsewhere
compacting the same file leaves the reader on a consistent, stale snapshot
until it remounts. Review record: `review-2026-09-run13-fixes.md`, runs 14–15.

## 2026-09-04 addendum — format version 3

Format 3 keeps the version-2 layout and adds two fields to the cleartext
auth-params block and to the sealed metadata: `kem` (ML-KEM-768 for every
new volume; absent means the round-3 Kyber-768 that versions 1 and 2 used)
and, for password volumes, `argon2` (`{t, m, p}`, the parameters the volume
was made with, so the shipped cost can be raised later without stranding
existing volumes; a reader is bounded to t ≤ 32, m ≤ 1 GiB). `open()`
compares every cleartext auth-params field with its sealed copy, requires
every sealed auth field to be present in the block, and checks the header's
version word against the sealed `format_version` (review runs 13–14), so an
edited, stripped or downgraded block is reported as tampering, not as a
wrong password; `_read_auth_params` also requires `mode` and validates the
share counts before any credential is asked for. `compact()`
preserves a container's version (a 2 stays a 2) because the new fields are
creation-time facts a rewrite cannot add. Design record:
`docs/design/audit-2026-09.md`, decision D7.
