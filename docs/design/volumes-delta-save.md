# Design: Delta-save for .qcv volumes (format v2)

Status: **implemented** — shipped as `VOLUME_FORMAT_VERSION = 2` (append-only journal + compaction). The prose below is kept as the design record; where it reads as a proposal, read it as history.

## Problem

`VolumeContainer.save()` rewrites the entire container on every invocation.
Even a 1-byte edit to one file inside a 1 GB volume writes 1 GB to disk (via
`.tmp` → `os.replace()` → `fsync()`). For a user who mounts a 5 GB vault, edits
a single document, and unmounts, the unmount cost is proportional to the whole
vault, not the edit.

The existing mitigations (this commit) bring mount, read, and save peak RAM
under control by lazy-loading blobs and streaming the save copy instead of
accumulating. But the wall-clock I/O cost of save itself — "rewrite the
world" — remains.

## Options

### A. Append-only log (chosen for follow-up)

Container layout becomes:

```
[Header]  (unchanged except FORMAT_VERSION=2 + journal pointer)
[Auth Params]   (unchanged)
[Baseline Metadata]     (snapshot at last full compact)
[Baseline Directory]    (snapshot at last full compact)
[Baseline Blobs...]     (snapshot)
[Journal Section]       (append-only log of new/modified/deleted entries)
    [Record 1 Header][Record 1 Body]
    [Record 2 Header][Record 2 Body]
    ...
```

Each journal record:

```
record_header: {
  type: "write" | "delete" | "rename" | "mkdir" | "rmdir",
  vpath: "...",
  nonce, chunk_count, data_length, ...
}
record_body:
  - for "write": the encrypted blob
  - for others: empty
```

`save()` only writes new records to the journal (append). On `open()`, replay
the journal on top of the baseline. When the journal exceeds a threshold
(e.g., 30% of the baseline size), run `compact()` to rebuild the baseline and
truncate the journal.

**Pros:** `save()` cost is proportional to the edit, not the container.
**Cons:** Format migration; open() must replay the log; compaction needs its
own atomic strategy (currently `.tmp` + `os.replace()` still works for
compaction, which is a rarer operation).

### B. Fixed-block allocation

Allocate all blob space in 4 KB / 64 KB blocks, track a free list. Overwrites
write to a new block and update the pointer; old block returns to the free
list. Save only writes changed blocks + metadata.

**Pros:** In-place edits possible; constant-time save.
**Cons:** Fragmentation; free-list management is bug-prone; requires a
full-volume rewrite to migrate from v1.

### C. Separate blobs-per-file (extract from container)

Split the .qcv into a directory of files: one for metadata, one per blob.
Save just rewrites the changed file(s).

**Pros:** Simple; reuses filesystem atomicity.
**Cons:** No longer a single-file container (breaks the UX promise of
"drag one file to back up your vault"); many small files is bad for cloud
storage syncing (Dropbox/iCloud behave poorly with thousands of tiny files).

## Decision

Go with **Option A (append-only log)** when this work is picked up. It
preserves the single-file UX, gives proportional save cost, and degrades to
the existing format for backward-compat reads (v1 = baseline with empty
journal).

Option B is rejected because fixed-block layout is complex relative to the
win. Option C is rejected because the single-file UX is non-negotiable.

## Trade-offs

- **Open latency** grows with journal size. We bound it by triggering a
  compact when the journal exceeds 30% of the baseline.
- **Crash safety** requires each journal record to be self-contained (own
  length prefix + own HMAC). If the tail of the journal is corrupt, replay
  stops at the last valid record — like a database WAL.
- **Compaction atomicity** keeps the `.tmp` + `os.replace()` approach for
  the full rebuild, inheriting the existing save() semantics. A user-visible
  "compact" menu item would let power users trigger it explicitly.
- **Backward compatibility:** v1 containers open as "baseline + empty
  journal" — the first save() with journal support writes a small journal
  and bumps the in-header FORMAT_VERSION field. Older app versions fail to
  open v2 containers with a clear version-mismatch error (reuses the existing
  FORMAT_VERSION gate).

## Scope (when this is picked up)

1. Bump `VOLUME_FORMAT_VERSION` to 2 and add reader/writer dispatch.
2. Add `_write_journal_record` and `_replay_journal` helpers.
3. Track a `_journal_dirty: list[dict]` on `VolumeContainer` in addition to
   `_file_data`. `save()` writes records; `compact()` rebuilds.
4. Trigger compact when `len(journal) > 0.3 * len(baseline)` on open or
   when user invokes "Compact volume" from the Volume Manager.
5. Migration test: v1 container → reopen → write a file → confirm journal
   appears and read-back works.
6. Crash test: simulate truncated journal → reopen → confirm replay stops
   at the last good record and the remaining state is consistent.

## Status

**Implemented.** Shipped as `VOLUME_FORMAT_VERSION = 2` in `core/volume.py`.

Deviations from the original proposal:

- The journal starts implicitly at `_data_offset + _baseline_size` (computed
  from the decrypted directory) instead of being recorded as an explicit
  offset field in the header. The 512-byte header layout is unchanged from
  v1; only its 4-byte format-version field (`_OFF_VERSION` in
  `core/volume.py`) is bumped to 2. This keeps the header layout stable
  across versions and avoids tying a header byte to a derived value that
  could drift. Since 2026-09-05 `open()` also cross-checks that field
  against the sealed `format_version` (review run 13, F-020).
- Each journal record carries its own encrypted header + GCM tag; a
  truncated tail simply fails to decrypt and replay stops there. No
  separate per-record HMAC on top of GCM.
- Compaction thresholds are implemented as `save()` heuristics rather
  than a background task. The original rule (journal > 30 % of the
  baseline, or > 1 MB against an empty baseline) was replaced by the
  dead-space rule in the 2026-09-04 addendum below (dead space > 30 % of
  live + 8 MB, or > 10k records); `save()` still rolls into `compact()`
  synchronously.
- V1 containers upgrade on first save via a single compact pass; mixed
  v1-header + v2-journal containers never exist on disk.
- `compact()` is a public method so future UI work can expose a
  "Compact volume" menu entry.

Test coverage: `TestFormatV2Journal` exercises replay of each op type,
auto-compact trigger, v1→v2 upgrade, truncated-journal tolerance, and
corrupt-record skip. Core coverage held at ≥ 95 %.

## 2026-09-04 addendum — compaction trigger, tombstones, compaction temp file

Measured in the audit (`docs/design/audit-2026-09.md`): replay cost is per
record (bodies are seeked over), so journal *size* predicted neither open
latency nor wasted disk. Two consequences of the 30 %-of-baseline rule:

- a volume that was filled and emptied kept its full size forever — the
  delete records were tiny, so the ratio never fired (2,000 files deleted:
  container grew by 174 KB and 138 MB of dead blobs stayed);
- 25 MB of fresh, live writes on a 64 MB baseline forced a full rewrite for
  no benefit.

`save()` now compacts when the **dead bytes** (data region minus the live
blobs actually on disk — deleted files, superseded versions, record headers)
exceed 30 % of the live bytes and the 8 MB floor, or when the journal holds
more than 10,000 records. Delete-all now compacts back to an empty container
on the save that empties it; a rewrite-heavy workload compacts at the same
point as before.

Two further changes from the same audit:

- **Tombstones before a write of the same path are dropped.** The editor
  atomic-save pattern emitted `[delete /final][write /final]`; a disk-full
  error while writing the body left the complete tombstone durable and the
  next open showed the file missing with nothing suspicious to report
  (reproduced). Replay's write sets the entry unconditionally, so the
  tombstone was redundant; without it the same failure keeps the previous
  content.
- **`compact()` writes through `mkstemp`** (`.<name>.qc-compact-*`) and
  copies the container's permission bits onto the replacement. The fixed
  `<path>.tmp` opened with the umask widened a 0600 container to 0644 on its
  first compaction, and was a symlink target.
- **Blob reads use one `pread()` descriptor** for the container's life
  (reopened after a compaction replaces the inode). Opening the file per 64 KB
  chunk was 44 µs against 2.5 µs for the read itself; an LRU-miss FUSE read
  went from 0.12 ms to 0.05 ms.
