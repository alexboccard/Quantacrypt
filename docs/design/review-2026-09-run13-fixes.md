# Review run 13 (2026-09-05) — fix batch

**Input:** `.review/FINAL.md` from the thirteenth fresh-agent `/iterative-review`
on v1.4.0 (`e30758c`): 37 findings, 0 Critical / 0 High / 2 Medium / 21 Low /
14 Nit, verdict *Healthy*. Rounds 2 and 3 were allowed to execute (test suite,
scratchpad repro scripts, a 600-seed differential journal fuzz); 15 findings
carry a reproduction and one (F-014) was found by the fuzz alone.

**Decision:** fix every finding in one batch — the two Mediums first, then the
"wrong story" cluster, then the nits — and keep the fuzz harness as a test.
Nothing here changes a wire format; the one format-level item (binding the
`.qcv` header as AAD) is deferred to the next `VOLUME_FORMAT_VERSION` bump.

## What changed, by finding

| ID | Sev | Change | Where |
|----|-----|--------|-------|
| F-001 | M | No-op `chown` (existence check via `set_attrs` with nothing to change) so fusepy stops answering `EROFS` to `cp -p` / `ditto` / `rsync -a` | `core/fuse_ops.py` |
| F-002 | M | `truncate()` refuses extension past `_max_writable_bytes()` with `EFBIG`, same as `write()` | `core/fuse_ops.py` |
| F-003 | L | `suspect_sidecar` decoded by `VolumeMountResult`, named in both UIs' "may have been altered" alert, documented in the protocol table | `CoreProtocol.swift`, `VolumesModel.swift`, `VolumesView.swift`, `ui/volume_manager.py`, `core-service-protocol.md` |
| F-004 | L | `volname` = sanitised container stem (`_volname_for`) | `core/fuse_ops.py` |
| F-005 | L | `stamp_version.py` also stamps `CFBundleVersion` | `scripts/stamp_version.py` |
| F-006 | L | Unmount loop in `Service.shutdown()` catches `BaseException` per volume and keeps going; the Swift client derives its shutdown deadline from the mounted count (`10 + 35·max(1,n)` s) | `core/service.py`, `CoreClient.swift`, `AppDelegate.swift`, `AppState.swift` |
| F-007 | L | `validate_kem` requires a `str` | `core/crypto.py` |
| F-008 | L | `decode_share` requires a JSON object and an integer `threshold`; Tk raw-code path also catches `TypeError` | `core/crypto.py`, `ui/decryptor.py` |
| F-009 | L | Decoder rejects a first word whose padding bits are set (`raw >> 545 != 0`) before masking; docstring/comment corrected | `core/crypto.py` |
| F-010 | L | `extract_share_codes` walks back from the end of a word run in 50-word checksum-verified segments; Swift `ShareFiles` splits exact multiples of 50 (its approximation, commented) | `core/package.py`, `ShareFiles.swift` |
| F-011 | L | Tk encryptor captures `out` and the source name at `_done`; pending-shares token is the output path | `ui/encryptor.py` |
| F-012 | L | `m ≥ 8·p`, salt ≥ 8 bytes, `HashingError` re-raised as `ValueError` | `core/crypto.py` |
| F-013 | L | `chmod`/`utimens` call `_persist_locked()`; mtime kept at fusepy's precision (float). **Plus a bug the live check exposed:** a `utimens` issued *before* close (the `cp -p` / rsync / tar order) was overwritten by the flush in `release()`, which rebuilt the entry with the copy time. `QuantaCryptFUSE._explicit_mtime` now carries the stamp into `write_file(mtime=…)`; a later `write()` clears it | `core/fuse_ops.py`, `core/volume.py` |
| F-014 | L | `_coalesce_pending_ops` drops setattrs a later write supersedes (the fuzz-verified one-liner); the differential fuzz lives in `tests/test_review_run13.py` (240 seeds) | `core/volume.py` |
| F-015 | L | `decrypt_streaming` coerces `n`/`sz`/`ts` (cap 9999-12-31); `os.utime` catch broadened | `core/crypto.py`, `core/package.py` |
| F-016 | L | Sidecar `os.open` `EROFS`/`EACCES`/`EPERM` → per-container lock under `~/Library/Application Support/QuantaCrypt/locks/<sha256>` (XDG state dir elsewhere); only `EWOULDBLOCK` means "another process", other flock errnos warn and proceed with the in-process guard | `core/fuse_ops.py` |
| F-017 | L | After the KEM private key unseals, decapsulation and metadata-HMAC failures raise `CorruptPayload`; `mount_volume(credential_proven=True)` → `VolumeContainer.open(credential_proven=True)` reports a metadata `InvalidTag` as tampering; README claim rewritten | `core/package.py`, `core/volume.py`, `core/fuse_ops.py`, `core/service.py`, `ui/volume_manager.py`, `README.md` |
| F-018 | L | Mount-point check ignores `.DS_Store`/`.localized`/`Icon\r`, names the first real entry, raises `InvalidInput` | `core/fuse_ops.py` |
| F-019 | L | `folder_stats`/`zip_folder` skip everything that is not `S_ISREG` (FIFOs, sockets, devices) and report it with the symlinks | `core/package.py` |
| F-020 | L | `open()` compares the header version with the sealed `format_version` | `core/volume.py` |
| F-021 | L | `_read_auth_params` validates `mode`/`threshold`/`total`; `open()` requires every sealed auth field to be present in the block | `core/volume.py` |
| F-022 | L | `addopts` measures the whole package; release `test` job runs `check_coverage.py --min 95` | `pyproject.toml`, `release.yml` |
| F-023 | L | conftest comment states the real invariant; `TestFixtureKdfFloor` reads every committed fixture's recorded parameters | `tests/conftest.py`, `tests/test_review_run13.py` |
| F-024 | N | README names the native shell as the accessible path | `README.md` |
| F-025 | N | `shell: bash` on the `tee` steps; `timeout-minutes: 60` on the release `test` job | `ci.yml`, `release.yml` |
| F-026 | N | `wait_idle` shares one deadline across workers | `core/service.py` |
| F-027 | N | A directory override is refused (names the executable inside a bundle) | `HelperLocator.swift` |
| F-028 | N | `mountPointChosenFor` resets the default when the volume changes | `VolumesModel.swift` |
| F-029 | N | Decrypted output fsynced before placement | `core/package.py` |
| F-030 | N | Foreground mount runs `save_all_dirty(apply_pending_unlink=True)` when `FUSE()` returns | `core/fuse_ops.py` |
| F-031 | N | Protocol doc, README FUSE line, RELEASING local install, encryptor comments updated | docs, `ui/encryptor.py` |
| F-032 | N | Delta-save doc corrected; dead test stub and side-effecting conditional removed | `volumes-delta-save.md`, `tests/test_audit_2026_09.py` |
| F-033 | N | Missing-HMAC message no longer mentions versions; `hmac` checked before the version keywords in both classifiers | `core/crypto.py`, `core/errors.py` |
| F-034 | N | `fmt_size` uses decimal units like Finder and the native shell | `ui/shared.py` |
| F-035 | N | `LRUCache.put` pops `_sizes` on update | `core/fuse_ops.py` |
| F-036 | N | Updater ignores a non-object JSON body | `ui/updater.py` |
| F-037 | N | Word-validity check uses the hash index | `core/crypto.py` |

## Trade-offs and deliberate choices

- **F-017 signal shape.** A successful `derive_volume_key_*` *is* the credential
  proof (the KEM private key only unseals under the right password/shares), so
  the caller passes `credential_proven=True` rather than the derive function
  returning a flag — the public signatures stay as they were. A caller that
  hands `open()` a key from elsewhere keeps the old "may be incorrect" answer.
- **F-020 and real v1 containers.** The sealed `format_version` arrived with the
  journal (`ec9e01b`), so genuine format-1 files carry none and are exempt
  (`is not None`). Two tests that simulated "v1" by patching the header word
  alone now rebuild the container the way the v1 code wrote it
  (`_downgrade_to_v1` in `tests/test_volume.py`).
- **F-010 asymmetry.** Python verifies each 50-word segment by checksum walking
  back from the end of the run; Swift, which has no wordlist, splits exact
  multiples of 50 and otherwise keeps the last 50. A header followed by two
  phrases resolves to two shares in Python and one in Swift; the native shell
  hands the text to the helper for the authoritative parse anyway.
- **F-016 no-lock case.** `ENOLCK`/`EOPNOTSUPP` (some NFS/SMB) now mounts with a
  logged warning and the in-process guard only; previously such a volume could
  not be mounted at all, and "another process" sent the user hunting.
- **F-013 cost.** Persisting on every `chmod`/`utimens` adds one journal append
  (with fsync) per attribute op; rsync-style copies already persist once per
  file in `release()`, so this roughly doubles the appends for that workload
  and buys durability of the last file's timestamp across SIGKILL.
- **F-027.** A `.app` override is refused, not resolved to `Contents/MacOS/…`:
  the approval store is keyed by the path the user typed.
- **F-006 client deadline.** With nothing mounted the deadline is now 45 s
  (was 30 s), per `10 + 35·max(1, n)`.

## Verification

- Python: `tests/test_review_run13.py` (63 tests, one per finding cluster,
  240-seed journal fuzz); full suite and per-file coverage floor — see the
  session log in `Profile/meta-learnings.md` for the numbers.
- Swift: 121 XCTest cases green, `-warnings-as-errors`.
- **Live check on macFUSE 5.1.3 (this host), 2026-09-05** — a throwaway
  volume mounted through `mount_volume(credential_proven=True)`:
  - `cp -p /etc/hosts`, `ditto`, `rsync -a`: all exit 0 (F-001; before the
    fix fusepy answered `EROFS` to the `fchown` each of them issues).
  - `cp -p` of a 0640 file stamped `1234567.5`: the mount shows
    `mode=0640 mtime=1234567.5`, and the reopened container holds the same —
    this is what surfaced the pre-close `utimens` loss noted under F-013;
    the first run showed `mtime=<copy time>`.
  - `os.chown` to the mounting user on a file the tools created: ok.
  - `ftruncate` past `_max_writable_bytes()`: `EFBIG` (F-002), nothing
    zero-filled.
  - `diskutil unmount` refused while the check script itself still held an
    fd open on the volume (its own bug) and succeeded once it did not — the
    app's "in use by another application" path, working as written.
  - Observation, not fixed: macFUSE writes AppleDouble `._*` sidecars for
    Finder/`cp -p` xattrs into the volume. Cryptomator mounts with
    `noappledouble`; whether FUSE-T accepts the option needs checking before
    it is added.

## Deferred

- Header-as-AAD for the `.qcv` metadata/directory GCM calls — next format bump
  (with the authenticated journal length trailer, F-038 of run 9).
- A compaction-interleaved journal fuzz (`compact()` mid-sequence,
  `_pending_unlink`) — the obvious next harness.

## Run 14 (2026-09-06) — validation of this batch, and the second batch

Run 14 (three fresh rounds + synthesis, `.review-archive-20260906T*/FINAL.md`)
reviewed the working tree above: **20 findings, 0 Critical / 0 High / 3 Medium /
13 Low / 4 Nit; batch status 30 hold / 5 incomplete / 2 regressed.** All three
Mediums were regressions of this batch, in two areas; all 20 are fixed below.
Round 3 also ran a compaction-interleaved differential fuzz (3000 journal / 3000
crash / 1500 FUSE-model seeds) whose only divergences were the `_explicit_mtime`
classes fixed here.

| Run-14 ID | Sev | Was | Change |
|-----------|-----|-----|--------|
| F-001, F-002, F-014 | M, M, L | The F-016 lock fallback mounted a read-only container (or a writable one in an unwritable folder) read-write; mutations failed after the in-memory index changed, compaction failed on `mkstemp`, unmount could not save; the `EACCES` fallback let two users each hold "the" lock | **Read-only mount mode replaces the fallback.** `mount_volume()` probes `os.access(W_OK)` on the container *and* its directory (`_container_writable`); an unwritable layout sets `VolumeContainer.read_only`, passes `-o ro` to `FUSE()`, takes no sidecar lock (two readers cannot corrupt a journal), and every mutating op (`create`/`mkdir`/`rmdir`/`unlink`/`rename`/`write`/`truncate`/`chmod`/`utimens`/`chown`, `open` for writing) raises `EROFS` before touching state; `save_all_dirty` is a no-op. The `volume_mount` result carries `read_only`, both UIs say "Mounted read-only". `_fallback_lock_path` is gone; `EACCES` on the sidecar of a writable layout means another user's lock → `busy` |
| F-003, F-006, F-007 (F-005) | M, L, L | A stale `_explicit_mtime` entry was applied to unrelated content renamed over the name; the stamp was lost on `save_all_dirty` and directory renames; `utimens` on a dirty file cost an extra journal append | The map is per-path state like the buffers: `flush()`/`release()`/`save_all_dirty()` consume it (an unchanged flush journals the stamp via `set_attrs`), `create`/`unlink`/the replaced rename destination drop it, directory `rename` re-keys it. `utimens` on buffered data updates the entry with `set_attrs(record=False)` and records nothing — the write record carries the stamp (one append per copied file) |
| F-005 | L | fusepy delivers libfuse's `UTIME_OMIT`/`UTIME_NOW` timespecs as `1.073741822`/`1.073741823` s; an atime-only `touch -a` stamped the file with 1970 | `utimens` treats those two values as "leave mtime" / "now" (`_FUSEPY_UTIME_OMIT/_NOW`) |
| F-013 | L | `chmod`/`utimens`/`chown` on the mount root returned `ENOENT`; `rsync -a src/ mount/` and `cp -Rp` exited non-zero after copying everything; `getattr("/")` reported `now` on every call | Root mode/mtime live on the `QuantaCryptFUSE` instance (mount time by default), settable, stable; not persisted — a remount's root is as new as the mount |
| F-009, F-012 | L, N | A block with no `mode` defaulted to a password prompt for a split-key volume (the run-13 F-021 fix was incomplete for the pre-derivation path); `threshold: 1` passed | `_read_auth_params` requires `mode` and `2 ≤ threshold`; the `"single"` defaults in `service.py` and the Tk manager are gone. `_AUTH_VOCABULARY` is pinned by a test to the union of both writers' keys |
| F-004 | L | `Service.shutdown()`'s join loop ran before the guarded unmount loop and joined each worker for the full 5 s | One deadline across the joins; a `ServiceStop` there breaks out and the unmount loop still runs |
| F-008 | L | `CFBundleVersion` stamped with the raw tag (`1.5.0-beta` is malformed to LaunchServices) | `_bundle_version()` keeps the numeric prefix; `TARGETS` carry an `expected(version)` so `--check` and the post-write verify compare the right value; `plan()` reports a missing file once and counts distinct files |
| F-010 | L | `truncate()` decrypted the whole file to shrink it; a path-based truncate left the plaintext resident for the life of the mount | `length == 0` reads nothing, a shrink reads `read_file_range(0, length)`, and a path-based truncate drops the buffer once persisted when no fd is open |
| F-011, F-018 | L, N | `extract_share_codes` only tried windows aligned to the *end* of a word run (a wordlist trailer hid the phrase); codes were collected before phrases, so "order of appearance" was false | `_phrases_in_run`: end-aligned pass, then start-aligned, then every offset only if both found nothing (bounds the 1-in-256 false accepts); one pass over the lines keeps codes and phrases in order |
| F-015 | L | The run-13 design note claimed genuine v1 containers sealed no `format_version`; `69ccf52` sealed it as 1 | Note corrected here; `_downgrade_to_v1` writes sealed 1. **Decision:** the one shape shipped code produced with header ≠ sealed — v1.3.0's `compact()` sealed the metadata before bumping the field, so a v1 container upgraded once by that same-day dev build carries header 2 / sealed 1 — is rejected as tampered rather than special-cased (population: 2026-04-21 dev builds only; test pins the rejection) |
| F-016 | L | `TestFixtureKdfFloor` asserted only inside `if "argon2" in …`, and no committed fixture recorded parameters | `tests/fixtures/current/{single.qcx,single.qcv}` (format 2 / 3, written outside pytest at the shipped cost) plus `credentials.json`; the test requires recorded parameters for recording formats and round-trips both fixtures under `real_argon2` |
| F-017 | N | `_AUTH_VOCABULARY` hand-maintained; `_words_to_int` dead; comment/docstring disagreement on which tool stamps before close | Pin test; dead function removed; comments say cp -p (before close) vs rsync/tar/unzip (after) |
| F-019 | N | Every subset run exits non-zero on `fail_under` | `--no-cov` documented in CLAUDE.md and README |
| F-020 | L | `volname=` passed to `FUSE()` on every platform; libfuse on Linux rejects unknown `-o` options | Passed on Darwin only |
| Nits | N | README credential-step sentence, volumes design addendum, ENOLCK warn-and-proceed untested | Fixed; tested |

### Live check 2 (macFUSE 5.1.3, this host)
Recorded in the session log; in brief: `rsync -a src/ mount/` and `cp -Rp src mount/copy` exit 0 (root `utimens` accepted), `cp -p`'s pre-close stamp survives, `touch -a` leaves the mtime alone, an `O_TRUNC` rewrite works without a full decrypt, and a 0444 container in a 0555 folder mounts with `read-only` in the mount flags, refuses `cp` with `EROFS`, leaves no sidecar lock and unmounts cleanly.

## Run 15 (2026-09-06) — validation of batch 2, and the third batch

Run 15 (`.review-archive-20260906T03*/FINAL.md`): **20 findings, 0 Critical /
0 High / 1 Medium / 16 Low / 3 Nit; batch 18 hold / 3 incomplete / 0
regressed; verdict Healthy.** The Medium is pre-existing since v1.3.0, not a
regression. Round 3's 2,500-seed model-based FUSE fuzz with compaction
interleaved found no content/index divergence; a 40-seed read-only fuzz found
none. All 20 are fixed below.

| Run-15 ID | Sev | Was | Change |
|-----------|-----|-----|--------|
| F-001 | M | `create()`/`mkdir()` dropped the kernel's umask-applied mode: every file 0644, every directory 0755, so `ssh-keygen` into the vault produced a key `ssh` refuses | `write_file(mode=)` / `mkdir(vpath, mode=)`; the FUSE ops pass the kernel's mode; type bits always come from the entry (`_typed_mode`) |
| F-010, F-017, F-015, F-003 | L | The deferred `utimens` stamp lived in two places (index entry via `set_attrs(record=False)` + the map), so `getattr` and disk disagreed after a superseding identical write; `chmod` on a dirty file still journaled at once; `release()`/`save_all_dirty()` lacked `flush()`'s unchanged shortcut; the sentinel guard matched one float | `_explicit_mtime` → `_deferred_attrs` (`mode` and `mtime`), kept **only** in the map: `getattr` overlays it, `write`/`truncate` drop the mtime (a modification) but not the mode, every flush path goes through one `_write_back()` (re-encrypt with the deferred attrs, or `set_attrs` when the bytes are unchanged). `set_attrs(record=)` reverted. `_decode_fuse_mtime()` decodes the nanosecond field (libfuse `(1<<30)-2/-1` and Darwin `-2/-1` alike) and clamps stored stamps at 0 |
| F-006 | L | A read-only reader beside a writer's `compact()` opened the new inode against the old index (every read `EINVAL`) | `VolumeContainer.open()` pins `_reader_fd` at once; the reader serves a consistent stale snapshot (documented in `encrypted-volumes.md`) |
| F-012 | L | Writability lost *after* mount: every later op failed after the fact and unmount could not save | `_persist_locked()` flips the mount read-only on `PermissionError`/`EROFS` (the failing change is reported and lost); `unmount_volume()` proceeds to the OS unmount on that class instead of "in use" |
| F-013 | L | `PermissionError` on the sidecar always said "in use by another user" | `stat` the sidecar: foreign uid → that sentence; own or missing → "could not be opened (permission denied); fix its permissions or remove it" |
| F-002 | L | `rmdir` counted unlinked-but-open children `readdir` already hid | `_pending_rmdir`: a directory whose only children are held open is hidden and removed with the last child's close (or at shutdown); re-creating it cancels the deferral |
| F-019, F-020, F-021 | L, L, N | Size-preserving `truncate` was a modification; a refused `EFBIG` path-truncate retained the whole plaintext; path-truncate ignored `_pending_unlink` | No-op when `length == current`; ceiling checked before anything is decrypted; `ENOENT` for a pending-unlink name |
| F-011 | L | `_phrases_in_run` returned on its first hit, so "share one / phrase / share two / phrase" (all wordlist words) kept only the last phrase | Each pass recurses on the part of the run it did not consume |
| F-005, F-016 | L | `Service.shutdown()`'s `get_mounted_volumes()` sat outside the `BaseException` guard | The mount list is taken under the same guard (falls back to the tracking dict) |
| F-004, F-018 | L | Pre-release tags: the checkout guard test demanded one string across files; the Tk bundle's plist still got the raw tag | The test compares each target with `expected(release)`; `build.py::_patch_plist` applies the numeric-prefix rule; RELEASING.md documents that a beta and its final share one `CFBundleVersion` |
| F-007, F-009, F-014 | L, L, N | Swift ignored the `read_only` now on every `volume_list` entry; the Tk mounted list never showed read-only; module docstring named macFUSE as FUSE-T | Swift decodes the wire flag (authoritative; the set is a fallback); Tk row carries a warning-coloured caption; docstring fixed |
| F-008 | L | Read-only mode documented only in the protocol table | `encrypted-volumes.md` "Read-only mounts" addendum + a README sentence |
| Nits | N | `_volume_locks` typing; `lock_fd` annotation | Fixed |

Fuzz harnesses used by the validators (journal + compaction, FUSE model,
read-only) live in the session scratchpad; the in-tree fuzz is
`TestJournalDifferentialFuzz` (240 seeds).

### Live check 3 (macFUSE 5.1.3, batch 3)
- `open(O_CREAT, 0600)`, `mkdir(0700)` and `ssh-keygen -f <mount>/key` all land with
  the requested mode and survive a reopen (F-001).
- `touch -a` leaves the mtime; a size-preserving `truncate` journals nothing.
- `rm -rf dir` with one file inside held open: exit 0. **What the mount taught:**
  libfuse's high-level API does not send `unlink` for an open file — it
  renames it to `.fuse_hiddenXXXX` and unlinks that on the last release, so
  `rmdir` sees that name (now counted as pending). Hiding a deferred
  directory from `getattr` made libfuse pass a NULL path on the open child's
  `flush` (`EINVAL` on close, last writes lost) — fd-based operations now
  resolve their path from the fd (`_fh_vpath`) and a deferred directory stays
  visible until its last child closes. macOS reclaims vnodes lazily, so that
  release may never arrive before unmount; the certain-shutdown path deletes
  `.fuse_hidden*` entries and the directories waiting on them.
- `cp -p` of one file journals ~14 records, not 1: the kernel delivers
  `chmod`/`utimens` **before** the buffered data write (so they are journaled
  at once, not deferred), and macFUSE stores the copied xattrs in an
  AppleDouble `._copied` sidecar whose own create/write/setattr traffic
  persists everything pending in between. Per-file record counts through a
  real mount therefore depend on kernel ordering; the deferral helps when
  the data arrives first (direct callers, some tools). `noappledouble` would
  remove the sidecar traffic — still an open question for FUSE-T.

## Run 16 (2026-09-06) — validation of batch 3, and the fourth batch

Run 16 (`.review-archive-20260906T*/FINAL.md`): **25 findings, 0 Critical /
0 High / 3 Medium / 13 Low / 9 Nit; batch 10 hold / 2 incomplete / 1
regressed; verdict Concerns.** All three Mediums sit in the two areas batch 3
rewrote (read-only mode and the deferred rmdir). Round 3's model-based FUSE
fuzz (1500 / 1000 / 1000 seeds) diverged only on the `release("-")` class
fixed here. All 25 are fixed below.

| Run-16 ID | Sev | Was | Change |
|-----------|-----|-----|--------|
| F-001 | M | `volume_list` and the Tk list reported the mount-time `read_only`; after a mid-session flip both UIs said "writable" | `get_mounted_volumes()` refreshes each entry's `read_only` from the live container, so every consumer (service, Tk, Swift's authoritative wire flag) sees the flip |
| F-002 | M | `apply_pending_unlinks()` deleted and saved on a read-only or flipped volume, so `unmount_volume()` raised **after** the OS unmount had succeeded ("permission denied" for a volume that was gone; `unmount_failed` at quit) | Early return when `read_only`; the sweep is provenance-tracked (below) |
| F-003 | M | A deferred `rmdir` returning 0 makes libfuse unhash the node; with `flag_nullpath_ok` unset libfuse then answers **ENOENT itself** for read/write/fsync/fstat on the open child (the batch-3 "NULL path" story was only half right: only `flush` got NULL and `release` got the placeholder `"-"`) | `flag_nullpath_ok = 1` on `QuantaCryptFUSE` (fusepy copies it; member order verified against macFUSE's `fuse.h`), `_fh_vpath` resolves **fd first** (handles NULL and `"-"`), `read()` converted, `readdir(None)` → ENOENT; a deferred directory is hidden from the namespace again (getattr/readdir) now that its open children are reachable by fd |
| F-008 (R2 F-101) | L | `release("-")` became the vpath `/-`: buffer retained, deferred directory visible until unmount, pending-unlink file never deleted (the fuzz's only divergence) | fd-first resolution (the release-time deletion of hidden names was withdrawn with the deferral; the shutdown sweep remains) |
| F-010, F-013 (R2 F-103) | L | The shutdown sweep deleted **any** `.fuse_hidden*` entry (a user's file, litter from a crashed session), and a non-empty one aborted the unmount; stale litter deferred `rmdir` forever | `_hidden_seen` records the names libfuse renamed to in this session; only those are swept (`OSError` caught, logged at INFO). A `.fuse_hidden*` child with no open fd is an ordinary entry: `rm -rf` unlinks it first, a bare `rmdir` gets ENOTEMPTY as on any filesystem |
| F-004, F-005, F-018 (R2 F-104) | L, L, N | `_pending_rmdir` not re-keyed by `rename`; a live entry created under a deferred directory left both deferrals stuck; `mkdir` over a deferred name ignored the mode; by-name `chmod`/`utimens`/`chown` on a pending-unlink path succeeded | Directory rename re-keys pending descendants; `create`/`mkdir`/`rename`-into cancel every deferred ancestor; `mkdir` over a deferred name applies the requested mode; the three attribute ops answer ENOENT for a pending-unlink name (fstat by fd still works) |
| F-016 (R2 F-102), F-016 (R1) | L | The refused change stayed in the namespace after the flip; buffers of other files were dropped silently at unmount | `VolumeContainer.discard_unsaved()` re-reads the index from disk at the flip; `flush` on a flipped mount answers EROFS before memory moves ahead; `release`/`save_all_dirty` log what they drop |
| F-011 (R1 F-007) | L | `write()` decrypted the whole file before the EFBIG check | Ceiling checked first, like `truncate` |
| F-015 (R1 F-011) | L | Sidecar lock opened without `O_NOFOLLOW` | `O_NOFOLLOW \| O_CLOEXEC` and an `S_ISREG` check on the fd |
| F-009 | L | `bump-version` stamped master from any tag, including one on an older commit | `git merge-base --is-ancestor` gate; `fetch-depth: 0` |
| F-021 (R3 F-201) | N | A pre-release tag produced `1.5.0b0` from `importlib.metadata` and `1.5.0-beta` everywhere else | `stamp_version.normalize_version()` writes the PEP 440 form everywhere; `CFBundleVersion` keeps the numeric prefix |
| F-020 (R1 F-015) | N | Every negative stamp clamped to 0; `truncate(-1)` truncated to 0 | Negative stamps floored to whole seconds (representable; no negative `tv_nsec`); `EINVAL` for a negative length |
| F-017, F-019, F-022, F-023 (R1 F-013/F-014, R2 F-105/F-106, R3 F-202/F-203) | N | Two FUSE-T install spellings; developer path outside `#if DEBUG`; class-scoped fixtures as instance methods; `except Exception: pass` around the whole unmount loop; `__del__` after `os` teardown; `run_tests.sh` regex missing digits | One `FUSE_INSTALL_HINT`; `devVenv` under `#if DEBUG`; `@classmethod`; the handler narrowed to the import; `_os_close` bound at import + guarded `__del__`; regex widened |
| F-014 (R1 F-010) | L | fusepy 3.0.1 (archived) with `use_ns` unset: float-second stamps, a DeprecationWarning per mount | **Accepted for now**: switching to `use_ns` changes `getattr`'s return contract (nanosecond ints) across every caller and test; noted here and in the dependency notes as the next FUSE-binding decision |

### What the mechanism turned out to be — and the decision it forced
The batch-3 note "hiding the directory made libfuse lose the child's path"
was wrong: a successful `rmdir` unhashes the node in libfuse whatever
`getattr` says. Without `flag_nullpath_ok` libfuse answers ENOENT for every
fd operation on such a child without calling the filesystem, `flush` gets a
NULL path, `release` the placeholder `"-"`. With the flag set the fd is the
identity everywhere, which is what `_fh_vpath` now implements.

**Live check 4 then showed the kernel side:** with the flag set, a `read(2)`
on the open child after `rm -rf` of its directory worked, but `fstat(2)`
answered ENOENT (macOS sends GETATTR without an fh) and the next `write(2)`
failed with **ENXIO — the macFUSE kernel revokes the child's vnode once the
rmdir succeeds.** No userspace flag changes that. So the deferred-rmdir
design (batches 3–4: F-002 of run 15, F-003/F-004/F-005 of run 16) is
**withdrawn**: `rmdir` of a directory holding an unlinked-but-open file
answers ENOTEMPTY, as it did before batch 3. `rm -rf` of such a folder
fails visibly and is retryable after the app closes the file, where the
alternative silently lost that app's unsaved writes. Run 15's F-002
("`rmdir` answers ENOTEMPTY for a directory readdir reports empty") is
therefore an accepted platform limitation. What stays from the attempt:
`flag_nullpath_ok` + fd-first `_fh_vpath` (robust against NULL / `"-"`
paths), `readdir(None)` → ENOENT, the `_hidden_seen` provenance for the
shutdown sweep, and stale `.fuse_hidden*` litter treated as an ordinary
entry.

## Run 17 (2026-09-06) — validation of batch 4, and the fifth batch

Run 17 **converged at round 2** (round 2 added nothing and refuted nothing):
**16 findings, 0 Critical / 0 High / 1 Medium / 11 Low / 4 Nit.** The
deferred-rmdir withdrawal held; the one regression is in the version work.
All 16 are fixed below.

| Run-17 ID | Sev | Was | Change |
|-----------|-----|-----|--------|
| F-001 | M | The PEP 440 spelling batch 4 stamps (`1.5.0b0`) parsed as `(1, 5)` in the Tk updater, so a pre-release build saw a banner for its own tag — and a *downgrade* banner for any stable 1.5.x | `_parse_version` takes the leading numeric release only (`1.5.0b0` = `v1.5.0-beta` = `(1,5,0)`). *Run 18 F-001:* this made `v1.5.0` compare **equal**, not newer — the rank-based `_version_key` below is what orders the final above its beta |
| F-002, F-003, F-016 | L, L, N | `_hidden_seen` recorded any rename *to* a `.fuse_hidden*` name (a user's own file swept at unmount) and never forgot a hidden name renamed away; an unlinked-but-open file reached through libfuse's hide-rename was still encrypted and journaled at every close and then tombstoned; a doomed file got EROFS / a "dropped" warning on a flipped mount | Provenance = libfuse's exact name shape (`.fuse_hidden` + 16 hex) **and** an open source; renames away or over a hidden name forget it. `flush`/`release`/`save_all_dirty` treat `_hidden_seen` like `_pending_unlink` (doomed: no write-back), checked before the read-only refusal |
| F-004, F-005, F-007 | L | A path-based `truncate` whose flush flipped the mount stranded its buffer; `save_all_dirty`'s read-only path touched `_dirty_files` outside `_lock`; a non-EROFS failure (ENOSPC) persisting deferred deletes after the OS unmount still raised | `try/finally` around the internal flush; the read-only path runs under the lock; `unmount_volume` logs a post-unmount persistence failure at ERROR and returns (the deletes reappear at the next mount) |
| F-006 | L | `write()` accepted a negative offset (spliced from the end of the buffer) | EINVAL |
| F-008 | L | `compact()`'s `os.replace` sat outside the temp-file cleanup: a refused replace (Finder-locked container) orphaned a full-size copy | The commit is inside the guard |
| F-012 | L | The Swift shell made any helper stderr line containing "Error" public in the unified log; batch-4 warnings embedded vault-internal file names | Publicity decided by the helper's level prefix (`qc-core ERROR`, `Traceback`); the Python side logs counts at WARNING and names at DEBUG |
| F-013 | N | A folder at the sidecar path surfaced as a raw `IsADirectoryError` | Friendly refusal |
| F-014 | N | The bump-version gate admitted a hotfix tag on master's history and treated a git failure as "not on master" | Explicit exit-code handling plus a version comparison against `pyproject.toml` |
| F-009, F-010 | L | RELEASING.md and the run-16 F-008 row described withdrawn behaviour; the ENOTEMPTY limitation had no user-facing home | RELEASING.md rewritten; `encrypted-volumes.md` "Known behaviour on macFUSE / FUSE-T" addendum; a README sentence |
| F-011 | L | A vacuous assertion and un-torn-down fake mounts in the tests | Fixture with teardown; assertion removed |
| F-015 | N | The Tk guided-setup screen kept its own copy of the install command | It imports `FUSE_INSTALL_CMD`/`FUSE_INSTALL_ALT` (the Swift model keeps its copy, documented) |


## Run 18 (2026-09-06) — validation of batch 5, and the sixth batch

Run 18 went the full three rounds (round 2 added one Low and refuted
round 1's F-004; round 3 — briefed to take the surfaces earlier rounds had
not read: the Tk wizards, the release path, the Swift tests — added ten,
all Low/Nit, and refuted F-004 again). **22 findings, 0 Critical / 0 High /
2 Medium / 8 Low / 12 Nit, verdict Concerns.** Batch 5: 12 hold, 1
incomplete, **1 regressed** — and both Mediums are batch 5's own. All 22 are
fixed below; the archive is `.review-archive-20260906T094346Z`.

| Run-18 ID | Sev | Was | Change |
|-----------|-----|-----|--------|
| F-001 | M | Batch 5's numeric-only `_parse_version` made a build stamped `1.5.0b0` compare *equal* to `v1.5.0`, so a beta build never saw its final (the run-17 row above said "`v1.5.0` is newer"; the code did not) | `_version_key(tag)` = numeric release + rank (pre-release −1, `+local` 0, `post` +1) used by `check_for_update`; `_parse_version` keeps its numeric contract. Proved on `1.5.0b0`, `v1.5.0-beta`, `1.5.0rc1`, `1.5.0.dev3`, `v1.5.0`, `1.5.0.post1`, `1.10.0`. The bump-version gate uses the same rank, so a `v1.5.0-beta` tag after `1.5.0` is on master leaves master alone |
| F-002 | M | `flush()` on a doomed file skipped the write **and** dropped the dirty flag, so a hidden temp file renamed back over a real name released empty (model fuzz 3/200) | `flush()` forgets nothing for a doomed file; `release()` drops the flag with the last descriptor. Live trace (macFUSE 5.1.3): libfuse keeps the node hidden through the rename and unlinks it at its new name after the last close, so on a mount the rescue is undone by the backend regardless — documented in `encrypted-volumes.md`; the fix keeps the direct API and the model honest |
| F-003, F-020 | L, N | The Swift publicity rule made a traceback's frames and cause line private while every `qc-core ERROR` line — several naming the container path — went public | Python side, so both hold: `safe_reason(exc)` (errno + strerror, exception type; never a path) in every ERROR line, the path and `exc_info` on a paired INFO record; `cli.py`'s `_LevelPrefixedFormatter` puts the level prefix on every continuation line (fusepy's logger included); `QuantaCryptFUSE.__call__` intercepts fusepy's uncaught-exception path (its ERROR traceback ends with a vault path more often than not) and answers EINVAL after a safe report. `CoreTransport` predicate extracted as `isPublicStderrLine` with an XCTest; protocol doc states the contract |
| F-004 (R3 F-201) | L | A pre-release tag was published as a full "latest" release, so `releases/latest` — what the updater polls — would offer the beta to every stable user | `stamp_version.is_prerelease()`; the release job passes `--prerelease --latest=false` when it is true; RELEASING.md says so |
| F-005 (R3 F-203) | L | The Tk manager's own hint says "`~/QuantaCrypt Volumes/<name>`"; typed, it mounted at a folder literally named `~` under the CWD | `expanduser` in `mount_volume` (both front ends agree) and on the Tk create/mount fields; live check 6 mounts `~/…` under `$HOME` |
| F-006 (R3 F-206) | L | Picking a file that failed to load left Decrypt armed against the previous file behind a card showing the new one | `_forget_file()` on either failure branch: payload, meta, path, info card and title cleared; `_validate` says "Open a .qcx file first" |
| F-007 | L | A regular file (or dangling symlink) at the mount point surfaced as "already exists — choose a different name" | `InvalidInput("… exists but is not a folder")` before the empty-folder check |
| F-008 (R3 F-204) | L | `_start` read the k/n `IntVar`s after `_freeze()`; an emptied Entry made `get()` raise and left the wizard busy and unclosable; `_reset` had the same read after clearing the shares guard | `_kn()` (guarded) read before `_busy=True`; `_reset` reads before it clears; a test pins the order |
| F-009 (R3 F-205) | L | Quit from the app menu, the Dock or ⌘Q bypassed the launcher's mounted-volume guard: Tk Aqua evaluates `::tk::mac::Quit` if it exists, else `exit` → `SystemExit` into `mainloop()`; the clipboard countdown died with the process | `_register_quit(root, launcher)` registers `::tk::mac::Quit` → the launcher's `_quit_app` (or wipe + destroy without one); `ClipboardTimer.wipe_all()` clears every armed copy on the way out |
| F-010 (R3 F-202) | L | The native shell dropped `skipped_symlinks`: a folder's links vanished from the archive with no notice | `EncryptResult.skippedSymlinks` + a line on the result card; the fixture test pins the wire keys the app reads (F-021) |
| F-011 | N | `decode_share` refused a lower-case `qcshare-` prefix that every caller had already routed to it | Case-insensitive prefix in `decode_share`; `ShareValidation.formatProblem` no longer demands capitals |
| F-012 | N | Bump-gate heredoc: a no-op `/dev/stdout` write and an unguarded `re.match` | Removed; guarded; rank-aware key (F-001) |
| F-013 | N | `normalize_version` had no branch for a `+local` segment | `VERSION_RE` refuses `+` |
| F-014 | N | `read()` accepted a negative offset | EINVAL (buffered and unbuffered paths) |
| F-015 | N | `decode_share` accepted JSON booleans for `index`/`value`/`modulus` | bool excluded like `threshold` |
| F-016 (R3 F-209) | N | A journal append that failed part-way (ENOSPC/EIO) left `_journal_records` inflated, bringing compaction forward | Counted locally, added after the fsync |
| F-017 | N | The post-unmount guard caught only `OSError`; `save()`→`compact()` raises `ValueError` for a container truncated beneath the mount | `except (OSError, ValueError)`; the test runs the real `apply_pending_unlinks` body |
| F-018 | N | Dead `_fake_unmount` stub | Removed |
| F-019 (R3 F-208) | N | A `tk.Menu` per right-click; `RecentFiles.clear()` could not fail | One menu per widget, rebuilt per click; `_write_raw`/`clear` return a bool and the launcher says so instead of dropping the rows |
| F-021 (R3 F-210) | N | Swift test strength: decoded fixtures discarded, empty `volume_list` fixture, an unsigned-bundled test satisfied by the DEBUG venv fallback, a guardrail asserting a string that exists only in a comment, a `CoreTransport` comment untrue for a signed-but-unpinned helper | Required wire keys per fixture (and per `volume_list` entry, dumped while mounted); assertion accepts only `nil` or the dev-venv origin; the guardrail asserts the real fallback text; the comment now says which launches carry a hash |
| F-022 (R3 F-207) | N | Declining "Switch share format?" asked twice (the revert fired the trace before the guard) | Guard first |

Refuted (rounds 2 and 3, independently): round 1's F-004 — the aliasing of an
open hidden name by a rename over it is the pre-existing vpath-keyed limitation
(`create()` docstring), and libfuse hides an open destination before the
filesystem's `rename` ever runs, so no mount can produce it.

### Live check 6 (macFUSE 5.1.3, batch 6)

Temp-file pattern (create, unlink, fsync, close): nothing listed, nothing
persisted, `_hidden_seen`/`_dirty_files` empty. `~/QuantaCrypt Volumes/b6`
mounts under `$HOME`, no literal `~` folder. The rescue rename was traced op
by op: `rename(/doc.txt → .fuse_hidden…)`, `fsync`, `rename(… → /doc.txt)`,
then at the user's `close(2)`: `flush(/doc.txt)`, `release(/doc.txt)`,
**`unlink(/doc.txt)` from libfuse itself** — the node stays hidden through
the rename. The write-back now happens (the content is persisted at that
release) and libfuse's delete then removes it, as it would any file.

### Verification (batch 6)

Non-GUI suite 891 passed (8 s). Full suite with whole-package coverage:
2578 passed and two test-side failures — `test_encryptor_ui.py::TestReset`
had pinned the *old* defect ("an emptied share field breaks Encrypt
another", expecting the TclError) and now asserts the fix; the new
decryptor forget-file test mis-unpacked a helper's tuple — both rewritten
and re-run green. Coverage 99 % (8 622 statements, 120 missed), every file
≥ 95 %. Swift: 128 XCTest green (one compile fix: an explicit
`EncryptResult` init with a defaulted `skippedSymlinks`, since four tests
build it memberwise). Live check 6 above. Run 19 staged.


## Run 19 (2026-09-06) — validation of batch 6, and the seventh batch

Run 19 went three rounds (round 2 added one Low; round 3 — briefed with the
surfaces no round had read in full — added two Mediums and, for the first
time this loop, executed the Swift suite: 128 green). **11 findings,
0 Critical / 0 High / 3 Medium / 6 Low / 2 Nit, verdict Concerns.** Batch 6
**holds: no regression in any round**; two of its fixes were incomplete
(the Quit hook, the batch twin of the k/n read) and one opened a contract
edge (the expanded mount point). The two other Mediums are v1.3.0
journal-design defects no earlier round had read as one path-identity
story. All 11 are fixed below; the archive is
`.review-archive-20260906T170829Z`. Round 2's first attempt spawned
sub-agents and died on the session's rate limit before writing anything;
validator briefs now forbid sub-agents.

| Run-19 ID | Sev | Was | Change |
|-----------|-----|-----|--------|
| F-001 | M | `::tk::mac::Quit` (run 18 F-205) routed through the launcher's mounted-volume guard only: a wizard showing just-generated shares, a running job or a running volume *create* was destroyed without a dialog | Every wizard has `can_quit()` — the same refusals as its close button, without destroying anything (encryptor: busy → refuse, unsaved form → confirm, `_check_shares_saved`; decryptor: busy → refuse with a status line, typed input → confirm; volume manager: `_close` is now `can_quit()` + teardown). `_register_quit` asks every child window before the launcher; a window that cannot answer is not a veto |
| F-002 (R3 F-201) | M | `compact()` through a symlinked container: `os.replace` onto the link turned it into a second, diverging copy; the real file kept the pre-compaction state, the sidecar lock then guarded the wrong file | `mount_volume` hands the container the resolved path; `compact()` creates its temp beside, `chmod`s from, and `os.replace`s onto `os.path.realpath(self.path)` |
| F-003 (R3 F-202) | M | A container replaced or shortened beneath a live mount (a sync client restoring a version, a backup copied over it): the path-based append extended the *foreign* file with a zero hole, acknowledged the write, lost it, and the next open reported the hole as tampering | `VolumeContainer._check_still_ours()` before every write path: the pinned reader's `(st_dev, st_ino)` must match `os.stat(path)` and the file must not be shorter than `_journal_end` (longer is our own failed append; a strict equality false-positived four failure-path tests). Raises `OSError(ESTALE)`; `_persist_locked` flips the mount read-only, logs once (path-free ERROR + private INFO), keeps serving the pinned inode and does **not** re-read the foreign file; `_persist_locked` early-returns on a flipped mount (memory stays dirty on purpose — live check 7 showed one event re-logged at every release without it); the pre-unmount save treats ESTALE like EROFS |
| F-004 | L | `volume_mount` echoed the client's `~/…` while the helper tracked the expanded path; `volume_unmount` with the echoed value failed, mis-coded `format` | The service expands once and echoes it; `unmount_volume` expands too; an untracked mount point raises `InvalidInput` (→ `invalid_input`); protocol doc updated |
| F-005 | L | `_start_batch` still read the IntVars after `_freeze()` (the twin of run 18 F-204) | `_kn()` before `_busy = True`; a behavioural test drives `_start()` in batch mode with an emptied field |
| F-006 | L | `save_all_dirty(apply_pending_unlink=False)` popped a doomed file's deferred attrs and cleared its dirty flag — the third flush path did what `flush()` was fixed not to do | Doomed files are skipped whole; only written-back paths are discarded |
| F-007 | L | `release()` applied a deferred delete and a save on a flipped mount: a second public ERROR and a full index re-read per close | No delete on a read-only volume; the pending entry is still dropped and the buffer bookkeeping still runs |
| F-008 (R2 F-101) | L | `_forget_file` dropped the payload but left the ticked card, the live buttons, the previous file's credential row and output folder | `_forget_file` = `_reset()` + Decrypt disabled: the whole screen returns to "open a file" under the error line |
| F-009 | L | `safe_reason` republished `strerror` (which `volume.py` fills with vault paths); an errno-less `OSError` escaping `__call__` made fusepy's wrapper raise `NameError` out of the ctypes callback (the kernel told "success"), errno 0 took its public-traceback branch | `safe_reason` uses `os.strerror(errno)`; `__call__` turns `errno` None/≤ 0 into a safe report + `OSError(EIO)` |
| F-010 | N | The `--prerelease` probe's exit status folded an import error into "stable release" | The verdict is captured (`yes`/`no`); anything else fails the step |
| F-011 | N | RELEASING.md named three stamp targets (there are four); the protocol doc said `{verified}` (it is `{verified, mode}`) and nothing about the echoed mount point | Fixed |

### Live check 7 (macFUSE 5.1.3, batch 7)

Mounted through a symlink: the container object holds the real path, the
lock is `<real>.lock`, and after `compact()` the link is still a link and the
real file holds both files. Container replaced beneath the mount (an older
copy `os.replace`d over it): the next `create` is refused (`EROFS` after the
`ESTALE` flip), exactly one ERROR line, the listing is still served from the
pinned inode, the pre-replacement file reads back, unmount is clean, and the
restored copy reopens with no suspect sidecar. Before the `_persist_locked`
early return, the same event logged four ERROR lines (every later release
retried the save).

### Verification (batch 7)

Non-GUI suite 901 passed (9 s); the six GUI files the batch touches 1 466
passed (8 min); full suite with whole-package coverage **2594 passed,
0 failed**, 99 % (8 676 statements, 118 missed), every file ≥ 95 %. Swift
unchanged by the batch (128 green, executed by run 19's round 3). Live
check 7 above. Two batch-side test corrections along the way: the strict
size equality in the identity check false-positived four failure-path tests
(our own failed appends leave the file longer) and was relaxed to "not
shorter"; a new GUI test set `_batch_paths` after `_build_batch_ui`, which
seeds the output folder from it. Run 20 staged.


## Run 20 (2026-09-06) — validation of batch 7, and the eighth batch

Run 20 went three rounds (round 2 added two Lows and a Nit; round 3 added
one Medium and executed the Swift suite, 128 green). **13 findings,
0 Critical / 0 High / 3 Medium / 6 Low / 4 Nit, verdict Concerns.** Batch 7
**held with no regression**; two of its fixes were incomplete and one opened
an adjacent edge. The three Mediums are all one design point: **identity was
keyed on the path, not the descriptor the mount holds.** Batch 8 re-roots it
on the pinned descriptor. All 13 are fixed below; the archive is
`.review-archive-20260906T*` (run 20).

| Run-20 ID | Sev | Was | Change |
|-----------|-----|-----|--------|
| F-001 | M | `compact()` dropped the pinned reader and relied on a lazy re-open, so the identity check was inode-blind on every write-without-read after a compaction; a restore then truncated the foreign file and appended into it | `compact()` opens the new inode before the `os.replace` and swaps the reader to it, never unpinning; a replace after a compaction is now `ESTALE` |
| F-002 | M | After an `ESTALE` flip the pinned inode was the only copy of the session's records; unmount / eject / exit freed it silently and the ERROR understated the loss as "this change" | `VolumeContainer.rescue_if_orphaned()` copies an orphaned inode (`st_nlink == 0`, records appended this session) to a `<vault>.qcv.stale-<stamp>` sidecar; called from the flip, the pre-unmount save, and the eject reaper (the twins round 2 found have no dirty state to trigger a save); the ERROR names the rescue |
| F-003 (R3 F-201) | M | The inode+size check was defeated by a same-inode in-place overwrite (`cp` / `> file`): inode matches, size ≥ journal end, no flip, and the append corrupted the copied-over file | `_check_still_ours` re-reads the 512-byte header through the pinned fd and rejects when `MAGIC`/`volume_id` no longer name this volume; the residual (an older copy of the *same* volume ≥ journal end) is the documented format-work gap |
| F-004 (R1 F-003) | L | `release()` skipped the deferred `volume.delete()` on a flipped mount, so an acknowledged unlink reappeared in the live namespace at the last close | The delete is applied (memory only; `_persist_locked` returns before saving a read-only volume), so the namespace matches what the kernel was told |
| F-005 (R1 F-005) | L | The volume manager's `can_quit()` set `_cancel_event` before returning — a side effect taken before a later window (or the launcher) could veto the quit, stranding a cancelled create behind an app that stayed open | `can_quit()` is a pure predicate on every window (the launcher too); the cancel moved to `commit_quit()`, which `_register_quit` runs only after all consent; `launcher._quit_app` split so the mounted-volume prompt is the predicate |
| F-006 (R2 F-102) | L | A rename / move of the mounted container was reported as "replaced or resized (a sync client?)" and blamed a sync client for an everyday action | `_check_still_ours` distinguishes moved (`st_nlink >= 1`) from removed (`== 0`); the ERROR is generic ("changed on disk … moved, replaced, or overwritten"), the specific reason on the private INFO line |
| F-007 (R1 F-004) | L | An untracked mount point at unmount raised a message ("a path we do not own") that both UIs turned into "something is still using it" for a volume already ejected | The helper says "already ejected"; both front ends treat `InvalidInput` on unmount as "already unmounted" — a status note and a refresh, no alert |
| F-008 (R2 F-101) | L | `discard_unsaved()` cleared the maps and *then* re-opened; a re-open that raised left a phantom entry whose blob was gone (a file that lists but decrypts to garbage) and swallowed the original error | The fresh state is built on a side container and adopted only if its open succeeds; `_persist_locked` wraps the call so the original `PermissionError` propagates |
| F-009 (R1 F-006) | L→N | The journal fuzz swallowed every `ValueError`/`KeyError`/`OSError` and never exercised directories or compaction | It catches only the model's expected refusals, adds `mkdir` ops and a `compact()` at a random save point; anything else fails the seed with its traceback |
| F-010 (R1 F-007) | N | The service expanded `~` in `mount_point` but not in `path`/`source`/`output`/`output_dir`/`embed_binary` | All path params are expanded; the protocol doc says so |
| F-011 (R1 F-008) | N | The write path opens by name after checking identity by path (a stat→open window); writing through the pinned descriptor would close it | Documented as the next journal-design direction — it neutralises new-inode replacement and rename but not the same-inode overwrite (F-003), so it is a partial answer that waits on the format work, not this batch |
| F-012 (R2 F-103) | N | The encryptor's `can_quit()` asked about a half-typed form; its close button did not | `can_quit()` drops the form prompt (kept on Escape only), so ⌘Q matches the close button |
| F-013 (R1 F-009) | N | The encryptor was silent on a busy drop and on a multi-folder drop; the decryptor speaks | It flashes the busy notice and names the folder it used |

### Live check 8 (macFUSE 5.1.3, batch 8)

Direct-ops (equivalent to a `nothreads` mount) confirmed all four identity
paths: a replace after a compaction → `ESTALE` and the restored copy intact;
a same-inode `O_TRUNC` overwrite → `ESTALE` (header); an orphaned inode →
rescued to a `.stale-` sidecar holding the session's records;
`discard_unsaved` leaving memory intact when the re-open is denied. A real
macFUSE mount then replayed F-002 end to end: the container replaced beneath
the live mount, the next write refused (`EROFS` after the flip), the mount
still serving what it opened, a `v.qcv.stale-<stamp>` sidecar holding both
files (plus Finder's `._` AppleDouble sidecars), and the restored older copy
on disk intact and not flagged suspicious.

### Verification (batch 8)

Non-GUI suite 907 passed; the five GUI files the quit refactor touches 1 172
passed (14 min); full suite with whole-package coverage **2601 passed,
0 failed**, 98 % overall (8 793 statements, 150 missed — the new rescue and
identity branches), every file at or above the 95 % gate. Swift 128 green
(the `VolumesModel` unmount change). Two batch-7 tests updated for the moved
message and the now-applied flipped delete; two pre-existing untracked-mount
tests updated for the "already ejected" wording. Live check 8 above. Run 21
staged.

## Run 21 (2026-09-06) — validation of batch 8, and the ninth batch

Run 21 **converged at round 2** (0 new, 0 refuted) — the first convergence
since run 17. **4 findings, 0 Critical / 0 High / 1 Medium / 2 Low / 1 Nit,
verdict Concerns.** Batch 8 **held with no regression**; all four are its own
incomplete-fix twins (the shape every recent run surfaces). Round 2
reproduced each and lowered F-001 to Low. All four are fixed below; the
archive is `.review-archive-*` (run 21).

| Run-21 ID | Sev | Was | Change |
|-----------|-----|-----|--------|
| F-001 | M | The batch-8 quit refactor made every window's `can_quit()` pure except the launcher's, which unmounts inline — and the launcher is index 0 of `winfo_children()`, so it ran before a wizard could veto: ⌘Q with a mounted volume and a busy wizard ejected the drive, then the wizard vetoed and the app stayed open | `_register_quit` asks the wizards first (pure predicates) and the launcher **last**, so its unmount runs only after every wizard consents; keeping the unmount in `can_quit` preserves "a failed unmount vetoes the quit". A regression test registers a launcher whose `can_quit` records the unmount alongside a vetoing wizard and asserts the unmount never ran |
| F-002 (R1 F-001) | L | The batch-8 `~` expansion reached six qc-core ops but missed `op_volume_mount`'s volume `path` and `op_inspect`'s `.qcx` `path`; the protocol doc it added promised expansion for all path params | Both expand `~`; the misleading "mount_volume expands ~" comment removed; the mount test stubs the KEM path and asserts the expanded path reaches `read_volume_auth_params` and `mount_volume` |
| F-003 | L | `rescue_if_orphaned` fired from the flip, the failed pre-unmount save and the reaper, but not from a clean (idle) `unmount_volume` or `_emergency_save_all` — an orphaned-but-clean mount ejected or SIGTERM'd freed the pinned fd without preserving it | An unconditional (idempotent) rescue after the save block in `unmount_volume` and a best-effort one in `_emergency_save_all`; tests drive both with an orphaned idle mount |
| F-004 | N | `_persist_locked` did not wrap `discard_unsaved()` as the run-20 note claimed, so a re-open failure would replace the original `PermissionError` | The call is wrapped; the original exception wins (the re-read failure is logged at INFO) |

### Verification (batch 9)

Non-GUI suite 907 passed. Swift unchanged by the batch (128 green from run
20). The identity/rescue core, the quit ordering and the `~` round-trip were
verified by the new tests and round 2's four reproductions. Full suite with
whole-package coverage **2604 passed, 0 failed**, 98 % (8 816 statements,
158 missed), every file at or above the 95 % gate. (An operational note: the
suite mounts a real macFUSE volume, so a run killed mid-way by an OOM leaks
that mount and holds ~6 GB — `diskutil unmount force` the leftover
`.../pytest-*/**/nfmnt` before rerunning.) Run 22 staged.

## Run 22 (2026-09-06) — validation of batch 9: LOOP TERMINATES

Run 22 **converged at round 2** and is the first run to report **zero
Medium+**: an initial deep review and an independent validator pass both
found batch 9 complete and regression-free. **2 findings, both Nit**, verdict
**Healthy**. The termination condition of the review→fix loop (a run reporting
zero Medium+) is met after ten batches.

| Run-22 ID | Sev | Was | Change (batch 10, a one-file polish — no review cycle) |
|-----------|-----|-----|--------|
| F-001 | N | The failed-save-during-unmount path logged the rescued sidecar on two INFO lines (the `except` and the new unconditional block) — no double copy, just a duplicate log | The unconditional block is skipped when the `except` already rescued (`rescued_here` flag), so one event is one log line |
| F-002 | N | `rescue_if_orphaned`'s `_stale_sidecar` check-and-set was not lock-bracketed, so two tear-down rescues straddling a wall-clock second could each create a `.stale-` file (benign 0600 encrypted duplicate) | A `_stale_lock` brackets the check and the `O_EXCL` reservation; the copy stays outside the lock |

### Verification (batch 10)

Non-GUI suite 909 passed; full suite with whole-package coverage **2604
passed, 0 failed**, 98 % (8 825 statements, 161 missed), every file at or
above the 95 % gate; no leaked FUSE mount. Swift unchanged by the batch (128
green from run 20). The two Nit fixes were confirmed by the existing
rescue/idempotency tests (`TestContainerReplacedBeneathTheMount`,
`TestErrorLinesNameNoPath`).

### The loop, end to end

Ten fix batches over runs 13–22, each validated by fresh-agent review rounds,
terminating when a run reported zero Medium+:

| Run | Batch | Findings (C/H/M/L/N) | Verdict | Mediums were |
|-----|-------|----------------------|---------|--------------|
| 13 | 1 | 37 total | Healthy | initial audit |
| 14 | 2 | 0/0/3/13/4 | Concerns | batch-1 regressions |
| 15 | 3 | 0/0/1/16/3 | Healthy | pre-existing since v1.3.0 |
| 16 | 4 | 0/0/3/13/9 | Concerns | batch-3 (deferred rmdir, kernel-level) |
| 17 | 5 | 0/0/1/11/4 | Concerns (converged r2) | batch-4 version parser |
| 18 | 6 | 0/0/2/8/12 | Concerns | batch-5 (updater equal; doomed flush) |
| 19 | 7 | 0/0/2/8/12 | Concerns | batch-6 incomplete + 2 v1.3.0 journal defects |
| 20 | 8 | 0/0/3/6/4 | Concerns | one identity root (path vs descriptor) |
| 21 | 9 | 0/0/1/2/1 | Concerns (converged r2) | batch-8 quit-ordering |
| 22 | 10 | 0/0/0/0/2 | **Healthy** | **none** |

Every batch remains **uncommitted** in the working tree (~61 files vs
`e30758c`) for the maintainer to commit. The Medium count fell 3 → 1 → 0 over
the last three runs; the surviving findings became progressively more
peripheral (a duplicate log line, a near-impossible sidecar race) until a run
found nothing that meets the Medium bar.
