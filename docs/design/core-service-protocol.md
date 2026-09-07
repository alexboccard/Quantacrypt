# Core service protocol (`qc-core`)

Date: 2026-09-02. Status: implemented (v1). Parent decision: `native-macos-ui.md`.

## Problem

The native macOS shell (SwiftUI) needs to drive the Python core — encrypt,
decrypt, verify, inspect, volumes — without importing Python. The Tk UI also
re-implements pieces of the core (key derivation, first-chunk verification,
output naming, folder zipping) that belong below the UI. Both need one
process-level API that streams progress and supports cancellation.

## Options considered

1. **HTTP daemon on localhost** (the trading client's pattern). Familiar, but
   secrets would travel over a socket any local process can connect to, and a
   port must be chosen and guarded. Rejected for a crypto tool.
2. **Embed CPython in the Swift app** (PythonKit + Python.xcframework). One
   binary, but every call crosses a GIL/threading boundary from Swift and FUSE
   mounts then live inside the GUI process. Kept as a later option.
3. **Helper process speaking JSON lines over stdin/stdout.** Only the parent
   can talk to it; no ports; the process owns the FUSE mounts and dies with
   the app (shutdown handlers unmount). Trivial to drive from `Process` in
   Swift and from tests in Python. **Chosen.**

## Design

Executable: `qc-core` (entry point `quantacrypt.cli:main`), also
`python -m quantacrypt.cli`. One request per line on stdin, one JSON object
per line on stdout, nothing else on stdout (logs go to stderr). Stderr has a privacy contract with the shell: a line is made public in the unified log only when it starts with `qc-core ERROR `, `qc-core CRITICAL `, `qc-core: ` or `Traceback`; every other line is private. The helper therefore keeps ERROR-level text path-free (errno and strerror, the exception type) and puts container paths, mount points and tracebacks on INFO records; a multi-line record carries its level prefix on every line, so a traceback logged at INFO stays private line by line (review run 18).

### Request

```json
{"id": "r1", "op": "encrypt", "params": {...}}
```

`id` is any string chosen by the client; every event for the request carries
it back. Requests run concurrently on worker threads; control ops (`cancel`,
`shutdown`, `version`, `ping`) are answered inline.

### Events

```json
{"id": "r1", "event": "progress", "stage": "kdf", "label": "Securing password", "pct": 0.0, "message": "<raw core message>"}
{"id": "r1", "event": "done", "result": {...}}
{"id": "r1", "event": "error", "code": "wrong_credentials", "message": "<friendly text>", "detail": "<raw exception>"}
```

Error codes: `wrong_credentials`, `cancelled`, `invalid_request` (the CLIENT
sent a malformed request — a UI treats it as its own bug), `invalid_input`
(the USER supplied something unusable: an unreadable share, too few shares,
no password; the message is written for them), `not_found`, `already_exists`, `permission_denied`, `io`, `format` (the file
itself is unreadable or its payload fails authentication AFTER the key was
proven — never reported as a wrong password), `busy`, `unsupported`, `internal`. `message` is the same
`friendly_error` text the Tk UI shows; `detail` is for logs and disclosure
triangles.

Stages: `compress`, `kdf`, `kem`, `lock`, `payload`, `write`, `split`,
`read`, `mount`, `verify`. `pct` is within the stage (0–1) when the core
reports one, else `null`.

### Ops

| op | params | result |
|---|---|---|
| `version` | — | `{version, format_version, platform, python}` |
| `ping` | — | `{}` |
| `fuse_check` | — | `{fuse_backend: {ok, detail}, fusepy: {ok, detail}, ok}` |
| `inspect` | `path` (.qcx) | `{path, size, version, mode, threshold, total, embedded, argon2}` |
| `volume_inspect` | `path` (.qcv) | `{path, size, format_version, mode, threshold, total}` |
| `encrypt` | `source` (file or folder), `output`, `mode` (`password`\|`shamir`), `password`, `k`, `n`, `embed_binary` (optional path prepended for self-executing files) | `{output, size, filename, mode, threshold, total, shares: [{index, code, mnemonic}], skipped_symlinks: [paths]}` — a folder's symlinks are left out of the archive (zipfile would store the target's bytes) and listed so the UI can name them |
| `decrypt` | `path`, `output_dir`, `password` or `shares` (codes or 50-word mnemonics), `verify_only` | `{verified, mode}` or `{output, filename, size, original_size, timestamp, renamed}` |
| `volume_create` | `path`, `mode`, `password` or `k`,`n` | `{path, mode, shares}` |
| `volume_mount` | `path`, `mount_point`, `password` or `shares` | `{mount_point, volume_path, journal_suspicious, suspect_sidecar, read_only}` — when the journal tail failed to verify, `journal_suspicious` is true and `suspect_sidecar` is the `<vault>.qcv.suspect-<stamp>` file it was copied to beside the volume (else `null`); a UI names that file in its alert, or the one artefact an investigation could use reads as litter. `read_only` is true when the container or its directory refuses writes and the drive was served `-o ro` instead of failing on the first save; a client treats it as false when absent (older helpers). `mount_point` is echoed as the helper tracks it: a leading `~` is expanded, and that is the value `volume_list` lists and `volume_unmount` takes |
| `volume_unmount` | `mount_point` | `{mount_point}` — `~` is expanded, so the value `volume_mount` echoed and the one the client sent both work |

Every path parameter (`path`, `source`, `output`, `output_dir`, `embed_binary`, `mount_point`) has a leading `~` expanded by the helper.

| `volume_list` | — | `{volumes: [{mount_point, volume_path, read_only, stats: {file_count, dir_count, total_plaintext_size, container_size, ...} \| null}]}` — `read_only` mirrors the mount result's flag so a client that rebuilds its list from this poll keeps it |
| `cancel` | `target` (request id) | `{cancelled: bool}` |
| `shutdown` | — | cancels in-flight work, unmounts every volume, THEN answers `{unmount_failed: [mount points]}` and exits |

**Vocabulary.** Requests accept `mode` = `password` (alias `single`) or
`shamir`; results always report the on-disk format's `mode` = `single` or
`shamir`, because that is what `inspect` reads back from a file.

**Cancellation semantics.** A `cancelled` error means *nothing was
written*: handlers raise it when they observe the token between stages or
chunks (`encrypt`, `decrypt`, `volume_create`), and `volume_create` removes a
container it had already written when the cancel lands after the write. A
handler that finishes despite a late cancel is reported as `done` — the
client must treat `done` as authoritative. `volume_mount` checks the token
before the FUSE call only; `fuse_check`, `volume_unmount`, `volume_list` and
the inspect ops are short and never cancel, so a client should fail such
requests locally after a grace period.

Passwords and shares travel in the request JSON. That is acceptable because
stdin is a private pipe from the parent process; the same secrets already
live in the parent's memory. The service never logs params.

### Lifecycle

- EOF on stdin → no more requests: in-flight work may finish for up to
  300 s (a one-shot client can write one request and close the pipe), then
  every volume is saved and unmounted and the process exits 0.
- `shutdown` → cancel in-flight requests, join workers, unmount volumes,
  answer `done` with any `unmount_failed` mount points, exit. The
  acknowledgement comes *after* the work so a client can start its escalation
  timer on it. That work is bounded per volume, not per request — a 5 s
  worker join plus up to 30 s for each `diskutil unmount` that waits on an
  open file — so a client's deadline for the answer must scale with the
  mounted count (the SwiftUI shell waits 10 + 35 × max(1, n) s) before it
  escalates to SIGTERM; a flat deadline abandons the remaining volumes.
- SIGTERM → the handler flags the loop, cancels workers and raises out of
  the blocked stdin read; teardown then runs in `run()`'s `finally` on the
  main thread outside the signal handler (which may be holding the mount
  lock), so the process never deadlocks on itself.
- One writer lock serialises stdout; events from different requests
  interleave line-by-line.
- Output files are written to a `0600` `mkstemp` file beside the output
  (`.<name>.qc-enc-*`, never `$TMPDIR`) and `os.replace`d; decrypt writes to
  a `mkstemp` file in the output directory and renames to the original
  filename (with `_2` suffixing on collision, reported as `renamed`).
- Folder sources are streamed: the zip archive is written straight into the
  cipher through that same temp file, so no plaintext staging file ever
  touches the disk and the transient space needed is the ciphertext alone.
  The result is named `<folder>.zip`; symlinks inside the folder are skipped
  and reported in `skipped_symlinks`.

## What moved into `core/`

- `core/package.py`: `load_pkg`, `derive_final_key`, `verify_first_chunk`,
  `encrypt_to_qcx`, `decrypt_qcx`, `safe_output_name`, `unique_path`,
  `folder_stats`, `zip_folder`, `batch_output_paths`, `normalize_shares`.
- `core/errors.py`: `friendly_error`, `classify_error`.
- `core/service.py`: the dispatcher; `cli.py`: the executable.

The Tk UI keeps its names (`decryptor.load_pkg`, `encryptor._zip_folder`,
`shared.friendly_error`) as re-exports so nothing user-facing changes in this
step. Follow-up: route the Tk wizards through `package.py` too and delete the
duplicated key-derivation code in `decryptor.py`.

## Trade-offs

- A helper process means one more binary to sign and bundle. Accepted; it is
  the same helper the Tk app would need for a `--classic` mode later.
- JSON lines cannot carry binary; every payload is a path. Fine: the core is
  file-to-file by design.
- Progress is stage + optional percent, not bytes. The client keeps its own
  ETA logic (as the Tk `StagedProgressBar` does).
