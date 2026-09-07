#!/usr/bin/env python3
"""Stamp a release version into every file that records one.

The release workflow used to do this with three `sed -i '' "s/^version = .*/…/"`
substitutions per build job.  `sed` exits 0 when its pattern matches nothing, so
a `version` line that grew leading whitespace, a reformatted `__version__`, or a
`CFBundleShortVersionString` switched to single quotes would have published a
release labelled with the *previous* version — and the in-app update checker
compares the running version against GitHub Releases, so every user would then
sit on a permanent "update available" banner that installing cannot clear.
A missed target has to be loud, which is the whole point of this script.

Usage:
    python3 scripts/stamp_version.py 1.4.0
    python3 scripts/stamp_version.py 1.4.0 --check   # verify only, write nothing
"""

from __future__ import annotations

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The version arrives straight from GITHUB_REF (`refs/tags/v…`), i.e. from
# whatever string someone managed to push as a tag.  A quote or a newline in it
# would corrupt the TOML/YAML it is written into, so reject it before any file
# is opened rather than repairing the damage afterwards.
#: No `+local` segment: normalize_version has no branch for one, so
#: `1.5.0-beta+ci` would stamp raw while setuptools wrote `1.5.0b0+ci`.
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.-]*$")

def normalize_version(version: str) -> str:
    """The one spelling of a pre-release everything agrees on.

    setuptools normalises `1.5.0-beta` to PEP 440 `1.5.0b0` in the wheel, so
    `importlib.metadata` reported that while the stamped literal, the plists
    and the release page said `1.5.0-beta`.  Stamp the PEP 440 form
    everywhere instead: `-alpha`/`-beta`/`-rc`/`-dev` (dot, dash or nothing
    as separator, optional number) become `a`/`b`/`rc`/`.dev` with a number.
    """
    m = re.fullmatch(
        r"(?P<rel>\d+(?:\.\d+)*)"
        r"(?:[-._]?(?P<pre>alpha|beta|rc|a|b|c|dev)[-._]?(?P<n>\d*))?",
        version.lower(),
    )
    if not m or not m["pre"]:
        return version
    tag = {"alpha": "a", "beta": "b", "c": "rc", "dev": ".dev"}.get(m["pre"], m["pre"])
    return f"{m['rel']}{tag}{m['n'] or 0}"


def is_prerelease(version: str) -> bool:
    """Whether the normalised form carries a pre-release marker.  The
    release job asks before `gh release create`: unmarked, a beta becomes
    `releases/latest` — what the in-app updater polls — and is offered to
    every stable user."""
    return re.search(r"\d(?:a|b|rc)\d|\.dev\d", normalize_version(version)) is not None


def _bundle_version(version: str) -> str:
    """The value Apple accepts for CFBundleVersion: up to three dot-separated
    integers.  LaunchServices orders duplicate app copies by it, and a
    pre-release tag (`1.5.0-beta`) written raw is malformed to it — the
    arbitrary choice the stamping set out to end."""
    m = re.match(r"\d+(?:\.\d+){0,2}", version)
    return m.group(0) if m else version


#: (path, pattern, render, expected).  Each pattern must match *exactly once*;
#: `render` rebuilds the matched span from the match so anything after it on
#: the line — `__init__.py`'s "keep in sync" comment, for one — survives.
#: `expected` maps the release version to the value that file should carry
#: (identity for all but CFBundleVersion).
TARGETS = (
    (
        "pyproject.toml",
        re.compile(r"""(?m)^(?P<pre>version[ \t]*=[ \t]*)(?P<val>"[^"]*"|'[^']*')[ \t]*$"""),
        lambda m, v: f'{m["pre"]}"{v}"',
        lambda v: v,
    ),
    (
        "src/quantacrypt/__init__.py",
        re.compile(r"""(?m)^(?P<pre>[ \t]*__version__[ \t]*=[ \t]*)(?P<val>"[^"]*"|'[^']*')"""),
        lambda m, v: f'{m["pre"]}"{v}"',
        lambda v: v,
    ),
    (
        # Stamped in every job, not just the native one: the Tk jobs ignore
        # this file, but keeping one code path means the native build cannot
        # be the only place a stamping bug shows up.
        "macos/project.yml",
        re.compile(
            r"""(?m)^(?P<pre>[ \t]*CFBundleShortVersionString:[ \t]*)"""
            r"""(?P<val>"[^"]*"|'[^']*'|[^\s#]+)[ \t]*$"""
        ),
        lambda m, v: f'{m["pre"]}"{v}"',
        lambda v: v,
    ),
    (
        # LaunchServices picks among duplicate copies of the app (a stale one
        # in ~/Downloads, a still-mounted DMG) by CFBundleVersion; a constant
        # "1" on every release made that choice arbitrary, so a .qcx could
        # open in last release's binary and report "newer format, update".
        "macos/project.yml",
        re.compile(
            r"""(?m)^(?P<pre>[ \t]*CFBundleVersion:[ \t]*)"""
            r"""(?P<val>"[^"]*"|'[^']*'|[^\s#]+)[ \t]*$"""
        ),
        lambda m, v: f'{m["pre"]}"{_bundle_version(v)}"',
        _bundle_version,
    ),
)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def plan(root: str, version: str) -> tuple[list[tuple[str, str, str, str, str]], list[str]]:
    """Resolve every target without writing anything.

    Returns (edits, problems) where an edit is (path, relative path, old
    value, new file text, expected value).  Planning before writing keeps a
    miss on the third target from leaving the first two rewritten.
    """
    edits: list[tuple[str, str, str, str, str]] = []
    problems: list[str] = []
    # Text per path, carried across targets: two patterns on one file
    # (project.yml's two version keys) must each see the other's rewrite, or
    # the last write silently undoes the first.
    texts: dict[str, str] = {}
    missing: set[str] = set()

    for rel, pattern, render, expected in TARGETS:
        path = os.path.join(root, rel)
        if path in missing:
            continue
        if path not in texts:
            if not os.path.isfile(path):
                problems.append(f"{rel}: file not found")
                missing.add(path)
                continue
            with open(path, encoding="utf-8") as f:
                texts[path] = f.read()
        text = texts[path]
        found = list(pattern.finditer(text))
        if not found:
            problems.append(
                f"{rel}: no line matching {pattern.pattern} — the format "
                f"changed and this stamp would have been a silent no-op"
            )
            continue
        if len(found) > 1:
            problems.append(
                f"{rel}: {len(found)} lines match {pattern.pattern} — "
                f"ambiguous, refusing to guess"
            )
            continue
        m = found[0]
        texts[path] = text[: m.start()] + render(m, version) + text[m.end():]
        edits.append((path, rel, _unquote(m["val"]), texts[path], expected(version)))

    return edits, problems


def stamp(root: str, version: str, *, check: bool = False) -> int:
    """Rewrite (or, with ``check``, verify) every version-bearing file."""
    version = normalize_version(version)
    edits, problems = plan(root, version)

    if check:
        for _, rel, old, _, want in edits:
            if old == want:
                print(f"  {rel}: {old}")
            else:
                problems.append(f"{rel}: is {old}, expected {want}")
    elif not problems:
        for path, rel, old, new_text, want in edits:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_text)
            print(f"  {rel}: {old} -> {want}")

    if problems:
        print("stamp_version: FAILED", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    if not check:
        # Read the files back rather than trusting the substitution: a render
        # bug that produced `version = ""1.4.0""` would still have written.
        written, verify_problems = plan(root, version)
        stale = [rel for _, rel, old, _, want in written if old != want]
        if verify_problems or stale:
            print("stamp_version: post-write verification FAILED", file=sys.stderr)
            for p in verify_problems + [f"{r}: still not {version}" for r in stale]:
                print(f"  {p}", file=sys.stderr)
            return 1

    files = len({rel for rel, *_ in TARGETS})
    print(f"stamp_version: all {files} file(s) at {version}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help="release version, without the leading 'v'")
    ap.add_argument("--check", action="store_true",
                    help="verify every file already carries it; write nothing")
    ap.add_argument("--root", default=ROOT, help="repository root (default: this checkout)")
    args = ap.parse_args(argv)

    if not VERSION_RE.match(args.version):
        print(f"stamp_version: {args.version!r} is not a version", file=sys.stderr)
        return 2

    return stamp(args.root, args.version, check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
