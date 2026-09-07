"""Release plumbing: version stamping, code signing, and workflow invariants.

Everything here covers behaviour that only ever runs on a release, which is
the worst place to discover it is broken: a `sed` that silently matched
nothing and shipped the previous version's number, a `codesign` failure that
was printed and ignored, and the scope of the token the build jobs run with.
"""

from __future__ import annotations

import importlib.util
import os
import re
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


stamp_version = _load("qc_stamp_version", os.path.join(SCRIPTS, "stamp_version.py"))
build_script = _load("qc_build_script", os.path.join(SCRIPTS, "build.py"))


# ── scripts/stamp_version.py ──────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path):
    """A miniature checkout carrying the three version-bearing files."""
    (tmp_path / "src" / "quantacrypt").mkdir(parents=True)
    (tmp_path / "macos").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "q"\nversion = "1.3.0"\n', encoding="utf-8")
    (tmp_path / "src" / "quantacrypt" / "__init__.py").write_text(
        '    __version__ = "1.3.0"  # keep in sync with pyproject.toml\n',
        encoding="utf-8")
    (tmp_path / "macos" / "project.yml").write_text(
        '        CFBundleShortVersionString: "1.3.0"\n'
        '        CFBundleVersion: "1"\n', encoding="utf-8")
    return tmp_path


def _texts(repo):
    return (
        (repo / "pyproject.toml").read_text(encoding="utf-8"),
        (repo / "src" / "quantacrypt" / "__init__.py").read_text(encoding="utf-8"),
        (repo / "macos" / "project.yml").read_text(encoding="utf-8"),
    )


def test_stamp_rewrites_every_file(repo):
    assert stamp_version.stamp(str(repo), "1.4.0") == 0
    toml, init, yml = _texts(repo)
    assert 'version = "1.4.0"' in toml
    assert '__version__ = "1.4.0"' in init
    assert 'CFBundleShortVersionString: "1.4.0"' in yml


def test_stamp_preserves_the_comment_and_the_indentation(repo):
    stamp_version.stamp(str(repo), "2.0.0")
    _, init, yml = _texts(repo)
    # sed's greedy `".*"` happened to keep these; a structural rewrite has to
    # keep them on purpose.
    assert init == '    __version__ = "2.0.0"  # keep in sync with pyproject.toml\n'
    assert yml.startswith('        CFBundleShortVersionString: "2.0.0"\n')
    # CFBundleVersion is stamped too (run 13 F-005: LaunchServices picks among
    # duplicate app copies by it), and the two keys must not clobber each
    # other's rewrite of the same file.
    assert 'CFBundleVersion: "2.0.0"' in yml


def test_stamp_quotes_an_unquoted_yaml_value(repo):
    (repo / "macos" / "project.yml").write_text(
        "        CFBundleShortVersionString: 1.3.0\n"
        "        CFBundleVersion: 1\n", encoding="utf-8")
    assert stamp_version.stamp(str(repo), "1.4.0") == 0
    assert (repo / "macos" / "project.yml").read_text(encoding="utf-8") == \
        '        CFBundleShortVersionString: "1.4.0"\n' \
        '        CFBundleVersion: "1.4.0"\n'


def test_a_target_that_no_longer_matches_fails_and_writes_nothing(repo, capsys):
    """The whole point: `sed` exited 0 here and shipped the old version."""
    (repo / "src" / "quantacrypt" / "__init__.py").write_text(
        '    __version__: str = "1.3.0"\n', encoding="utf-8")
    before = _texts(repo)

    assert stamp_version.stamp(str(repo), "1.4.0") == 1

    assert _texts(repo) == before, "a miss must not half-rewrite the checkout"
    assert "__init__.py" in capsys.readouterr().err


def test_an_ambiguous_file_is_refused(repo, capsys):
    (repo / "pyproject.toml").write_text(
        '[project]\nversion = "1.3.0"\n\n[tool.other]\nversion = "9.9.9"\n',
        encoding="utf-8")
    assert stamp_version.stamp(str(repo), "1.4.0") == 1
    assert "ambiguous" in capsys.readouterr().err


def test_check_reports_a_stale_file_then_passes_once_stamped(repo):
    assert stamp_version.stamp(str(repo), "1.4.0", check=True) == 1
    stamp_version.stamp(str(repo), "1.4.0")
    assert stamp_version.stamp(str(repo), "1.4.0", check=True) == 0


@pytest.mark.parametrize("bad", ['1.0.0"; rm -rf /', "v1.0.0", "", "1.0.0\nx"])
def test_a_tag_that_is_not_a_version_is_rejected_before_any_write(repo, bad):
    before = _texts(repo)
    assert stamp_version.main([bad, "--root", str(repo)]) == 2
    assert _texts(repo) == before


def test_the_real_checkout_still_matches_every_pattern():
    """Guards the regexes against a reformat of the files they target."""
    edits, problems = stamp_version.plan(ROOT, "0.0.0")
    assert not problems, problems
    # Every file must carry what the checkout's release version implies for
    # it — CFBundleVersion holds the numeric prefix, so a pre-release checkout
    # legitimately shows two strings (run 15 F-004).
    release = next(old for _, rel, old, _, _ in edits if rel == "pyproject.toml")
    assert len(edits) == len(stamp_version.TARGETS)      # plan() keeps TARGETS order
    for (_, rel, old, _, _), (_, _, _, expected) in zip(edits, stamp_version.TARGETS):
        assert old == expected(release), (rel, old, release)


def test_the_tk_bundle_plist_gets_a_numeric_build_number(tmp_path, monkeypatch):
    """Run 15: the native app's rule (scripts/stamp_version.py) applied to the
    Tk bundle's Info.plist too — both DMG kinds must order the same way."""
    import plistlib
    spec = importlib.util.spec_from_file_location(
        "build_script", os.path.join(ROOT, "scripts", "build.py"))
    build = importlib.util.module_from_spec(spec); spec.loader.exec_module(build)
    app = tmp_path / "QuantaCrypt.app"; (app / "Contents").mkdir(parents=True)
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleName": "QuantaCrypt"}, f)
    monkeypatch.setattr(build, "_read_version", lambda: "1.5.0-beta")
    build._patch_plist(str(app), "icon")
    with open(app / "Contents" / "Info.plist", "rb") as f:
        plist = plistlib.load(f)
    assert plist["CFBundleShortVersionString"] == "1.5.0-beta"
    assert plist["CFBundleVersion"] == "1.5.0"


# ── scripts/build.py: code signing ────────────────────────────────────────

#: 64-bit little-endian Mach-O.  The sweep identifies binaries by magic, so a
#: fixture with plausible names but no magic would test nothing.
MACHO = b"\xcf\xfa\xed\xfe" + b"\0" * 60


@pytest.fixture
def app_bundle(tmp_path):
    app = tmp_path / "quantacrypt.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "MacOS" / "quantacrypt").write_bytes(MACHO)
    (app / "Contents" / "Frameworks").mkdir()
    (app / "Contents" / "Frameworks" / "libcrypto.dylib").write_bytes(MACHO)
    # No extension and no pattern the old glob list would have matched.
    (app / "Contents" / "Frameworks" / "Tcl").write_bytes(MACHO)
    (app / "Contents" / "Resources" / "tk").mkdir(parents=True)
    (app / "Contents" / "Resources" / "tk" / "init.tcl").write_text("not a binary")
    return app


def _fake_codesign(monkeypatch, fails=lambda cmd: False):
    calls: list[list[str]] = []

    def run(cmd, **kw):
        calls.append(list(cmd))
        rc = 1 if fails(cmd) else 0
        return SimpleNamespace(returncode=rc, stdout="", stderr="mock failure")

    monkeypatch.setattr(build_script, "subprocess", SimpleNamespace(run=run))
    return calls


def _is_verify(cmd):
    return "--verify" in cmd


def test_signing_success_verifies_the_finished_bundle(app_bundle, monkeypatch, capsys):
    calls = _fake_codesign(monkeypatch)
    build_script._codesign_app_bundle(str(app_bundle), name="quantacrypt")

    signed = [c[-1] for c in calls if not _is_verify(c)]
    assert str(app_bundle / "Contents" / "Frameworks" / "libcrypto.dylib") in signed
    # The extensionless framework binary the glob list could not see.
    assert str(app_bundle / "Contents" / "Frameworks" / "Tcl") in signed
    assert str(app_bundle / "Contents" / "MacOS" / "quantacrypt") in signed
    assert not any(c.endswith("init.tcl") for c in signed), "data files are not code"
    nested = signed.index(str(app_bundle / "Contents" / "Frameworks" / "libcrypto.dylib"))
    assert nested < signed.index(str(app_bundle / "Contents" / "MacOS" / "quantacrypt")), \
        "nested binaries sign before the executable that will seal them"
    assert signed[-1] == str(app_bundle), "the outer bundle is signed last"
    assert any(c[:4] == ["codesign", "--verify", "--deep", "--strict"] for c in calls)
    assert "verified" in capsys.readouterr().out


@pytest.mark.parametrize("target", ["libcrypto.dylib", "MacOS/quantacrypt", "outer"])
def test_a_signing_failure_at_any_depth_stops_the_build(
        app_bundle, monkeypatch, capsys, target):
    """It used to print "(non-fatal)" and publish the DMG anyway."""
    def fails(cmd):
        if _is_verify(cmd):
            return False
        last = cmd[-1]
        if target == "outer":
            return last == str(app_bundle)
        return last.endswith(target)

    _fake_codesign(monkeypatch, fails)
    with pytest.raises(SystemExit) as e:
        build_script._codesign_app_bundle(str(app_bundle), name="quantacrypt")
    assert e.value.code == 1
    assert "Code signing failed" in capsys.readouterr().out


def test_a_bundle_that_signs_but_does_not_verify_stops_the_build(
        app_bundle, monkeypatch, capsys):
    """Each target can sign cleanly and the bundle still be rejected."""
    _fake_codesign(monkeypatch, _is_verify)
    with pytest.raises(SystemExit) as e:
        build_script._codesign_app_bundle(str(app_bundle), name="quantacrypt")
    assert e.value.code == 1
    assert "verification failed" in capsys.readouterr().out


# ── the workflows ─────────────────────────────────────────────────────────

def _workflow(name: str) -> str:
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        return f.read()


def _job(text: str, name: str) -> str:
    """The block for one job, from its header to the next job header."""
    heads = [m for m in re.finditer(r"(?m)^  (?P<name>[A-Za-z0-9_-]+):$", text)]
    for i, m in enumerate(heads):
        if m["name"] == name:
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            return text[m.start():end]
    raise AssertionError(f"no job named {name}")


def test_release_grants_write_only_to_the_two_jobs_that_need_it():
    text = _workflow("release.yml")
    assert re.search(r"(?m)^permissions:\n  contents: read$", text), \
        "workflow-scoped contents: write is inherited by every build job"
    for job in ("release", "bump-version"):
        assert "contents: write" in _job(text, job)
    for job in ("test", "build-arm64", "build-x86_64", "build-native"):
        assert "contents: write" not in _job(text, job)


def test_release_stamps_the_version_structurally():
    text = _workflow("release.yml")
    assert "sed -i" not in text, "sed exits 0 on a no-match; the stamp must fail loudly"
    assert text.count("scripts/stamp_version.py") == 4, \
        "three build jobs plus bump-version"


def test_both_tk_build_jobs_verify_the_signature_before_uploading():
    text = _workflow("release.yml")
    for job in ("build-arm64", "build-x86_64"):
        assert "codesign --verify --deep --strict dist/tk/quantacrypt.app" in _job(text, job)


def test_bump_version_relocks_so_the_lock_cannot_lag_a_release():
    job = _job(_workflow("release.yml"), "bump-version")
    assert "uv lock" in job
    assert "uv.lock requirements-lock.txt" in job


def test_ci_runs_the_split_gate_and_the_per_file_coverage_floor():
    text = _workflow("ci.yml")
    assert "scripts/run_tests.sh" in text
    assert "scripts/check_coverage.py --min 95" in text
    assert "uv lock --check" in text
    assert re.search(r"(?m)^permissions:\n  contents: read$", text)


# ── 2026-09 audit: entitlements, debuggability, pinned build inputs ─────────

def test_ad_hoc_signing_adds_no_entitlements_or_timestamp(app_bundle, monkeypatch):
    monkeypatch.delenv("CODESIGN_IDENTITY", raising=False)
    calls = _fake_codesign(monkeypatch)
    build_script._codesign_app_bundle(str(app_bundle), name="quantacrypt")
    for c in calls:
        assert "--entitlements" not in c and "--timestamp" not in c and "runtime" not in c


def test_a_developer_id_signs_the_executable_and_bundle_with_entitlements(app_bundle, monkeypatch):
    """The hardened runtime refuses libfuse (another Team ID) and cffi's
    executable memory unless the two entitlements are granted; notarization
    needs the secure timestamp.  Nested dylibs carry neither."""
    monkeypatch.setenv("CODESIGN_IDENTITY", "Developer ID Application: Someone (TEAM)")
    calls = _fake_codesign(monkeypatch)
    build_script._codesign_app_bundle(str(app_bundle), name="quantacrypt")
    signs = [c for c in calls if not _is_verify(c)]
    exe = str(app_bundle / "Contents" / "MacOS" / "quantacrypt")
    for c in signs:
        assert "--timestamp" in c and "runtime" in c
        entitled = "--entitlements" in c
        if c[-1] in (exe, str(app_bundle)):
            assert entitled and c[c.index("--entitlements") + 1] == build_script.ENTITLEMENTS
        else:
            assert not entitled, c


def test_the_entitlements_file_grants_exactly_what_pyinstaller_needs():
    import plistlib
    with open(build_script.ENTITLEMENTS, "rb") as f:
        ent = plistlib.load(f)
    assert ent == {
        "com.apple.security.cs.disable-library-validation": True,
        "com.apple.security.cs.allow-unsigned-executable-memory": True,
    }


def test_the_native_build_never_injects_get_task_allow():
    cmd = build_script._native_xcodebuild_cmd("-", "arm64", "/dd")
    assert "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO" in cmd
    assert cmd[-1] == "build" and "CODE_SIGNING_ALLOWED=YES" in cmd
    signed = build_script._native_xcodebuild_cmd("Developer ID Application: X", None, "/dd")
    assert "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO" in signed
    assert "CODE_SIGNING_ALLOWED=YES" not in signed and "ARCHS=arm64" not in signed


def test_a_debuggable_bundle_stops_the_build(monkeypatch, capsys):
    def run(cmd, **kw):
        return SimpleNamespace(returncode=0, stderr="",
                               stdout="[Key] com.apple.security.get-task-allow\n[Value] [Bool] true\n")
    monkeypatch.setattr(build_script, "subprocess", SimpleNamespace(run=run))
    with pytest.raises(SystemExit) as e:
        build_script._assert_not_debuggable("/some/app.app")
    assert e.value.code == 1
    assert "get-task-allow" in capsys.readouterr().out


def test_a_non_debuggable_bundle_passes(monkeypatch):
    def run(cmd, **kw):
        return SimpleNamespace(returncode=0, stderr="", stdout="[Dict]\n")
    monkeypatch.setattr(build_script, "subprocess", SimpleNamespace(run=run))
    build_script._assert_not_debuggable("/some/app.app")


lock_subset = _load("qc_lock_subset", os.path.join(SCRIPTS, "lock_subset.py"))


def test_lock_subset_extracts_a_hash_pinned_block(tmp_path, capsys):
    lock = tmp_path / "lock.txt"
    lock.write_text(
        "# generated\n"
        "argon2-cffi==25.1.0 \\\n"
        "    --hash=sha256:aaaa \\\n"
        "    --hash=sha256:bbbb\n"
        "setuptools==84.0.0 \\\n"
        "    --hash=sha256:cccc\n"
        "wheel==0.45.0 ; python_version < '3.99' \\\n"
        "    --hash=sha256:dddd\n", encoding="utf-8")
    assert lock_subset.main(["--lock", str(lock), "Setuptools", "wheel"]) == 0
    out = capsys.readouterr().out
    assert out == ("setuptools==84.0.0 \\\n    --hash=sha256:cccc\n"
                   "wheel==0.45.0 ; python_version < '3.99' \\\n    --hash=sha256:dddd\n")


def test_lock_subset_fails_on_a_package_the_lock_does_not_pin(tmp_path, capsys):
    lock = tmp_path / "lock.txt"
    lock.write_text("setuptools==84.0.0 \\\n    --hash=sha256:cccc\n", encoding="utf-8")
    assert lock_subset.main(["--lock", str(lock), "setuptools", "not-there"]) == 1
    assert "not-there" in capsys.readouterr().err


def test_the_real_lock_pins_the_build_backend(capsys):
    """CI installs setuptools from this block before building with no
    isolation; the block has to exist and carry hashes."""
    assert lock_subset.main(["--lock", os.path.join(ROOT, "requirements-lock.txt"), "setuptools"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("setuptools==") and "--hash=sha256:" in out


def test_every_workflow_action_is_pinned_to_a_commit_sha():
    for name in ("ci.yml", "release.yml", "codeql.yml"):
        for m in re.finditer(r"uses:\s*(\S+)@(\S+)(.*)", _workflow(name)):
            ref, comment = m.group(2), m.group(3)
            assert re.fullmatch(r"[0-9a-f]{40}", ref), f"{name}: {m.group(1)}@{ref} is not a SHA"
            assert re.search(r"#\s*v\d", comment), f"{name}: {m.group(1)} pin lacks a version comment"


def test_no_workflow_installs_from_a_mutable_source():
    for name in ("ci.yml", "release.yml", "codeql.yml"):
        # Comments may name the anti-patterns; commands may not.
        text = "\n".join(l for l in _workflow(name).splitlines()
                         if not l.strip().startswith("#"))
        assert "brew install" not in text, f"{name}: brew resolves whatever the tap serves that day"
        assert "--upgrade pip" not in text
        assert re.search(r"pip install .*(-r requirements-lock\.txt|\.)$", text, re.M)
        for line in text.splitlines():
            if "pip install" in line and "-r " in line and "--require-hashes" not in line:
                raise AssertionError(f"{name}: unpinned install: {line.strip()}")


def test_the_release_publishes_checksums_and_provenance():
    text = _workflow("release.yml")
    release = _job(text, "release")
    assert "SHA256SUMS" in release
    assert "attest-build-provenance" in release
    assert "id-token: write" in release and "attestations: write" in release
    native = _job(text, "build-native")
    assert "get-task-allow" in native, "the artefact check for debuggability"
    bump = _job(text, "bump-version")
    assert "persist-credentials: false" in bump


def test_the_x86_and_arm_builds_share_one_interpreter_version():
    text = _workflow("release.yml")
    ver = re.search(r'PYTHON_VERSION: "(\d+\.\d+\.\d+)"', text).group(1)
    assert f"python-{ver}-macos11.pkg" in text
    assert "python-version: ${{ env.PYTHON_VERSION }}" in text
    assert re.search(r'PYTHON_PKG_SHA256: "[0-9a-f]{64}"', text)


def test_install_xcodegen_pins_a_release_and_its_digest():
    with open(os.path.join(SCRIPTS, "install_xcodegen.sh"), encoding="utf-8") as f:
        text = f.read()
    assert re.search(r'^XCODEGEN_VERSION="\d+\.\d+\.\d+"$', text, re.M)
    assert re.search(r'^XCODEGEN_SHA256="[0-9a-f]{64}"$', text, re.M)
    assert "shasum -a 256 -c" in text and "set -euo pipefail" in text
