#!/usr/bin/env python3
"""
Build script — produces a self-contained macOS app bundle.

  macOS:   dist/tk/quantacrypt.app   (double-clickable .app bundle)

The app handles all three launch modes:
  - Run directly              → Launcher (choose Encrypt or Decrypt)
  - quantacrypt myfile.qcx   → Decryptor (opens that file)
  - ./myfile.qcx             → Decryptor (self-executing .qcx)

When encrypting with "Embed decryptor" ticked, the binary embeds itself
into the .qcx file. No companion files needed — just the one binary.

Usage:
  python3 scripts/build.py                 (full build: tests → app → DMG)
  python3 scripts/build.py --test-only     (run tests + coverage only)
  python3 scripts/build.py --no-dmg        (build app bundle, skip DMG)
"""

import io
import os
import re
import plistlib
import shutil
import struct
import subprocess
import sys

# ROOT = repo root (one level up from scripts/)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, "src")
PKG  = os.path.join(SRC, "quantacrypt")
DIST = os.path.join(ROOT, "dist")
# The Tk app lives one level down: its bundle name "quantacrypt.app" and the
# native shell's "QuantaCrypt.app" are the SAME path on a case-insensitive
# APFS volume, so building both into dist/ made the second build silently
# replace the first (measured: the native app on disk was the Tk app).  DMGs
# still land in dist/ — their names differ.
TK_DIST = os.path.join(DIST, "tk")
WORK = os.path.join(ROOT, "build")
NAME = "quantacrypt"
BUNDLE_ID = "com.alexboccard.quantacrypt"
QCX_UTI   = "com.alexboccard.quantacrypt.qcx"
QCV_UTI   = "com.alexboccard.quantacrypt.qcv"
DOC_ICON_NAME = "doc_icon.icns"
VOL_ICON_NAME = "vol_icon.icns"

SUF = ".app"

HIDDEN = [
    "quantacrypt", "quantacrypt.core", "quantacrypt.core.crypto",
    "quantacrypt.core.volume", "quantacrypt.core.fuse_ops",
    "quantacrypt.ui", "quantacrypt.ui.shared", "quantacrypt.ui.launcher",
    "quantacrypt.ui.encryptor", "quantacrypt.ui.decryptor", "quantacrypt.ui.updater",
    "quantacrypt.ui.volume_manager",
    "cryptography", "cryptography.hazmat.primitives.ciphers.aead",
    "argon2", "argon2.low_level",
    "kyber_py", "kyber_py.kyber",
    "shamirs", "shamirs.shamirs",
    "mnemonic",
    # fusepy (module name "fuse") must ship in the bundle or the frozen app
    # can never mount volumes — check_fuse_available() fails permanently and
    # the in-app pip installer can't run inside a PyInstaller bundle.  The
    # FUSE *backend* (macFUSE / FUSE-T) is still detected at runtime.
    "fuse",
    "tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox",
    # tkinterdnd2 must be in hidden imports so PyInstaller collects the
    # package. The native tkdnd/ directory is also bundled via --add-data below
    # because TkinterDnD._require() locates it via os.path.dirname(__file__).
    "tkinterdnd2", "tkinterdnd2.TkinterDnD",
    # zxcvbn must be bundled so the password strength bar works correctly
    # and the weak-password dialog fires. Without it the binary silently uses a
    # simpler fallback estimator and skips the weak-password warning entirely.
    "zxcvbn",
]


def _make_icns(png_path, out_path):
    """Generate a minimal .icns from a PNG using Pillow.

    Writes PNG-encoded icon slices for every standard macOS size so the dock
    icon looks sharp on both standard and Retina displays.
    """
    from PIL import Image
    src = Image.open(png_path).convert("RGBA")
    _LANCZOS = getattr(Image, "Resampling", Image).LANCZOS

    # (type_code, pixel_size)
    SIZES = [
        (b"icp4",   16), (b"icp5",   32), (b"icp6",   64),
        (b"ic07",  128), (b"ic08",  256), (b"ic09",  512),
        (b"ic10", 1024),
    ]

    chunks = b""
    for code, px in SIZES:
        resized = src.resize((px, px), _LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format="PNG")
        data = buf.getvalue()
        chunk_len = 8 + len(data)          # 4-byte type + 4-byte length + data
        chunks += code + struct.pack(">I", chunk_len) + data

    header = b"icns" + struct.pack(">I", 8 + len(chunks))
    with open(out_path, "wb") as f:
        f.write(header + chunks)



def _build_icon():
    """Return (icon_flag_args, icon_path_for_cleanup) for PyInstaller --icon."""
    png = os.path.join(PKG, "assets", "icon.png")
    if not os.path.isfile(png):
        print("[!] icon.png not found — building without custom icon")
        return [], None

    out = os.path.join(ROOT, "icon.icns")
    try:
        _make_icns(png, out)
        print(f"[+] Generated {out}")
        return ["--icon", out], out
    except Exception as e:
        print(f"[!] Could not generate .icns ({e}) — skipping icon")
        return [], None


def _build_doc_icon():
    """Generate a .icns for the .qcx document type icon.

    Returns the path to the generated file, or None if doc_icon.png is missing.
    The .icns is copied into the .app bundle's Resources/ directory after build.
    """
    png = os.path.join(PKG, "assets", "doc_icon.png")
    if not os.path.isfile(png):
        print("[!] doc_icon.png not found — .qcx files will use a generic icon")
        return None

    out = os.path.join(ROOT, DOC_ICON_NAME)
    try:
        _make_icns(png, out)
        print(f"[+] Generated {out}")
        return out
    except Exception as e:
        print(f"[!] Could not generate doc .icns ({e}) — skipping document icon")
        return None


def _build_vol_icon():
    """Generate a .icns for the .qcv volume type icon.

    Returns the path to the generated file, or None if vol_icon.png is missing.
    The .icns is copied into the .app bundle's Resources/ directory after build.
    """
    png = os.path.join(PKG, "assets", "vol_icon.png")
    if not os.path.isfile(png):
        print("[!] vol_icon.png not found — .qcv files will use a generic icon")
        return None

    out = os.path.join(ROOT, VOL_ICON_NAME)
    try:
        _make_icns(png, out)
        print(f"[+] Generated {out}")
        return out
    except Exception as e:
        print(f"[!] Could not generate vol .icns ({e}) — skipping volume icon")
        return None


def _find_tkinterdnd2():
    """Return the tkinterdnd2 package directory, or None if not installed.
    Needed to add the native tkdnd shared-library tree via --add-data so that
    TkinterDnD._require() can resolve tkdnd/<platform>/ via __file__ at runtime.
    A hidden-import entry alone is not sufficient -- the package must be present
    on disk inside _MEIPASS, not just importable."""
    try:
        import tkinterdnd2 as _t
        return os.path.dirname(_t.__file__)
    except ImportError:
        return None


def _read_version():
    """Read the project version from pyproject.toml (single source of truth)."""
    toml_path = os.path.join(ROOT, "pyproject.toml")
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        import tomli as tomllib  # Python 3.10 fallback
    with open(toml_path, "rb") as f:
        cfg = tomllib.load(f)
    return cfg["project"]["version"]


def _patch_plist(app_path, icon_name, vol_icon_name=None):
    """Patch the Info.plist inside a built .app bundle.

    Sets the version strings, adds CFBundleDocumentTypes, and exports
    UTExportedTypeDeclarations so macOS recognises .qcx files and routes
    double-clicks to QuantaCrypt.
    """
    plist_path = os.path.join(app_path, "Contents", "Info.plist")
    with open(plist_path, "rb") as f:
        plist = plistlib.load(f)

    version = _read_version()
    plist["CFBundleIdentifier"] = BUNDLE_ID
    plist["CFBundleShortVersionString"] = version   # user-facing "1.0.0"
    # Build number: up to three dot-separated integers, or LaunchServices
    # cannot order duplicate app copies by it.  Same rule as
    # scripts/stamp_version.py::_bundle_version for the native app; a
    # pre-release tag ("1.5.0-beta") keeps only its numeric prefix.
    m = re.match(r"\d+(?:\.\d+){0,2}", version)
    plist["CFBundleVersion"] = m.group(0) if m else version

    # Declare that we handle .qcx and .qcv documents
    plist["CFBundleDocumentTypes"] = [
        {
            "CFBundleTypeName": "QuantaCrypt Encrypted File",
            "CFBundleTypeRole": "Editor",
            "LSHandlerRank": "Owner",
            "LSItemContentTypes": [QCX_UTI],
            "CFBundleTypeExtensions": ["qcx"],
            **({"CFBundleTypeIconFile": icon_name} if icon_name else {}),
        },
        {
            "CFBundleTypeName": "QuantaCrypt Encrypted Volume",
            "CFBundleTypeRole": "Editor",
            "LSHandlerRank": "Owner",
            "LSItemContentTypes": [QCV_UTI],
            "CFBundleTypeExtensions": ["qcv"],
            # Only attach the .qcv icon when we actually generated one — do
            # NOT silently fall back to the .qcx doc icon, which would make
            # the two file types visually indistinguishable in Finder.
            **({"CFBundleTypeIconFile": vol_icon_name} if vol_icon_name else {}),
        },
    ]

    # Export UTIs so macOS knows what .qcx and .qcv mean even before
    # the user has ever opened one
    plist["UTExportedTypeDeclarations"] = [
        {
            "UTTypeIdentifier": QCX_UTI,
            "UTTypeDescription": "QuantaCrypt Encrypted File",
            "UTTypeConformsTo": ["public.data"],
            "UTTypeTagSpecification": {
                "public.filename-extension": ["qcx"],
                "public.mime-type": "application/x-quantacrypt",
            },
            **({"UTTypeIconFile": icon_name} if icon_name else {}),
        },
        {
            "UTTypeIdentifier": QCV_UTI,
            "UTTypeDescription": "QuantaCrypt Encrypted Volume",
            "UTTypeConformsTo": ["public.data"],
            "UTTypeTagSpecification": {
                "public.filename-extension": ["qcv"],
                "public.mime-type": "application/x-quantacrypt-volume",
            },
            # As above: only attach a per-UTI icon when we have a real .qcv
            # icon; avoid the .qcx icon masquerading as the .qcv icon.
            **({"UTTypeIconFile": vol_icon_name} if vol_icon_name else {}),
        },
    ]

    with open(plist_path, "wb") as f:
        plistlib.dump(plist, f)

    print(f"[+] Patched {plist_path}")
    print(f"    Version:       {version}")
    print(f"    Bundle ID:     {BUNDLE_ID}")
    print(f"    Document type: .qcx → {QCX_UTI}")
    print(f"    Document type: .qcv → {QCV_UTI}")


def _create_dmg(app_path, arch_label="", name=None):
    """Create a .dmg installer with a drag-to-Applications layout.

    The DMG contains:
      - The .app bundle
      - A symlink to /Applications

    Uses Finder's native icon view with snap-to-grid so the layout
    stays clean regardless of how the user resizes the window.

    Requires macOS (hdiutil + osascript).  Skipped gracefully on other platforms.
    """
    if sys.platform != "darwin":
        print("[!] DMG creation requires macOS — skipping")
        return None

    suffix = f"-{arch_label}" if arch_label else ""
    dmg_path = os.path.join(DIST, f"{name or NAME}{suffix}.dmg")
    volume_name = "QuantaCrypt"
    window_w, window_h = 480, 300
    icon_size = 128

    # Remove old DMG if present
    if os.path.isfile(dmg_path):
        os.remove(dmg_path)

    # Create a temporary writable DMG
    tmp_dmg = os.path.join(DIST, f"{name or NAME}_tmp.dmg")
    if os.path.isfile(tmp_dmg):
        os.remove(tmp_dmg)

    # Calculate size: app size + 20 MB headroom
    app_size = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, files in os.walk(app_path)
        for f in files
    )
    dmg_size_mb = max(app_size // 1_000_000 + 20, 50)

    print(f"\n[+] Creating DMG ({dmg_size_mb} MB)...")

    # Create a temporary read-write DMG
    subprocess.run([
        "hdiutil", "create",
        "-size", f"{dmg_size_mb}m",
        "-fs", "HFS+",
        "-volname", volume_name,
        tmp_dmg,
    ], check=True, capture_output=True)

    # Mount it
    result = subprocess.run(
        ["hdiutil", "attach", tmp_dmg, "-readwrite", "-noverify", "-noautoopen"],
        check=True, capture_output=True, text=True,
    )
    # Parse mount point from hdiutil output
    mount_point = None
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            mount_point = parts[-1].strip()
    if not mount_point:
        mount_point = f"/Volumes/{volume_name}"

    try:
        # Copy the .app into the DMG
        dest_app = os.path.join(mount_point, os.path.basename(app_path))
        subprocess.run(["cp", "-R", app_path, dest_app], check=True)

        # Create Applications symlink
        os.symlink("/Applications", os.path.join(mount_point, "Applications"))

        # Use AppleScript to configure the Finder window appearance.
        # "snap to grid" arrangement keeps icons centred even if the
        # user resizes the window — no fixed-position background needed.
        applescript = f'''
            tell application "Finder"
                tell disk "{volume_name}"
                    open
                    set current view of container window to icon view
                    set toolbar visible of container window to false
                    set statusbar visible of container window to false
                    set the bounds of container window to {{200, 200, {200 + window_w}, {200 + window_h}}}
                    set viewOptions to the icon view options of container window
                    set arrangement of viewOptions to snap to grid
                    set icon size of viewOptions to {icon_size}
                    close
                    open
                    update without registering applications
                    delay 2
                    close
                end tell
            end tell
        '''
        subprocess.run(["osascript", "-e", applescript],
                       capture_output=True, timeout=60)

    finally:
        # Unmount
        subprocess.run(["hdiutil", "detach", mount_point, "-quiet"],
                       capture_output=True)

    # Convert to a compressed, read-only DMG
    subprocess.run([
        "hdiutil", "convert", tmp_dmg,
        "-format", "UDZO",
        "-imagekey", "zlib-level=9",
        "-o", dmg_path,
    ], check=True, capture_output=True)

    # Clean up the temporary writable DMG
    os.remove(tmp_dmg)

    sz = os.path.getsize(dmg_path) / 1_000_000
    print(f"[+] Created {dmg_path}  ({sz:.1f} MB)")
    return dmg_path


def _run_tests():
    """Run the test suite with coverage and abort the build on failure.

    Reads the minimum coverage threshold from pyproject.toml
    ([tool.coverage.report] fail_under).  Defaults to 0 (no minimum)
    if the key is absent, so coverage data is still collected and printed.
    """
    print(f"\n{'='*60}\n  Running tests + coverage\n{'='*60}\n")

    # Read fail_under from pyproject.toml so there's a single source of truth
    fail_under = 0
    toml_path = os.path.join(ROOT, "pyproject.toml")
    if os.path.isfile(toml_path):
        try:
            import tomllib  # Python 3.11+
        except ModuleNotFoundError:
            try:
                import tomli as tomllib  # Python 3.10 fallback
            except ModuleNotFoundError:
                tomllib = None
        if tomllib:
            with open(toml_path, "rb") as f:
                cfg = tomllib.load(f)
            fail_under = (
                cfg.get("tool", {})
                   .get("coverage", {})
                   .get("report", {})
                   .get("fail_under", 0)
            )

    cmd = [
        sys.executable, "-m", "pytest",
        "--tb=short", "-q",
        f"--cov-fail-under={fail_under}",
    ]

    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print(f"\n[!] Tests failed or coverage below {fail_under}% — aborting build.")
        sys.exit(1)

    print(f"\n[+] All tests passed (coverage >= {fail_under}%)\n")


def _parse_args():
    """Parse build CLI arguments."""
    import argparse
    p = argparse.ArgumentParser(description="Build QuantaCrypt macOS app bundle")
    p.add_argument("--arch", choices=["arm64", "x86_64", "universal2"],
                   default=None,
                   help="Target architecture. Default: current machine's arch. "
                        "Use 'universal2' for a fat binary that runs on both "
                        "Intel and Apple Silicon.")
    p.add_argument("--skip-tests", action="store_true",
                   help="Skip the test suite (useful for CI split builds)")
    p.add_argument("--test-only", action="store_true",
                   help="Run tests and coverage only — skip the build entirely")
    p.add_argument("--native", action="store_true",
                   help="Build the native SwiftUI app: helper + icons + xcodegen + "
                        "xcodebuild Release → dist/QuantaCrypt.app (+ DMG unless --no-dmg)")
    p.add_argument("--helper", action="store_true",
                   help="Build only the qc-core helper (dist/qc-core.app) "
                        "for the native macOS shell; skips icons and DMG")
    p.add_argument("--icons", action="store_true",
                   help="Render only the .icns files into "
                        "macos/QuantaCrypt/Resources; required before a plain "
                        "`xcodegen generate && xcodebuild` on a fresh clone")
    p.add_argument("--no-dmg", action="store_true",
                   help="Build the .app bundle but skip DMG creation")
    return p.parse_args()


#: Mach-O magics, 32/64-bit and fat, both byte orders.
_MACHO_MAGIC = (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def _iter_macho(root):
    """Every Mach-O file under `root`, symlinks excluded.

    Symlinks are skipped because a framework's Versions/Current/… aliases
    would otherwise be signed twice under two names, and codesign follows the
    link anyway.
    """
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if os.path.islink(path):
                continue
            try:
                with open(path, "rb") as f:
                    if f.read(4) in _MACHO_MAGIC:
                        yield path
            except OSError:
                continue


def _codesign_app_bundle(app_path, name=None):
    """Ad-hoc sign every binary inside the .app bundle, inside-out.

    macOS requires consistent code signatures across all Mach-O binaries
    in a bundle.  Embedded frameworks (e.g. Python.framework from
    python.org) arrive with their own Team ID signature.  Ad-hoc re-signing
    every binary with ``codesign --force --sign -`` strips the original
    identity and replaces it with a uniform ad-hoc signature so macOS
    won't reject the bundle for mismatched Team IDs.

    Order matters: sign nested binaries first, then the main executable,
    then the outer .app — otherwise the outer signature invalidates.
    """
    # TODO: Replace ad-hoc signing with Developer ID certificate for notarization.
    #   1. Read identity from CODESIGN_IDENTITY env var (fall back to "-" for ad-hoc)
    #   2. Add "--options runtime" flag (hardened runtime, required for notarization)
    #   3. Add notarization + stapling steps to release.yml:
    #        xcrun notarytool submit <dmg> --apple-id --password --team-id --wait
    #        xcrun stapler staple <dmg>
    #   4. GitHub secrets needed: DEVELOPER_ID_CERT_BASE64, DEVELOPER_ID_CERT_PASSWORD,
    #      APPLE_ID, APPLE_ID_PASSWORD, APPLE_TEAM_ID
    #   5. CI keychain setup: create temp keychain, import .p12, codesign, then clean up
    identity = os.environ.get("CODESIGN_IDENTITY", "-")

    sign_cmd = ["codesign", "--force", "--sign", identity]
    # What the main executable and the outer bundle get on top: the
    # hardened runtime needs a secure timestamp to notarize, and the two
    # entitlements in scripts/hardened-runtime.entitlements — library
    # validation would otherwise refuse libfuse (another Team ID) and cffi's
    # executable memory.  Nested dylibs carry no entitlements.
    exe_cmd = list(sign_cmd)
    if identity != "-":
        sign_cmd += ["--options", "runtime", "--timestamp"]
        exe_cmd = sign_cmd + ["--entitlements", ENTITLEMENTS]

    # Every step below used to swallow its result: steps 1 and 2 never looked
    # at the return code and step 3 printed "(non-fatal)" and returned, so a
    # build that signed nothing still produced a DMG, uploaded it as a release
    # asset and exited 0.  An .app with absent or inconsistent signatures
    # opens as "damaged and can't be opened" rather than showing the expected
    # unidentified-developer prompt — the exact failure this signing exists to
    # prevent — so a signing error has to stop the build.
    failures = []

    def _sign(target, entitled=False):
        cmd = exe_cmd if entitled else sign_cmd
        r = subprocess.run(cmd + [target], capture_output=True, text=True)
        if r.returncode != 0:
            failures.append(
                (target, r.stderr.strip() or f"codesign exited {r.returncode}")
            )

    # 1. Sign every Mach-O in the bundle, identified by magic rather than by
    #    name.  The glob list this replaces (**/*.so, **/*.dylib,
    #    **/*.framework/Versions/*/*/* …) matched by shape, which cut both
    #    ways: measured on dist/qc-core.app it hit 179 paths of which only 59
    #    were code — it was signing Info.plist files and Python.framework's
    #    own _CodeSignature/CodeResources, i.e. writing to the very resources
    #    that framework's signature seals — while any binary whose layout had
    #    no matching pattern would have gone unsigned, and one unsigned nested
    #    binary is what makes the finished .app "damaged" on another machine.
    main_exe = os.path.join(app_path, "Contents", "MacOS", name or NAME)
    targets = [p for p in _iter_macho(app_path) if p != main_exe]
    # Deepest first, so a nested bundle's contents are signed before the
    # bundle that seals them.
    targets.sort(key=lambda p: p.count(os.sep), reverse=True)
    for path in targets:
        _sign(path)

    # 2. Sign the main executable, after everything it ships with and before
    #    the outer bundle that seals the lot.
    if os.path.isfile(main_exe):
        _sign(main_exe, entitled=True)

    # 3. Sign the outer .app bundle
    _sign(app_path, entitled=True)

    if failures:
        print(f"[!] Code signing failed for {len(failures)} target(s):")
        for target, err in failures:
            print(f"    {target}: {err}")
        sys.exit(1)

    # 4. Verify rather than trust the exit codes: every target can sign
    #    cleanly and the bundle still fail as a whole — a stale resource seal
    #    in an embedded framework, a nested bundle signed in the wrong order.
    #    This is the check Gatekeeper makes, and the native build has always
    #    made it (_build_native); the Tk build did not.
    v = subprocess.run(["codesign", "--verify", "--deep", "--strict", app_path],
                       capture_output=True, text=True)
    if v.returncode != 0:
        print(f"[!] Signature verification failed: {v.stderr.strip()}")
        sys.exit(1)
    print(f"[+] Code signing succeeded and verified ({identity})")


def _post_build(app_path, doc_icon_tmp, arch_label, *,
                skip_dmg=False, vol_icon_tmp=None):
    """Install doc/vol icons, patch plist, code-sign, create DMG, and print summary."""
    resources_dir = os.path.join(app_path, "Contents", "Resources")
    os.makedirs(resources_dir, exist_ok=True)

    # Copy the document icon (.qcx) into the .app bundle's Resources directory
    doc_icon_name = None
    if doc_icon_tmp and os.path.isfile(doc_icon_tmp):
        dest = os.path.join(resources_dir, DOC_ICON_NAME)
        shutil.copy2(doc_icon_tmp, dest)
        os.remove(doc_icon_tmp)
        doc_icon_name = DOC_ICON_NAME
        print(f"[+] Installed {dest}")

    # Copy the volume icon (.qcv) into Resources
    vol_icon_name = None
    if vol_icon_tmp and os.path.isfile(vol_icon_tmp):
        dest = os.path.join(resources_dir, VOL_ICON_NAME)
        shutil.copy2(vol_icon_tmp, dest)
        os.remove(vol_icon_tmp)
        vol_icon_name = VOL_ICON_NAME
        print(f"[+] Installed {dest}")

    # Patch Info.plist with .qcx and .qcv file-association metadata
    _patch_plist(app_path, doc_icon_name, vol_icon_name=vol_icon_name)

    # Ad-hoc code sign the .app bundle so macOS Gatekeeper shows the
    # standard "unidentified developer" dialog instead of "damaged".
    # We must sign from the inside out: first every embedded binary
    # (frameworks, .so, .dylib), then the main executable, then the
    # outer bundle.  Using just `--deep` is unreliable, and
    # `--options runtime` (hardened runtime) requires matching Team IDs
    # which breaks ad-hoc signing when embedded frameworks (like
    # Python.framework from python.org) carry a different Team ID.
    print("[*] Ad-hoc code signing the .app bundle …")
    _codesign_app_bundle(app_path)

    # .app is a directory — report total size by walking it
    total = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, files in os.walk(app_path)
        for f in files
    )
    sz = total / 1_000_000

    # Create distributable DMG with drag-to-Applications layout
    dmg_path = None
    if not skip_dmg:
        dmg_path = _create_dmg(app_path, arch_label)
    else:
        print("[*] Skipping DMG creation (--no-dmg)")

    print(f"\n{'=' * 60}")
    print(f"  BUILD COMPLETE  ({arch_label})")
    print(f"{'=' * 60}")
    print(f"  App:  {app_path}  ({sz:.1f} MB)")
    if dmg_path:
        dmg_sz = os.path.getsize(dmg_path) / 1_000_000
        print(f"  DMG:  {dmg_path}  ({dmg_sz:.1f} MB)")
    print()
    if dmg_path:
        print("  Share the .dmg — recipients open it and drag to Applications.")
    else:
        print("  Double-click the .app to launch, or drag it to /Applications.")
    print("  First launch: right-click → Open → Open to bypass Gatekeeper.")
    print(f"  If macOS says 'damaged': xattr -cr /Applications/{NAME}.app")
    print(f"{'=' * 60}\n")


HELPER_NAME = "qc-core"


def _build_helper(args):
    """Build dist/qc-core.app: the JSON-lines core service as a background
    app bundle (no Tk).  A bundle — not a loose onedir folder — because the
    SwiftUI app nests it under Contents/Helpers/, and codesign only accepts
    nested code that is itself a signed bundle (loose data files next to a
    Mach-O fail with "code object is not signed at all").  It runs headless:
    LSUIElement keeps it out of the Dock; stdin/stdout are ordinary pipes."""
    import plistlib
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name",      HELPER_NAME,
        "--distpath",  DIST,
        "--workpath",  os.path.join(WORK, "helper"),
        "--specpath",  os.path.join(WORK, "helper"),
        "--onedir",
        "--windowed",              # produces the .app bundle layout
        "--clean",
        "--noconfirm",
        "--osx-bundle-identifier", BUNDLE_ID + ".core",
        "--paths",     SRC,
    ]
    if args.arch:
        cmd += ["--target-arch", args.arch]
    for h in HIDDEN:
        if "tkinter" in h or "zxcvbn" in h or ".ui" in h:
            continue
        cmd += ["--hidden-import", h]
    for mod in ("tkinter", "_tkinter", "tkinterdnd2", "quantacrypt.ui"):
        cmd += ["--exclude-module", mod]
    # No --add-data of the source tree: the modules are collected through
    # --paths/--hidden-import; copying src/ would smuggle the excluded Tk
    # UI and __pycache__ into the helper.
    cmd += ["--hidden-import", "quantacrypt.core.service",
            "--hidden-import", "quantacrypt.core.package",
            "--hidden-import", "quantacrypt.core.errors"]
    cmd.append(os.path.join(PKG, "cli.py"))
    print(f"\n{'='*60}\n  Building helper: {HELPER_NAME}.app\n{'='*60}")
    if args.arch == "x86_64":
        cmd = ["arch", "-x86_64"] + cmd
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print("[!] Helper build failed"); sys.exit(1)
    app = os.path.join(DIST, HELPER_NAME + ".app")
    # PyInstaller also leaves a bare onedir tree next to the .app; drop it so
    # only one artefact exists to copy.
    shutil.rmtree(os.path.join(DIST, HELPER_NAME), ignore_errors=True)
    plist_path = os.path.join(app, "Contents", "Info.plist")
    with open(plist_path, "rb") as f:
        plist = plistlib.load(f)
    plist["LSUIElement"] = True        # no Dock icon, no menu bar
    plist["LSBackgroundOnly"] = True
    plist["CFBundleDisplayName"] = "QuantaCrypt Core"
    with open(plist_path, "wb") as f:
        plistlib.dump(plist, f)
    _codesign_app_bundle(app, name=HELPER_NAME)
    exe = os.path.join(app, "Contents", "MacOS", HELPER_NAME)
    # Smoke: the binary must answer a version request and exit on EOF.
    probe = '{"id":"1","op":"version"}\n'
    r = subprocess.run([exe], input=probe, capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or '"version"' not in r.stdout:
        print(f"[!] Helper smoke test failed:\n{r.stdout}\n{r.stderr}"); sys.exit(1)
    total = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(app) for f in fs)
    print(f"[+] Built {app} ({total / 1_000_000:.1f} MB), smoke test OK")
NATIVE_DIR = os.path.join(ROOT, "macos")
NATIVE_NAME = "QuantaCrypt"
ENTITLEMENTS = os.path.join(ROOT, "scripts", "hardened-runtime.entitlements")


def _assert_not_debuggable(app):
    """Fail if the bundle carries com.apple.security.get-task-allow.

    It is the entitlement that lets any same-user process take the app's
    task port and read the memory holding passwords and shares — the one
    switch that re-opens a hardened-runtime app to debugging.  Xcode injects
    it into every non-archive build unless CODE_SIGN_INJECT_BASE_ENTITLEMENTS
    is NO, and notarization rejects it outright.
    """
    r = subprocess.run(["codesign", "-d", "--entitlements", "-", app],
                       capture_output=True, text=True)
    if "get-task-allow" in (r.stdout + r.stderr):
        print(f"[!] {app} carries com.apple.security.get-task-allow"); sys.exit(1)


def _stage_native_icons():
    """Render the app/document/volume icons into macos/QuantaCrypt/Resources.

    The .icns files are generated artifacts (gitignored), but project.yml
    lists them as resources — xcodegen's `optional: true` only silences the
    *generation*-time missing-path check, so the reference still lands in the
    project and `xcodebuild` fails at CpResource if they are absent. Any path
    that generates the project and builds it must run this first: `--native`,
    CI's macos-shell job, and a fresh clone following the README/CLAUDE.md
    dev command.
    """
    res_dir = os.path.join(NATIVE_DIR, NATIVE_NAME, "Resources")
    os.makedirs(res_dir, exist_ok=True)
    _, icon_tmp = _build_icon()
    staged = []
    for tmp, name in ((icon_tmp, "icon.icns"),
                      (_build_doc_icon(), DOC_ICON_NAME),
                      (_build_vol_icon(), VOL_ICON_NAME)):
        dest = os.path.join(res_dir, name)
        if tmp and os.path.isfile(tmp):
            shutil.move(tmp, dest)
            print(f"[+] Icon → {dest}")
            staged.append(name)
        elif not os.path.isfile(dest):
            # Better a placeholder than a build that fails at CpResource: the
            # icon is cosmetic, the build is not.
            open(dest, "wb").close()
            print(f"[!] Could not render {name} — wrote an empty placeholder")
    return staged


def _native_xcodebuild_cmd(identity, arch, derived):
    """The Release xcodebuild invocation.  CODE_SIGN_INJECT_BASE_ENTITLEMENTS
    is off because a plain ``build`` action otherwise injects get-task-allow
    into the product (see _assert_not_debuggable)."""
    cmd = ["xcodebuild", "-project", f"{NATIVE_NAME}.xcodeproj", "-scheme", NATIVE_NAME,
           "-configuration", "Release", "-derivedDataPath", derived,
           f"CODE_SIGN_IDENTITY={identity}", "CODE_SIGN_STYLE=Manual",
           "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO"]
    if arch:
        cmd += [f"ARCHS={arch}", "ONLY_ACTIVE_ARCH=NO"]
    if identity == "-":
        cmd += ["CODE_SIGNING_ALLOWED=YES"]
    cmd.append("build")
    return cmd


def _build_native(args):
    """One command → one .app.  Builds the qc-core helper bundle, renders
    the app/document icons from src/quantacrypt/assets into the Xcode
    resources, generates the project, builds Release, copies the result to
    dist/ and wraps it in the same drag-to-Applications DMG as the Tk app."""
    _build_helper(args)
    _stage_native_icons()

    if shutil.which("xcodegen") is None:
        print("[!] xcodegen not found — brew install xcodegen"); sys.exit(1)
    subprocess.run(["xcodegen", "generate"], cwd=NATIVE_DIR, check=True)

    derived = os.path.join(NATIVE_DIR, "build")
    identity = os.environ.get("CODESIGN_IDENTITY", "-")
    cmd = _native_xcodebuild_cmd(identity, args.arch, derived)
    print(f"\n{'='*60}\n  Building native app: {NATIVE_NAME}.app\n{'='*60}")
    r = subprocess.run(cmd, cwd=NATIVE_DIR, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-4000:]); print(r.stderr[-2000:])
        print("[!] xcodebuild failed"); sys.exit(1)
    built = os.path.join(derived, "Build", "Products", "Release", f"{NATIVE_NAME}.app")
    app = os.path.join(DIST, f"{NATIVE_NAME}.app")
    shutil.rmtree(app, ignore_errors=True)
    shutil.copytree(built, app, symlinks=True)
    helper_exe = os.path.join(app, "Contents", "Helpers", "qc-core.app", "Contents", "MacOS", "qc-core")
    if not os.path.isfile(helper_exe):
        print("[!] The helper was not bundled into the app"); sys.exit(1)
    v = subprocess.run(["codesign", "--verify", "--deep", "--strict", app],
                       capture_output=True, text=True)
    if v.returncode != 0:
        print(f"[!] Signature check failed: {v.stderr.strip()}"); sys.exit(1)
    _assert_not_debuggable(app)
    total = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(app) for f in fs)
    print(f"[+] Built {app} ({total / 1_000_000:.1f} MB, helper bundled, signature OK, not debuggable)")
    if not args.no_dmg:
        import platform
        _create_dmg(app, args.arch or platform.machine(), name=f"{NATIVE_NAME}-native")
    else:
        print("[*] Skipping DMG creation (--no-dmg)")


def main():
    args = _parse_args()
    os.makedirs(DIST, exist_ok=True)

    # ── Gate: tests + coverage must pass before we build ──
    if not args.skip_tests:
        _run_tests()

    if args.test_only:
        return

    if args.native:
        _build_native(args)
        return

    if args.icons:
        _stage_native_icons()
        return

    if args.helper:
        _build_helper(args)
        return

    # ── Gate: the optional `strength` extra must be installed so the shipped
    # binary has working password-strength feedback.  zxcvbn is listed in
    # HIDDEN above, but PyInstaller silently drops unresolved hidden imports
    # — the resulting app would fall back to a much weaker built-in estimator
    # without any indication to the user.  Refuse to build rather than ship
    # a quietly-degraded binary.
    try:
        import zxcvbn  # noqa: F401
    except ImportError:
        print(
            "\n[!] zxcvbn is not installed in this environment.\n"
            "    The password-strength meter and weak-password warning "
            "would silently degrade in the built binary.\n"
            "    Install it with:\n"
            "        pip install -e \".[dev,dnd,strength]\"\n"
        )
        sys.exit(1)

    icon_args, icon_tmp = _build_icon()
    doc_icon_tmp = _build_doc_icon()
    vol_icon_tmp = _build_vol_icon()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name",      NAME,
        "--distpath",  TK_DIST,
        "--workpath",  WORK,
        "--specpath",  WORK,
        "--noconsole",
        "--clean",
        "--noconfirm",
        "--osx-bundle-identifier", BUNDLE_ID,
    ] + icon_args

    # Universal binary / arch targeting (macOS only)
    target_arch = args.arch
    if target_arch:
        cmd += ["--target-arch", target_arch]
        arch_label = target_arch
    else:
        import platform
        arch_label = platform.machine()  # arm64 or x86_64

    # --onedir produces a proper .app bundle (double-clickable, Dock-friendly).
    for h in HIDDEN:
        cmd += ["--hidden-import", h]

    sep = ":"

    # Bundle the entire src/quantacrypt package so all modules are available
    cmd += ["--add-data", f"{PKG}{sep}quantacrypt"]

    # Bundle icon.png so the runtime iconphoto call can find it inside the app
    png = os.path.join(PKG, "assets", "icon.png")
    if os.path.isfile(png):
        cmd += ["--add-data", f"{png}{sep}."]

    # Bundle the entire tkinterdnd2 package tree so the native
    # tkdnd/<platform>/ directory is available at _MEIPASS/tkinterdnd2/ at runtime.
    tkdnd2_dir = _find_tkinterdnd2()
    if tkdnd2_dir:
        cmd += ["--add-data", f"{tkdnd2_dir}{sep}tkinterdnd2"]
    else:
        print("[!] WARNING: tkinterdnd2 not installed -- drag-and-drop will be disabled.")
        print("    Install with: pip install tkinterdnd2")

    # Add src/ to paths so quantacrypt package is importable
    cmd += ["--paths", SRC]
    cmd.append(os.path.join(PKG, "__main__.py"))

    print(f"\n{'='*60}\n  Building: {NAME}{SUF}  ({arch_label})\n{'='*60}")
    # When building for x86_64 on Apple Silicon (even under Rosetta),
    # wrap the PyInstaller subprocess with `arch -x86_64`.  Child
    # processes do NOT inherit the Rosetta constraint from their parent,
    # so without this explicit wrapping PyInstaller would run as arm64.
    # Note: we check for x86_64 target regardless of platform.machine()
    # because under Rosetta, machine() reports "x86_64" even though the
    # underlying hardware is arm64 and children would revert to arm64.
    if target_arch == "x86_64":
        cmd = ["arch", "-x86_64"] + cmd
    result = subprocess.run(cmd, cwd=ROOT)

    # Clean up the generated platform icon (icns/ico) — only needed during build
    if icon_tmp and os.path.isfile(icon_tmp):
        os.remove(icon_tmp)

    if result.returncode != 0:
        # Clean up icon temp files on failure (success path handles it in _post_build)
        for tmp in (doc_icon_tmp, vol_icon_tmp):
            if tmp and os.path.isfile(tmp):
                os.remove(tmp)
        print("[!] Build failed"); sys.exit(1)

    _post_build(os.path.join(TK_DIST, NAME + SUF), doc_icon_tmp, arch_label,
                skip_dmg=args.no_dmg, vol_icon_tmp=vol_icon_tmp)


if __name__ == "__main__":
    main()
