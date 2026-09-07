"""Background update checker — queries GitHub Releases API.

Usage from the launcher:

    from quantacrypt.ui.updater import check_for_update
    check_for_update(parent_widget, current_version)

The check runs in a daemon thread so the UI is never blocked.  If a newer
release is found, a small banner is inserted into *parent_widget* with a
button that opens the release page.  If the check fails (no network, API
error, etc.) it silently does nothing — the user should never be bothered
by update-check failures.  Dismissing a release is remembered (``AppPrefs``)
so the same banner does not come back every launch.
"""

import json
import re
import threading
import tkinter as tk
import urllib.request
import webbrowser
from typing import Optional, Tuple

from quantacrypt.ui.shared import C, F, SP, ICON, FlatButton, AppPrefs, safe_after

_REPO = "alexboccard/QuantaCrypt"
_API_URL = f"https://api.github.com/repos/{_REPO}/releases/latest"
_RELEASES_URL = f"https://github.com/{_REPO}/releases"
_TIMEOUT = 5  # seconds
_MAX_BODY = 1 << 20   # a release document is a few KB; anything more is not one
_MAX_TAG = 64         # longest tag ever shown or remembered
_PREF_DISMISSED = "dismissed_update"


def _release_page(url) -> str:
    """``html_url`` from the response, or the releases page when it points
    anywhere but this project on GitHub — the JSON is only as trustworthy
    as the connection that carried it."""
    if isinstance(url, str) and url.startswith(f"https://github.com/{_REPO}/"):
        return url
    return _RELEASES_URL


_NUMERIC_PREFIX = re.compile(r"\s*[vV]?(\d+(?:\.\d+)*)")


def _parse_version(tag: str) -> Tuple[int, ...]:
    """Turn 'v1.2.3', '1.2.3-beta' or the PEP 440 '1.2.3b0' into (1, 2, 3).

    Only the leading numeric release matters: a pre-release build compares
    equal to its tag and older than the final.  Splitting on '-' and
    stopping at the first non-integer *component* read the stamped
    '1.5.0b0' as (1, 5), so every stable 1.5.x looked newer — including
    older ones — and the banner installing could never clear came back.
    """
    m = _NUMERIC_PREFIX.match(tag)
    if not m:
        return (0,)
    return tuple(int(p) for p in m.group(1).split("."))


def _version_key(tag: str) -> Tuple[Tuple[int, ...], int]:
    """What check_for_update orders by: the release, then a rank.

    The rank puts a pre-release below its final and a post-release above
    it, so a `1.5.0b0` build is offered `v1.5.0` — the release its users
    are waiting for — while `v1.5.0-beta` itself stays "up to date".  Any
    remainder after the numeric release counts as a pre-release marker
    (`b0`, `-beta`, `rc1`, `.dev3`) except a PEP 440 local segment (`+ci`)
    and `post`: enumerating spellings is how the `\b`-terminated form
    missed the stamped `1.5.0b0`.
    """
    m = _NUMERIC_PREFIX.match(tag)
    if not m:
        return ((0,), 0)
    rest = tag[m.end():].strip().lstrip("-._").lower()
    if not rest or rest.startswith("+"):
        rank = 0
    elif rest.startswith("post"):
        rank = 1
    else:
        rank = -1
    return (_parse_version(tag), rank)


def _fetch_latest() -> Optional[dict]:
    """Query GitHub for the latest release.  Returns None on any error."""
    try:
        req = urllib.request.Request(
            _API_URL,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "QuantaCrypt-UpdateCheck"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read(_MAX_BODY))
    except Exception:
        return None


def check_for_update(parent: "tk.Toplevel", current_version: str) -> None:
    """Spawn a background thread to check for updates.

    If a newer version is found (and the user hasn't dismissed that exact
    release before), schedule a banner to be added to *parent* on the main
    thread via ``after()``.
    """

    def _worker():
        data = _fetch_latest()
        # A JSON array, or a captive-portal page that happens to parse,
        # would raise in the daemon thread — a traceback, no banner.
        if not isinstance(data, dict):
            return

        tag = data.get("tag_name", "")
        html_url = data.get("html_url", "")

        if not tag or not isinstance(tag, str) or len(tag) > _MAX_TAG:
            return

        try:
            latest = _version_key(tag)
            current = _version_key(current_version)
        except Exception:
            return

        if latest <= current:
            return  # already up to date

        if AppPrefs.get(_PREF_DISMISSED) == tag:
            return  # the user already said "not this one"

        display_ver = tag.lstrip("vV")
        current_disp = current_version.lstrip("vV")

        # Schedule the UI update on the main thread; safe_after also skips
        # the hop when the launcher is destroyed before it fires.
        safe_after(parent, lambda: _show_banner(parent, display_ver, current_disp,
                                                tag, html_url))

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def _show_banner(parent: "tk.Toplevel", version: str, current: str,
                 tag: str, url: str) -> None:
    """Insert a subtle update banner near the top of the parent widget.

    Prefers a ``_banner_slot`` frame provided by the parent; otherwise packs
    after the parent's second child (logo section + divider)."""
    slot = getattr(parent, "_banner_slot", None)
    if slot is not None:
        banner = tk.Frame(slot, bg=C["surface"], highlightbackground=C["accent"],
                          highlightthickness=1)
        banner.pack(fill="x", pady=(0, SP["s"]))
    else:
        banner = tk.Frame(parent, bg=C["surface"], highlightbackground=C["accent"],
                          highlightthickness=1)
        children = parent.pack_slaves()
        if len(children) >= 2:
            banner.pack(fill="x", padx=SP["xxl"], pady=(0, SP["s"]), after=children[1])
        else:
            banner.pack(fill="x", padx=SP["xxl"], pady=(0, SP["s"]))

    inner = tk.Frame(banner, bg=C["surface"])
    inner.pack(fill="x", padx=SP["m"], pady=SP["s"])

    tk.Label(inner, text=f"Update available: v{version} (you have v{current})",
             font=F["caption"], bg=C["surface"], fg=C["text2"]).pack(side="left")

    def _dismiss():
        AppPrefs.set(_PREF_DISMISSED, tag)
        banner.destroy()

    FlatButton(inner, ICON["close"], _dismiss, primary=False, small=True).pack(
        side="right")
    FlatButton(inner, "See what's new", lambda: webbrowser.open(_release_page(url)),
               primary=False, small=True).pack(side="right", padx=(0, SP["s"]))
