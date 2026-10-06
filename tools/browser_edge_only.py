"""Edge-only browser policy: every Hermes browser path drives the user's REAL Microsoft Edge.

On unless ``browser.edge_only: false``. While on, the only browser Hermes may open is the installed
``msedge.exe`` — launched VISIBLE on a Hermes-owned profile (``<HERMES_HOME>/edge-profile``) with a
loopback CDP port (``browser.edge_cdp_port``, default 9333) — and every backend attaches to it over CDP.
Never a packaged/headless Chromium (agent-browser / Playwright), cloud browser, Camofox or Lightpanda.

Fail closed: if Edge is missing, or the port is served by anything other than the installed Edge binary,
callers get an error instead of a silent fallback to another browser.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_EDGE_CDP_PORT = 9333  # not 9222: VS Code's js-debug and /browser connect squat that one
_LAUNCH_TIMEOUT_S = 20.0
_launch_lock = threading.Lock()


def _browser_setting(key: str, default):
    try:
        from hermes_cli.config import read_raw_config
        browser_cfg = read_raw_config().get("browser", {})
        if isinstance(browser_cfg, dict) and key in browser_cfg:
            return browser_cfg[key]
    except Exception as e:
        logger.debug("edge-only: could not read browser.%s: %s", key, e)
    return default


def edge_only_enabled() -> bool:
    """``browser.edge_only`` (default True). Read on every call so flipping it needs no restart."""
    value = _browser_setting("edge_only", True)
    if isinstance(value, str):
        return value.strip().lower() not in ("false", "0", "no", "off")
    return bool(value)


def edge_cdp_port() -> int:
    try:
        port = int(_browser_setting("edge_cdp_port", DEFAULT_EDGE_CDP_PORT))
        return port if 1024 <= port <= 65535 else DEFAULT_EDGE_CDP_PORT
    except (TypeError, ValueError):
        return DEFAULT_EDGE_CDP_PORT


def edge_cdp_root() -> str:
    """HTTP CDP discovery root Hermes uses for Edge (no I/O — safe for schema-build gates)."""
    return f"http://127.0.0.1:{edge_cdp_port()}"


def edge_executable() -> Optional[str]:
    from hermes_cli.browser_connect import chromium_executable
    return chromium_executable("edge")


def edge_profile_dir() -> str:
    from hermes_constants import get_hermes_home
    return str(get_hermes_home() / "edge-profile")


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _port_owner_exe(port: int) -> Optional[str]:
    """Executable of the process LISTENING on loopback ``port``; None when it can't be determined."""
    try:
        import psutil
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port and conn.pid:
                return psutil.Process(conn.pid).exe()
    except Exception as e:
        logger.debug("edge-only: could not resolve owner of port %s: %s", port, e)
    return None


def _endpoint_reports_edge(http_root: str) -> bool:
    try:
        import requests
        payload = requests.get(f"{http_root}/json/version", timeout=2).json()
    except Exception:
        return False
    return "Edg/" in f"{payload.get('Browser', '')} {payload.get('User-Agent', '')}"


def is_real_edge_endpoint(http_root: str, port: int) -> Tuple[bool, str]:
    """``(ok, reason)``: the CDP endpoint must be served by the INSTALLED msedge.exe.

    The listening process's binary is the authority; the ``Edg/`` product string alone is only trusted
    when the owner can't be read (a Chromium can fake a user agent, not its executable path).
    """
    exe = edge_executable()
    if not exe:
        return False, "Microsoft Edge is not installed (msedge.exe not found)."
    owner = _port_owner_exe(port)
    if owner is not None:
        if _same_file(owner, exe):
            return True, ""
        return False, f"port {port} is served by {owner!r}, not the installed Microsoft Edge ({exe})."
    if _endpoint_reports_edge(http_root):
        return True, ""
    return False, f"the browser on port {port} does not identify as Microsoft Edge."


def _launch_edge(exe: str, port: int) -> None:
    profile = edge_profile_dir()
    os.makedirs(profile, exist_ok=True)
    argv = [exe, f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
            "--no-first-run", "--no-default-browser-check"]
    kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0)
                                   | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(argv, **kwargs)  # detached: Edge outlives the tool call, like the user's own browser
    logger.info("edge-only: launched Microsoft Edge (%s) on CDP port %d, profile %s", exe, port, profile)


def ensure_real_edge_cdp() -> Tuple[Optional[str], Optional[str]]:
    """``(http_cdp_root, error)`` for a running, verified real Edge — launching it when needed."""
    from hermes_cli.browser_connect import discover_local_cdp_url, local_port_in_use

    port = edge_cdp_port()
    with _launch_lock:
        root = discover_local_cdp_url(port)
        if root:
            ok, reason = is_real_edge_endpoint(root, port)
            return (root, None) if ok else (None, f"Edge-only browser policy: {reason}")
        if local_port_in_use(port):
            return None, (f"Edge-only browser policy: port {port} is taken by another application. "
                          "Close it or set browser.edge_cdp_port to a free port.")
        exe = edge_executable()
        if not exe:
            return None, "Edge-only browser policy: Microsoft Edge is not installed (msedge.exe not found)."
        try:
            _launch_edge(exe, port)
        except OSError as e:
            return None, f"Edge-only browser policy: could not launch Microsoft Edge: {e}"
        deadline = time.monotonic() + _LAUNCH_TIMEOUT_S
        while time.monotonic() < deadline:
            root = discover_local_cdp_url(port, timeout=0.5)
            if root:
                ok, reason = is_real_edge_endpoint(root, port)
                return (root, None) if ok else (None, f"Edge-only browser policy: {reason}")
            time.sleep(0.25)
    return None, (f"Edge-only browser policy: Microsoft Edge did not open its debug port {port} within "
                  f"{int(_LAUNCH_TIMEOUT_S)}s. Retry, or close Edge windows using the Hermes profile.")


def blocked_backend_error(what: str) -> str:
    return (f"Edge-only browser policy: refusing to start {what}. Hermes may only open the real "
            "Microsoft Edge (set browser.edge_only: false in config.yaml to allow other browsers).")
