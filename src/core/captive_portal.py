"""
Captive portal detection.

Probes a well-known HTTP endpoint that returns 204 No Content on a clean network.
Any other response (redirect, HTML page, wrong status) indicates a captive portal
is intercepting traffic — the relay will not work until the user authenticates.

Probe endpoint: http://connectivitycheck.gstatic.com/generate_204
Same endpoint used by Android and ChromeOS for connectivity checks.
"""

import asyncio
import logging
import webbrowser

log = logging.getLogger("CaptivePortal")

_PROBE_HOST = "connectivitycheck.gstatic.com"
_PROBE_PATH = "/generate_204"
_PROBE_PORT = 80
_PROBE_TIMEOUT = 5.0


async def probe() -> tuple[bool, str | None]:
    """Probe for a captive portal.

    Opens a raw HTTP/1.1 connection (no redirects) to the probe endpoint.
    Returns (is_captive, portal_url):
      - (False, None)       → network is clean
      - (True, "http://...") → captive portal detected, redirect URL known
      - (True, None)        → captive portal detected, no redirect URL
    On any network error the function returns (False, None) so a transient
    failure never blocks startup.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(_PROBE_HOST, _PROBE_PORT),
            timeout=_PROBE_TIMEOUT,
        )
    except Exception as exc:
        log.debug("Probe connect failed: %s", exc)
        return False, None

    try:
        writer.write((
            f"GET {_PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {_PROBE_HOST}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode())
        await writer.drain()

        status_line = await asyncio.wait_for(
            reader.readline(), timeout=_PROBE_TIMEOUT
        )
        parts = status_line.decode(errors="replace").split()
        if len(parts) < 2:
            return False, None

        try:
            status_code = int(parts[1])
        except ValueError:
            return False, None

        if status_code == 204:
            return False, None  # clean network

        # Read headers to find Location redirect
        portal_url: str | None = None
        while True:
            line = await asyncio.wait_for(
                reader.readline(), timeout=_PROBE_TIMEOUT
            )
            decoded = line.decode(errors="replace").strip()
            if not decoded:
                break
            lower = decoded.lower()
            if lower.startswith("location:"):
                portal_url = decoded.split(":", 1)[1].strip()

        return True, portal_url

    except asyncio.TimeoutError:
        log.debug("Probe timed out")
        return False, None
    except Exception as exc:
        log.debug("Probe error: %s", exc)
        return False, None
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def startup_check(config: dict) -> None:
    """Run a single probe at startup and warn if a captive portal is found.

    When captive_portal.open_browser is true and a redirect URL is available,
    the portal page is opened in the default browser automatically.
    """
    cp_cfg = config.get("captive_portal") or {}
    log.info("Checking for captive portal…")
    is_captive, portal_url = await probe()

    if not is_captive:
        log.info("Network is clean — no captive portal detected.")
        return

    if portal_url:
        log.warning(
            "Captive portal detected! All traffic is being intercepted.\n"
            "  Portal URL : %s\n"
            "  The relay will not work until you authenticate on the portal.\n"
            "  Tip: open the URL above in a browser, sign in, then retry.",
            portal_url,
        )
    else:
        log.warning(
            "Captive portal detected! The connectivity probe returned an "
            "unexpected response (not HTTP 204). The relay may not work until "
            "you authenticate on the network's captive portal."
        )

    if cp_cfg.get("open_browser", False) and portal_url:
        log.info("Opening captive portal in default browser: %s", portal_url)
        try:
            webbrowser.open(portal_url)
        except Exception as exc:
            log.debug("Failed to open browser: %s", exc)


async def monitor(config: dict) -> None:
    """Background task: re-probe periodically and log state transitions.

    Logs a warning when the portal becomes active mid-session (e.g. the
    network lease expired and the ISP requires re-authentication), and an
    info message when the portal clears and the network is clean again.
    """
    cp_cfg = config.get("captive_portal") or {}
    interval = max(10.0, float(cp_cfg.get("check_interval", 30)))

    last_captive: bool | None = None

    while True:
        try:
            await asyncio.sleep(interval)
            is_captive, portal_url = await probe()

            if is_captive and last_captive is not True:
                if portal_url:
                    log.warning(
                        "Captive portal became active — relay traffic is being "
                        "intercepted. Portal URL: %s",
                        portal_url,
                    )
                else:
                    log.warning(
                        "Captive portal became active — relay traffic is being "
                        "intercepted."
                    )
                last_captive = True

            elif not is_captive and last_captive is True:
                log.info(
                    "Captive portal cleared — network is clean again. "
                    "Relay should resume normally."
                )
                last_captive = False

            else:
                last_captive = is_captive

        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.debug("Monitor error: %s", exc)
