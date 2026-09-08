import asyncio
import importlib.resources
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from contextlib import asynccontextmanager
from html import escape
from ipaddress import ip_address
from pathlib import Path
from string import Template
from typing import Any, Optional
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener, urlopen

from fastapi import FastAPI, Request, WebSocket
from fastapi.logger import logger
from fastapi.responses import HTMLResponse, Response

import pymobiledevice3.resources
from pymobiledevice3.services.web_protocol.cdp_browser import (
    HELD_TARGETS,
    PAGE_HANDOVER_TIMEOUT,
    PAGE_LOCKS,
    PAGE_TAKEOVERS,
    TARGET_CREATION_TIMEOUT,
    CdpBrowser,
    HeldTargets,
    adopt_held_target,
    iter_inspectable,
    target_title,
    target_type,
    target_url,
)
from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.web_protocol.cdp_trace import (
    BRIDGE_TO_EDITOR,
    EDITOR_TO_BRIDGE,
    ProtocolTrace,
)
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import (
    Application,
    AutomationAvailability,
    Page,
    WebinspectorService,
    WirTypes,
)

# chrome://inspect routes a network target's DevTools through Chrome's browser-process relay,
# which deadlocks after sustained console traffic (the console/screen freeze). Serving the DevTools
# frontend here - opened as an ordinary http page - makes it connect straight to the bridge's
# WebSocket, bypassing that relay entirely. The frontend is proxied (not bundled): from the
# officially hosted build (pinned to a revision compatible with the WIR<->CDP translation) when it
# is reachable, otherwise from a locally installed Chrome, which serves its own bundled frontend.
DEVTOOLS_FRONTEND_REV = "0fcdce5f4fdec8d442d7df760cb541f1ca6e446d"
DEVTOOLS_FRONTEND_HOST = "chrome-devtools-frontend.appspot.com"
_frontend_cache: dict[str, tuple[bytes, str]] = {}

# The local Chrome's assets must be fetched without a proxy. urllib applies proxy configuration
# to loopback addresses as well - neither the no_proxy/ExceptionsList defaults nor macOS'
# "exclude simple hostnames" cover 127.0.0.1 - so on a proxied network every asset request for
# the fallback frontend would be sent to the proxy and come back empty, leaving a blank DevTools
# window. Browsers bypass loopback implicitly; this opener does the same.
_DIRECT_OPENER = build_opener(ProxyHandler({}))

# Names/locations for the Chrome/Chromium binary used for the offline frontend fallback.
_CHROME_BINARY_NAMES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    "chrome.exe",
)
_CHROME_DEFAULT_PATHS: dict[str, tuple[str, ...]] = {
    "darwin": (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ),
    "win32": (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ),
    "linux": (
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ),
}


NO_TARGETS_MESSAGE = "No inspectable pages. Open a page in Safari."
NO_TARGETS_MESSAGE_HTML = f'<p class="empty">{NO_TARGETS_MESSAGE}</p>'

# How often the landing page re-reads the target list. Serving one is a read of already-pushed
# state (see refresh_listings), so this can be short enough that a tab opened or closed on the
# device shows up about as fast as it does in Safari's own Develop menu. The page still stops
# polling while it is not the visible tab.
INDEX_POLL_INTERVAL_MS = 750

# The project logo, served as the landing page's favicon and header image (see serve_logo).
LOGO_PNG = (importlib.resources.files(pymobiledevice3.resources) / "webinspector" / "logo.png").read_bytes()

# Label of the landing page's pause-on-launch switch (see pause_new_targets endpoints).
PAUSE_NEW_TARGETS_LABEL = "Pause new JSContexts on launch"

# Badge shown next to a debuggable's title: (text, tooltip). "paused" is a JSContext the bridge is
# holding on its first statement; the other two say who is debugging it right now - the device
# reports the Web Inspector connection attached to each debuggable, and WebKit serves one session
# per debuggable, so anyone else has to wait for that connection to let go.
BADGES: dict[str, tuple[str, str]] = {
    "paused": ("paused", "Held by the bridge on its first statement; open it to land on the pause."),
    "bridge": ("attached here", "Being debugged through this bridge; opening it takes it over from that session."),
    "other": (
        "held elsewhere",
        "Being debugged over another Web Inspector connection (Safari, another pymobiledevice3); "
        "detach that debugger first.",
    ),
}


def target_label(page: Page) -> str:
    """The landing page's link text. It sits under its process's header there, so a JSContext needs
    only its number (its /json/list title carries the process too, for editors listing targets flat)."""
    if page.type_ == WirTypes.JAVASCRIPT:
        return f"{page.web_title or 'JSContext'} #{page.id_}"
    return page.web_title or page.web_url or f"page {page.id_}"


def application_info(inspector: WebinspectorService, application: Application) -> dict[str, Any]:
    """The process a debuggable belongs to, as the landing page shows it: identity, icon, the
    application hosting it when it is a proxy for one (web content running out of process), and
    whether it accepts Remote Automation sessions."""
    host = inspector.connected_application.get(application.host) if application.proxy else None
    return {
        "id": application.id_,
        "name": application.name,
        "pid": application.pid,
        "bundle": application.bundle,
        "icon": f"/icon/{application.id_}" if application.icon else "",
        "host": host.name if host is not None and host is not application else "",
        "automation": application.availability == AutomationAvailability.AVAILABLE,
    }


def bridge_version() -> str:
    """The running pymobiledevice3's version, or "" when the package was not built (a bare checkout
    without its generated version module)."""
    try:
        from pymobiledevice3._version import __version__
    except ImportError:
        return ""
    return __version__


AUTOMATION_TITLE = "Accepts Remote Automation sessions (Settings > Safari > Advanced > Remote Automation)."
INDICATE_TITLE = "Hover to highlight this page on the device."
FILTER_PLACEHOLDER = "Filter by title, URL, process, bundle or pid"


def search_text(application: Application, page: Page) -> str:
    """What the landing page's filter box matches a target against."""
    return " ".join((
        target_label(page),
        target_url(application, page),
        application.name,
        application.bundle,
        str(application.pid),
    )).lower()


def debugged_by(inspector: WebinspectorService, page: Page) -> str:
    """Who is debugging a page right now: "" for nobody, "bridge" for a session of this bridge, "other"
    for a different Web Inspector connection."""
    if not page.web_connection_id:
        return ""
    return "bridge" if page.web_connection_id == inspector.connection_id else "other"


INDEX_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f5f5f7; --card: #ffffff; --text: #1d1d1f; --muted: #6e6e73; --line: #e5e5ea;
  --accent: #0a84ff; --page: #dbeafe; --page-text: #1e40af; --js: #fef3c7; --js-text: #92400e;
  --paused: #fde68a; --paused-text: #78350f; --held: #fecaca; --held-text: #7f1d1d; --switch: #c7c7cc;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1c1c1e; --card: #2c2c2e; --text: #f5f5f7; --muted: #98989d; --line: #3a3a3c;
    --page: #1e3a8a; --page-text: #bfdbfe; --js: #78350f; --js-text: #fde68a;
    --paused: #92400e; --paused-text: #fef3c7; --held: #7f1d1d; --held-text: #fecaca; --switch: #48484a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { max-width: 760px; margin: 0 auto; padding: 18px 16px 32px; }
header { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 20px; margin-bottom: 12px; }
.logo { height: 40px; width: auto; }
h1 { font-size: 17px; font-weight: 600; margin: 0; flex: 1 1 auto; }
h1 small { display: block; font-size: 12px; font-weight: 400; color: var(--muted); }
.toggle { display: inline-flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; font-size: 13px; }
.toggle input { position: absolute; opacity: 0; width: 0; height: 0; }
.switch {
  position: relative; width: 34px; height: 20px; border-radius: 10px; background: var(--switch);
  transition: background .15s;
}
.switch::after {
  content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%;
  background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,.3); transition: transform .15s;
}
.toggle input:checked + .switch { background: var(--accent); }
.toggle input:checked + .switch::after { transform: translateX(14px); }
.toggle input:focus-visible + .switch { outline: 2px solid var(--accent); outline-offset: 2px; }
.hint { flex-basis: 100%; margin: 0; font-size: 12px; color: var(--muted); }
details.app + details.app { margin-top: 16px; }
.app-header { display: flex; align-items: center; gap: 8px; margin: 0 0 6px 2px; cursor: pointer; list-style: none; }
.app-header::-webkit-details-marker { display: none; }
.app-header::before {
  content: ""; flex: none; width: 6px; height: 6px; margin: 0 2px 2px 0;
  border-right: 1.5px solid var(--muted); border-bottom: 1.5px solid var(--muted);
  transform: rotate(45deg); transition: transform .15s;
}
details.app:not([open]) > .app-header { margin-bottom: 0; }
details.app:not([open]) > .app-header::before { transform: rotate(-45deg); margin: 0 0 0 2px; }
.app-header img.icon { width: 22px; height: 22px; border-radius: 5px; flex: none; }
.app-header .name { font-size: 13.5px; font-weight: 600; }
.app-header small { color: var(--muted); font-size: 11.5px; overflow-wrap: anywhere; }
.app-header small.count { margin-left: auto; white-space: nowrap; }
ul.targets { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
li.target {
  background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 7px 12px;
  display: grid; grid-template-columns: auto 1fr; grid-template-rows: auto auto auto; column-gap: 10px; row-gap: 0;
  align-items: center;
}
.kind {
  grid-row: 1 / span 3; font-size: 10px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
  padding: 2px 7px; border-radius: 999px; white-space: nowrap;
}
.kind.page { background: var(--page); color: var(--page-text); }
.kind.jscontext { background: var(--js); color: var(--js-text); }
li.target a { color: var(--accent); font-weight: 500; text-decoration: none; overflow-wrap: anywhere; }
li.target a:hover { text-decoration: underline; }
li.target small { color: var(--muted); font-size: 11.5px; overflow-wrap: anywhere; }
.badge {
  display: inline-block; margin-left: 6px; font-size: 10px; font-weight: 600; padding: 1px 7px;
  border-radius: 999px; background: var(--paused); color: var(--paused-text); vertical-align: 1px;
}
.badge.held { background: var(--held); color: var(--held-text); }
.badge.auto { background: var(--page); color: var(--page-text); }
input.filter {
  flex-basis: 100%; margin-top: 4px; padding: 6px 10px; border-radius: 8px; border: 1px solid var(--line);
  background: var(--card); color: var(--text); font: 13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
input.filter:focus { outline: 2px solid var(--accent); outline-offset: -1px; border-color: transparent; }
li.target[data-indicate] .kind { cursor: crosshair; }
details.attach { grid-column: 2; margin-top: 2px; font-size: 12px; }
details.attach summary, details.editors summary { cursor: pointer; color: var(--muted); }
details.attach summary:hover, details.editors summary:hover { color: var(--text); }
.snippet { position: relative; margin-top: 6px; }
details.attach pre {
  margin: 0; padding: 8px 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--line);
  font: 11.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-x: auto; user-select: all;
}
button.copy {
  position: absolute; top: 5px; right: 5px; font: 11px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  padding: 2px 7px; border-radius: 5px; border: 1px solid var(--line); background: var(--card); color: var(--text);
  cursor: pointer; opacity: 0; transition: opacity .15s;
}
.snippet:hover button.copy, button.copy:focus-visible, button.copy.done { opacity: 1; }
button.copy:hover { border-color: var(--accent); }
button.copy.done { color: var(--accent); border-color: var(--accent); }
details.editors { flex-basis: 100%; font-size: 12px; color: var(--muted); }
details.editors p { margin: 6px 0 0; }
details.editors code { font: 11.5px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--text); }
p.empty { color: var(--muted); text-align: center; padding: 28px 0; }
"""

INDEX_SCRIPT = Template("""
(function () {
  const BADGES = $badges;
  const AUTOMATION_TITLE = $automation_title;
  const INDICATE_TITLE = $indicate_title;
  const container = document.getElementById('targets');
  const toggle = document.getElementById('pause-new-targets');
  const filter = document.getElementById('filter');
  // Narrow the list to targets mentioning every word typed; a process whose targets are all
  // hidden goes with them. Re-applied after every rebuild of the list, so it sticks.
  function applyFilter() {
    const words = filter.value.toLowerCase().split(/\\s+/).filter(Boolean);
    for (const group of container.querySelectorAll('details.app')) {
      let shown = 0;
      for (const item of group.querySelectorAll('li.target')) {
        const match = words.every((word) => item.dataset.search.includes(word));
        item.hidden = !match;
        shown += match ? 1 : 0;
      }
      group.hidden = shown === 0;
    }
  }
  filter.addEventListener('input', applyFilter);
  // Hovering a page highlights its view on the device, as Safari's Develop menu does.
  let indicated = null;
  async function indicate(id, enabled) {
    try {
      await fetch('/api/indicate', {
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({id, enabled}),
      });
    } catch (error) {
      // The bridge is momentarily busy or gone; the highlight is cosmetic.
    }
  }
  container.addEventListener('mouseover', (event) => {
    const item = event.target.closest('li.target');
    const id = item ? item.dataset.indicate || null : null;
    if (id === indicated) {
      return;
    }
    if (indicated !== null) {
      indicate(indicated, false);
    }
    indicated = id;
    if (indicated !== null) {
      indicate(indicated, true);
    }
  });
  container.addEventListener('mouseleave', () => {
    if (indicated !== null) {
      indicate(indicated, false);
      indicated = null;
    }
  });
  // Process groups the user folded; the list is rebuilt whenever it changes, so the fold has to
  // outlive the elements.
  const folded = new Set();
  container.addEventListener('toggle', (event) => {
    const group = event.target;
    if (!group.classList.contains('app')) {
      return;
    }
    if (group.open) {
      folded.delete(group.dataset.app);
    } else {
      folded.add(group.dataset.app);
    }
  }, true);
  let rendered = null;
  function render(targets) {
    container.textContent = '';
    if (!targets.length) {
      const empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = $empty;
      container.appendChild(empty);
      return;
    }
    let section = null;
    let list = null;
    for (const target of targets) {
      if (section === null || section.dataset.app !== target.application.id) {
        section = document.createElement('details');
        section.className = 'app';
        section.dataset.app = target.application.id;
        section.open = !folded.has(target.application.id);
        const header = document.createElement('summary');
        header.className = 'app-header';
        if (target.application.icon) {
          const icon = document.createElement('img');
          icon.className = 'icon';
          icon.src = target.application.icon;
          icon.alt = '';
          header.appendChild(icon);
        }
        const name = document.createElement('span');
        name.className = 'name';
        name.textContent = target.application.name;
        const details = document.createElement('small');
        details.textContent = target.application.bundle + ' \u00b7 pid ' + target.application.pid
          + (target.application.host ? ' \u00b7 in ' + target.application.host : '');
        header.append(name, details);
        if (target.application.automation) {
          const automation = document.createElement('span');
          automation.className = 'badge auto';
          automation.textContent = 'automation';
          automation.title = AUTOMATION_TITLE;
          header.appendChild(automation);
        }
        const count = document.createElement('small');
        count.className = 'count';
        const total = targets.filter((t) => t.application.id === target.application.id).length;
        count.textContent = total + (total === 1 ? ' target' : ' targets');
        header.appendChild(count);
        list = document.createElement('ul');
        list.className = 'targets';
        section.append(header, list);
        container.appendChild(section);
      }
      const kind = document.createElement('span');
      kind.className = 'kind ' + (target.type === 'node' ? 'jscontext' : 'page');
      kind.textContent = target.type === 'node' ? 'JSContext' : 'Page';
      if (target.type !== 'node') {
        kind.title = INDICATE_TITLE;
      }
      const title = document.createElement('span');
      const link = document.createElement('a');
      link.href = target.devtoolsFrontendUrl;
      link.textContent = target.label;
      title.appendChild(link);
      const state = target.paused ? 'paused' : target.debugged_by;
      if (state) {
        const badge = document.createElement('span');
        badge.className = 'badge' + (state === 'other' ? ' held' : '');
        badge.textContent = BADGES[state].text;
        badge.title = BADGES[state].title;
        title.appendChild(badge);
      }
      const url = document.createElement('small');
      url.textContent = target.url;
      const attach = document.createElement('details');
      attach.className = 'attach';
      const summary = document.createElement('summary');
      summary.textContent = 'Attach from VS Code';
      const config = document.createElement('pre');
      config.textContent = JSON.stringify(target.attach, null, 4);
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'copy';
      copy.title = 'Copy to clipboard';
      copy.textContent = 'Copy';
      const snippet = document.createElement('div');
      snippet.className = 'snippet';
      snippet.append(copy, config);
      attach.append(summary, snippet);
      const item = document.createElement('li');
      item.className = 'target';
      item.dataset.search = target.search;
      if (target.type !== 'node') {
        item.dataset.indicate = target.id;
      }
      item.append(kind, title, url, attach);
      list.appendChild(item);
    }
    applyFilter();
  }
  container.addEventListener('click', async (event) => {
    const button = event.target.closest('button.copy');
    if (!button) {
      return;
    }
    const text = button.parentElement.querySelector('pre').textContent;
    try {
      await navigator.clipboard.writeText(text);
    } catch (error) {
      // No clipboard API (a non-loopback host over plain http): fall back to a selection copy.
      const range = document.createRange();
      range.selectNodeContents(button.parentElement.querySelector('pre'));
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      document.execCommand('copy');
      selection.removeAllRanges();
    }
    button.textContent = 'Copied';
    button.classList.add('done');
    setTimeout(() => {
      button.textContent = 'Copy';
      button.classList.remove('done');
    }, 1500);
  });
  let pending = false;
  toggle.addEventListener('change', async () => {
    pending = true;
    try {
      const response = await fetch('/pause-new-targets', {
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({enabled: toggle.checked}),
      });
      toggle.checked = (await response.json()).enabled;
    } catch (error) {
      toggle.checked = !toggle.checked;
    } finally {
      pending = false;
    }
  });
  async function poll() {
    if (!document.hidden) {
      try {
        const listing = await (await fetch('/api/targets', {cache: 'no-store'})).json();
        const serialized = JSON.stringify(listing.targets);
        if (serialized !== rendered) {
          rendered = serialized;
          render(listing.targets);
        }
        if (!pending) {
          toggle.checked = listing.pause_new_targets;
        }
      } catch (error) {
        // The bridge is momentarily busy or gone; leave the list as it is and try again.
      }
    }
    setTimeout(poll, $interval);
  }
  setTimeout(poll, $interval);
})();
""").substitute(
    empty=json.dumps(NO_TARGETS_MESSAGE),
    interval=INDEX_POLL_INTERVAL_MS,
    badges=json.dumps({name: {"text": text, "title": title} for name, (text, title) in BADGES.items()}),
    automation_title=json.dumps(AUTOMATION_TITLE),
    indicate_title=json.dumps(INDICATE_TITLE),
)


def find_chrome(explicit: Optional[str] = None) -> Optional[str]:
    """Locate a Chrome/Chromium binary for the offline frontend fallback: an explicit path, then
    the PATH, then the running platform's known install locations. Returns None if none is found."""
    if explicit:
        return explicit if Path(explicit).exists() else None
    for name in _CHROME_BINARY_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for candidate in _CHROME_DEFAULT_PATHS.get(sys.platform, ()):
        if Path(candidate).exists():
            return candidate
    return None


def _reap_local_frontend() -> None:
    """Tear down the fallback Chrome and its throwaway profile, if one is running."""
    proc: Optional[subprocess.Popen[bytes]] = getattr(app.state, "local_chrome_proc", None)
    if proc is not None:
        proc.terminate()
        app.state.local_chrome_proc = None
    profile: Optional[str] = getattr(app.state, "local_chrome_profile", None)
    if profile:
        shutil.rmtree(profile, ignore_errors=True)
        app.state.local_chrome_profile = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.frontend_lock = asyncio.Lock()
    # Per-page state belongs to one run of the bridge. An asyncio primitive binds to the event loop
    # that created it, and a page handler killed without unwinding - a forced shutdown, a loop torn
    # down under it - leaves its lock held. Either one carried into a later run in the same process
    # (a second asyncio.run, a test) wedges every connection to that page: it waits out
    # PAGE_HANDOVER_TIMEOUT for a lock nobody is left to release, then fails outright because the
    # lock belongs to a loop that is gone.
    PAGE_LOCKS.clear()
    PAGE_TAKEOVERS.clear()
    HELD_TARGETS.clear()
    await app.state.inspector.connect()
    # The bridge's own automatic-inspection debugger (`--pause-new-targets`); toggled from the
    # landing page as well, so it exists either way and is merely started or not.
    app.state.holder = HeldTargets(app.state.inspector)
    if getattr(app.state, "pause_new_targets", False):
        await app.state.holder.start()
    try:
        yield
    finally:
        await app.state.holder.stop()
        _reap_local_frontend()


app = FastAPI(lifespan=lifespan)


def _is_loopback(url: str) -> bool:
    """Whether url addresses this machine, and so must be fetched without going through a proxy."""
    host = urlsplit(url).hostname or ""
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(".localhost")


async def _fetch(url: str) -> Optional[tuple[bytes, str]]:
    """Fetch a frontend asset off the event loop; None on any failure."""

    def _get() -> tuple[bytes, str]:
        # Anything on this machine - the fallback Chrome - is fetched directly; see _DIRECT_OPENER.
        opener = _DIRECT_OPENER.open if _is_loopback(url) else urlopen
        with opener(url, timeout=20) as response:
            return response.read(), response.headers.get_content_type()

    try:
        return await asyncio.get_event_loop().run_in_executor(None, _get)
    except Exception:
        return None


async def _launch_local_frontend() -> Optional[str]:
    """Start a throwaway headless Chrome that serves its own bundled DevTools frontend over http and
    return its origin. Used only when the hosted build is unreachable."""
    chrome = getattr(app.state, "chrome_path", None)
    if not chrome:
        logger.error(
            "DevTools frontend unavailable: the hosted build is unreachable and no Chrome binary "
            "was found. Install Chrome/Chromium or pass --chrome <path>."
        )
        return None
    _reap_local_frontend()
    profile = tempfile.mkdtemp(prefix="pmd3-devtools-frontend-")
    app.state.local_chrome_profile = profile
    app.state.local_chrome_proc = subprocess.Popen(
        [
            chrome,
            "--headless=new",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    port_file = Path(profile) / "DevToolsActivePort"
    for _ in range(80):
        if port_file.exists():
            try:
                return f"http://127.0.0.1:{int(port_file.read_text().splitlines()[0])}"
            except (ValueError, IndexError):
                return None
        await asyncio.sleep(0.1)
    logger.error("local Chrome did not expose a debugging port in time")
    return None


async def _frontend_base() -> Optional[str]:
    """Base URL to serve the DevTools frontend from: the hosted build when reachable, otherwise a
    locally launched Chrome. Resolved once per run and kept, but a failure is deliberately not
    remembered - the causes are transient (a network that comes back, a Chrome that lost the race
    to publish its port), and remembering one served 404s, and so a blank DevTools window, for the
    rest of the session."""
    base = getattr(app.state, "frontend_base", None)
    if base:
        return base
    async with app.state.frontend_lock:
        base = getattr(app.state, "frontend_base", None)
        if base:
            return base
        rev = getattr(app.state, "frontend_rev", DEVTOOLS_FRONTEND_REV)
        hosted = f"https://{DEVTOOLS_FRONTEND_HOST}/serve_rev/@{rev}"
        if await _fetch(f"{hosted}/inspector.html") is not None:
            app.state.frontend_base = hosted
        else:
            local = await _launch_local_frontend()
            app.state.frontend_base = f"{local}/devtools" if local else None
            if local:
                logger.info("serving the DevTools frontend from a local Chrome (hosted build unreachable)")
        return app.state.frontend_base


# Both spellings: Chrome's DevTools HTTP endpoint answers /json/version and /json/version/
# identically, and Playwright's connectOverCDP fetches the trailing-slash form. Without the second
# route it falls through to the /json catch-all below and gets the target list (no
# webSocketDebuggerUrl), so connectOverCDP fails with "Invalid URL: undefined".
@app.get("/json/version")
@app.get("/json/version/")
def version(request: Request):
    host = request.headers.get("host", "localhost:9222")
    return {
        "Browser": "Safari",
        "Protocol-Version": "1.1",
        "User-Agent": "pymobiledevice3",
        "V8-Version": "7.2.233",
        "WebKit-Version": "537.36 (@cfede9db1d154de0468cb0538479f34c0755a0f4)",
        "webSocketDebuggerUrl": f"ws://{host}/devtools/browser/{app.state.inspector.connection_id}",
    }


async def refresh_listings() -> None:
    """Ask every connected application to re-report its pages, and wait for the replies.

    `webinspectord` pushes a fresh listing on its own whenever a page opens, closes or navigates,
    but not the instant an application connects or a page moves to another process - answering
    from the cache alone then left those out, and an editor that lists targets once attached to
    whatever was left without offering a choice. The wait is for the replies themselves (a few
    milliseconds), not a fixed delay; see WebinspectorService.get_open_pages.
    """
    await app.state.inspector.get_open_pages()


@app.get("/json{_:path}")
async def available_targets(request: Request, _: str):
    await refresh_listings()
    host = request.headers.get("host", "localhost:9222")
    targets: list[dict[str, Any]] = []
    for target_id, application, page in iter_inspectable(app.state.inspector):
        targets.append({
            "description": "",
            "id": target_id,
            "title": target_title(application, page),
            "type": target_type(page),
            "url": target_url(application, page),
            "webSocketDebuggerUrl": f"ws://{host}/devtools/page/{target_id}",
            "devtoolsFrontendUrl": f"{_frontend_url(page)}?ws={host}/devtools/page/{target_id}",
        })
        if application.icon:
            # chrome://inspect renders it next to the target, as it does a page's favicon.
            targets[-1]["faviconUrl"] = f"http://{host}/icon/{application.id_}"
    return targets


def attach_config(application: Application, page: Page, host: str, target_id: str) -> dict[str, Any]:
    """The VS Code launch.json configuration that attaches to exactly this debuggable.

    js-debug's `chrome` attach takes web pages only and picks them by URL; a JSContext (a
    `node` target) is reached by its websocket address directly.
    """
    title = target_title(application, page)
    if page.type_ == WirTypes.JAVASCRIPT:
        return {
            "name": f"Attach to {title}",
            "type": "node",
            "request": "attach",
            "websocketAddress": f"ws://{host}/devtools/page/{target_id}",
        }
    address, _, port = host.rpartition(":")
    return {
        "name": f"Attach to {title or page.web_url}",
        "type": "chrome",
        "request": "attach",
        "address": address or host,
        "port": int(port) if port.isdigit() else 9222,
        "urlFilter": page.web_url,
        "webRoot": "${workspaceFolder}",
    }


@app.get("/api/targets")
async def landing_targets(request: Request) -> dict[str, Any]:
    """What the landing page renders: the /json/list targets plus what the listing knows on top -
    which of them the bridge is holding paused, who is debugging each one, and whether the bridge
    is taking new ones (the page's switch)."""
    await refresh_listings()
    host = request.headers.get("host", "127.0.0.1:9222")
    targets: list[dict[str, Any]] = []
    for target_id, application, page in iter_inspectable(app.state.inspector):
        targets.append({
            "id": target_id,
            "title": target_title(application, page),
            "label": target_label(page),
            "type": target_type(page),
            "url": target_url(application, page),
            "application": application_info(app.state.inspector, application),
            "search": search_text(application, page),
            "paused": target_id in HELD_TARGETS,
            "debugged_by": debugged_by(app.state.inspector, page),
            "webSocketDebuggerUrl": f"ws://{host}/devtools/page/{target_id}",
            "devtoolsFrontendUrl": f"{_frontend_url(page)}?ws={host}/devtools/page/{target_id}",
            "attach": attach_config(application, page, host, target_id),
        })
    return {"targets": targets, "pause_new_targets": app.state.holder.running}


@app.post("/api/indicate")
async def indicate_target(request: Request) -> dict[str, bool]:
    """Highlight a page's view on the device, or clear it: {"id": target id, "enabled": bool}.
    JSContexts have no view; asking for one is answered with enabled=false and nothing sent."""
    body = await request.json()
    try:
        application, page = app.state.inspector.find_page_id(str(body["id"]))
    except KeyError:
        return {"enabled": False}
    if page.type_ == WirTypes.JAVASCRIPT:
        return {"enabled": False}
    enabled = bool(body.get("enabled", True))
    await app.state.inspector.indicate_web_view(application, page, enabled)
    return {"enabled": enabled}


@app.get("/pause-new-targets")
async def get_pause_new_targets() -> dict[str, bool]:
    """Whether the bridge attaches to and pauses every JSContext an app creates (see HeldTargets)."""
    return {"enabled": app.state.holder.running}


@app.post("/pause-new-targets")
async def set_pause_new_targets(request: Request) -> dict[str, bool]:
    """Switch pause-on-launch on or off at runtime - the landing page's toggle. Off lets go of
    every context still held, and stops webinspectord from offering new ones."""
    body = await request.json()
    if bool(body.get("enabled")):
        await app.state.holder.start()
    else:
        await app.state.holder.stop()
    return {"enabled": app.state.holder.running}


def _frontend_url(page: Page) -> str:
    """DevTools frontend entry point for a debuggable. A JSContext gets Chrome's JavaScript-only
    entry point (the one it uses for Node.js); inspector.html would come up expecting the Page/DOM
    domains that JavaScriptCore's inspector does not implement."""
    return "/devtools/js_app.html" if page.type_ == WirTypes.JAVASCRIPT else "/devtools/inspector.html"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Landing page: link each inspectable page to the locally-served DevTools frontend, which
    connects directly to the bridge (bypassing chrome://inspect's relay). Use this instead of
    chrome://inspect to avoid the console/screen freeze.

    The listing keeps itself current, so a tab opened - or a JSContext made inspectable - after
    the page was loaded appears without reloading it by hand."""
    await refresh_listings()
    host = request.headers.get("host", "127.0.0.1:9222")
    checked = " checked" if app.state.holder.running else ""
    version = bridge_version()
    product = f"pymobiledevice3 {escape(version)}" if version else "pymobiledevice3"
    return HTMLResponse(
        "<!doctype html><meta charset=utf-8>"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>pymobiledevice3 Web Inspector</title>"
        '<link rel="icon" type="image/png" href="/logo.png">'
        f"<style>{INDEX_STYLE}</style>"
        "<main><header>"
        '<img class="logo" src="/logo.png" alt="">'
        f"<h1>Web Inspector<small>{product} &middot; inspectable pages and JSContexts on the device</small></h1>"
        f'<label class="toggle"><input type="checkbox" id="pause-new-targets"{checked}>'
        f'<span class="switch"></span>{PAUSE_NEW_TARGETS_LABEL}</label>'
        '<p class="hint">Attaches to every JSContext an app creates before it runs and stops it on its '
        "first statement; open it from the list to land on the pause. "
        "Pages cannot be held before they run.</p>"
        '<details class="editors"><summary>Attach from an editor</summary>'
        "<p><b>VS Code</b>: expand a target below and put its configuration into "
        "<code>.vscode/launch.json</code> (js-debug is built in). A page configuration attaches "
        "to that page by URL; a JSContext configuration attaches to that context by its "
        "websocket address, so it is specific to the process listed.</p>"
        "<p><b>WebStorm</b>: Run &gt; Edit Configurations &gt; Add &gt; <b>Attach to Node.js/Chrome</b>, "
        f"host <code>{escape(host.rpartition(':')[0] or host)}</code>, port "
        f"<code>{escape(host.rpartition(':')[2])}</code>, attach to "
        "<i>Chrome or Node.js &gt; 6.3 started with --inspect</i>. Debug it and pick the page or "
        "JSContext from the list WebStorm shows.</p></details>"
        '<details class="editors"><summary>Using chrome://inspect instead</summary>'
        "<p>Chrome does not let a web page link to <code>chrome://inspect</code>, so this page cannot "
        "open it for you: type <code>chrome://inspect/#devices</code> into the address bar. Chrome "
        "looks for a bridge at <code>localhost:9222</code> on its own; for any other address, add "
        f"<code>{escape(host)}</code> under <b>Configure...</b> next to <i>Discover network targets</i>. "
        "Prefer this page when you can: chrome://inspect routes DevTools through Chrome's "
        "browser-process relay, which deadlocks under sustained console traffic and freezes the "
        "console and screen, whereas the links below connect to the bridge directly.</p></details>"
        f'<input class="filter" id="filter" type="search" placeholder="{FILTER_PLACEHOLDER}" '
        'aria-label="Filter targets" autocomplete="off">'
        "</header>"
        # Rendered server-side once so the list is there before any script runs, then kept up to
        # date in place by INDEX_SCRIPT.
        f'<div id="targets">{targets_html(app.state.inspector, host)}</div>'
        "</main>"
        f"<script>{INDEX_SCRIPT}</script>"
    )


def targets_html(inspector: WebinspectorService, host: str) -> str:
    """The landing page's target list, grouped by process; each group folds on its header. Names,
    titles and URLs come from the device, so they are escaped."""
    sections: list[str] = []
    items: list[str] = []
    current: Optional[Application] = None

    def flush() -> None:
        if current is None or not items:
            return
        info = application_info(inspector, current)
        icon = f'<img class="icon" src="{escape(info["icon"])}" alt="">' if info["icon"] else ""
        host = f" &middot; in {escape(info['host'])}" if info["host"] else ""
        automation = (
            f'<span class="badge auto" title="{escape(AUTOMATION_TITLE)}">automation</span>'
            if info["automation"]
            else ""
        )
        count = f"{len(items)} target{'' if len(items) == 1 else 's'}"
        header = (
            f'<summary class="app-header">{icon}<span class="name">{escape(info["name"])}</span>'
            f"<small>{escape(info['bundle'])} &middot; pid {info['pid']}{host}</small>{automation}"
            f'<small class="count">{count}</small></summary>'
        )
        sections.append(f'<details class="app" open>{header}<ul class="targets">{"".join(items)}</ul></details>')
        items.clear()

    for target_id, application, page in iter_inspectable(inspector):
        if application is not current:
            flush()
            current = application
        frontend = f"{_frontend_url(page)}?ws={host}/devtools/page/{target_id}"
        title = target_label(page)
        is_jscontext = page.type_ == WirTypes.JAVASCRIPT
        if is_jscontext:
            kind = '<span class="kind jscontext">JSContext</span>'
            attributes = ""
        else:
            kind = f'<span class="kind page" title="{escape(INDICATE_TITLE)}">Page</span>'
            attributes = f' data-indicate="{escape(target_id)}"'
        attributes += f' data-search="{escape(search_text(application, page))}"'
        # Attached before it ran and stopped on its first statement; opening it lands there.
        # Otherwise, whoever is debugging it now.
        state = "paused" if target_id in HELD_TARGETS else debugged_by(inspector, page)
        badge = ""
        if state:
            text, tooltip = BADGES[state]
            held = " held" if state == "other" else ""
            badge = f'<span class="badge{held}" title="{escape(tooltip)}">{escape(text)}</span>'
        config = json.dumps(attach_config(application, page, host, target_id), indent=4)
        attach = (
            '<details class="attach"><summary>Attach from VS Code</summary>'
            '<div class="snippet"><button type="button" class="copy" title="Copy to clipboard">Copy</button>'
            f"<pre>{escape(config, quote=False)}</pre></div></details>"
        )
        items.append(
            f'<li class="target"{attributes}>{kind}<span><a href="{escape(frontend)}">{escape(title)}</a>{badge}</span>'
            f"<small>{escape(target_url(application, page))}</small>{attach}</li>"
        )
    flush()
    if not sections:
        return NO_TARGETS_MESSAGE_HTML
    return "".join(sections)


@app.get("/logo.png")
@app.get("/favicon.ico")
async def serve_logo() -> Response:
    """The project logo; /favicon.ico as well, for browsers that ask for the default icon path."""
    return Response(content=LOGO_PNG, media_type="image/png")


@app.get("/icon/{app_id}")
async def application_icon(app_id: str) -> Response:
    """The icon the device reports for a connected process, for the landing page's headers."""
    application = app.state.inspector.connected_application.get(app_id)
    if application is None or not application.icon:
        return Response(status_code=404)
    return Response(content=application.icon, media_type="image/png", headers={"Cache-Control": "max-age=3600"})


@app.get("/devtools/{path:path}")
async def devtools_frontend(path: str) -> Response:
    """Serve the DevTools frontend so it connects to the bridge's WebSocket directly instead of
    through chrome://inspect's relay. Assets are proxied - from the hosted build, or from a local
    Chrome when that is unreachable - and cached per run."""
    if path not in _frontend_cache:
        base = await _frontend_base()
        if base is None:
            return Response(status_code=404)
        result = await _fetch(f"{base}/{path}")
        if result is None:
            return Response(status_code=404)
        _frontend_cache[path] = result
    data, content_type = _frontend_cache[path]
    return Response(content=data, media_type=content_type)


def _trace() -> Optional[ProtocolTrace]:
    """The protocol trace this run records to, if `--trace` was given."""
    return getattr(app.state, "trace", None)


async def from_cdp(target: CdpTarget, websocket: WebSocket) -> None:
    trace = _trace()
    async for message in websocket.iter_json():
        logger.debug(f"CDP INPUT:  {message}")
        if trace is not None:
            trace.record(EDITOR_TO_BRIDGE, message, session=target.session_id, page=str(target.page_id))
        await target.send(message)


async def to_cdp(target: CdpTarget, websocket: WebSocket) -> None:
    trace = _trace()
    while True:
        message = await target.receive()
        logger.debug(f"CDP OUTPUT:  {message}")
        if trace is not None:
            trace.record(BRIDGE_TO_EDITOR, message, session=target.session_id, page=str(target.page_id))
        await websocket.send_json(message)


@app.websocket("/devtools/browser/{connection_id}")
async def browser_debugger(websocket: WebSocket, connection_id: str):
    """Browser-level endpoint (the one /json/version advertises): flat-session Target-domain
    debugging for Chrome-compatible clients such as VS Code's js-debug and Puppeteer."""
    await websocket.accept()
    browser = CdpBrowser(
        app.state.inspector,
        websocket,
        pause_on_start=getattr(app.state, "pause_new_targets", False),
        trace=_trace(),
    )
    try:
        await browser.run()
    finally:
        await browser.close()


@app.websocket("/devtools/page/{page_id}")
async def page_debugger(websocket: WebSocket, page_id: str):
    try:
        application, page = app.state.inspector.find_page_id(page_id)
    except KeyError:
        # The page closed on the device between being listed and being opened here - a link the
        # user had on screen a moment too long. Refuse the connection instead of erroring out.
        logger.warning(f"page {page_id} is no longer inspectable")
        await websocket.close()
        return
    session_id = str(uuid.uuid4()).upper()
    protocol = SessionProtocol(app.state.inspector, session_id, application, page, method_prefix="")
    # Accept before the device-side target setup: DevTools drops the connection if the
    # websocket handshake stalls behind the WIR socket establishment.
    await websocket.accept()
    # WebKit serves one inspector session per debuggable, so sessions are serialized per page.
    # Ask whoever holds this one to hand it over: a DevTools tab left attached (in a background
    # tab, another window, a frontend the user never closed) holds the page for as long as it
    # lives, and waiting it out behind PAGE_LOCKS is invisible to the newcomer - its websocket is
    # already accepted, so the frontend just comes up blank and swallows everything typed into it.
    # Most visible on JSContexts, whose debuggable outlives every page that ever inspected it.
    superseded = PAGE_TAKEOVERS.get(page_id)
    if superseded is not None:
        logger.info(f"page {page_id}: taking the page over from the session holding it")
        superseded.set()
    # The lock is still taken, so the old session's WIR teardown completes before this one's
    # socket setup (webinspectord ignores a setup that races a teardown). Only the session holding
    # the page when this one arrived is asked to step aside - connections that are merely queued
    # here alongside it are left to run in turn, so a burst of them still all get served.
    lock = PAGE_LOCKS.setdefault(page_id, asyncio.Lock())
    try:
        await asyncio.wait_for(lock.acquire(), PAGE_HANDOVER_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        logger.error(f"page {page_id}: the session holding it did not release it in time")
        await websocket.close()
        return
    taken_over = asyncio.Event()
    PAGE_TAKEOVERS[page_id] = taken_over
    try:
        held = adopt_held_target(page_id)
        try:
            if held is not None:
                # The bridge attached before the context ran and kept it paused on its first
                # statement for exactly this: the frontend takes that session over and, once its
                # debugger is on, is shown the pause.
                target = held
            else:
                # Bound the wait: if the device never reports the target (e.g. webinspectord is
                # in a bad state), fail the connection instead of keeping a zombie handler alive.
                target = await asyncio.wait_for(CdpTarget.create(protocol), TARGET_CREATION_TIMEOUT)
        except (asyncio.TimeoutError, TimeoutError):
            # A page already being debugged over another Web Inspector connection - a second
            # pymobiledevice3, Safari's own Web Inspector, or a client that exited without
            # detaching - never reports a target, and the listing says who holds it. Naming them
            # beats "the device did not answer", which sends people looking at the device.
            holder = page.web_connection_id
            if holder and holder != app.state.inspector.connection_id:
                logger.error(
                    f"page {page_id}: already being debugged over Web Inspector connection {holder}; "
                    "close that debugger, or the process that left it attached, and reconnect"
                )
            else:
                logger.error(f"page {page_id}: device did not report an inspection target in time")
            await app.state.inspector.teardown_inspector_socket(session_id, application.id_, page.id_)
            await websocket.close()
            return
        tasks: list[asyncio.Task[Any]] = [
            asyncio.create_task(from_cdp(target, websocket)),
            asyncio.create_task(to_cdp(target, websocket)),
            asyncio.create_task(taken_over.wait()),
        ]
        try:
            # from_cdp ends when the client disconnects, taken_over when a newer connection claims
            # the page; tear everything down so the target's queue-consumer tasks don't keep
            # draining wir_events of future sessions.
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await target.close()
            if taken_over.is_set():
                # Close rather than leave it hanging: the superseded frontend shows a disconnect
                # instead of silently going dead.
                await websocket.close()
    finally:
        if PAGE_TAKEOVERS.get(page_id) is taken_over:
            del PAGE_TAKEOVERS[page_id]
        lock.release()
