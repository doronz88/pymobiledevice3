"""Vendor compact summaries of the two protocols the CDP bridge translates between.

The bridge speaks Chrome's DevTools Protocol to editors and WebKit's inspector protocol to the
device. Both are open source and this script is the only way their definitions enter the repo:

- WebKit: Source/JavaScriptCore/inspector/protocol/*.json in the WebKit repository.
- Chrome:  json/browser_protocol.json and json/js_protocol.json in ChromeDevTools/devtools-protocol.

It writes tests/services/test_web_protocol/protocol/{webkit,cdp}_protocol.json - one entry per
command (parameter names, whether each is optional, return names) and per event (parameter
names) - pinned to the upstream commits below. The conformance test reads those files. Re-run
after bumping the pins.
"""

import datetime
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Optional

WEBKIT_COMMIT = "587e3a7c563e482a45c3b186d9d5f093aadfb4a8"
CDP_COMMIT = "90778954a4820558eb0a98194e89000d40087ba4"
WEBKIT_DOMAINS = [
    "Animation",
    "Audit",
    "Browser",
    "CPUProfiler",
    "CSS",
    "Canvas",
    "Console",
    "DOM",
    "DOMDebugger",
    "DOMStorage",
    "Debugger",
    "GenericTypes",
    "Heap",
    "IndexedDB",
    "Inspector",
    "LayerTree",
    "Memory",
    "Network",
    "Page",
    "Recording",
    "Runtime",
    "ScriptProfiler",
    "Security",
    "ServiceWorker",
    "Storage",
    "Target",
    "Timeline",
    "Worker",
]
OUT = Path(__file__).resolve().parents[2] / "tests" / "services" / "test_web_protocol" / "protocol"


def fetch(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def compact_domain(domain: dict[str, Any]) -> dict[str, Any]:
    def params(items: Optional[list[dict[str, Any]]]) -> dict[str, Any]:
        return {
            p["name"]: {"optional": bool(p.get("optional", False)), "type": p.get("type") or p.get("$ref", "")}
            for p in (items or [])
        }

    def names(items: Optional[list[dict[str, Any]]]) -> list[str]:
        return [item["name"] for item in (items or [])]

    commands: list[dict[str, Any]] = domain.get("commands", [])
    events: list[dict[str, Any]] = domain.get("events", [])
    return {
        "commands": {
            c["name"]: {"params": params(c.get("parameters")), "returns": names(c.get("returns"))} for c in commands
        },
        "events": {e["name"]: {"params": params(e.get("parameters"))} for e in events},
    }


def main() -> None:
    fetched = datetime.date.today().isoformat()
    webkit: dict[str, Any] = {}
    for name in WEBKIT_DOMAINS:
        url = f"https://raw.githubusercontent.com/WebKit/WebKit/{WEBKIT_COMMIT}/Source/JavaScriptCore/inspector/protocol/{name}.json"
        domain = fetch(url)
        webkit[domain["domain"]] = compact_domain(domain)
        print(f"webkit {domain['domain']}: {len(webkit[domain['domain']]['commands'])} commands")
    (OUT / "webkit_protocol.json").write_text(
        json.dumps(
            {
                "source": {
                    "repo": "WebKit/WebKit",
                    "commit": WEBKIT_COMMIT,
                    "path": "Source/JavaScriptCore/inspector/protocol",
                    "fetched": fetched,
                },
                "domains": webkit,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
    cdp: dict[str, Any] = {}
    for file in ("browser_protocol.json", "js_protocol.json"):
        url = f"https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/{CDP_COMMIT}/json/{file}"
        for domain in fetch(url)["domains"]:
            cdp[domain["domain"]] = compact_domain(domain)
    print(f"cdp: {len(cdp)} domains")
    (OUT / "cdp_protocol.json").write_text(
        json.dumps(
            {
                "source": {
                    "repo": "ChromeDevTools/devtools-protocol",
                    "commit": CDP_COMMIT,
                    "path": "json",
                    "fetched": fetched,
                },
                "domains": cdp,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    sys.exit(main())
