"""Vendor compact summaries of the two protocols the CDP bridge translates between.

The bridge speaks Chrome's DevTools Protocol to editors and WebKit's inspector protocol to the
device. Both are open source and this script is the only way their definitions enter the repo:

- WebKit: Source/JavaScriptCore/inspector/protocol/*.json in the WebKit repository.
- Chrome:  json/browser_protocol.json and json/js_protocol.json in ChromeDevTools/devtools-protocol.
- Node:    src/inspector/domain_node_*.pdl in nodejs/node - the domains a Node.js inspector target
           adds on top of Chrome's (NodeRuntime, NodeWorker, NodeTracing), which editors attaching
           "as Node" (VS Code's node attach, WebStorm) send to a JSContext.

It writes tests/services/test_web_protocol/protocol/{webkit,cdp,node}_protocol.json - one entry per
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
NODE_COMMIT = "ec564135f429b6eb0b82910cace8b29eb1868b2a"
NODE_DOMAINS = ["domain_node_runtime", "domain_node_worker", "domain_node_tracing"]
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


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode()


def parse_pdl(text: str) -> dict[str, Any]:
    """Node's protocol is written in PDL, the indented plain-text form Chromium's protocol tooling
    accepts; indentation is all the structure needed here. Returns {domain: compact domain}."""
    domains: dict[str, Any] = {}
    domain: dict[str, Any] = {}
    member: Optional[dict[str, Any]] = None
    returns: Optional[list[str]] = None
    params: Optional[dict[str, Any]] = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        words = line.split()
        if indent == 0 and len(words) >= 2 and words[-2] == "domain":
            domain = {"commands": {}, "events": {}}
            domains[words[-1]] = domain
        elif indent == 2:
            member = returns = params = None
            if words[0] in ("command", "event"):
                member = {"params": {}} if words[0] == "event" else {"params": {}, "returns": []}
                domain["commands" if words[0] == "command" else "events"][words[-1]] = member
        elif indent == 4 and member is not None:
            params = member["params"] if words[0] == "parameters" else None
            returns = member["returns"] if words[0] == "returns" else None
        elif indent == 6 and (params is not None or returns is not None):
            optional = words[0] == "optional"
            if optional:
                words = words[1:]
            if returns is not None:
                returns.append(words[-1])
            elif params is not None:
                params[words[-1]] = {"optional": optional, "type": " ".join(words[:-1])}
    return domains


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
    node: dict[str, Any] = {}
    for name in NODE_DOMAINS:
        node.update(
            parse_pdl(
                fetch_text(f"https://raw.githubusercontent.com/nodejs/node/{NODE_COMMIT}/src/inspector/{name}.pdl")
            )
        )
    for domain_name, node_domain in node.items():
        print(f"node {domain_name}: {len(node_domain['commands'])} commands, {len(node_domain['events'])} events")
    (OUT / "node_protocol.json").write_text(
        json.dumps(
            {
                "source": {"repo": "nodejs/node", "commit": NODE_COMMIT, "path": "src/inspector", "fetched": fetched},
                "domains": node,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
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
