"""The CDP bridge against the two protocol definitions it translates between.

Every protocol name the bridge uses is checked against the spec that governs its role (see
protocol_inventory): CDP methods it handles and events it emits against Chrome's protocol; WebKit
commands it sends (with their literal parameters) and WebKit events it translates against
WebKit's. The specs are vendored by misc/protocol/fetch_protocols.py, pinned to upstream commits.

These tests need no device; they read the bridge's source. A name that fails here is either a typo,
a command one side has since removed or renamed (Page.setForcedAppearance was one: gone from
WebKit, iOS 26 answered it with "not found"), or a bridge-internal invention that must be
justified below.
"""

import json
import re

from pymobiledevice3.services.web_protocol.cdp_target import (
    NOOP_ABSENT_DOMAINS,
    REPLAYED_KEYED_SETUP_METHODS,
    REPLAYED_MULTI_SETUP_METHODS,
    REPLAYED_SETUP_METHODS,
    WEBKIT_ONLY_EVENTS,
)
from tests.services.test_web_protocol.protocol_inventory import (
    REPO,
    SPECS,
    Inventory,
    collect,
    command_params,
    in_commands,
    in_events,
    load_spec,
)

# CDP methods the bridge answers that the pinned Chrome protocol no longer defines, with the
# reason each is kept. Anything else outside the spec fails.
CDP_METHODS_NO_LONGER_IN_SPEC = {
    # Defined in CDP through mid-2025 (devtools-protocol f9ae1d44 still carries it) and gone since;
    # Chrome builds from before the removal still send it, so it keeps its local acknowledgement.
    "Network.clearAcceptedEncodingsOverride": "removed from CDP after 2025-06",
}

FETCHER = REPO / "misc/protocol/fetch_protocols.py"

inventory: Inventory = collect()
webkit = load_spec("webkit")
cdp = load_spec("cdp")


def test_the_inventory_found_the_bridge() -> None:
    """Guards the AST extraction itself: an empty inventory would pass every check below."""
    assert inventory.constants["NOOP_ABSENT_DOMAINS"] == set(NOOP_ABSENT_DOMAINS)
    assert inventory.constants["WEBKIT_ONLY_EVENTS"] == set(WEBKIT_ONLY_EVENTS)
    assert inventory.constants["REPLAYED_SETUP_METHODS"] == set(REPLAYED_SETUP_METHODS)
    assert len(inventory.client_handled) > 60
    assert len(inventory.webkit_events_handled) > 10
    assert len({s.method for s in inventory.webkit_bound}) > 20
    assert len({s.method for s in inventory.client_bound_events}) > 8


def test_handled_cdp_methods_are_cdp_commands() -> None:
    unknown = sorted(
        m for m in inventory.client_handled if not in_commands(cdp, m) and m not in CDP_METHODS_NO_LONGER_IN_SPEC
    )
    assert unknown == [], f"handled but not in Chrome's protocol: {unknown}"
    stale_allowlist = sorted(
        m for m in CDP_METHODS_NO_LONGER_IN_SPEC if in_commands(cdp, m) or m not in inventory.client_handled
    )
    assert stale_allowlist == [], f"allowlist entries no longer needed: {stale_allowlist}"


def test_no_op_domains_are_absent_from_webkit() -> None:
    """Input/Overlay requests are acknowledged instead of forwarded because WebKit has no such
    domains; should WebKit grow one, forwarding must be reconsidered."""
    present = sorted(d for d in NOOP_ABSENT_DOMAINS if d in webkit)
    assert present == []


def test_translated_webkit_events_are_webkit_events() -> None:
    unknown = sorted(m for m in inventory.webkit_events_handled if not in_events(webkit, m))
    assert unknown == [], f"translated but not a WebKit event: {unknown}"
    dropped_unknown = sorted(m for m in WEBKIT_ONLY_EVENTS if not in_events(webkit, m))
    assert dropped_unknown == [], f"dropped as WebKit-only but not a WebKit event: {dropped_unknown}"
    in_chrome_too = sorted(m for m in WEBKIT_ONLY_EVENTS if in_events(cdp, m))
    assert in_chrome_too == [], f"dropped as WebKit-only yet Chrome defines it: {in_chrome_too}"


def test_messages_sent_to_the_device_are_webkit_commands() -> None:
    unknown = sorted({f"{s.method} ({s.where})" for s in inventory.webkit_bound if not in_commands(webkit, s.method)})
    assert unknown == [], f"sent to the device but not a WebKit command: {unknown}"


def test_literal_parameters_match_the_webkit_command() -> None:
    """Where the bridge builds a device message from literals, its keys must be the command's
    parameters and every required one must be present."""
    problems: list[str] = []
    for send in inventory.webkit_bound:
        if send.params is None or not in_commands(webkit, send.method):
            continue
        spec = command_params(webkit, send.method)
        unknown = sorted(send.params - set(spec))
        missing = sorted(k for k, v in spec.items() if not v["optional"] and k not in send.params)
        if unknown or missing:
            problems.append(f"{send.method} in {send.where}: unknown={unknown} missing={missing}")
    assert problems == []


def test_replayed_setup_methods_are_webkit_commands() -> None:
    """Setup replayed onto the target after a process swap must be something the target answers."""
    replayed = set(REPLAYED_SETUP_METHODS) | set(REPLAYED_MULTI_SETUP_METHODS) | set(REPLAYED_KEYED_SETUP_METHODS)
    unknown = sorted(m for m in replayed if not in_commands(webkit, m))
    assert unknown == [], f"replayed but not a WebKit command: {unknown}"
    for method, key in REPLAYED_KEYED_SETUP_METHODS.items():
        assert key in command_params(webkit, method), f"{method} has no parameter {key!r}"


def test_events_emitted_to_the_client_are_cdp_events() -> None:
    unknown = sorted({f"{s.method} ({s.where})" for s in inventory.client_bound_events if not in_events(cdp, s.method)})
    assert unknown == [], f"emitted to the client but not a Chrome event: {unknown}"


def test_every_protocol_name_in_the_bridge_belongs_to_a_spec() -> None:
    """Catches what the role-based checks cannot see: names in comparisons, sets and comments-as-code."""

    def known(name: str) -> bool:
        return in_commands(cdp, name) or in_events(cdp, name) or in_commands(webkit, name) or in_events(webkit, name)

    unknown = sorted(
        f"{n} ({', '.join(sorted(files))})"
        for n, files in inventory.all_names.items()
        if not known(n) and n not in CDP_METHODS_NO_LONGER_IN_SPEC
    )
    assert unknown == [], f"in neither protocol: {unknown}"


def fetcher_pins() -> dict[str, str]:
    source = FETCHER.read_text()
    pins: dict[str, str] = {}
    for name in ("webkit", "cdp"):
        match = re.search(rf'^{name.upper()}_COMMIT = "([0-9a-f]{{40}})"', source, re.M)
        assert match is not None, f"{name.upper()}_COMMIT pin missing from {FETCHER}"
        pins[name] = match.group(1)
    return pins


def test_vendored_specs_match_the_fetcher_pins() -> None:
    """The JSON under protocol/ must be what fetch_protocols.py would produce for its pins."""
    for spec, commit in fetcher_pins().items():
        header = json.loads((SPECS / f"{spec}_protocol.json").read_text())["source"]
        assert header["commit"] == commit, (
            f"{spec}_protocol.json was fetched at another commit; re-run {FETCHER.relative_to(REPO)}"
        )
