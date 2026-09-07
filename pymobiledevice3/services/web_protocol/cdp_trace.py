"""Record every message the CDP bridge exchanges, in both directions, as JSON lines.

Four directions are recorded: what the editor sends the bridge and what the bridge answers it
(the CDP side), and what the bridge sends the device and what the device sends back (the
WebKit inspector side). A trace is what turns "step-over did not land in WebStorm" into a
reproducible report: it shows exactly which request got no reply, or which reply the editor
never acted on, without guessing at either end.

Each line is one message:

    {"t": <seconds since the trace started>, "dir": "<direction>", "session": "<inspector
     session>", "page": "<page id>", "msg": {...}}

A trace contains page content, evaluation results and script sources; treat it as sensitive.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional, TextIO, cast

logger = logging.getLogger(__name__)

EDITOR_TO_BRIDGE = "editor->bridge"
BRIDGE_TO_EDITOR = "bridge->editor"
BRIDGE_TO_DEVICE = "bridge->device"
DEVICE_TO_BRIDGE = "device->bridge"


class ProtocolTrace:
    """A JSON-lines protocol trace, flushed per message so a crash loses nothing."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._file: Optional[TextIO] = path.open("w", encoding="utf-8")
        self._started = time.monotonic()
        self._failed = False

    def record(self, direction: str, message: Any, *, session: str = "", page: str = "") -> None:
        """Append one message. Never raises into the bridge: a trace that cannot be written is
        logged once and abandoned, the debugging session it was watching goes on."""
        if self._file is None or self._failed:
            return
        try:
            line = json.dumps(
                {
                    "t": round(time.monotonic() - self._started, 6),
                    "dir": direction,
                    "session": session,
                    "page": page,
                    "msg": message,
                },
                default=str,
            )
            self._file.write(line + "\n")
            self._file.flush()
        except Exception:
            self._failed = True
            logger.exception(f"protocol trace {self.path} cannot be written; tracing stopped")

    def device_hook(self, direction: str, session: str, message: Any) -> None:
        """The inspector service's hook shape: (direction, session id, message).

        A page target speaks through WebKit's Target domain: every message is wrapped in
        Target.sendMessageToTarget or Target.dispatchMessageFromTarget with the real one
        JSON-encoded inside. Record the inner message, and note the wrapper and target id, so a
        trace reads as the protocol exchange it is rather than as a stream of envelopes.
        """
        page = ""
        if isinstance(message, dict):
            wrapped = cast(dict[str, Any], message)
            wrapper = wrapped.get("method")
            params = wrapped.get("params")
            if wrapper in ("Target.sendMessageToTarget", "Target.dispatchMessageFromTarget") and isinstance(
                params, dict
            ):
                inner = cast(dict[str, Any], params).get("message")
                if isinstance(inner, str):
                    try:
                        unwrapped = json.loads(inner)
                    except ValueError:
                        unwrapped = None
                    if isinstance(unwrapped, dict):
                        page = str(cast(dict[str, Any], params).get("targetId", ""))
                        message = {**cast(dict[str, Any], unwrapped), "_wrapper": wrapper}
        self.record(direction, message, session=session, page=page)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
