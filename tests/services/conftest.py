"""Service-level test fixtures and parametrization for XCUITest integration tests.

XCUITest configurations are loaded from ``tests/services/xcuitest.json``
(not tracked by git).  Copy ``xcuitest.json.example`` to ``xcuitest.json``
and fill in your own bundle identifiers and optional per-config settings.

The file is a JSON array of objects with the following fields:

.. code-block:: json

    [
      {
        "id":              "my_app",
        "runner_bundle_id": "com.example.MyApp.xctrunner",
        "target_bundle_id": "com.example.MyApp",
        "runner_env":      {},
        "timeout":         30.0
      }
    ]

Any test that declares an ``xcuitest_cfg`` parameter is automatically
parametrized over all entries in the JSON file.  If the file is absent the
tests are skipped.

The ``--xcuitest-config`` CLI option allows pointing to a different file:

    pytest --xcuitest-config /path/to/my_config.json ...
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

_DEFAULT_CONFIG_FILE = Path(__file__).parent / "xcuitest.json"

# Module-level cache: config id -> config dict, populated once per session.
_XCUITEST_CONFIGS: dict[str, dict[str, Any]] = {}


def _load_xcuitest_configs(path: Path) -> list[dict[str, Any]]:
    """Return the list of XCUITest configuration objects from *path*."""
    if not path.exists():
        return []
    return json.loads(path.read_text())


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrize any test that uses the ``xcuitest_cfg`` fixture.

    We parametrize with simple string IDs (not dicts) so that VS Code's pytest
    adapter can serialize the parameter values without crashing.  The actual
    config dict is resolved inside the ``xcuitest_cfg`` fixture below.
    """
    if "xcuitest_cfg" not in metafunc.fixturenames:
        return

    config_path = Path(metafunc.config.getoption("--xcuitest-config") or _DEFAULT_CONFIG_FILE)
    configs = _load_xcuitest_configs(config_path)

    # Populate module-level cache so the fixture can look up by id.
    for cfg in configs:
        _XCUITEST_CONFIGS[cfg["id"]] = cfg

    if not configs:
        metafunc.parametrize(
            "xcuitest_cfg",
            [
                pytest.param(
                    "__skip__",
                    marks=pytest.mark.skip(
                        reason=f"No XCUITest configurations found — create {config_path} "
                        f"(see {config_path.parent / 'xcuitest.json.example'})"
                    ),
                )
            ],
            indirect=True,
        )
    else:
        metafunc.parametrize(
            "xcuitest_cfg",
            [c["id"] for c in configs],
            ids=[c["id"] for c in configs],
            indirect=True,
        )


@pytest.fixture
def xcuitest_cfg(request) -> dict[str, Any]:
    """Resolve the string config ID injected by pytest_generate_tests into the full dict."""
    cfg_id: str = request.param
    return _XCUITEST_CONFIGS[cfg_id]
