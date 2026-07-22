# Contributing

Contributions are welcome through issues, discussions, and pull requests.

## Development Setup

```shell
python3 -m pip install -U -e ".[test]"
python3 -m pip install -U pre-commit
pre-commit install
```

## Local Checks

```shell
pytest
pre-commit run --all-files
```

The pre-commit hooks include ruff and pyright (pinned to the same version CI uses), so a clean
local run means a clean CI run. The pyright hook resolves imports from your `.venv`, so make sure
the editable install above ran inside it.

## Style Notes

- Keep changes focused and include tests when behavior changes.
- The codebase is pyright-clean (`standard` mode, Python 3.9 target) and CI enforces it. Prefer real fixes
  (honest annotations, explicit narrowing) over suppressions; when a suppression is unavoidable
  (inherently dynamic APIs), use a rule-specific `# pyright: ignore[ruleName]`, never a blanket
  `# type: ignore`.

## Need Help?

- Discord: <https://discord.gg/52mZGC3JXJ>

## Recommended Reading

- [Understanding iDevice protocol layers](misc/understanding_idevice_protocol_layers.md)
- [Documentation site](https://doronz88.github.io/pymobiledevice3/)
- [Writing commands with service_provider](docs/guides/writing-commands-with-service-provider.md)
- [AGENTS](AGENTS.md)
