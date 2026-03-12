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
```

## Style Notes

- Keep changes focused and include tests when behavior changes.

## Need Help?

- Discord: <https://discord.gg/52mZGC3JXJ>

## Recommended Reading

- [Understanding iDevice protocol layers](misc/understanding_idevice_protocol_layers.md)
- [Documentation index](docs/README.md)
- [Writing commands with service_provider](docs/guides/writing-commands-with-service-provider.md)
- [AGENTS](AGENTS.md)
