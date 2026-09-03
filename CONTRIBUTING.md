# Contributing

Thank you for considering a contribution to ShardGuard.

## Development

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -e .
shardguard scan fixtures/MOCK_/M01_shard_three_modules --skip-verify --open
```

## Guidelines

- Keep public docs and benchmark notes in clear technical English.
- Do not commit secrets, private hostnames, or infrastructure IPs.
- Prefer small, focused pull requests with a short rationale.
- Add or update fixtures when changing detection behavior.

## License

Contributions are accepted under the Apache-2.0 license.
