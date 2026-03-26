# Contributing

## Development workflow

- Keep API additions backwards compatible where possible.
- Add tests for every new public behavior.
- Keep docs, examples, and changelog-impacting changes aligned.

## Testing

Run before opening a PR:

- `cargo check && cargo test`

## Coding style

- Preserve stable public method names unless there is no safe alternative.
- Prefer small, explicit public helpers over complex generic abstractions.
- Keep comments and tests focused on behavior, not implementation.
