# Contributing to frost-zec

Thanks for taking the time to look at this. frost-zec handles keys that can
move real funds, so changes are reviewed with that in mind.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on
  the approach.
- Security problems: please do not open a public issue. Use GitHub's private
  vulnerability reporting on this repository instead.

## Code style

The project follows the
[librustzcash style guides](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md#styleguides).
In practice:

- Code is formatted with `cargo fmt`, and `cargo clippy --all-targets -- -D warnings`
  must pass.
- Prefer clear types and explicit error handling over `unwrap()` outside tests.
- Comments explain why, not what. Cite the ZIP or protocol section a check
  comes from.
- Never log or print secret material: shares, `sk`, `qsk`, nonces or backup
  strings.

## Tests

Every change runs the full test suite:

```bash
cargo test
```

Changes to the co-signer's checks (`src/check.rs`) need a test that shows the
check refusing a bad input, not only accepting a good one. Changes to the key
derivation or the backup format must keep passing the vectors in
`tests/fixtures/`.

## Commits and pull requests

- Keep commits focused, one logical change each, with a message that says what
  changed and why.
- Rebase on `master` rather than merging it into your branch.
- A pull request should pass CI before review.

By contributing, you agree that your contributions are licensed under the MIT
license of this repository.
