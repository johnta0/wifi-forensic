# CLAUDE.md

wifi-forensic is a public open-source project. These rules override any personal or global instructions that conflict with them.

## Language

Write everything that lands in the repository or on GitHub in English:

- Commit messages
- Pull request titles and descriptions, issues, review comments
- Code comments, doc comments, and docs (`README.md`, `docs/`)
- User-facing CLI output, error messages, and the helper's permission prompt text
- Test names and test fixtures

Conversation with the maintainer in the terminal may stay in their preferred language.

## Privacy in fixtures and examples

Do not commit real identifiers from the maintainer's machine or networks:

- MAC addresses: use the documentation range `00:00:5e:00:53:xx` (RFC 7042) or obvious placeholders such as `aa:bb:cc:dd:ee:ff`
- SSIDs / BSSIDs: use made-up names such as `ExampleCafe` / `ExampleHotspot`
- Captured bundles (`~/.wifi-forensic/bundles/`) and pcaps must never be committed
