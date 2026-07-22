# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-22

First release.

### Added

- `verify()` — validate a solved token against `POST /siteverify`. Returns
  `success`, `score`, `risk`, `hostname`, `challengeTs` and the stable
  `reasons` codes that explain the score.
- `classify()` — score submitted content for spam and abuse via `POST /classify`.
- `feedback()` — report a verification as `human` or `bot` to correct detection.
- `agent` on the result — a cryptographically verified AI agent (Web Bot Auth),
  when the site's Agent policy allows it through.
- `human` on the result — an attested real human, from a device Private Access
  Token or a WebAuthn passkey.
- `honeypot` verify option — forwards the widget's invisible decoy field so the
  data plane can flag or reject a submission that filled it in.
- Automatic retries on transient failures (network, `429`, `5xx`), each carrying
  a per-verify idempotency key so a retried single-use token replays the first
  outcome instead of failing.
- Configurable API host for self-hosted deployments.
- Targets .NET 8.

### Notes

- The seven SDKs are held to one shared response contract, enforced by a
  byte-identical golden fixture and a contract test in every language.

[0.1.0]: https://github.com/krynox-security/sdk-dotnet/releases/tag/v0.1.0
