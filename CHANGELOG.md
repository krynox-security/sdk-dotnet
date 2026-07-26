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
- Automatic retries on transient failures (network, `429`, `5xx`), each carrying
  a per-verify idempotency key so a retried single-use token replays the first
  outcome instead of failing.
- Configurable API host for self-hosted deployments — either a full verify URL
  ending in `/siteverify` or a plain base URL. `ClassifyAsync` and
  `FeedbackAsync` derive their URLs from it: a `/siteverify` suffix (a trailing
  slash is ignored) is replaced, otherwise the path is appended to the base.
  Previously a base URL was left unchanged, so a classify payload was POSTed at
  the verify endpoint.
- `User-Agent: krynox-captcha-dotnet/<version>` on every request (verify,
  classify, feedback), so API traffic is attributable to SDK and version.
- Targets .NET 8.

### Notes

- The seven SDKs are held to one shared response contract, enforced by a
  byte-identical golden fixture and a contract test in every language.
- `KrynoxCaptcha.Version` (the source of the `User-Agent`) is asserted against
  the assembly informational version — i.e. the csproj `<Version>` — by a test,
  so the two cannot drift.
- Request bodies are built as `Dictionary<string, object?>`, and
  `JsonIgnoreCondition.WhenWritingNull` only applies to POCO properties, so
  absent optionals (`remoteip`, `note`, `fields`, …) are serialized as explicit
  JSON `null` rather than omitted. This is known and intended: the data plane
  treats an explicit `null` exactly as an absent key. It is a cosmetic
  wire-level difference from the other SDKs — please don't "fix" it.

[0.1.0]: https://github.com/krynox-security/sdk-dotnet/releases/tag/v0.1.0
