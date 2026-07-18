# Krynox.Captcha (.NET)

Official server-side verification SDK for **Krynox Captcha**. Targets .NET 8 (uses the
built-in `System.Text.Json` + `HttpClient` — no external dependencies).

```bash
dotnet add package Krynox.Captcha
```

```csharp
using Krynox.Captcha;

var krynox = new KrynoxCaptcha(Environment.GetEnvironmentVariable("KRYNOX_SECRET")!);

// in your request handler
var r = await krynox.VerifyAsync(token, remoteIp);
if (!r.Success)
    return Results.BadRequest("Captcha verification failed");

// optional: privacy-preserving risk hint + explainable reason codes
if (r.Risk == "high" || r.Reasons.Contains("tor-exit"))
{
    // add friction (email verification, manual review, …)
}
```

### Reasons, agents & attested humans

- `r.Reasons` — stable codes explaining the score (`"tor-exit"`, `"elevated-request-rate"`, …).
- `r.Agent` — non-null when a **verified AI agent** (Web Bot Auth) was forwarded:
  `.Verified`, `.Name`, `.Allowlisted`. Allowlist good bots instead of blocking them.
- `r.Human` — non-null when a **device-attested human** (Private Access Token) was forwarded:
  `.Attested`, `.Method`, `.Issuer`.

```csharp
if (r.Agent is { Verified: true, Allowlisted: true }) { /* trusted crawler */ }
if (r.Human is { Attested: true }) { /* proven human, skip friction */ }
```

### Content classification (spam/abuse)

```csharp
var c = await krynox.ClassifyAsync(text: comment, ip: clientIp); // or fields: {...}
if (c.Blocked || c.Classification == "BAD")
    return Results.BadRequest("rejected");
```

### Reliability

Transient failures (network, `429`, `5xx`) are retried automatically (default **2**, exponential
backoff; `retries` constructor arg). A retried `VerifyAsync` carries an **idempotency key** so it
never fails the single-use token — the server replays the first outcome.

### Feedback (false-positive correction)

```csharp
// a real user got blocked by mistake → un-block their IP
var fb = await krynox.FeedbackAsync("human", clientIp, "support ticket #1234");

// confirm a bot you let through
await krynox.FeedbackAsync("bot", suspiciousIp);
```

### API
- `new KrynoxCaptcha(secret, endpoint?, TimeSpan? timeout, int retries = 2)`
- `VerifyAsync(response, remoteip?, idempotencyKey?) → Task<KrynoxResult>`
- `ClassifyAsync(text?, fields?, ip?) → Task<KrynoxClassification>`
- `FeedbackAsync(label, ip?, note?) → Task<KrynoxFeedback>` — `label` is `"human"` or `"bot"`

`KrynoxResult`: `Success`, `Score`, `Risk`, `Hostname`, `ChallengeTs`, `ErrorCodes`, `Reasons`, `Agent`, `Human`
`KrynoxClassification`: `Ok`, `Score`, `Classification`, `Reasons`, `Blocked`, `ErrorCodes`.
Error codes: `KrynoxErrorCode.RateLimited`, etc.

Self-hosting? Pass an endpoint like `https://captcha.your-domain/siteverify`.

MIT licensed. Docs: <https://krynox.net/docs>
