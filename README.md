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

// optional: privacy-preserving risk hint
if (r.Risk == "high")
{
    // add friction (email verification, manual review, …)
}
```

### Feedback (false-positive correction)

```csharp
// a real user got blocked by mistake → un-block their IP
var fb = await krynox.FeedbackAsync("human", clientIp, "support ticket #1234");

// confirm a bot you let through
await krynox.FeedbackAsync("bot", suspiciousIp);
```

### API
- `new KrynoxCaptcha(secret, endpoint?, TimeSpan? timeout)`
- `VerifyAsync(response, remoteip?) → Task<KrynoxResult>`
- `FeedbackAsync(label, ip?, note?) → Task<KrynoxFeedback>` — `label` is `"human"` or `"bot"`

`KrynoxResult`: `Success`, `Score`, `Risk`, `Hostname`, `ChallengeTs`, `ErrorCodes`

Self-hosting? Pass an endpoint like `https://captcha.your-domain/siteverify`.

MIT licensed. Docs: <https://krynox.id/docs>
