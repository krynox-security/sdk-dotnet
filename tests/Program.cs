using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Krynox.Captcha;

// ---------------------------------------------------------------------------
// Golden contract v1 — schema/enum drift
// ---------------------------------------------------------------------------
using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "golden-v1.json")));
var golden = document.RootElement;
var names = typeof(KrynoxResult).GetProperties().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
string[] required = ["ChallengeTs", "Hostname", "Action", "CData", "Reasons"];
if (!required.All(names.Contains)) throw new Exception("KrynoxResult is missing golden contract fields");
if (golden.GetProperty("classify").GetProperty("classification").GetString() != "NEUTRAL")
    throw new Exception("classifier enum drifted from the golden contract");
Console.WriteLine("golden contract v1: ok");

// ---------------------------------------------------------------------------
// Integration tests — the real SDK over real HTTP against a local mock data
// plane (System.Net.HttpListener). Scenarios: happy path (exact body keys —
// note: bodies are Dictionary<string, object?>, and JsonIgnoreCondition
// .WhenWritingNull only applies to POCO properties, so absent optionals are
// serialized as explicit null), 500→200 and 429→200 retries with a stable
// idempotency key, exhausted retries, timeout, API failure parsing,
// classify()/feedback(), the User-Agent header, both derived-URL shapes, and
// "honeypot"/"sitekey" never sent.
// ---------------------------------------------------------------------------
const string Secret = "kcps_test_secret";
var goldenVerify = golden.GetProperty("verify").GetRawText();
var goldenClassify = golden.GetProperty("classify").GetRawText();
var goldenError = golden.GetProperty("error").GetRawText();

int port;
{
    var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
    probe.Start();
    port = ((IPEndPoint)probe.LocalEndpoint).Port;
    probe.Stop();
}
var baseUrl = $"http://127.0.0.1:{port}";

var recorded = new ConcurrentQueue<(string Path, string Body, string? UserAgent)>();
var hits = new ConcurrentDictionary<string, int>();
var listener = new HttpListener();
listener.Prefixes.Add(baseUrl + "/");
listener.Start();

_ = Task.Run(async () =>
{
    while (listener.IsListening)
    {
        HttpListenerContext ctx;
        try { ctx = await listener.GetContextAsync(); }
        catch { break; }
        _ = Task.Run(async () =>
        {
            var path = ctx.Request.Url!.AbsolutePath;
            string reqBody;
            using (var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8))
                reqBody = await reader.ReadToEndAsync();
            recorded.Enqueue((path, reqBody, ctx.Request.Headers["User-Agent"]));
            var n = hits.AddOrUpdate(path, 1, (_, v) => v + 1);
            var (status, payload) = path switch
            {
                "/siteverify" or "/sv-remoteip" => (200, goldenVerify),
                "/fail" => (200, goldenError),
                "/retry500" => n == 1 ? (500, """{"error":"boom"}""") : (200, goldenVerify),
                "/retry429" => n == 1 ? (429, """{"error":"rate-limited"}""") : (200, goldenVerify),
                "/exhaust" => (500, "boom"), // non-JSON body → SDK yields request-failed
                "/slow" => (0, goldenVerify), // sentinel: delay below, then 200
                // Both derived-URL shapes: `<base>/siteverify` collapses to `<base>/classify`,
                // while a plain base endpoint (`/base`, with or without a trailing slash)
                // appends to give `/base/classify`.
                "/classify" or "/base/classify" => (200, goldenClassify),
                "/feedback" or "/base/feedback" => (200, """{"ok":true,"corrected":true}"""),
                _ => (404, """{"error":"not-found"}"""),
            };
            if (status == 0) { await Task.Delay(1500); status = 200; }
            try
            {
                var bytes = Encoding.UTF8.GetBytes(payload);
                ctx.Response.StatusCode = status;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
            }
            catch { /* client gave up (timeout scenario) — expected */ }
        });
    }
});

static void Check(bool condition, string what)
{
    if (!condition) throw new Exception("integration: " + what);
}
List<(string Path, string Body, string? UserAgent)> At(string path) => recorded.Where(r => r.Path == path).ToList();
static JsonElement BodyOf((string Path, string Body, string? UserAgent) req) => JsonDocument.Parse(req.Body).RootElement.Clone();
static string[] Keys(JsonElement el) => el.EnumerateObject().Select(p => p.Name).ToArray();

// 1. happy path — golden fixture parsing + exact body keys (null keys omitted)
var sdk = new KrynoxCaptcha(Secret, baseUrl + "/siteverify", TimeSpan.FromSeconds(2));
var r = await sdk.VerifyAsync("test-token");
Check(r.Success, "happy: success");
Check(r.Score == 0.91, "happy: score");
Check(r.Risk == "low", "happy: risk");
Check(r.Hostname == "app.example.com", "happy: hostname");
Check(r.ChallengeTs == "2026-07-19T00:00:00.000Z", "happy: challenge_ts");
Check(r.Reasons.SequenceEqual(new[] { "verified-agent" }), "happy: reasons");
Check(r.ErrorCodes.Count == 0, "happy: no error codes");
Check(r.Action == "signup", "happy: action");
Check(r.CData == "order-42", "happy: cdata");
Check(r.Agent is { Verified: true, Name: "ExampleBot", Allowlisted: true }, "happy: agent");
Check(r.Human is { Attested: true, Method: "passkey", Issuer: null }, "happy: human");
var svReqs = At("/siteverify");
Check(svReqs.Count == 1, "happy: exactly one hit");
var happyBody = BodyOf(svReqs[0]);
Check(Keys(happyBody).SequenceEqual(new[] { "secret", "response", "remoteip", "idempotency_key" }), "happy: exact body keys");
Check(happyBody.GetProperty("remoteip").ValueKind == JsonValueKind.Null, "happy: explicit null remoteip when absent");
Check(happyBody.GetProperty("secret").GetString() == Secret, "happy: secret forwarded");
Check(happyBody.GetProperty("response").GetString() == "test-token", "happy: response forwarded");
Check(Regex.IsMatch(happyBody.GetProperty("idempotency_key").GetString()!, "^[0-9a-f]{32}$"), "happy: 16-byte hex idempotency key");

// 1b. remoteip present when supplied
var sdkRip = new KrynoxCaptcha(Secret, baseUrl + "/sv-remoteip", TimeSpan.FromSeconds(2));
Check((await sdkRip.VerifyAsync("test-token", "203.0.113.9")).Success, "remoteip: success");
var ripBody = BodyOf(At("/sv-remoteip")[0]);
Check(Keys(ripBody).SequenceEqual(new[] { "secret", "response", "remoteip", "idempotency_key" }), "remoteip: key present");
Check(ripBody.GetProperty("remoteip").GetString() == "203.0.113.9", "remoteip: value forwarded");

// 2. 500-then-200 — exactly 2 hits, same idempotency key
var sdk500 = new KrynoxCaptcha(Secret, baseUrl + "/retry500", TimeSpan.FromSeconds(2));
r = await sdk500.VerifyAsync("tok");
Check(r.Success && r.Score == 0.91, "retry500: success after retry");
var r500 = At("/retry500");
Check(r500.Count == 2, "retry500: exactly two hits");
var key1 = BodyOf(r500[0]).GetProperty("idempotency_key").GetString();
var key2 = BodyOf(r500[1]).GetProperty("idempotency_key").GetString();
Check(key1 is not null && key1 == key2, "retry500: same idempotency key on both attempts");
Check(Regex.IsMatch(key1!, "^[0-9a-f]{32}$"), "retry500: hex idempotency key");

// 3. 429-then-200
var sdk429 = new KrynoxCaptcha(Secret, baseUrl + "/retry429", TimeSpan.FromSeconds(2));
r = await sdk429.VerifyAsync("tok");
Check(r.Success && r.Score == 0.91, "retry429: success after retry");
var r429 = At("/retry429");
Check(r429.Count == 2, "retry429: exactly two hits");
Check(BodyOf(r429[0]).GetProperty("idempotency_key").GetString() == BodyOf(r429[1]).GetProperty("idempotency_key").GetString(),
    "retry429: same idempotency key on both attempts");

// 4. exhausted retries → request-failed
var sdkX = new KrynoxCaptcha(Secret, baseUrl + "/exhaust", TimeSpan.FromSeconds(2));
r = await sdkX.VerifyAsync("tok");
Check(!r.Success && r.ErrorCodes.SequenceEqual(new[] { KrynoxErrorCode.RequestFailed }), "exhaust: request-failed");
Check(At("/exhaust").Count == 3, "exhaust: exactly three hits (initial + 2 retries)");

// 6. API failure body parsing
var sdkFail = new KrynoxCaptcha(Secret, baseUrl + "/fail", TimeSpan.FromSeconds(2));
r = await sdkFail.VerifyAsync("tok");
Check(!r.Success, "fail: not success");
Check(r.ErrorCodes.SequenceEqual(new[] { "invalid-input-response" }), "fail: error-codes parsed");
Check(r.Reasons.Count == 0, "fail: no reasons");

// 7. classify() / feedback() on the derived endpoints
var c = await sdk.ClassifyAsync(text: "cheap pills, buy now", ip: "203.0.113.9");
Check(c.Ok && c.Score == 0.55 && c.Classification == "NEUTRAL" && c.Reasons.SequenceEqual(new[] { "risky-ip" }) && !c.Blocked,
    "classify: golden parse");
var cReqs = At("/classify");
Check(cReqs.Count == 1, "classify: /classify hit exactly once");
var cBody = BodyOf(cReqs[0]);
Check(Keys(cBody).SequenceEqual(new[] { "secret", "text", "fields", "ip" }), "classify: exact body keys");
Check(cBody.GetProperty("fields").ValueKind == JsonValueKind.Null, "classify: explicit null fields when absent");
Check(cBody.GetProperty("text").GetString() == "cheap pills, buy now", "classify: text forwarded");
var f = await sdk.FeedbackAsync("human", "203.0.113.9");
Check(f.Ok && f.Corrected, "feedback: ok + corrected");
var fReqs = At("/feedback");
Check(fReqs.Count == 1, "feedback: /feedback hit exactly once");
var fBody = BodyOf(fReqs[0]);
Check(Keys(fBody).SequenceEqual(new[] { "secret", "label", "ip", "note" }), "feedback: exact body keys");
Check(fBody.GetProperty("note").ValueKind == JsonValueKind.Null, "feedback: explicit null note when absent");

// 9. derived URLs — both endpoint shapes
// (a) a /siteverify endpoint with a trailing slash still collapses to the sibling path
var sdkSlash = new KrynoxCaptcha(Secret, baseUrl + "/siteverify/", TimeSpan.FromSeconds(2), retries: 0);
Check((await sdkSlash.ClassifyAsync(text: "spam")).Ok, "derive: trailing-slash /siteverify → /classify");
Check(At("/classify").Count == 2, "derive: trailing slash collapsed to /classify");
Check((await sdkSlash.FeedbackAsync("bot")).Ok, "derive: trailing-slash /siteverify → /feedback");
Check(At("/feedback").Count == 2, "derive: trailing slash collapsed to /feedback");

// (b) a plain base endpoint appends the path — it must NOT keep POSTing at the verify URL
foreach (var baseEndpoint in new[] { baseUrl + "/base", baseUrl + "/base/" })
{
    var sdkBase = new KrynoxCaptcha(Secret, baseEndpoint, TimeSpan.FromSeconds(2), retries: 0);
    Check((await sdkBase.ClassifyAsync(text: "spam")).Ok, $"derive: base URL → /base/classify ({baseEndpoint})");
    Check((await sdkBase.FeedbackAsync("bot")).Ok, $"derive: base URL → /base/feedback ({baseEndpoint})");
}
Check(At("/base/classify").Count == 2, "derive: /base/classify hit twice");
Check(At("/base/feedback").Count == 2, "derive: /base/feedback hit twice");
Check(At("/base").Count == 0, "derive: a base endpoint is never POSTed a classify payload");

// 10. User-Agent — exact value, and the const cannot drift from the csproj <Version>
Check(KrynoxCaptcha.UserAgent == "krynox-captcha-dotnet/0.1.0", "ua: exact constant");
var informational = typeof(KrynoxCaptcha).Assembly
    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "";
Check(informational.Split('+')[0] == KrynoxCaptcha.Version, $"ua: Version tracks the csproj <Version> (assembly says '{informational}')");
Check(recorded.All(req => req.UserAgent == KrynoxCaptcha.UserAgent), "ua: sent on every request so far");

// 5. timeout — per-attempt CancellationTokenSource cuts off the slow handler
var sdkSlow = new KrynoxCaptcha(Secret, baseUrl + "/slow", TimeSpan.FromMilliseconds(300), retries: 0);
var sw = Stopwatch.StartNew();
r = await sdkSlow.VerifyAsync("tok");
sw.Stop();
Check(!r.Success && r.ErrorCodes.SequenceEqual(new[] { KrynoxErrorCode.RequestFailed }), "timeout: request-failed");
Check(sw.ElapsedMilliseconds < 1400, "timeout: cancelled by the per-attempt timeout, not the 1.5 s slow handler");

// 8. "honeypot" (and "sitekey") never sent, and every request carried the User-Agent
var all = recorded.ToArray();
Check(all.Length >= 18, "sanity: requests were recorded");
Check(all.All(req => !req.Body.Contains("honeypot") && !req.Body.Contains("sitekey")), "honeypot/sitekey never sent");
Check(all.All(req => req.UserAgent == KrynoxCaptcha.UserAgent), "User-Agent sent on every request");

listener.Stop();
Console.WriteLine("integration tests: ok (10 scenarios)");
