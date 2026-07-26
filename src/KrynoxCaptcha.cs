using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Krynox.Captcha;

/// <summary>A cryptographically verified AI agent (Web Bot Auth), when forwarded.</summary>
public sealed record KrynoxAgent(bool Verified, string? Name, bool Allowlisted);

/// <summary>A device-attested real human (Private Access Token), when forwarded.</summary>
public sealed record KrynoxHuman(bool Attested, string? Method, string? Issuer);

/// <summary>Outcome of a verification.</summary>
public sealed record KrynoxResult(
    bool Success,
    double? Score,
    string? Risk,
    string? Hostname,
    string? ChallengeTs,
    IReadOnlyList<string> ErrorCodes,
    IReadOnlyList<string> Reasons,
    KrynoxAgent? Agent,
    KrynoxHuman? Human,
    string? Action,
    string? CData);

/// <summary>Outcome of a feedback report.</summary>
public sealed record KrynoxFeedback(bool Ok, bool Corrected);

/// <summary>Outcome of a content classification.</summary>
public sealed record KrynoxClassification(
    bool Ok,
    double? Score,
    string? Classification,
    IReadOnlyList<string> Reasons,
    bool Blocked,
    IReadOnlyList<string> ErrorCodes);

/// <summary>Machine-readable error codes returned by the API + SDK transport.</summary>
public static class KrynoxErrorCode
{
    public const string MissingResponse = "missing-input-response";
    public const string InvalidResponse = "invalid-input-response";
    public const string InvalidSecret = "invalid-input-secret";
    public const string RateLimited = "rate-limited";
    public const string Timeout = "timeout";
    public const string RequestFailed = "request-failed";
}

/// <summary>
/// Krynox Captcha — official server-side verification SDK (.NET).
///
/// <code>
/// var krynox = new KrynoxCaptcha(Environment.GetEnvironmentVariable("KRYNOX_SECRET")!);
/// var r = await krynox.VerifyAsync(token, remoteip);
/// if (!r.Success) return BadRequest();
/// if (r.Risk == "high" || r.Reasons.Contains("tor-exit")) { /* add friction */ }
/// </code>
/// </summary>
public sealed class KrynoxCaptcha
{
    public const string DefaultEndpoint = "https://api.krynox.net/siteverify";

    /// <summary>Package version — kept in lockstep with the csproj &lt;Version&gt; (asserted by a test).</summary>
    public const string Version = "0.1.0";

    /// <summary>Sent as <c>User-Agent</c> on every request, so the API can attribute traffic to SDK + version.</summary>
    public const string UserAgent = "krynox-captcha-dotnet/" + Version;

    private static readonly HttpClient Http = new();
    private static readonly JsonSerializerOptions JsonOpts =
        new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    private readonly string _secret;
    private readonly string _endpoint;
    private readonly TimeSpan _timeout;
    private readonly int _retries;

    public KrynoxCaptcha(string secret, string? endpoint = null, TimeSpan? timeout = null, int retries = 2)
    {
        if (string.IsNullOrEmpty(secret))
            throw new ArgumentException("KrynoxCaptcha: secret key is required", nameof(secret));
        _secret = secret;
        _endpoint = endpoint ?? DefaultEndpoint;
        _timeout = timeout ?? TimeSpan.FromSeconds(5);
        _retries = retries;
    }

    /// <summary>Verify a captcha response token from the widget.</summary>
    public async Task<KrynoxResult> VerifyAsync(string response, string? remoteip = null, string? idempotencyKey = null)
    {
        if (string.IsNullOrEmpty(response))
            return Failed(KrynoxErrorCode.MissingResponse);

        // A token is single-use, so a retried verify carries an idempotency key — the server returns
        // the first outcome instead of failing the now-consumed token.
        var key = idempotencyKey ?? (_retries > 0 ? RandomKey() : null);
        var body = new Dictionary<string, object?>
        {
            ["secret"] = _secret,
            ["response"] = response,
            ["remoteip"] = remoteip,
            ["idempotency_key"] = key,
        };
        var data = await PostAsync(_endpoint, body).ConfigureAwait(false);
        if (data is not { } el)
            return Failed(KrynoxErrorCode.RequestFailed);

        return new KrynoxResult(
            GetBool(el, "success"),
            GetDouble(el, "score"),
            GetString(el, "risk"),
            GetString(el, "hostname"),
            GetString(el, "challenge_ts"),
            GetArray(el, "error-codes"),
            GetArray(el, "reasons"),
            ParseAgent(el),
            ParseHuman(el),
            GetString(el, "action"),
            GetString(el, "cdata"));
    }

    /// <summary>
    /// Report detection-quality feedback ("human" | "bot"). Flagging an auto-blocked IP as
    /// "human" un-blocks it server-side (false-positive correction).
    /// </summary>
    public async Task<KrynoxFeedback> FeedbackAsync(string label, string? ip = null, string? note = null)
    {
        var body = new Dictionary<string, object?> { ["secret"] = _secret, ["label"] = label, ["ip"] = ip, ["note"] = note };
        var data = await PostAsync(Derive("/feedback"), body).ConfigureAwait(false);
        if (data is not { } el) return new KrynoxFeedback(false, false);
        return new KrynoxFeedback(GetBool(el, "ok"), GetBool(el, "corrected"));
    }

    /// <summary>Score submitted content (a <paramref name="text"/> string or a <paramref name="fields"/> map) for spam/abuse.</summary>
    public async Task<KrynoxClassification> ClassifyAsync(
        string? text = null, IReadOnlyDictionary<string, object?>? fields = null, string? ip = null)
    {
        var body = new Dictionary<string, object?> { ["secret"] = _secret, ["text"] = text, ["fields"] = fields, ["ip"] = ip };
        var data = await PostAsync(Derive("/classify"), body).ConfigureAwait(false);
        if (data is not { } el)
            return new KrynoxClassification(false, null, null, Array.Empty<string>(), false, new[] { KrynoxErrorCode.RequestFailed });

        return new KrynoxClassification(
            GetBool(el, "ok"),
            GetDouble(el, "score"),
            GetString(el, "classification"),
            GetArray(el, "reasons"),
            GetBool(el, "blocked"),
            GetArray(el, "error-codes"));
    }

    private static KrynoxResult Failed(string code) =>
        new(false, null, null, null, null, new[] { code }, Array.Empty<string>(), null, null, null, null);

    /// <summary>
    /// Derive a sibling endpoint ("/classify", "/feedback") from the configured verify endpoint.
    /// An endpoint ending in <c>/siteverify</c> (a trailing slash is ignored) has that suffix
    /// replaced; anything else is treated as a base URL and the path is appended.
    /// </summary>
    private string Derive(string path)
    {
        var root = _endpoint.EndsWith("/", StringComparison.Ordinal) ? _endpoint[..^1] : _endpoint;
        if (root.EndsWith("/siteverify", StringComparison.Ordinal))
            root = root[..^"/siteverify".Length];
        return root + path;
    }

    private static string RandomKey() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    /// <summary>POST JSON, retrying transient failures (network / 429 / 5xx). Returns the parsed body or null.</summary>
    private async Task<JsonElement?> PostAsync(string url, object body)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        for (var attempt = 0; attempt <= _retries; attempt++)
        {
            try
            {
                using var cts = new CancellationTokenSource(_timeout);
                using var content = new StringContent(json, Encoding.UTF8, "application/json");
                using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
                req.Headers.UserAgent.ParseAdd(UserAgent);
                using var res = await Http.SendAsync(req, cts.Token).ConfigureAwait(false);
                var status = (int)res.StatusCode;
                if ((status == 429 || status >= 500) && attempt < _retries)
                {
                    await Task.Delay(Backoff(attempt)).ConfigureAwait(false);
                    continue;
                }
                var text = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(text);
                return doc.RootElement.Clone();
            }
            catch
            {
                if (attempt >= _retries) return null;
                await Task.Delay(Backoff(attempt)).ConfigureAwait(false);
            }
        }
        return null;
    }

    private static TimeSpan Backoff(int attempt) =>
        TimeSpan.FromMilliseconds(Math.Min(1000, 100 * Math.Pow(2, attempt)));

    private static KrynoxAgent? ParseAgent(JsonElement e)
    {
        if (!e.TryGetProperty("agent", out var a) || a.ValueKind != JsonValueKind.Object) return null;
        return new KrynoxAgent(GetBool(a, "verified"), GetString(a, "name"), GetBool(a, "allowlisted"));
    }

    private static KrynoxHuman? ParseHuman(JsonElement e)
    {
        if (!e.TryGetProperty("human", out var h) || h.ValueKind != JsonValueKind.Object) return null;
        return new KrynoxHuman(GetBool(h, "attested"), GetString(h, "method"), GetString(h, "issuer"));
    }

    private static bool GetBool(JsonElement e, string k) =>
        e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;

    private static double? GetDouble(JsonElement e, string k) =>
        e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : null;

    private static string? GetString(JsonElement e, string k) =>
        e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static IReadOnlyList<string> GetArray(JsonElement e, string k)
    {
        if (!e.TryGetProperty(k, out var v) || v.ValueKind != JsonValueKind.Array)
            return Array.Empty<string>();
        var list = new List<string>();
        foreach (var item in v.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String)
                list.Add(item.GetString()!);
        return list;
    }
}
