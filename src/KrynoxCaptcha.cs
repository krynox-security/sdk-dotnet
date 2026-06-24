using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Krynox.Captcha;

/// <summary>Outcome of a verification.</summary>
public sealed record KrynoxResult(
    bool Success,
    double? Score,
    string? Risk,
    string? Hostname,
    string? ChallengeTs,
    IReadOnlyList<string> ErrorCodes);

/// <summary>Outcome of a feedback report.</summary>
public sealed record KrynoxFeedback(bool Ok, bool Corrected);

/// <summary>
/// Krynox Captcha — official server-side verification SDK (.NET).
///
/// <code>
/// var krynox = new KrynoxCaptcha(Environment.GetEnvironmentVariable("KRYNOX_SECRET")!);
/// var r = await krynox.VerifyAsync(token, remoteip);
/// if (!r.Success) return BadRequest();
/// if (r.Risk == "high") { /* add friction */ }
/// </code>
/// </summary>
public sealed class KrynoxCaptcha
{
    public const string DefaultEndpoint = "https://api.krynox.id/siteverify";

    private static readonly HttpClient Http = new();
    private static readonly JsonSerializerOptions JsonOpts =
        new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    private readonly string _secret;
    private readonly string _endpoint;
    private readonly TimeSpan _timeout;

    public KrynoxCaptcha(string secret, string? endpoint = null, TimeSpan? timeout = null)
    {
        if (string.IsNullOrEmpty(secret))
            throw new ArgumentException("KrynoxCaptcha: secret key is required", nameof(secret));
        _secret = secret;
        _endpoint = endpoint ?? DefaultEndpoint;
        _timeout = timeout ?? TimeSpan.FromSeconds(5);
    }

    /// <summary>Verify a captcha response token from the widget.</summary>
    public async Task<KrynoxResult> VerifyAsync(string response, string? remoteip = null)
    {
        if (string.IsNullOrEmpty(response))
            return new KrynoxResult(false, null, null, null, null, new[] { "missing-input-response" });

        var body = new Dictionary<string, object?> { ["secret"] = _secret, ["response"] = response, ["remoteip"] = remoteip };
        var data = await PostAsync(_endpoint, body).ConfigureAwait(false);
        if (data is not { } el)
            return new KrynoxResult(false, null, null, null, null, new[] { "request-failed" });

        return new KrynoxResult(
            GetBool(el, "success"),
            GetDouble(el, "score"),
            GetString(el, "risk"),
            GetString(el, "hostname"),
            GetString(el, "challenge_ts"),
            GetArray(el, "error-codes"));
    }

    /// <summary>
    /// Report detection-quality feedback ("human" | "bot"). Flagging an auto-blocked IP as
    /// "human" un-blocks it server-side (false-positive correction).
    /// </summary>
    public async Task<KrynoxFeedback> FeedbackAsync(string label, string? ip = null, string? note = null)
    {
        var fb = _endpoint.EndsWith("/siteverify", StringComparison.Ordinal)
            ? _endpoint[..^"/siteverify".Length] + "/feedback"
            : _endpoint;
        var body = new Dictionary<string, object?> { ["secret"] = _secret, ["label"] = label, ["ip"] = ip, ["note"] = note };
        var data = await PostAsync(fb, body).ConfigureAwait(false);
        if (data is not { } el) return new KrynoxFeedback(false, false);
        return new KrynoxFeedback(GetBool(el, "ok"), GetBool(el, "corrected"));
    }

    private async Task<JsonElement?> PostAsync(string url, object body)
    {
        try
        {
            using var cts = new CancellationTokenSource(_timeout);
            var json = JsonSerializer.Serialize(body, JsonOpts);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var res = await Http.PostAsync(url, content, cts.Token).ConfigureAwait(false);
            var text = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.Clone();
        }
        catch
        {
            return null;
        }
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
