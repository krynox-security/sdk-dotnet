using System.Text.Json;
using Krynox.Captcha;

using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "golden-v1.json")));
var golden = document.RootElement;
var names = typeof(KrynoxResult).GetProperties().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
string[] required = ["ChallengeTs", "Hostname", "Action", "CData", "Reasons"];
if (!required.All(names.Contains)) throw new Exception("KrynoxResult is missing golden contract fields");
if (golden.GetProperty("classify").GetProperty("classification").GetString() != "NEUTRAL")
    throw new Exception("classifier enum drifted from the golden contract");
Console.WriteLine("golden contract v1: ok");
