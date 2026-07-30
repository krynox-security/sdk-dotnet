# Graph Report - sdk-dotnet  (2026-07-30)

## Corpus Check
- 7 files · ~3,833 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 52 nodes · 88 edges · 6 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `ae9c5863`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- KrynoxCaptcha.cs
- KrynoxCaptcha
- Krynox.Captcha (.NET)
- .VerifyAsync
- [0.1.0] - 2026-07-22
- KrynoxCaptcha.csproj

## God Nodes (most connected - your core abstractions)
1. `KrynoxCaptcha` - 20 edges
2. `Krynox.Captcha (.NET)` - 6 edges
3. `KrynoxResult` - 3 edges
4. `Changelog` - 3 edges
5. `[0.1.0] - 2026-07-22` - 3 edges
6. `Krynox.Captcha` - 2 edges
7. `KrynoxAgent` - 2 edges
8. `KrynoxHuman` - 2 edges
9. `KrynoxFeedback` - 2 edges
10. `KrynoxClassification` - 2 edges

## Surprising Connections (you probably didn't know these)
- `KrynoxCaptcha` --references--> `string`  [EXTRACTED]
  src/KrynoxCaptcha.cs →   _Bridges community 0 → community 1_

## Import Cycles
- None detected.

## Communities (6 total, 0 thin omitted)

### Community 0 - "KrynoxCaptcha.cs"
Cohesion: 0.22
Nodes (7): Krynox.Captcha, KrynoxAgent, KrynoxClassification, KrynoxErrorCode, KrynoxFeedback, KrynoxHuman, string

### Community 1 - "KrynoxCaptcha"
Cohesion: 0.29
Nodes (7): HttpClient, int, IReadOnlyDictionary, JsonSerializerOptions, KrynoxCaptcha, Task, TimeSpan

### Community 2 - "Krynox.Captcha (.NET)"
Cohesion: 0.29
Nodes (6): API, Content classification (spam/abuse), Feedback (false-positive correction), Krynox.Captcha (.NET), Reasons, agents & attested humans, Reliability

### Community 3 - ".VerifyAsync"
Cohesion: 0.32
Nodes (3): IReadOnlyList, JsonElement, KrynoxResult

### Community 4 - "[0.1.0] - 2026-07-22"
Cohesion: 0.33
Nodes (5): [0.1.0] - 2026-07-22, Added, Changelog, Notes, [Unreleased]

### Community 5 - "KrynoxCaptcha.csproj"
Cohesion: 0.33
Nodes (4): net8.0, Microsoft.NET.Sdk, net8.0, Microsoft.NET.Sdk

## Knowledge Gaps
- **12 isolated node(s):** `net8.0`, `Microsoft.NET.Sdk`, `net8.0`, `Microsoft.NET.Sdk`, `[Unreleased]` (+7 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `KrynoxCaptcha` connect `KrynoxCaptcha` to `KrynoxCaptcha.cs`, `.VerifyAsync`?**
  _High betweenness centrality (0.214) - this node is a cross-community bridge._
- **What connects `net8.0`, `Microsoft.NET.Sdk`, `net8.0` to the rest of the system?**
  _12 weakly-connected nodes found - possible documentation gaps or missing edges._