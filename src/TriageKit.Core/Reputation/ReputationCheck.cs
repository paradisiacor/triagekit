using TriageKit.Core.Engine;
using TriageKit.Core.Intel;

namespace TriageKit.Core.Reputation;

/// <summary>
/// Looks up the riskiest files found by earlier checks across all available reputation providers,
/// combines the verdicts and raises plain-language findings. Runs last (needs the populated file cache).
/// </summary>
public sealed class ReputationCheck : ICheck
{
    private readonly IReadOnlyList<IReputationProvider> _providers;
    public ReputationCheck(IEnumerable<IReputationProvider> providers) => _providers = providers.ToList();

    public string Name => "Reputation";
    public bool IsSlow => true;
    public int Order => 100;

    /// <summary>Unsigned files in risky folders first, then other unsigned files, then signed files in risky folders.</summary>
    internal static List<FileIntel> SelectCandidates(IEnumerable<FileIntel> files, int max) =>
        files.Where(f => f.Exists && f.SHA256 is not null && !SelfIdentity.IsSelf(f.Path, f.SHA256) && (!f.IsSigned || f.Suspicious || f.SignatureStatus == SignatureStatus.HashMismatch))
             .OrderBy(f => f.SignatureStatus == SignatureStatus.HashMismatch ? 0 : !f.IsSigned && f.Suspicious ? 1 : !f.IsSigned ? 2 : 3)
             .GroupBy(f => f.SHA256, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).Take(max).ToList();

    public object? Run(CheckContext ctx)
    {
        var active = _providers.Where(p => p.IsAvailable(ctx)).ToList();
        var candidates = SelectCandidates(ctx.Files.All, ctx.Options.ReputationMaxFiles);
        var summaries = candidates.ToDictionary(f => f.SHA256!, f => new ReputationSummary
            { Path = f.Path, SHA256 = f.SHA256, Signed = f.IsSigned, Signer = f.Signer }, StringComparer.OrdinalIgnoreCase);
        var notes = new List<string>();

        foreach (var provider in active)
        {
            var todo = candidates.Take(provider.MaxLookups(ctx)).ToList();
            // Skip files another provider already identified as known-good (saves quota and time).
            todo = todo.Where(f => !summaries[f.SHA256!].Sources.Any(s => s.Verdict == Verdict.KnownGood)).ToList();
            if (todo.Count == 0) continue;
            ctx.Log($"{provider.Name}: checking {todo.Count} file(s)");

            var batch = provider.LookupBatch(todo, ctx);
            if (batch is not null)
            {
                foreach (var f in todo) if (batch.TryGetValue(f.SHA256!, out var v)) summaries[f.SHA256!].Sources.Add(v);
                continue;
            }
            int consecutiveErrors = 0;
            for (int i = 0; i < todo.Count && !ctx.Cancellation.IsCancellationRequested; i++)
            {
                ctx.Log($"{provider.Name}: {i + 1}/{todo.Count}");
                var v = provider.Lookup(todo[i], ctx);
                summaries[todo[i].SHA256!].Sources.Add(v);
                consecutiveErrors = v.Verdict == Verdict.Error ? consecutiveErrors + 1 : 0;
                if (consecutiveErrors >= 3)
                {
                    notes.Add($"{provider.Name}: not reachable ({v.Detail}); remaining lookups skipped");
                    ctx.Add(Severity.Info, "Reputation", $"{provider.Name} could not be reached", v.Detail ?? "",
                            "Check the internet connection, or allow TriageKit in your firewall (e.g. Portmaster).", ruleId: "reputation.unreachable");
                    break;
                }
                if (v.Verdict == Verdict.Error && v.Detail is "quota" or "key rejected")
                {
                    notes.Add($"{provider.Name}: {v.Detail}; remaining lookups skipped");
                    ctx.Add(Severity.Info, "Reputation", $"{provider.Name} lookups stopped ({v.Detail})", "",
                            v.Detail == "quota" ? "Free keys have per-minute and daily limits." : "Check the key in config.json.");
                    break;
                }
                var delay = provider.Delay(ctx);
                if (delay > TimeSpan.Zero && i < todo.Count - 1) Thread.Sleep(delay);
            }
        }

        foreach (var s in summaries.Values)
        {
            (s.Overall, s.Label) = VerdictAggregator.Combine(s.Sources);
            Raise(ctx, s);
        }

        if (active.Count == 0)
            ctx.Add(Severity.Info, "Reputation", "No reputation sources were available", "File reputation lookups were skipped.",
                    "Make sure Microsoft Defender is installed and the PC is online.");

        return new
        {
            Providers = _providers.Select(p => new { p.Name, Available = p.IsAvailable(ctx) }).ToList(),
            Checked = summaries.Count, Notes = notes,
            Results = summaries.Values.OrderBy(s => s.Overall switch { Verdict.Malicious => 0, Verdict.Suspicious => 1, Verdict.Unknown => 2, Verdict.Error => 3, Verdict.Clean => 4, _ => 5 })
                .Select(s => new
                {
                    Risk = s.Overall switch { Verdict.Malicious => Risk.Critical, Verdict.Suspicious when s.Signed && s.Sources.Where(x => x.Verdict is Verdict.Malicious or Verdict.Suspicious).All(x => x.Feed is not null) => Risk.Info, Verdict.Suspicious => Risk.High, Verdict.Unknown when !s.Signed => Risk.Medium, _ => Risk.Info },
                    s.Path, Verdict = s.Overall.ToString(), s.Label, s.Signed, s.Signer,
                    Sources = string.Join(" | ", s.Sources.Select(x => $"{x.Provider}: {x.Verdict}{(x.Label is null ? "" : $" ({x.Label})")}")),
                    Links = string.Join(" ", s.Sources.Where(x => x.Link is not null).Select(x => x.Link)),
                    s.SHA256
                }).ToList()
        };
    }

    private static string Feeds(ReputationSummary s) =>
        string.Concat(s.Sources.Where(x => x.Feed is not null).Select(x => $" (listed in {x.Feed})"));

    private static void Raise(CheckContext ctx, ReputationSummary s)
    {
        var file = Path.GetFileName(s.Path);
        var who = string.Join(", ", s.Sources.Where(x => x.Verdict is Verdict.Malicious or Verdict.Suspicious).Select(x => x.Provider));
        var evidence = new { s.Path, s.SHA256, s.Label, Sources = s.Sources, Link = s.Sources.FirstOrDefault(x => x.Link is not null)?.Link };
        switch (s.Overall)
        {
            case Verdict.Malicious:
                ctx.Add(Severity.Critical, "Reputation", $"{file} is known malware{(s.Label is null ? "" : $" ({s.Label})")}",
                        $"{s.Path}\nIdentified by: {who}",
                        "Treat this PC as compromised: disconnect it from the internet, remove the file with your antivirus, and change important passwords from a different device.",
                        evidence, "T1204.002", "reputation.malicious");
                break;
            // Only a malware-sharing feed lists it, and the file carries a valid signature: feeds also collect harmless
            // files that shipped next to malware (runtime DLLs, installers), so don't call a signed file suspicious.
            case Verdict.Suspicious when s.Signed && s.Sources.Where(x => x.Verdict is Verdict.Malicious or Verdict.Suspicious).All(x => x.Feed is not null):
                ctx.Add(Severity.Info, "Reputation", $"{file} appears on a malware-sharing list but is validly signed",
                        $"{s.Path}\nSigned by: {s.Signer}\n{string.Join("; ", s.Sources.Where(x => x.Feed is not null).Select(x => x.Detail))}",
                        "Usually a false listing: these lists also collect harmless files that were bundled with malware. Nothing to do unless other findings point to this file.",
                        evidence, "T1204.002", "reputation.listed-signed");
                break;
            case Verdict.Suspicious:
                ctx.Add(Severity.High, "Reputation", $"{file} is flagged as suspicious{(s.Label is null ? "" : $" ({s.Label})")}",
                        $"{s.Path}\nFlagged by: {who}{Feeds(s)}. A single listing or heuristic detection can be a false positive for unsigned or packed software.",
                        "Find out where this file came from. If you don't trust the source, remove it. Check the linked report for details.",
                        evidence, "T1204.002", "reputation.suspicious");
                break;
            // Skip when a malware rule already reported this file: one clear finding beats two overlapping ones.
            case Verdict.Unknown when !s.Signed && PathHeuristics.IsSuspicious(s.Path) && !ctx.Findings.Any(f => f.RuleId?.StartsWith("yara.") == true && f.Detail?.StartsWith(s.Path ?? "\0", StringComparison.OrdinalIgnoreCase) == true):
                ctx.Add(Severity.Medium, "Reputation", $"Unknown file in a risky folder: {file}",
                        $"{s.Path} is unsigned, in a risky location, and no reputation source recognises it.",
                        "Custom malware is often unique. If you don't know what this file is, remove it or ask someone you trust to review it.",
                        evidence, "T1204.002", "reputation.unknown");
                break;
        }
    }
}
