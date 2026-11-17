using System.Globalization;
using System.Net;
using System.Text;
using TriageKit.Core.Engine;

namespace TriageKit.Core.Agent;

/// <summary>Renders history.html: score trend, scan list, and what changed in the latest scan. All text is HTML-encoded.</summary>
public static class HistoryReport
{
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    public static string Render(string computer, IReadOnlyList<ScanSummary> scans, ScanDiff? latestDiff)
    {
        var chrono = scans.OrderBy(s => s.Started).ToList();
        var sb = new StringBuilder();
        sb.Append("""
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TriageKit history</title>
<style>
:root{--bg:#f3f4f0;--card:#fff;--ink:#13212b;--muted:#5a6872;--line:#d9ddd6;--accent:#c96f12;--crit:#a3241d;--high:#d1462f;--med:#c98612;--low:#2f6fae;--ok:#23784b;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0f1619;--card:#162127;--ink:#e8ece9;--muted:#9aa8ae;--line:#26343b;--accent:#f0a04b;--crit:#ff6b5f;--high:#ff8a66;--med:#f2b84b;--low:#6fa8e6;--ok:#5ccb8e;color-scheme:dark}}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 24px 60px;display:grid;gap:18px}
h1{font-size:24px;margin:0}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:800px){.grid{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.num{font-variant-numeric:tabular-nums}
.pill{font-size:11px;font-weight:700;color:#fff;border-radius:10px;padding:2px 8px;text-transform:uppercase}
.Critical{background:var(--crit)}.High{background:var(--high)}.Medium{background:var(--med)}.Low{background:var(--low)}.Info{background:var(--muted)}
ul{margin:0;padding-left:0;list-style:none;display:grid;gap:8px}li small{color:var(--muted);display:block}
.empty{color:var(--muted)}a{color:var(--accent)}svg text{fill:var(--muted);font-size:11px}
</style></head><body><main>
""");
        sb.Append($"<h1>Security history: {E(computer)}</h1>");
        sb.Append($"<p class=\"empty\" style=\"margin:0\">{scans.Count} scan(s) stored on this PC. Generated {DateTime.Now:yyyy-MM-dd HH:mm}.</p>");

        // Score trend (one scale, 0-100, labelled gridlines).
        sb.Append("<div class=\"card\"><h2>Security score over time</h2>");
        if (chrono.Count < 2) sb.Append("<p class=\"empty\">The trend appears after the second scan.</p>");
        else
        {
            const int W = 1000, H = 220, L = 40, R = 10, T = 10, B = 30;
            double X(int i) => L + (W - L - R) * (chrono.Count == 1 ? 0 : i / (double)(chrono.Count - 1));
            double Y(int score) => T + (H - T - B) * (1 - score / 100.0);
            sb.Append($"<svg viewBox=\"0 0 {W} {H}\" width=\"100%\" role=\"img\" aria-label=\"Score trend\">");
            foreach (var g in new[] { 0, 25, 50, 75, 100 })
                sb.Append($"<line x1=\"{L}\" x2=\"{W - R}\" y1=\"{Y(g):0.#}\" y2=\"{Y(g):0.#}\" stroke=\"var(--line)\"/><text x=\"{L - 8}\" y=\"{Y(g) + 4:0.#}\" text-anchor=\"end\">{g}</text>");
            var pts = string.Join(" ", chrono.Select((s, i) => $"{X(i).ToString("0.#", CultureInfo.InvariantCulture)},{Y(s.Score).ToString("0.#", CultureInfo.InvariantCulture)}"));
            sb.Append($"<polygon points=\"{X(0).ToString("0.#", CultureInfo.InvariantCulture)},{Y(0).ToString("0.#", CultureInfo.InvariantCulture)} {pts} {X(chrono.Count - 1).ToString("0.#", CultureInfo.InvariantCulture)},{Y(0).ToString("0.#", CultureInfo.InvariantCulture)}\" fill=\"var(--accent)\" opacity=\"0.12\"/>");
            sb.Append($"<polyline points=\"{pts}\" fill=\"none\" stroke=\"var(--accent)\" stroke-width=\"2.5\"/>");
            var last = chrono.Count - 1;
            sb.Append($"<circle cx=\"{X(last).ToString("0.#", CultureInfo.InvariantCulture)}\" cy=\"{Y(chrono[last].Score).ToString("0.#", CultureInfo.InvariantCulture)}\" r=\"5\" fill=\"var(--accent)\"/>");
            sb.Append($"<text x=\"{L}\" y=\"{H - 8}\">{E(chrono[0].Started.ToString("yyyy-MM-dd"))}</text><text x=\"{W - R}\" y=\"{H - 8}\" text-anchor=\"end\">{E(chrono[last].Started.ToString("yyyy-MM-dd"))}</text>");
            sb.Append("</svg>");
        }
        sb.Append("</div>");

        // Latest changes
        sb.Append("<div class=\"grid\">");
        void List(string title, IEnumerable<FindingRecord> items, string empty)
        {
            sb.Append($"<div class=\"card\"><h2>{E(title)}</h2>");
            var l = items.ToList();
            if (l.Count == 0) sb.Append($"<p class=\"empty\">{E(empty)}</p>");
            else
            {
                sb.Append("<ul>");
                foreach (var f in l.Take(25)) sb.Append($"<li><span class=\"pill {f.Severity}\">{f.Severity}</span> {E(f.Title)}<small>{E(f.Recommendation)}</small></li>");
                sb.Append("</ul>");
            }
            sb.Append("</div>");
        }
        List("New since the previous scan", latestDiff?.New ?? new(), "Nothing new. Good.");
        List("Fixed since the previous scan", latestDiff?.Resolved ?? new(), "Nothing was resolved since last time.");
        sb.Append("</div>");

        // Scan table
        sb.Append("<div class=\"card\"><h2>All scans</h2><table><thead><tr><th>When</th><th>Type</th><th>Score</th><th>Verdict</th><th>Critical / High / Medium</th><th>New</th><th>Fixed</th><th>Report</th></tr></thead><tbody>");
        foreach (var s in scans)
        {
            int C(string k) => s.Counts.TryGetValue(k, out var v) ? v : 0;
            var link = s.ReportPath is null ? "" : $"<a href=\"{E(new Uri(s.ReportPath).AbsoluteUri)}\">Open</a>";
            sb.Append($"<tr><td>{E(s.Started.ToString("yyyy-MM-dd HH:mm"))}</td><td>{(s.Quick ? "Quick" : "Full")}</td><td class=\"num\">{s.Score}</td><td>{E(s.Verdict)}</td><td class=\"num\">{C("Critical")} / {C("High")} / {C("Medium")}</td><td class=\"num\">{s.NewCount}</td><td class=\"num\">{s.ResolvedCount}</td><td>{link}</td></tr>");
        }
        sb.Append("</tbody></table></div></main></body></html>");
        return sb.ToString();
    }
}
