using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using TriageKit.Core.Engine;

namespace TriageKit.Core.Reporting;

public static class ReportWriter
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        // Default encoder escapes < > & ' " so untrusted strings cannot break out of the HTML <script> block.
        Encoder = JavaScriptEncoder.Default,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 32,
    };

    public static string ToJson(ScanResult result) => JsonSerializer.Serialize(result, JsonOptions);

    /// <summary>Embeds the JSON into the offline HTML template. Extra escaping for line separators is belt-and-braces.</summary>
    public static string ToHtml(string json, string? template = null)
    {
        template ??= LoadTemplate();
        var bs = "\\";
        var safe = json.Replace("<", bs + "u003C").Replace(">", bs + "u003E")
                       .Replace(((char)0x2028).ToString(), bs + "u2028").Replace(((char)0x2029).ToString(), bs + "u2029");
        const string marker = "\"__TRIAGE_DATA__\"";
        if (!template.Contains(marker)) throw new InvalidOperationException("Report template marker missing");
        return template.Replace(marker, safe);
    }

    public static string LoadTemplate()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("report-template.html")
                      ?? throw new InvalidOperationException("Report template missing");
        using var r = new StreamReader(s, Encoding.UTF8);
        return r.ReadToEnd();
    }

    /// <summary>Writes results.json, report.html and a SHA-256 manifest (chain of custody).</summary>
    public static (string Html, string Json) Write(ScanResult result, string outDir)
    {
        Directory.CreateDirectory(outDir);
        var utf8 = new UTF8Encoding(false);
        var json = ToJson(result);
        var jsonPath = Path.Combine(outDir, "results.json");
        File.WriteAllText(jsonPath, json, utf8);
        var htmlPath = Path.Combine(outDir, "report.html");
        File.WriteAllText(htmlPath, ToHtml(json), utf8);
        WriteManifest(outDir);
        return (htmlPath, jsonPath);
    }

    /// <summary>Writes report-shareable.html: personal details removed, raw data left out.</summary>
    public static string WriteShareable(ScanResult result, string outDir)
    {
        var path = Path.Combine(outDir, "report-shareable.html");
        File.WriteAllText(path, ToHtml(ToJson(Redactor.Redact(result))), new UTF8Encoding(false));
        WriteManifest(outDir);
        return path;
    }

    private static void WriteManifest(string outDir)
    {
        var lines = Directory.GetFiles(outDir).Where(f => !f.EndsWith("manifest.sha256", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f).Select(f => $"{Hash(f)}  {Path.GetFileName(f)}");
        File.WriteAllLines(Path.Combine(outDir, "manifest.sha256"), lines.ToList(), Encoding.ASCII);
    }

    private static string Hash(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return Convert.ToHexString(SHA256.HashData(fs));
    }
}
