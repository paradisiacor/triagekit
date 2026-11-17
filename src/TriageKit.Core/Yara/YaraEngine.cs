using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace TriageKit.Core.Yara;

/// <summary>
/// A pure-C# engine for a practical subset of the YARA rule language.
///
/// Supported:
///   rule NAME [: tags] { meta: ... strings: ... condition: ... }   (private/global modifiers accepted, ignored)
///   text strings  "..." with modifiers ascii, wide, nocase, fullword (escapes \" \\ \n \r \t \xHH)
///   hex strings   { 4D 5A ?? 9? [2-4] (00 | FF) }
///   regex strings /.../ with i and s flags
///   conditions:   and, or, not, ( ), true, false, comparisons (== != &lt; &lt;= &gt; &gt;=), + - arithmetic,
///                 integers (dec, hex, KB, MB), filesize, uint8/16/32[be](offset), int8/16/32(offset),
///                 $s, #s, @s[n], $s at N, $s in (A..B), N of (...), any/all/none of them|(...), wildcards ($a*)
/// Files are matched as raw bytes (mapped 1:1 to Latin-1 characters), so hex and binary text strings work exactly.
/// </summary>
public sealed class YaraRule
{
    public required string Name { get; init; }
    public List<string> Tags { get; } = new();
    public Dictionary<string, string> Meta { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<YaraString> Strings { get; } = new();
    public required Node Condition { get; init; }
    public string Source { get; set; } = "";
}

public sealed class YaraString
{
    public required string Id { get; init; }            // "$a" (anonymous strings get "$#n")
    public required Regex Pattern { get; init; }
    public string Display { get; init; } = "";
}

public sealed class YaraMatch
{
    public required YaraRule Rule { get; init; }
    public Dictionary<string, List<int>> Hits { get; } = new();
}

public sealed class YaraSyntaxException : Exception
{
    public YaraSyntaxException(string msg, int line) : base($"line {line}: {msg}") { }
}

// ======================================================================== condition AST

public abstract class Node { }
internal sealed class BoolLit(bool v) : Node { public bool V = v; }
internal sealed class IntLit(long v) : Node { public long V = v; }
internal sealed class FileSize : Node { }
internal sealed class StrRef(string id) : Node { public string Id = id; }                 // $a
internal sealed class StrCount(string id) : Node { public string Id = id; }               // #a
internal sealed class StrOffset(string id, Node? index) : Node { public string Id = id; public Node? Index = index; }  // @a[i]
internal sealed class StrAt(string id, Node at) : Node { public string Id = id; public Node At = at; }
internal sealed class StrIn(string id, Node lo, Node hi) : Node { public string Id = id; public Node Lo = lo, Hi = hi; }
internal sealed class ReadInt(string fn, Node offset) : Node { public string Fn = fn; public Node Offset = offset; }
internal sealed class Unary(string op, Node a) : Node { public string Op = op; public Node A = a; }
internal sealed class Binary(string op, Node a, Node b) : Node { public string Op = op; public Node A = a, B = b; }
internal sealed class OfExpr(Node quantifier, List<string> set) : Node { public Node Quantifier = quantifier; public List<string> Set = set; }  // quantifier: IntLit, or StrRef("all"/"any"/"none") marker
internal sealed class Quant(string kind) : Node { public string Kind = kind; }

// ======================================================================== lexer

internal enum T { Ident, StrId, CountId, OffsetId, Int, String, Hex, Regex, Sym, Eof }
internal readonly record struct Tok(T Type, string Text, int Line, long Int = 0, string Flags = "");

internal sealed class Lexer
{
    private readonly string _s; private int _i; private int _line = 1;
    public Lexer(string s) { _s = s; }

    public List<Tok> All()
    {
        var list = new List<Tok>();
        Tok t; do { t = Next(); list.Add(t); } while (t.Type != T.Eof);
        return list;
    }

    private char C(int o = 0) => _i + o < _s.Length ? _s[_i + o] : '\0';

    private void SkipWs()
    {
        while (_i < _s.Length)
        {
            if (C() == '\n') { _line++; _i++; }
            else if (char.IsWhiteSpace(C())) _i++;
            else if (C() == '/' && C(1) == '/') { while (_i < _s.Length && C() != '\n') _i++; }
            else if (C() == '/' && C(1) == '*') { _i += 2; while (_i < _s.Length && !(C() == '*' && C(1) == '/')) { if (C() == '\n') _line++; _i++; } _i += 2; }
            else break;
        }
    }

    // Regex literals and division never coexist in this subset; '/' after '=' in strings section starts a regex.
    private Tok? _prev;
    private Tok Next()
    {
        SkipWs();
        if (_i >= _s.Length) return new(T.Eof, "", _line);
        int start = _i; char c = C();
        Tok tok;
        if (c == '"') tok = ReadString();
        else if (c == '{' && _prev is { Type: T.Sym, Text: "=" }) tok = ReadHex();
        else if (c == '/' && _prev is { Type: T.Sym, Text: "=" }) tok = ReadRegex();
        else if (c is '$' or '#' or '@')
        {
            _i++;
            while (char.IsLetterOrDigit(C()) || C() is '_' or '*') _i++;
            var text = _s[start.._i];
            tok = new(c == '$' ? T.StrId : c == '#' ? T.CountId : T.OffsetId, "$" + text[1..], _line);
        }
        else if (char.IsDigit(c))
        {
            long v;
            if (c == '0' && (C(1) is 'x' or 'X')) { _i += 2; int s2 = _i; while (Uri.IsHexDigit(C())) _i++; v = long.Parse(_s[s2.._i], NumberStyles.HexNumber); }
            else { while (char.IsDigit(C())) _i++; v = long.Parse(_s[start.._i], CultureInfo.InvariantCulture); }
            if (C() == 'K' && C(1) == 'B') { v *= 1024; _i += 2; }
            else if (C() == 'M' && C(1) == 'B') { v *= 1024 * 1024; _i += 2; }
            tok = new(T.Int, _s[start.._i], _line, v);
        }
        else if (char.IsLetter(c) || c == '_')
        {
            while (char.IsLetterOrDigit(C()) || C() == '_') _i++;
            tok = new(T.Ident, _s[start.._i], _line);
        }
        else
        {
            string two = _i + 1 < _s.Length ? _s.Substring(_i, 2) : "";
            if (two is "==" or "!=" or "<=" or ">=" or "..") { _i += 2; tok = new(T.Sym, two, _line); }
            else { _i++; tok = new(T.Sym, c.ToString(), _line); }
        }
        _prev = tok;
        return tok;
    }

    private Tok ReadString()
    {
        var sb = new StringBuilder(); _i++;
        while (_i < _s.Length && C() != '"')
        {
            if (C() == '\\')
            {
                _i++;
                switch (C())
                {
                    case 'n': sb.Append('\n'); break; case 'r': sb.Append('\r'); break; case 't': sb.Append('\t'); break;
                    case '"': sb.Append('"'); break; case '\\': sb.Append('\\'); break;
                    case 'x': sb.Append((char)Convert.ToInt32(_s.Substring(_i + 1, 2), 16)); _i += 2; break;
                    default: sb.Append('\\').Append(C()); break;
                }
                _i++;
            }
            else { if (C() == '\n') throw new YaraSyntaxException("unterminated string", _line); sb.Append(C()); _i++; }
        }
        _i++;
        return new(T.String, sb.ToString(), _line);
    }

    private Tok ReadHex()
    {
        int start = ++_i;
        while (_i < _s.Length && C() != '}') { if (C() == '\n') _line++; _i++; }
        var body = _s[start.._i]; _i++;
        return new(T.Hex, body, _line);
    }

    private Tok ReadRegex()
    {
        var sb = new StringBuilder(); _i++;
        while (_i < _s.Length && C() != '/')
        {
            if (C() == '\\' && C(1) == '/') { sb.Append('/'); _i += 2; continue; }
            if (C() == '\\') { sb.Append(C()).Append(C(1)); _i += 2; continue; }
            if (C() == '\n') throw new YaraSyntaxException("unterminated regex", _line);
            sb.Append(C()); _i++;
        }
        _i++;
        int fs = _i; while (C() is 'i' or 's') _i++;
        return new(T.Regex, sb.ToString(), _line, 0, _s[fs.._i]);
    }
}

// ======================================================================== parser

public static class YaraParser
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(3);

    public static List<YaraRule> Parse(string source, string sourceName = "")
    {
        var p = new P(new Lexer(source).All());
        var rules = new List<YaraRule>();
        while (!p.At(T.Eof))
        {
            if (p.IsIdent("import") || p.IsIdent("include")) throw new YaraSyntaxException("imports/includes are not supported", p.Peek.Line);
            while (p.IsIdent("private") || p.IsIdent("global")) p.Take();
            p.ExpectIdent("rule");
            var r = ParseRule(p);
            r.Source = sourceName;
            if (rules.Any(x => x.Name == r.Name)) throw new YaraSyntaxException($"duplicate rule {r.Name}", p.Peek.Line);
            rules.Add(r);
        }
        return rules;
    }

    private static YaraRule ParseRule(P p)
    {
        var name = p.Expect(T.Ident).Text;
        var tags = new List<string>();
        if (p.IsSym(":")) { p.Take(); while (p.At(T.Ident)) tags.Add(p.Take().Text); }
        p.ExpectSym("{");
        var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var strings = new List<YaraString>();
        Node? cond = null;
        while (!p.IsSym("}"))
        {
            var section = p.Expect(T.Ident).Text; p.ExpectSym(":");
            switch (section)
            {
                case "meta":
                    while (p.At(T.Ident) && !(p.PeekAt(1) is { Type: T.Sym, Text: ":" }))
                    {
                        var k = p.Take().Text; p.ExpectSym("=");
                        var v = p.Take();
                        meta[k] = v.Type == T.Int ? v.Int.ToString(CultureInfo.InvariantCulture) : v.Text;
                    }
                    break;
                case "strings":
                    int anon = 0;
                    while (p.At(T.StrId))
                    {
                        var id = p.Take().Text; if (id == "$") id = "$#" + anon++;
                        p.ExpectSym("=");
                        var v = p.Take();
                        var mods = new HashSet<string>();
                        while (p.At(T.Ident) && p.Peek.Text is "ascii" or "wide" or "nocase" or "fullword" or "private") mods.Add(p.Take().Text);
                        if (strings.Any(s => s.Id == id)) throw new YaraSyntaxException($"duplicate string {id}", v.Line);
                        strings.Add(new YaraString { Id = id, Pattern = Compile(v, mods), Display = v.Type == T.String ? v.Text : v.Type == T.Hex ? "{" + v.Text.Trim() + "}" : "/" + v.Text + "/" });
                    }
                    break;
                case "condition":
                    cond = ParseOr(p);
                    break;
                default: throw new YaraSyntaxException($"unknown section {section}", p.Peek.Line);
            }
        }
        p.ExpectSym("}");
        if (cond is null) throw new YaraSyntaxException($"rule {name} has no condition", p.Peek.Line);
        var rule = new YaraRule { Name = name, Condition = cond };
        rule.Tags.AddRange(tags);
        foreach (var kv in meta) rule.Meta[kv.Key] = kv.Value;
        rule.Strings.AddRange(strings);
        Validate(rule, cond);
        return rule;
    }

    private static void Validate(YaraRule r, Node n)
    {
        void Check(string id)
        {
            if (id is "them" ) return;
            bool ok = id.EndsWith('*') ? r.Strings.Any(s => s.Id.StartsWith(id[..^1])) : r.Strings.Any(s => s.Id == id);
            if (!ok) throw new YaraSyntaxException($"rule {r.Name}: undefined string {id}", 0);
        }
        switch (n)
        {
            case StrRef s: Check(s.Id); break; case StrCount s: Check(s.Id); break; case StrOffset s: Check(s.Id); break;
            case StrAt s: Check(s.Id); Validate(r, s.At); break; case StrIn s: Check(s.Id); Validate(r, s.Lo); Validate(r, s.Hi); break;
            case OfExpr o: foreach (var id in o.Set) Check(id); break;
            case Unary u: Validate(r, u.A); break; case Binary b: Validate(r, b.A); Validate(r, b.B); break;
            case ReadInt ri: Validate(r, ri.Offset); break;
        }
    }

    // ---- string compilation: everything becomes a .NET regex over Latin-1 decoded bytes
    private static Regex Compile(Tok v, HashSet<string> mods)
    {
        var opts = RegexOptions.CultureInvariant | RegexOptions.Compiled;
        string pattern;
        switch (v.Type)
        {
            case T.String:
            {
                bool wide = mods.Contains("wide"), ascii = mods.Contains("ascii") || !wide;
                if (mods.Contains("nocase")) opts |= RegexOptions.IgnoreCase;
                var bytes = Encoding.UTF8.GetBytes(v.Text);   // literal text as UTF-8 bytes (matches YARA for ASCII)
                string Esc(byte[] b) => string.Concat(b.Select(x => EscByte(x)));
                var alts = new List<string>();
                if (ascii) alts.Add(Esc(bytes));
                if (wide) alts.Add(string.Concat(bytes.Select(x => EscByte(x) + "\\x00")));
                pattern = alts.Count == 1 ? alts[0] : "(?:" + string.Join("|", alts) + ")";
                if (mods.Contains("fullword")) pattern = @"(?<![A-Za-z0-9])" + pattern + @"(?![A-Za-z0-9])";
                break;
            }
            case T.Hex: pattern = HexToRegex(v.Text, v.Line); opts |= RegexOptions.Singleline; break;
            case T.Regex:
                pattern = v.Text;
                if (v.Flags.Contains('i')) opts |= RegexOptions.IgnoreCase;
                if (v.Flags.Contains('s')) opts |= RegexOptions.Singleline;
                break;
            default: throw new YaraSyntaxException("expected string, hex or regex", v.Line);
        }
        try { return new Regex(pattern, opts, MatchTimeout); }
        catch (ArgumentException e) { throw new YaraSyntaxException("invalid pattern: " + e.Message, v.Line); }
    }

    private static string EscByte(byte b) => (b is >= (byte)'a' and <= (byte)'z') || (b is >= (byte)'A' and <= (byte)'Z') || (b is >= (byte)'0' and <= (byte)'9')
        ? ((char)b).ToString() : $"\\x{b:X2}";

    internal static string HexToRegex(string body, int line)
    {
        var sb = new StringBuilder(); int i = 0;
        string s = Regex.Replace(body, @"//[^\n]*|/\*.*?\*/", "", RegexOptions.Singleline);
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '(') { sb.Append("(?:"); i++; continue; }
            if (c == ')') { sb.Append(')'); i++; continue; }
            if (c == '|') { sb.Append('|'); i++; continue; }
            if (c == '[')
            {
                int end = s.IndexOf(']', i); if (end < 0) throw new YaraSyntaxException("unterminated jump", line);
                var jump = s[(i + 1)..end].Trim(); i = end + 1;
                if (jump.Contains('-'))
                {
                    var parts = jump.Split('-'); var lo = parts[0].Trim(); var hi = parts[1].Trim();
                    sb.Append("[\\x00-\\xFF]{").Append(lo.Length == 0 ? "0" : lo).Append(',').Append(hi).Append('}');
                }
                else sb.Append("[\\x00-\\xFF]{").Append(jump).Append('}');
                continue;
            }
            if (i + 1 >= s.Length) throw new YaraSyntaxException("odd number of hex digits", line);
            char h = s[i], l = s[i + 1]; i += 2;
            if (h == '?' && l == '?') sb.Append("[\\x00-\\xFF]");
            else if (h == '?') { var lv = Convert.ToInt32(l.ToString(), 16); sb.Append('[').Append(string.Concat(Enumerable.Range(0, 16).Select(x => $"\\x{(x << 4) | lv:X2}"))).Append(']'); }
            else if (l == '?') { var hv = Convert.ToInt32(h.ToString(), 16); sb.Append($"[\\x{hv << 4:X2}-\\x{(hv << 4) | 0xF:X2}]"); }
            else if (Uri.IsHexDigit(h) && Uri.IsHexDigit(l)) sb.Append($"\\x{Convert.ToByte($"{h}{l}", 16):X2}");
            else throw new YaraSyntaxException($"invalid hex byte '{h}{l}'", line);
        }
        return sb.ToString();
    }

    // ---- condition grammar (precedence: or < and < not < comparison < additive < primary)
    private static Node ParseOr(P p) { var a = ParseAnd(p); while (p.IsIdent("or")) { p.Take(); a = new Binary("or", a, ParseAnd(p)); } return a; }
    private static Node ParseAnd(P p) { var a = ParseNot(p); while (p.IsIdent("and")) { p.Take(); a = new Binary("and", a, ParseNot(p)); } return a; }
    private static Node ParseNot(P p) { if (p.IsIdent("not")) { p.Take(); return new Unary("not", ParseNot(p)); } return ParseCmp(p); }
    private static Node ParseCmp(P p)
    {
        var a = ParseAdd(p);
        if (p.At(T.Sym) && p.Peek.Text is "==" or "!=" or "<" or "<=" or ">" or ">=") { var op = p.Take().Text; return new Binary(op, a, ParseAdd(p)); }
        return a;
    }
    private static Node ParseAdd(P p)
    {
        var a = ParsePrimary(p);
        while (p.At(T.Sym) && p.Peek.Text is "+" or "-") { var op = p.Take().Text; a = new Binary(op, a, ParsePrimary(p)); }
        return a;
    }
    private static Node ParsePrimary(P p)
    {
        var t = p.Peek;
        // quantifier "of" set
        if ((t.Type == T.Int || (t.Type == T.Ident && t.Text is "any" or "all" or "none")) && p.PeekAt(1) is { Type: T.Ident, Text: "of" })
        {
            p.Take(); p.Take();
            Node q = t.Type == T.Int ? new IntLit(t.Int) : new Quant(t.Text);
            return new OfExpr(q, ParseSet(p));
        }
        switch (t.Type)
        {
            case T.Int: p.Take(); return new IntLit(t.Int);
            case T.StrId:
                p.Take();
                if (p.IsIdent("at")) { p.Take(); return new StrAt(t.Text, ParseAdd(p)); }
                if (p.IsIdent("in")) { p.Take(); p.ExpectSym("("); var lo = ParseAdd(p); p.ExpectSym(".."); var hi = ParseAdd(p); p.ExpectSym(")"); return new StrIn(t.Text, lo, hi); }
                return new StrRef(t.Text);
            case T.CountId: p.Take(); return new StrCount(t.Text);
            case T.OffsetId:
            {
                p.Take(); Node? idx = null;
                if (p.IsSym("[")) { p.Take(); idx = ParseAdd(p); p.ExpectSym("]"); }
                return new StrOffset(t.Text, idx);
            }
            case T.Ident:
                p.Take();
                switch (t.Text)
                {
                    case "true": return new BoolLit(true);
                    case "false": return new BoolLit(false);
                    case "filesize": return new FileSize();
                    case "uint8": case "uint16": case "uint32": case "int8": case "int16": case "int32":
                    case "uint16be": case "uint32be": case "int16be": case "int32be":
                        p.ExpectSym("("); var off = ParseAdd(p); p.ExpectSym(")"); return new ReadInt(t.Text, off);
                    default: throw new YaraSyntaxException($"unsupported identifier '{t.Text}' (modules are not supported)", t.Line);
                }
            case T.Sym when t.Text == "(":
                p.Take(); var e = ParseOr(p); p.ExpectSym(")"); return e;
            case T.Sym when t.Text == "-":
                p.Take(); return new Binary("-", new IntLit(0), ParsePrimary(p));
        }
        throw new YaraSyntaxException($"unexpected '{t.Text}' in condition", t.Line);
    }
    private static List<string> ParseSet(P p)
    {
        if (p.IsIdent("them")) { p.Take(); return new List<string> { "them" }; }
        p.ExpectSym("(");
        var set = new List<string>();
        do { if (p.IsSym(",")) p.Take(); set.Add(p.Expect(T.StrId).Text); } while (p.IsSym(","));
        p.ExpectSym(")");
        return set;
    }

    private sealed class P
    {
        private readonly List<Tok> _t; private int _i;
        public P(List<Tok> t) => _t = t;
        public Tok Peek => _t[_i];
        public Tok PeekAt(int o) => _t[Math.Min(_i + o, _t.Count - 1)];
        public bool At(T type) => Peek.Type == type;
        public bool IsIdent(string s) => Peek.Type == T.Ident && Peek.Text == s;
        public bool IsSym(string s) => Peek.Type == T.Sym && Peek.Text == s;
        public Tok Take() => _t[_i++];
        public Tok Expect(T type) { if (!At(type)) throw new YaraSyntaxException($"expected {type}, got '{Peek.Text}'", Peek.Line); return Take(); }
        public void ExpectSym(string s) { if (!IsSym(s)) throw new YaraSyntaxException($"expected '{s}', got '{Peek.Text}'", Peek.Line); Take(); }
        public void ExpectIdent(string s) { if (!IsIdent(s)) throw new YaraSyntaxException($"expected '{s}', got '{Peek.Text}'", Peek.Line); Take(); }
    }
}

// ======================================================================== scanner

public sealed class YaraScanner
{
    private const int MaxHitsPerString = 256;
    private readonly IReadOnlyList<YaraRule> _rules;
    public YaraScanner(IEnumerable<YaraRule> rules) => _rules = rules.ToList();
    public int RuleCount => _rules.Count;

    public List<YaraMatch> Scan(byte[] data) => Scan(data, null, default, out _);

    /// <summary>
    /// Scans with a total time budget for the whole file. When the budget runs out the remaining rules are skipped and
    /// <paramref name="incomplete"/> is set, so a crafted file can't hold the scan for minutes.
    /// </summary>
    public List<YaraMatch> Scan(byte[] data, TimeSpan? budget, CancellationToken ct, out bool incomplete)
    {
        incomplete = false;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var text = Encoding.Latin1.GetString(data);
        var results = new List<YaraMatch>();
        foreach (var rule in _rules)
        {
            if (ct.IsCancellationRequested || (budget is { } b && clock.Elapsed > b)) { incomplete = true; break; }
            var hits = new Dictionary<string, List<int>>();
            foreach (var s in rule.Strings)
            {
                var offs = new List<int>();
                try
                {
                    for (var m = s.Pattern.Match(text); m.Success && offs.Count < MaxHitsPerString; m = m.NextMatch())
                    {
                        offs.Add(m.Index);
                        if (m.Length == 0) break;
                    }
                }
                catch (RegexMatchTimeoutException) { incomplete = true; }
                hits[s.Id] = offs;
            }
            var ev = new Eval(rule, hits, data);
            bool ok;
            try { ok = ev.Bool(rule.Condition); } catch (IndexOutOfRangeException) { ok = false; }
            if (ok)
            {
                var m = new YaraMatch { Rule = rule };
                foreach (var kv in hits.Where(h => h.Value.Count > 0)) m.Hits[kv.Key] = kv.Value;
                results.Add(m);
            }
        }
        return results;
    }

    private sealed class Eval
    {
        private readonly YaraRule _r; private readonly Dictionary<string, List<int>> _h; private readonly byte[] _d;
        public Eval(YaraRule r, Dictionary<string, List<int>> h, byte[] d) { _r = r; _h = h; _d = d; }

        private IEnumerable<string> Expand(List<string> set) => set.SelectMany(id =>
            id == "them" ? _r.Strings.Select(s => s.Id)
            : id.EndsWith('*') ? _r.Strings.Where(s => s.Id.StartsWith(id[..^1])).Select(s => s.Id)
            : new[] { id }).Distinct();

        public bool Bool(Node n) => n switch
        {
            BoolLit b => b.V,
            StrRef s => _h[s.Id].Count > 0,
            StrAt s => _h[s.Id].Contains((int)Int(s.At)),
            StrIn s => _h[s.Id].Any(o => o >= Int(s.Lo) && o <= Int(s.Hi)),
            Unary { Op: "not" } u => !Bool(u.A),
            Binary { Op: "and" } b => Bool(b.A) && Bool(b.B),
            Binary { Op: "or" } b => Bool(b.A) || Bool(b.B),
            Binary { Op: "==" } b => Int(b.A) == Int(b.B),
            Binary { Op: "!=" } b => Int(b.A) != Int(b.B),
            Binary { Op: "<" } b => Int(b.A) < Int(b.B),
            Binary { Op: "<=" } b => Int(b.A) <= Int(b.B),
            Binary { Op: ">" } b => Int(b.A) > Int(b.B),
            Binary { Op: ">=" } b => Int(b.A) >= Int(b.B),
            OfExpr o => Of(o),
            _ => Int(n) != 0,
        };

        private bool Of(OfExpr o)
        {
            var ids = Expand(o.Set).ToList();
            int matched = ids.Count(id => _h[id].Count > 0);
            return o.Quantifier switch
            {
                Quant { Kind: "all" } => matched == ids.Count,
                Quant { Kind: "any" } => matched >= 1,
                Quant { Kind: "none" } => matched == 0,
                IntLit i => matched >= i.V,
                _ => false
            };
        }

        public long Int(Node n) => n switch
        {
            IntLit i => i.V,
            FileSize => _d.LongLength,
            StrCount c => _h[c.Id].Count,
            StrOffset s => _h[s.Id].Count >= (s.Index is null ? 1 : Int(s.Index)) ? _h[s.Id][(int)(s.Index is null ? 1 : Int(s.Index)) - 1] : -1,
            ReadInt r => Read(r.Fn, Int(r.Offset)),
            Binary { Op: "+" } b => Int(b.A) + Int(b.B),
            Binary { Op: "-" } b => Int(b.A) - Int(b.B),
            _ => Bool(n) ? 1 : 0,
        };

        private long Read(string fn, long off)
        {
            int size = fn.Contains("8") ? 1 : fn.Contains("16") ? 2 : 4;
            if (off < 0 || off + size > _d.Length) throw new IndexOutOfRangeException();
            bool be = fn.EndsWith("be"); bool signed = !fn.StartsWith("u");
            ulong v = 0;
            for (int k = 0; k < size; k++) { int idx = be ? k : size - 1 - k; v = (v << 8) | _d[off + idx]; }
            if (!signed) return (long)v;
            return size switch { 1 => (sbyte)v, 2 => (short)v, _ => (int)v };
        }
    }
}
