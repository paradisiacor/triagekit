// Publisher tool for TriageKit rule packs.
//   rulepack keygen <outDir>                      create a new P-256 key pair (keep the private key OFFLINE)
//   rulepack sign   <packDir> <private.pem> <ver> write manifest.json + manifest.sig
//   rulepack verify <packDir> [public.pem]        check a pack (defaults to the key built into TriageKit)
using TriageKit.Core.Agent;
using TriageKit.Core.Rules;

if (args.Length == 0) { Console.WriteLine("usage: rulepack keygen <outDir> | sign <packDir> <private.pem> <version> | verify <packDir> [public.pem]"); return 1; }
switch (args[0])
{
    case "keygen":
    {
        var (priv, pub) = RulePack.GenerateKeyPair();
        Directory.CreateDirectory(args[1]);
        File.WriteAllText(Path.Combine(args[1], "rulepack-private.pem"), priv);
        File.WriteAllText(Path.Combine(args[1], "rulepack-public.pem"), pub);
        Console.WriteLine("Key pair written. Copy rulepack-public.pem to src/TriageKit.Core/Resources/ and store the private key offline.");
        return 0;
    }
    case "sign":
    {
        var m = RulePack.Sign(args[1], File.ReadAllText(args[2]), args[3]);
        Console.WriteLine($"Signed {m.Files.Count} file(s), version {m.Version}.");
        var check = RulePack.Verify(args[1], null);
        Console.WriteLine(check.Trusted ? "Verifies against the key built into TriageKit." : $"WARNING: does not verify against the built-in key ({check.Error}).");
        return 0;
    }
    case "verify":
    {
        var r = RulePack.Verify(args[1], args.Length > 2 ? File.ReadAllText(args[2]) : null);
        Console.WriteLine(r.Trusted ? $"OK - version {r.Version}" : $"REJECTED - {r.Error}");
        return r.Trusted ? 0 : 2;
    }
}
Console.WriteLine("unknown command"); return 1;
