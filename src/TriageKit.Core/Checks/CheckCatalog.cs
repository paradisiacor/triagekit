using System.Runtime.Versioning;
using TriageKit.Core.Engine;
using TriageKit.Core.Reputation;
using TriageKit.Core.Yara;

namespace TriageKit.Core.Checks;

public static class CheckCatalog
{
    /// <summary>All checks, in the order they appear in the report. Scanner re-orders by ICheck.Order.</summary>
    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<ICheck> All() => new ICheck[]
    {
        new SystemPostureCheck(), new DefenderCheck(), new ProcessCheck(), new AutostartCheck(), new NetworkCheck(),
        new EventLogCheck(), new BrowserExtensionCheck(), new SoftwareCheck(), new RecentFilesCheck(),
        new CertificateCheck(), new DriverCheck(), new PrivacyCheck(), new HardeningCheck(), new HiddenPersistenceCheck(), new RunHistoryCheck(), new SessionTheftCheck(), new ModuleCheck(),
        new StabilityCheck(), new SystemHealthCheck(), new PerformanceCheck(), new HardwareSetupCheck(), new SensorsCheck(), new LivePerformanceCheck(), new GamerProtectionCheck(),
        new DefenderQuickScanCheck(), new AutorunsCheck(), new YaraCheck(), new DeepFileScanCheck(),
        new ReputationCheck(new IReputationProvider[] { new CirclHashlookupProvider(), new DefenderFileScanProvider(), new MalwareBazaarProvider(), new VirusTotalProvider() }),
    };
}
