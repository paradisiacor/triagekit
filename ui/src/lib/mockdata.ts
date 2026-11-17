// Sample backend for design previews only (vite --mode preview). Not included in the release build.
const FINDINGS = [
 {
  "severity": "High",
  "category": "Defender",
  "title": "Defender exclusion: Path C:\\Users\\alex\\Downloads\\GameTools",
  "detail": "Defender does not scan anything matching this exclusion. Malware often adds exclusions for itself.",
  "recommendation": "Remove the exclusion in Windows Security > Virus & threat protection > Exclusions, unless you know exactly why it is there.",
  "mitre": "T1562.001",
  "ruleId": "defender.exclusion",
  "evidence": {
   "Type": "Path",
   "Value": "C:\\Users\\alex\\Downloads\\GameTools"
  }
 },
 {
  "severity": "High",
  "category": "System",
  "title": "User Account Control (UAC) is disabled",
  "detail": "Every program runs with full administrator rights, so malware gets total control instantly.",
  "recommendation": "Turn UAC back on (Control Panel > User Accounts > Change User Account Control settings) and restart.",
  "mitre": "T1548.002",
  "ruleId": "system.uac-disabled",
  "evidence": null
 },
 {
  "severity": "High",
  "category": "Persistence",
  "title": "Unsigned program starts with Windows: updater.exe",
  "detail": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\nC:\\Users\\alex\\AppData\\Roaming\\Updater\\updater.exe",
  "recommendation": "If you do not recognise this program, disable it in Task Manager > Startup and scan the file.",
  "mitre": "T1547.001",
  "ruleId": "persistence.run-key",
  "evidence": {
   "Location": "HKCU Run",
   "Path": "C:\\Users\\alex\\AppData\\Roaming\\Updater\\updater.exe",
   "Signed": false
  }
 },
 {
  "severity": "Medium",
  "category": "Defender",
  "title": "Defender detected Trojan:Win32/Etset!rfn",
  "detail": "Generic/heuristic detection - this can be a false positive for unsigned or packed software. Detected 2026-11-12T20:22:42.",
  "recommendation": "Check that the file was removed and where it came from. If it was software you trust, verify it on VirusTotal.",
  "mitre": null,
  "ruleId": "defender.detection-generic",
  "evidence": {
   "Time": "2026-11-12T20:22:42",
   "Threat": "Trojan:Win32/Etset!rfn",
   "Resources": "file:_C:\\Users\\alex\\Downloads\\GameTools\\PrivateServer\\server\\scriptprocess.dll",
   "Process": "C:\\Windows\\explorer.exe",
   "User": "DESKTOP-7Q2K\\alex",
   "Status": 3
  }
 },
 {
  "severity": "Medium",
  "category": "Defender",
  "title": "Defender detected Trojan:Win32/Wacatac.B!ml",
  "detail": "Generic/heuristic detection - this can be a false positive for unsigned or packed software. Detected 2026-11-12T20:20:59.",
  "recommendation": "Check that the file was removed and where it came from. If it was software you trust, verify it on VirusTotal.",
  "mitre": null,
  "ruleId": "defender.detection-generic",
  "evidence": {
   "Time": "2026-11-12T20:20:59",
   "Threat": "Trojan:Win32/Wacatac.B!ml",
   "Resources": "file:_C:\\Users\\alex\\Downloads\\GameTools\\OldGame\\bin\\game.exe",
   "Process": "C:\\Windows\\explorer.exe",
   "User": "DESKTOP-7Q2K\\alex",
   "Status": 3
  }
 },
 {
  "severity": "Medium",
  "category": "Events",
  "title": "Defender real-time protection was switched off 2 times (last at 2026-11-13T19:53:19); it is on again now",
  "detail": "Turning protection off temporarily is common when installing games or tools, but malware does it too.",
  "recommendation": "If you don't remember switching it off, run a full Defender scan and check Defender's protection history.",
  "mitre": "T1562.001",
  "ruleId": "events.defender-disabled",
  "evidence": [
   {
    "Time": "2026-11-13T14:31:43",
    "Id": 5001,
    "Message": "Microsoft Defender Antivirus Real-time Protection scanning for malware and other potentially unwanted software was disabled."
   },
   {
    "Time": "2026-11-13T19:53:19",
    "Id": 5001,
    "Message": "Microsoft Defender Antivirus Real-time Protection scanning for malware and other potentially unwanted software was disabled."
   }
  ]
 },
 {
  "severity": "Low",
  "category": "Files",
  "title": "2 script file(s) recently created in AppData/ProgramData/Temp",
  "detail": "Scripts in these folders are a common way malware gets started.",
  "recommendation": "Make sure you recognise these scripts.",
  "mitre": "T1059",
  "ruleId": "files.scripts",
  "evidence": null
 },
 {
  "severity": "Low",
  "category": "Software",
  "title": "Remote-access tool installed: AnyDesk",
  "detail": "These tools are legitimate, but scammers and attackers use them to take full control of a PC.",
  "recommendation": "Uninstall it if you don't use it regularly, and never let someone you don't know connect.",
  "mitre": "T1219",
  "ruleId": "software.remote-access",
  "evidence": {
   "Tool": "AnyDesk",
   "Installed": "AnyDesk",
   "Version": "ad 9.7.16",
   "Publisher": "AnyDesk Software GmbH",
   "Running": true
  }
 },
 {
  "severity": "Low",
  "category": "Software",
  "title": "Remote-access tool installed: Parsec",
  "detail": "These tools are legitimate, but scammers and attackers use them to take full control of a PC.",
  "recommendation": "Uninstall it if you don't use it regularly, and never let someone you don't know connect.",
  "mitre": "T1219",
  "ruleId": "software.remote-access",
  "evidence": {
   "Tool": "Parsec",
   "Installed": "Parsec Virtual Display Driver",
   "Version": "0.45.0.0",
   "Publisher": "Parsec Cloud Inc.",
   "Running": true
  }
 },
 {
  "severity": "Low",
  "category": "Software",
  "title": "Remote-access tool installed: TeamViewer",
  "detail": "These tools are legitimate, but scammers and attackers use them to take full control of a PC.",
  "recommendation": "Uninstall it if you don't use it regularly, and never let someone you don't know connect.",
  "mitre": "T1219",
  "ruleId": "software.remote-access",
  "evidence": {
   "Tool": "TeamViewer",
   "Installed": "TeamViewer",
   "Version": "15.83.5",
   "Publisher": "TeamViewer",
   "Running": false
  }
 },
 {
  "severity": "Low",
  "category": "System",
  "title": "3 accounts are local administrators",
  "detail": "DESKTOP-7Q2K\\Administrator, DESKTOP-7Q2K\\alex, DESKTOP-7Q2K\\sam",
  "recommendation": "Keep administrator accounts to a minimum and use a standard account for everyday work.",
  "mitre": "T1078.003",
  "ruleId": "system.many-admins",
  "evidence": null
 },
 {
  "severity": "Low",
  "category": "System",
  "title": "System drive is not encrypted",
  "detail": "If the device is lost or stolen, files can be read by anyone.",
  "recommendation": "Turn on BitLocker or Device encryption (Settings > Privacy & security > Device encryption).",
  "mitre": null,
  "ruleId": "system.bitlocker-off",
  "evidence": null
 },
 {
  "severity": "Info",
  "category": "Defender",
  "title": "Ransomware protection (Controlled Folder Access) is off",
  "detail": "",
  "recommendation": "Consider enabling it in Windows Security > Ransomware protection.",
  "mitre": null,
  "ruleId": "defender.cfa-off",
  "evidence": null
 },
 {
  "severity": "Info",
  "category": "Files",
  "title": "Recent-file sweep stopped at 400 items",
  "detail": "",
  "recommendation": "Increase RecentFileMaxItems in config.json for a deeper sweep.",
  "mitre": null,
  "ruleId": null,
  "evidence": null
 }
];
export default FINDINGS;
