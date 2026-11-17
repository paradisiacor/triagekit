/*
  TriageKit core rules (original work, licensed with TriageKit).
  Supported meta keys: description, severity (critical|high|medium|low|info), mitre, advice, target (pe|script|any)
  Rules are designed for low false positives on everyday PCs: most require several independent indicators.
*/

rule Ransomware_ShadowCopy_Destruction : ransomware
{
    meta:
        description = "Deletes Windows backups (shadow copies / recovery) - a hallmark of ransomware"
        severity = "critical"
        mitre = "T1490"
        advice = "Disconnect the PC from the network immediately and do not pay. Restore files from an offline backup."
        target = "any"
    strings:
        $a = "vssadmin delete shadows" nocase ascii wide
        $b = "vssadmin.exe delete shadows" nocase ascii wide
        $c = "shadowcopy delete" nocase ascii wide
        $d = "recoveryenabled no" nocase ascii wide
        $e = "wbadmin delete catalog" nocase ascii wide
        $f = "delete systemstatebackup" nocase ascii wide
    condition:
        2 of them
}

rule Ransomware_Note_Text : ransomware
{
    meta:
        description = "Contains ransom-note wording together with payment instructions"
        severity = "critical"
        mitre = "T1486"
        advice = "Disconnect the PC from the network immediately. Do not pay; contact a professional and restore from offline backups."
        target = "any"
    strings:
        $n1 = "your files have been encrypted" nocase ascii wide
        $n2 = "all your files are encrypted" nocase ascii wide
        $n3 = "your important files are encrypted" nocase ascii wide
        $n4 = "to decrypt your files" nocase ascii wide
        $p1 = "bitcoin" nocase ascii wide
        $p2 = ".onion" nocase ascii wide
        $p3 = "tor browser" nocase ascii wide
        $p4 = "decryption key" nocase ascii wide
    condition:
        any of ($n*) and 2 of ($p*)
}

rule Stealer_Browser_And_Wallet_Harvesting : stealer
{
    meta:
        description = "Collects saved browser passwords, cookies and crypto wallets - typical information-stealer behaviour"
        severity = "high"
        mitre = "T1555.003"
        advice = "Assume saved passwords and logged-in sessions are stolen: change passwords from another device, sign out of all sessions, and move crypto to a new wallet."
        target = "pe"
    strings:
        $b1 = "\\Google\\Chrome\\User Data" nocase ascii wide
        $b2 = "\\Microsoft\\Edge\\User Data" nocase ascii wide
        $b3 = "\\BraveSoftware\\Brave-Browser\\User Data" nocase ascii wide
        $b4 = "\\Mozilla\\Firefox\\Profiles" nocase ascii wide
        $f1 = "Login Data" ascii wide
        $f2 = "Local State" ascii wide
        $f3 = "Web Data" ascii wide
        $f4 = "logins.json" ascii wide
        $f5 = "key4.db" ascii wide
        $w1 = "wallet.dat" nocase ascii wide
        $w2 = "\\Exodus\\exodus.wallet" nocase ascii wide
        $w3 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $w4 = "\\Electrum\\wallets" nocase ascii wide
        $w5 = "\\Telegram Desktop\\tdata" nocase ascii wide
        $c1 = "CryptUnprotectData" ascii
        $c2 = "encrypted_key" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of ($b*) and 3 of ($f*) and (any of ($w*) or all of ($c*))
}

rule Stealer_Discord_Token_Grabber : stealer discord
{
    meta:
        description = "Searches Discord's local storage for login tokens - used to hijack Discord accounts"
        severity = "high"
        mitre = "T1528"
        advice = "Change your Discord password (this invalidates tokens), enable 2FA, and review Authorized Apps and Devices."
        target = "any"
    strings:
        $d1 = "discord" nocase ascii wide
        $l1 = "Local Storage\\leveldb" nocase ascii wide
        $l2 = "Local Storage/leveldb" nocase ascii wide
        $t1 = "dQw4w9WgXcQ:" ascii wide
        $t2 = /[\w-]{24}\.[\w-]{6}\.[\w-]{27}/
        $x1 = "discordcanary" nocase ascii wide
        $x2 = "discordptb" nocase ascii wide
    condition:
        $d1 and any of ($l*) and (any of ($t*) or all of ($x*))
}

rule Exfiltration_Telegram_Bot : exfiltration
{
    meta:
        description = "Sends data to a Telegram bot - a common way stealers upload stolen files"
        severity = "high"
        mitre = "T1567"
        advice = "Find out what this program is. If unknown, remove it and change passwords from another device."
        target = "any"
    strings:
        $api = "api.telegram.org/bot" nocase ascii wide
        $m1 = "sendDocument" ascii wide
        $m2 = "sendMessage" ascii wide
        $m3 = "sendPhoto" ascii wide
        $m4 = "chat_id" ascii wide
    condition:
        $api and 2 of ($m*)
}

rule Exfiltration_Discord_Webhook : exfiltration discord
{
    meta:
        description = "Posts data to a Discord webhook - frequently used by stealers and token grabbers"
        severity = "high"
        mitre = "T1567"
        advice = "Find out what this program is. If unknown, remove it and change passwords from another device."
        target = "any"
    strings:
        $w1 = /discord(app)?\.com\/api\/webhooks\/\d{17,20}\/[\w-]{60,}/ nocase
    condition:
        $w1
}

rule Defense_Evasion_Defender_Tampering : evasion
{
    meta:
        description = "Disables Microsoft Defender or adds Defender exclusions"
        severity = "high"
        mitre = "T1562.001"
        advice = "Check Windows Security for exclusions and disabled protection, and remove this program if you don't know it."
        target = "any"
    strings:
        $a1 = "Add-MpPreference" nocase ascii wide
        $a2 = "Set-MpPreference" nocase ascii wide
        $o1 = "-ExclusionPath" nocase ascii wide
        $o2 = "-ExclusionProcess" nocase ascii wide
        $o3 = "-ExclusionExtension" nocase ascii wide
        $o4 = "-DisableRealtimeMonitoring" nocase ascii wide
        $o5 = "-DisableBehaviorMonitoring" nocase ascii wide
        $o6 = "-DisableIOAVProtection" nocase ascii wide
        $r1 = "DisableAntiSpyware" ascii wide
        $r2 = "\\Windows Defender\\Real-Time Protection" nocase ascii wide
    condition:
        (any of ($a*) and any of ($o*)) or all of ($r*)
}

rule Defense_Evasion_AMSI_Bypass : evasion
{
    meta:
        description = "Contains code to switch off Windows' script-scanning interface (AMSI): a known bypass recipe in a script, or the patch bytes in a program"
        severity = "high"
        mitre = "T1562.001"
        advice = "Legitimate software does not do this. Remove the file and run a full antivirus scan."
        target = "any"
    strings:
        $a1 = "amsiInitFailed" nocase ascii wide
        $a2 = "AmsiScanBuffer" ascii wide
        $a3 = "AmsiUtils" ascii wide
        $r1 = "GetField" ascii wide
        $r2 = "NonPublic" ascii wide
        $p1 = "VirtualProtect" ascii wide
        $x1 = "\xB8\x57\x00\x07\x80\xC3"
        $x2 = "0xB8, 0x57, 0x00, 0x07, 0x80" nocase ascii wide
        $x3 = "0xB8,0x57,0x00,0x07,0x80" nocase ascii wide
    condition:
        (not uint16(0) == 0x5A4D and ($a1 or ($a3 and $r1 and $r2) or ($a2 and $p1 and 1 of ($x2, $x3))))
        or (uint16(0) == 0x5A4D and $a2 and $p1 and $x1)
}

rule Loader_PowerShell_Download_Cradle : loader
{
    meta:
        description = "Script that downloads and immediately runs code from the internet"
        severity = "high"
        mitre = "T1059.001"
        advice = "Find out who created this script. If you didn't, delete it and check scheduled tasks and startup items."
        target = "script"
    strings:
        $d1 = "DownloadString" nocase ascii wide
        $d2 = "DownloadFile" nocase ascii wide
        $d3 = "Net.WebClient" nocase ascii wide
        $d4 = "Invoke-WebRequest" nocase ascii wide
        $d5 = "Start-BitsTransfer" nocase ascii wide
        $x1 = "IEX" ascii wide fullword
        $x2 = "Invoke-Expression" nocase ascii wide
        $x3 = "FromBase64String" nocase ascii wide
        $x4 = "-EncodedCommand" nocase ascii wide
        $x5 = "Start-Process" nocase ascii wide
        $x6 = "-WindowStyle Hidden" nocase ascii wide
    condition:
        filesize < 2MB and any of ($d*) and 2 of ($x*)
}

rule Loader_Script_Dropper_VBS_JS : loader
{
    meta:
        description = "VBScript/JScript that downloads a file and runs it"
        severity = "high"
        mitre = "T1059.005"
        advice = "Delete the script unless you know exactly what it is, and check startup items and scheduled tasks."
        target = "script"
    strings:
        $h1 = "MSXML2.XMLHTTP" nocase ascii wide
        $h2 = "WinHttp.WinHttpRequest" nocase ascii wide
        $h3 = "MSXML2.ServerXMLHTTP" nocase ascii wide
        $s1 = "ADODB.Stream" nocase ascii wide
        $s2 = "SaveToFile" nocase ascii wide
        $r1 = "WScript.Shell" nocase ascii wide
        $r2 = "Shell.Application" nocase ascii wide
        $r3 = ".Run" nocase ascii wide
        $r4 = "ShellExecute" nocase ascii wide
    condition:
        filesize < 2MB and any of ($h*) and any of ($s*) and 2 of ($r*)
}

rule Loader_LOLBin_Download : loader
{
    meta:
        description = "Uses built-in Windows tools (certutil, bitsadmin, mshta) to download files - a common malware trick"
        severity = "high"
        mitre = "T1105"
        advice = "Delete the script unless you know exactly what it is."
        target = "script"
    strings:
        $c1 = /certutil(\.exe)?\s+[-\/]urlcache/ nocase
        $c2 = /bitsadmin(\.exe)?\s+\/transfer/ nocase
        $c3 = /mshta(\.exe)?\s+["']?https?:\/\// nocase
        $c4 = /regsvr32(\.exe)?\s.*\/i:https?:\/\// nocase
    condition:
        any of them
}

rule Miner_Stratum_Configuration : miner
{
    meta:
        description = "Contains cryptocurrency-mining pool configuration"
        severity = "high"
        mitre = "T1496"
        advice = "If you didn't install a miner yourself, remove it - miners are often installed by malware and slow the PC down."
        target = "any"
    strings:
        $s1 = "stratum+tcp://" nocase ascii wide
        $s2 = "stratum+ssl://" nocase ascii wide
        $s3 = "stratum2+tcp://" nocase ascii wide
        $o1 = "--donate-level" ascii wide
        $o2 = "\"donate-level\"" ascii wide
        $o3 = "randomx" nocase ascii wide
        $o4 = "--cpu-max-threads-hint" ascii wide
        $o5 = "nicehash" nocase ascii wide
    condition:
        any of ($s*) and any of ($o*)
}

rule Clipper_Crypto_Address_Swap : stealer crypto
{
    meta:
        description = "Monitors the clipboard and contains crypto-address patterns - used to swap wallet addresses when you paste"
        severity = "high"
        mitre = "T1115"
        advice = "Always double-check wallet addresses after pasting. Remove this program and move funds to a new wallet if you're unsure."
        target = "pe"
    strings:
        $c1 = "GetClipboardData" ascii wide
        $c2 = "SetClipboardData" ascii wide
        $c3 = "AddClipboardFormatListener" ascii wide
        $c4 = "Clipboard.SetText" ascii wide
        $r1 = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii wide
        $r2 = "^0x[a-fA-F0-9]{40}$" ascii wide
        $r3 = "^T[A-Za-z1-9]{33}$" ascii wide
        $r4 = "^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of ($c*) and 2 of ($r*)
}

rule RAT_AntiAnalysis_And_Persistence : rat
{
    meta:
        description = "Combines sandbox/VM detection with self-installation for persistence - typical of remote-access trojans"
        severity = "high"
        mitre = "T1497"
        advice = "Disconnect the PC from the internet, remove the file, and change passwords from another device."
        target = "pe"
    strings:
        $v1 = "SbieDll.dll" ascii wide
        $v2 = "VBoxService" nocase ascii wide
        $v3 = "vmtoolsd" nocase ascii wide
        $v4 = "Select * from Win32_ComputerSystem" nocase ascii wide
        $v5 = "wine_get_unix_file_name" ascii wide
        $v6 = "CheckRemoteDebuggerPresent" ascii
        $p1 = "schtasks /create" nocase ascii wide
        $p2 = "\\CurrentVersion\\Run" nocase ascii wide
        $p3 = "\\Start Menu\\Programs\\Startup" nocase ascii wide
        $p4 = "/sc onlogon" nocase ascii wide
        $n1 = "Pastebin" nocase ascii wide
        $n2 = "keylogger" nocase ascii wide
        $n3 = "Remote Desktop" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of ($v*) and 2 of ($p*) and any of ($n*)
}

rule Keylogger_API_Combination : spyware
{
    meta:
        description = "Uses the Windows functions keyloggers rely on (key state polling + active-window tracking + logging)"
        severity = "medium"
        mitre = "T1056.001"
        advice = "Some legitimate tools (games, hotkey apps) do this too. Check that you recognise the program."
        target = "pe"
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "SetWindowsHookExA" ascii
        $k3 = "SetWindowsHookExW" ascii
        $w1 = "GetForegroundWindow" ascii
        $w2 = "GetWindowTextW" ascii
        $l1 = "[ENTER]" nocase ascii wide
        $l2 = "[BACKSPACE]" nocase ascii wide
        $l3 = "[CTRL]" nocase ascii wide
        $l4 = "[TAB]" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and any of ($k*) and all of ($w*) and 2 of ($l*)
}

rule Packer_UPX : packer
{
    meta:
        description = "Program is compressed with UPX (common for malware, but also used by legitimate tools)"
        severity = "info"
        target = "pe"
    strings:
        $u0 = "UPX0" ascii
        $u1 = "UPX1" ascii
        $u2 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Test_EICAR : test
{
    meta:
        description = "EICAR antivirus test file (harmless, made to test security software)"
        severity = "low"
        advice = "This is a harmless test file. Delete it if you didn't put it there to test your antivirus."
        target = "any"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii
    condition:
        $e at 28 or ($e and filesize < 256)
}

rule Evasion_AntiVM_AntiSandbox : evasion
{
    meta:
        description = "Program checks whether it runs in a virtual machine, sandbox or debugger (malware uses this to hide from analysis)"
        severity = "low"
        advice = "On its own this isn't proof: some games' anti-cheat and copy protection do the same. Together with other findings for this file, treat it as malware."
        mitre = "T1497"
        target = "pe"
    strings:
        $vm1 = "VBoxService" nocase ascii wide
        $vm2 = "VBoxTray" nocase ascii wide
        $vm3 = "vmtoolsd" nocase ascii wide
        $vm4 = "VMware Tools" nocase ascii wide
        $vm5 = "SbieDll.dll" nocase ascii wide
        $vm6 = "wine_get_unix_file_name" ascii
        $vm7 = "HARDWARE\\ACPI\\DSDT\\VBOX__" nocase ascii wide
        $vm8 = "qemu-ga" nocase ascii wide
        $vm9 = "vmsrvc" nocase ascii wide
        $vm10 = "prl_tools" nocase ascii wide
        $vm11 = "WDAGUtilityAccount" nocase ascii wide
        $vm12 = "cuckoomon" nocase ascii wide
        $an1 = "wireshark" nocase ascii wide
        $an2 = "procmon" nocase ascii wide
        $an3 = "x64dbg" nocase ascii wide
        $an4 = "ollydbg" nocase ascii wide
        $an5 = "processhacker" nocase ascii wide
        $an6 = "fiddler" nocase ascii wide
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
    condition:
        uint16(0) == 0x5A4D and (3 of ($vm*) or (2 of ($vm*) and 2 of ($an*)) or (1 of ($vm*) and 3 of ($an*) and 1 of ($dbg*)))
}

rule Stealer_Script_Browser_And_Apps : stealer
{
    meta:
        description = "Script that reads browser passwords and cookies together with crypto wallets or app sessions (Python, JavaScript, PowerShell and AutoIt info stealers)"
        severity = "high"
        advice = "Don't run it. If it already ran: disconnect from the internet, run a full check, then change passwords and sign out of all sessions from a clean device (Google, Microsoft, Discord, Steam, banking)."
        mitre = "T1555.003"
        target = "any"
    strings:
        $b1 = "Login Data" nocase ascii wide
        $b2 = "encrypted_key" ascii wide
        $b3 = "Local State" ascii wide
        $b4 = "CryptUnprotectData" nocase ascii wide
        $b5 = "logins.json" ascii wide
        $b6 = "key4.db" ascii wide
        $b7 = /[^_]os_crypt/ ascii wide
        $b8 = /Network.{1,3}Cookies/ nocase ascii wide
        $a1 = "wallet.dat" nocase ascii wide
        $a2 = "exodus.wallet" nocase ascii wide
        $a3 = /Electrum.{1,4}wallets/ nocase ascii wide
        $a4 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $a5 = /[\\\/'"]tdata[\\\/'"]/ ascii wide
        $a6 = "Telegram Desktop" nocase ascii wide
        $a7 = /ssfn[0-9]{5,}/ ascii wide
        $a8 = "loginusers.vdf" nocase ascii wide
        $a9 = /discord.{1,4}Local Storage/ nocase ascii wide
        $a10 = "recentservers.xml" nocase ascii wide
        $a11 = /atomic.{1,4}Local Storage/ nocase ascii wide
        $a12 = ".ROBLOSECURITY" ascii wide
        $x1 = "sqlite3" nocase ascii wide
        $x2 = "shutil.copy" ascii wide
        $x3 = "Copy-Item" nocase ascii wide
        $x4 = "readFileSync" ascii wide
        $x5 = "copyFileSync" ascii wide
        $x6 = "FileCopy" ascii wide
        $x7 = "requests.post" ascii wide
        $x8 = "Invoke-RestMethod" nocase ascii wide
    condition:
        not uint16(0) == 0x5A4D and 3 of ($b*) and 2 of ($a*) and 1 of ($x*)
}

rule Clipper_Script_Crypto_Address_Swap : stealer crypto
{
    meta:
        description = "Script that reads and rewrites the clipboard and contains crypto wallet address patterns (a clipper that swaps the address you copy for the thief's)"
        severity = "high"
        advice = "Don't run it. If it ran, check the last crypto addresses you pasted, run a full check and remove it. Always compare the first and last characters of a pasted wallet address."
        mitre = "T1115"
        target = "any"
    strings:
        $get1 = "GetClipboardData" ascii wide
        $get2 = "Get-Clipboard" nocase ascii wide
        $get3 = "pyperclip.paste" ascii wide
        $get4 = "Clipboard]::GetText" nocase ascii wide
        $get5 = "ClipGet" ascii wide
        $get6 = "clipboard.readText" ascii wide
        $get7 = "clipboardy" ascii wide
        $get8 = "win32clipboard.GetClipboardData" ascii wide
        $set1 = "SetClipboardData" ascii wide
        $set2 = "Set-Clipboard" nocase ascii wide
        $set3 = "pyperclip.copy" ascii wide
        $set4 = "Clipboard]::SetText" nocase ascii wide
        $set5 = "ClipPut" ascii wide
        $set6 = "clipboard.writeText" ascii wide
        $set7 = "Clipboard.SetText" ascii wide
        $r1 = "(bc1|[13])" ascii wide
        $r2 = "0x[a-fA-F0-9]{40}" ascii wide
        $r3 = "T[A-Za-z1-9]{33}" ascii wide
        $r4 = "[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}" ascii wide
        $r5 = "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" ascii wide
        $r6 = "[a-km-zA-HJ-NP-Z1-9]{25,34}" ascii wide
        $r7 = "[a-zA-HJ-NP-Z0-9]{25,39}" ascii wide
        $r8 = "ltc1" ascii wide
        $h1 = /bc1q[a-z0-9]{38,58}/ ascii wide
        $h2 = /0x[a-fA-F0-9]{40}[^a-fA-F0-9]/ ascii
    condition:
        not uint16(0) == 0x5A4D and 1 of ($get*) and 1 of ($set*) and (2 of ($r*) or (1 of ($r*) and 1 of ($h*)) or 2 of ($h*))
}

rule Stealer_Browser_Debugging_Cookie_Dump : stealer
{
    meta:
        description = "Starts a browser with remote debugging and pulls cookies out over the debugging port (the method stealers use to get around Chrome's app-bound encryption)"
        severity = "high"
        advice = "Don't run it. If it already ran, follow the sign-out steps from a clean device: your browser sessions were readable."
        mitre = "T1539"
        target = "any"
    strings:
        $f1 = "--remote-debugging-port" ascii wide
        $f2 = "--headless" ascii wide
        $f3 = "--user-data-dir" ascii wide
        $c1 = "Network.getAllCookies" ascii wide
        $c2 = "Storage.getCookies" ascii wide
        $c3 = "webSocketDebuggerUrl" ascii wide
        $c4 = "/json/version" ascii wide
        $c5 = "/json/list" ascii wide
    condition:
        $f1 and 1 of ($c1, $c2) and (1 of ($c3, $c4, $c5) or ($f2 and $f3))
}

rule Stealer_AppBound_Decryption : stealer
{
    meta:
        description = "Calls Chrome's elevation service or decrypts 'v20' app-bound cookies (used to steal sessions from current Chrome and Edge)"
        severity = "high"
        advice = "Don't run it. If it already ran, follow the sign-out steps from a clean device."
        mitre = "T1555.003"
        target = "any"
    strings:
        $e1 = "IElevator" ascii wide
        $e2 = "DecryptData" ascii wide
        $e3 = "app_bound_encrypted_key" ascii wide
        $e4 = "ElevationService" nocase ascii wide
        $v1 = "v20" ascii wide
        $k1 = "Local State" ascii wide
        $k2 = "Login Data" ascii wide
        $k3 = /Network.{1,3}Cookies/ ascii wide
    condition:
        ($e1 and $e2 and $e3) or ($e3 and $v1 and 1 of ($e1, $e2, $e4) and 1 of ($k*))
}

rule Stealer_Roblox_Cookie_Logger : stealer gaming
{
    meta:
        description = "Reads the Roblox login cookie and sends it somewhere (Roblox account theft)"
        severity = "high"
        advice = "Don't run it. If it ran: in Roblox, Settings > Security > 'Log out of all other sessions', then change your password."
        mitre = "T1539"
        target = "any"
    strings:
        $r = ".ROBLOSECURITY" ascii wide
        $s1 = "api/webhooks" ascii wide
        $s2 = "api.telegram.org/bot" ascii wide
        $s3 = "requests.post" ascii wide
        $s4 = "Invoke-RestMethod" nocase ascii wide
        $s5 = "fetch(" ascii wide
        $s6 = "XMLHttpRequest" ascii wide
        $s7 = "UploadString" ascii wide
    condition:
        $r and 1 of ($s*)
}
