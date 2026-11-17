Optional third-party tools
==========================
TriageKit works without anything in this folder. If these tools are present they are used automatically.
They are not bundled because their licence does not allow redistribution.

Sysinternals Autoruns (Microsoft, free)
   Download: https://learn.microsoft.com/sysinternals/downloads/autoruns
   Put autorunsc64.exe in:   tools\Sysinternals\
   TriageKit only runs it if it carries a valid Microsoft signature.

Turn it off in config.json ("RunAutoruns": false) for faster scans.
