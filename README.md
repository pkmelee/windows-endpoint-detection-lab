# Windows Endpoint Detection Lab

Detection engineering lab demonstrating Sysmon-based behavioral detection of two MITRE ATT&CK techniques on Windows 11. Built with the SwiftOnSecurity Sysmon configuration to capture process-level telemetry and identify suspicious activity patterns that signature-based AV would miss.

## MITRE ATT&CK Mapping

| Technique | Name | Sub-technique |
|-----------|------|---------------|
| T1059.001 | Command and Scripting Interpreter | PowerShell |
| T1055 | Process Injection (Abnormal Parent-Child) | — |

## Lab Environment

| Component | Details |
|-----------|---------|
| Hypervisor | VirtualBox |
| Target OS | Windows 11 (10.0.26100) |
| Endpoint Telemetry | Sysmon v15.20 |
| Sysmon Config | [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (schema 4.50) |
| Log Source | `Microsoft-Windows-Sysmon/Operational` |

## Why SwiftOnSecurity Config?

The default Sysmon configuration captures almost nothing actionable. The SwiftOnSecurity community config is a curated ruleset built around the MITRE ATT&CK framework — it filters out routine OS noise while logging the process creation, network, and registry behaviors attackers actually use. Loading it transforms Sysmon from a generic process logger into a detection-grade telemetry source.

```powershell
# Install custom config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig-export.xml"
sysmon -c sysmonconfig-export.xml
```

Verification: `sysmon -c` returned schema version 4.50 with full ProcessCreate, NetworkConnect, FileCreate, and RegistryEvent rule groups loaded.

---

## Detection 1: T1059.001 — Encoded PowerShell Execution

### Attack Technique
Adversaries use PowerShell's `-EncodedCommand` flag to execute base64-encoded commands. This obfuscates the payload from casual inspection and bypasses signature detection that scans for known-bad command strings. Used heavily by Cobalt Strike, ransomware loaders, and post-exploitation frameworks.

### Simulation
```powershell
$cmd = "Write-Host 'T1059-FINAL-CAPTURE'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

The payload itself is benign (`Write-Host`), but the technique — encoded command execution — is what triggers detection. Detection engineering catches behavior, not specific strings.

### Sysmon Detection (Event ID 1 — Process Create)

```
UtcTime: 2026-04-30 16:58:18.766
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand
             VwByAGkAdABlAC0ASABvAHMAdAAgACcAVAAxADAANQA5AC0ARgBJAE4AQQBMAC0AQwBBAFAAVABVAFIARQAnAA==
User: labuser\labfriend
IntegrityLevel: High
Hashes: MD5=A97E6573B97B44C96122BFA543A82EA1
        SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Detection Logic
Sysmon Event ID 1 logs the full command line including the base64-encoded payload. A SOC analyst can:
1. Filter for `CommandLine` containing `-EncodedCommand` or `-enc` (case-insensitive — attackers use abbreviations)
2. Decode the base64 string post-incident to reconstruct the attacker's actual payload
3. Pivot on `ParentImage` to identify how the encoded shell was spawned

### KQL/SPL Equivalent (for future Splunk integration)
```
EventCode=1 (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *")
```

---

## Detection 2: T1055 — Abnormal Parent-Child Process Chain

### Attack Technique
Adversaries spawn shell interpreters from unusual parent processes to evade detection. A common pattern is `cmd.exe` spawning `powershell.exe`, which indicates either: (1) a script-based payload kicking off PowerShell from a command shell, (2) living-off-the-land tooling chaining built-in binaries, or (3) malicious document macros executing post-exploitation commands.

While this lab uses a benign chain to demonstrate the technique, the same parent-child relationship appears in real intrusions — Cobalt Strike beacons, Emotet droppers, and ransomware affiliates routinely exhibit this pattern.

### Simulation
```powershell
cmd.exe /c "powershell.exe -Command Write-Host 'T1055-PARENT-CHILD-MARKER'; whoami"
```

This creates the chain: `cmd.exe → powershell.exe → whoami.exe` — a 3-deep process tree showing recon behavior from a non-standard origin.

### Sysmon Detection (Event ID 1 — Process Create)

```
UtcTime: 2026-04-30 16:50:35.258
Image: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -Command Write-Host 'T1055-PARENT-CHILD-MARKER'; whoami
User: labuser\labfriend
IntegrityLevel: High
Hashes: MD5=0CB6529404FAEF431547CFF590744553
        SHA256=3BFEDAAA40D9E19E45A3EE10C0F14B1750B01619EBB9F39BE3865BCFDACDD2E5
ParentImage: C:\Windows\SysWOW64\cmd.exe
ParentCommandLine: "C:\WINDOWS\system32\cmd.exe" /c "powershell.exe -Command Write-Host
                   'T1055-PARENT-CHILD-MARKER'; whoami"
```

### Detection Logic
The smoking gun is the `ParentImage` field — `cmd.exe` spawning `powershell.exe` is anomalous in a normal user workflow. Combined with the recon command (`whoami`) running as a descendant, this chain matches the early-stage behavior of multiple known intrusion sets.

Detection rule outline:
1. `EventID = 1` (Process Create)
2. `Image` ends in `powershell.exe`
3. `ParentImage` ends in `cmd.exe`
4. Optional: correlate with subsequent `whoami.exe` / `net.exe` / `systeminfo.exe` child events within a short time window

### KQL/SPL Equivalent
```
EventCode=1 Image="*\\powershell.exe" ParentImage="*\\cmd.exe"
```

---

## Defensive Takeaways

- **Default Sysmon is insufficient.** The default config logs almost nothing useful — SwiftOnSecurity (or a similar curated ruleset) is the minimum viable baseline for detection engineering on Windows endpoints.
- **Process telemetry beats signature AV for behavioral techniques.** Encoded PowerShell and abnormal parent-child chains have no static signature, but the technique itself is observable in process metadata.
- **Parent-child relationships are high-signal indicators.** Most attacker techniques produce unusual process trees. Monitoring `ParentImage` is consistently more valuable than scanning `CommandLine` alone.
- **Hashes enable IOC pivoting.** Sysmon's MD5/SHA256/IMPHASH fields let analysts hunt for the same binary across a fleet once one detection fires.

## Next Steps

- Forward Sysmon logs to Splunk via Universal Forwarder for centralized analysis (Lab #2)
- Build SPL detection rules for both techniques and tune for false positives
- Correlate Sysmon Event ID 1 with Event ID 3 (network connections) and Event ID 11 (file creation) for richer attack reconstruction
- Extend coverage to T1086 (PowerShell), T1003 (credential dumping), T1071 (C2 channels)

## Skills Demonstrated
Sysmon configuration & deployment · MITRE ATT&CK framework · PowerShell-based attack simulation · Windows event log analysis · Process tree analysis · Detection logic design · Endpoint telemetry engineering
