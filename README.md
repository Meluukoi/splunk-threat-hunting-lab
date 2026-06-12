# splunk-threat-hunting-lab
Threat hunting exercises using Splunk, Sysmon, and Windows telemetry to identify suspicious activity and reconstruct attacker behavior.
The objective is to develop hypothesis-driven hunts, identify suspicious activity, and correlate endpoint telemetry to reconstruct attacker behavior.

---

## Lab Environment

### Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Viewer
- PowerShell
- Command Prompt

### Data Sources

- Microsoft-Windows-Sysmon/Operational
- Windows Security Logs
- Windows System Logs

---



# Threat Hunt 1: PowerShell Reconnaissance Activity

## Hunting Hypothesis

An attacker may use PowerShell to execute reconnaissance commands in order to gather information about the current user and system.

## Hunt Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
"WindowsPowerShell" "whoami"
```

## Investigation

PowerShell reconnaissance activity was successfully identified and investigated using Sysmon Process Creation events.

The investigation identified:

- PowerShell process execution
- Parent-child process relationships
- Command-line activity
- User context associated with execution
- Reconnaissance behavior through `whoami.exe`

Analysis of Sysmon Event ID 1 telemetry revealed PowerShell spawning `whoami.exe`, providing visibility into user enumeration activity and process execution behavior.

This visibility can assist analysts in identifying reconnaissance activity commonly performed during the early stages of an attack.

## Findings

The investigation confirmed that PowerShell launched `whoami.exe` under the user context `MELUU\milad`.

Process telemetry showed:

- Parent Process: `powershell.exe`
- Child Process: `whoami.exe`
- Activity Type: User Enumeration
- Data Source: Sysmon Event ID 1

The observed behavior aligns with reconnaissance techniques used to identify the currently logged-on user and gather system information.

## MITRE ATT&CK Mapping

| Technique | ID |
|------------|------------|
| System Owner/User Discovery | T1033 |
| PowerShell | T1059.001 |

## Screenshots

### PowerShell Reconnaissance Investigation

PowerShell execution spawning `whoami.exe`, demonstrating user discovery activity and parent-child process visibility through Sysmon Event ID 1.

![PowerShell Reconnaissance Investigation](screenshots/powershell-whoami-hunt.png)
