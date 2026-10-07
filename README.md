# Elastic Lab 18 — Multi-Stage Endpoint Attack Investigation

## Overview

This lab investigates a simulated multi-stage endpoint attack using controlled activity on a Windows 11 endpoint and Elastic Security for investigation and correlation.

The exercise combines several behaviors commonly encountered during endpoint investigations, including PowerShell execution, system and process discovery, file creation, scheduled task creation, Windows service creation, Windows Security log clearing, and failed network authentication.

All activities were intentionally performed in a controlled lab environment using benign commands and test artifacts. No malware, destructive payload, or unauthorized system access was used.

The investigation follows an evidence-driven approach: an observed action is treated as evidence of that action, not automatically as proof of malicious activity.

---

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 11 Pro |
| Hostname | `DESKTOP-9MMM37V` |
| User | `desktop-9mmm37v\dell` |
| PowerShell | PowerShell 7.6.6 |
| SIEM | Elastic Security / Kibana |
| Endpoint | Physical Windows workstation |
| Investigation Date | 07 October 2026 |

---

## Investigation Objective

The objective was to determine whether multiple controlled endpoint activities could be correlated into a coherent multi-stage attack sequence using local Windows evidence and Elastic telemetry.

The investigation focused on:

- Initial PowerShell execution
- System and process discovery
- Controlled file creation
- Scheduled task creation
- Windows service creation
- Windows Security log manipulation
- Failed network authentication
- Elastic SIEM visibility
- Timeline reconstruction
- Identification of telemetry gaps
- Evidence-based classification of each stage

---

## Simulated Attack Chain

The investigation modeled the following sequence:

```text
PowerShell Execution
        ↓
System / Process Discovery
        ↓
File Creation
        ↓
Scheduled Task Creation
        ↓
Windows Service Creation
        ↓
Security Log Clearing
        ↓
Failed Network Authentication
        ↓
Elastic SIEM Investigation
        ↓
Cleanup
```

This sequence represents a controlled simulation rather than a confirmed real-world compromise.

---

## Key Findings

### PowerShell Execution

A controlled PowerShell command executed successfully:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Elastic Lab 18 Initial Execution'"
```

Local execution was confirmed by the returned output.

Elastic process telemetry did not provide sufficient evidence to independently correlate the execution.

### Discovery Activity

The endpoint was queried for:

- Current user
- Hostname
- IP configuration
- Windows operating system information
- Running processes
- Running services

These activities were confirmed locally.

### File Creation

A controlled artifact was created:

```text
C:\Users\Public\Lab18_Stage3.txt
```

The file contained benign test text and was successfully verified locally.

Elastic message searches for the filename and test text returned no matching results.

### Scheduled Task

A scheduled task named `ElasticLab18` was successfully created.

The task was configured as:

```text
Task: \ElasticLab18
Action: cmd.exe /c echo Elastic Lab 18 Scheduled Task
Schedule: One time
Run time: 07 October 2026 23:59
Status: Ready
```

The task had not executed during the investigation.

Elastic searches for `ElasticLab18` returned no matching telemetry.

### Windows Service

A controlled service named `ElasticLab18Svc` was successfully created:

```text
SERVICE_NAME: ElasticLab18Svc
TYPE: 10 WIN32_OWN_PROCESS
STATE: STOPPED
```

The service was not executed as part of the test and was subsequently deleted during cleanup.

### Security Log Clearing

The Windows Security log was intentionally cleared as part of the controlled defense-evasion simulation.

A local Event ID `1102` was subsequently observed:

```text
07-10-2026 05:42:36
Event ID: 1102
Provider: Microsoft-Windows-Eventlog
The audit log was cleared.
```

Elastic also successfully ingested and displayed this Event ID `1102`.

This was the strongest directly correlated stage between local Windows evidence and Elastic telemetry.

### Failed Authentication

The following controlled authentication attempt was performed:

```powershell
net use \\localhost\IPC$ /user:FakeLabUser WrongPassword
```

Windows returned:

```text
System error 1326 has occurred.
The user name or password is incorrect.
```

However, no local Event ID `4625` was subsequently returned, and Elastic did not return a matching Event ID `4625` / Logon Type `3`.

Therefore, the investigation does not claim that a 4625 event was generated or that lateral movement occurred.

---

## Elastic Visibility Findings

| Activity | Local Evidence | Elastic Evidence | Assessment |
|---|---|---|---|
| PowerShell execution | Confirmed | Not correlated | Local execution confirmed |
| Discovery | Confirmed | Not established | Local activity |
| File creation | Confirmed | No matching message telemetry | Visibility gap |
| Scheduled task | Confirmed | No matching telemetry | Visibility gap |
| Service creation | Confirmed | Not correlated | Local activity |
| Security log clearing | Event 1102 confirmed | Event 1102 observed | Correlated |
| Failed authentication | Error 1326 confirmed | No 4625 observed | Visibility gap |
| Lateral movement | Not established | Not observed | Insufficient evidence |

---

## Evidence Classification

### Confirmed

- Controlled PowerShell execution
- System and process discovery
- Controlled file creation
- Scheduled task creation
- Windows service creation
- Security log clearing
- Local failed authentication attempt
- Cleanup of created test artifacts

### Observed in Elastic

- Event ID `1102`
- Host `desktop-9mmm37v`
- User `Dell`
- Security audit log cleared event

### Not Observed in Elastic

- PowerShell process execution telemetry
- Scheduled task name
- File artifact name/content
- Event ID `4625`
- Event ID `4625` with Logon Type `3`

### Not Established

- Malware execution
- Successful lateral movement
- Credential compromise
- Persistence through the scheduled task
- Persistence through the Windows service
- Actual attacker activity

---

## MITRE ATT&CK Context

The simulated behaviors can be mapped to the following ATT&CK techniques for investigative learning:

| Technique | Context |
|---|---|
| T1059.001 | PowerShell |
| T1082 | System Information Discovery |
| T1057 | Process Discovery |
| T1053.005 | Scheduled Task/Job: Scheduled Task |
| T1543.003 | Windows Service |
| T1070.001 | Clear Windows Event Logs |
| T1021.002 | SMB/Windows Admin Shares — investigative context only |

The ATT&CK mappings describe the behavior simulated in the lab and do not indicate that an actual attack occurred.

---

## Investigation Principles

This lab follows several important SOC investigation principles:

- Do not treat a single artifact as proof of compromise.
- Do not classify legitimate PowerShell as malicious without supporting evidence.
- Do not classify scheduled task or service creation as malicious without context.
- Do not infer lateral movement from a failed authentication attempt alone.
- Distinguish local endpoint evidence from SIEM visibility.
- Treat missing telemetry as a visibility limitation rather than proof that activity did not occur.
- Document what was confirmed, what was observed, and what could not be established.

---

## Cleanup

All controlled artifacts were removed after the investigation.

```powershell
Remove-Item "C:\Users\Public\Lab18_Stage3.txt" -Force
schtasks.exe /Delete /TN "ElasticLab18" /F
sc.exe delete ElasticLab18Svc
```

Post-cleanup validation confirmed that the scheduled task and service no longer existed.

---

## Conclusion

This lab demonstrated how a SOC analyst can investigate a sequence of related endpoint behaviors while maintaining evidence discipline. Several stages were confirmed locally, but only Event ID 1102 was directly correlated in Elastic. The absence of Elastic telemetry for other stages was treated as a visibility limitation rather than evidence that the activity did not occur. The exercise therefore demonstrates both multi-stage investigation methodology and the importance of understanding endpoint telemetry coverage before making incident conclusions.
