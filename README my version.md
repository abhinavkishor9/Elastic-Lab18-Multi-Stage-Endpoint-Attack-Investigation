# Elastic-Lab18-Multi-Stage-Endpoint-Attack-Investigation
## Overview
A multi-stage endpoint attack is an intrusion where an attacker performs multiple actions after gaining execution on a system. Instead of looking at each event independently, a SOC analyst correlates the activities by time, host, user, process, artifact, and technique.

A simplified attack chain can look like:

Execution → Discovery → File Creation → Persistence → Defense Evasion → Authentication Activity → Investigation

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

## Lab Objectives

- Establish a controlled Windows endpoint baseline including hostname, user context, operating system, network configuration, processes, and services.
- Simulate an initial PowerShell execution using a benign command and validate the activity directly on the endpoint.
- Perform controlled system and process discovery to understand the type of information an attacker could obtain after gaining endpoint access.
- Create and validate a benign file artifact in a commonly accessible Windows directory.
- Investigate whether file creation activity can be identified or correlated through available Elastic telemetry.
- Create a controlled Windows Scheduled Task and examine its configuration, execution state, and available Task Scheduler telemetry.
- Create a controlled Windows service to simulate a potential persistence mechanism and validate its installation and state.
- Simulate Windows Security Event Log manipulation using `wevtutil` and investigate the resulting Event ID `1102`.
- Correlate locally generated Event ID `1102` with Elastic SIEM telemetry and validate whether the event is successfully ingested.
- Perform a controlled failed SMB/IPC$ authentication attempt using invalid credentials and investigate whether Event ID `4625` is generated locally or observed in Elastic.
- Evaluate the difference between an authentication failure, a Windows security event, and confirmed lateral movement.
- Build a chronological investigation timeline by correlating endpoint actions, timestamps, users, hosts, and available SIEM evidence.
- Separate confirmed endpoint activity from activity that was not observed through Elastic telemetry.
- Identify endpoint and SIEM telemetry gaps without treating missing data as proof that an activity did not occur.
- Apply evidence-based investigation principles by distinguishing confirmed, observed, not observed, and not established findings.
- Map the simulated behaviors to relevant MITRE ATT&CK techniques for investigation and detection-engineering context.
- Perform complete cleanup of the controlled file, scheduled task, and Windows service after the investigation.
- Document the investigation methodology, findings, limitations, and evidence gaps in a format suitable for SOC/DFIR portfolio review.
---

## Lab Scenario

A SOC analyst is investigating a suspected multi-stage endpoint attack on a Windows 11 workstation. The objective is to reconstruct a sequence of related endpoint activities and determine whether the available Windows and Elastic telemetry can support the suspected attack chain.

The investigation is performed in a controlled lab environment using the physical Windows endpoint `DESKTOP-9MMM37V`. No malware or destructive payload is used. Instead, benign commands and controlled administrative actions are used to simulate behaviors commonly associated with different stages of an endpoint compromise.

The simulated activity follows a progression:

- Initial PowerShell execution to represent command execution after an initial foothold.
- System and process discovery to simulate attacker reconnaissance.
- Creation of a benign file artifact to represent payload or staging activity.
- Scheduled Task creation to simulate a potential persistence mechanism.
- Windows service creation to simulate another persistence or execution mechanism.
- Windows Security log clearing to simulate defense-evasion behavior.
- Failed SMB/IPC$ authentication using invalid credentials to investigate network authentication telemetry.

The investigation compares **local Windows evidence** with **Elastic SIEM visibility**. Each activity is validated locally where possible, followed by targeted Elastic searches using available event fields and message data.

A key part of the scenario is determining what can actually be proven. PowerShell execution, task creation, service creation, or log clearing are not automatically treated as malicious simply because they can be associated with attacker techniques. Similarly, a failed authentication attempt is not considered proof of lateral movement.

The analyst must therefore classify findings as:

- **Confirmed** — directly supported by endpoint evidence.
- **Observed in Elastic** — successfully correlated through SIEM telemetry.
- **Not observed** — expected telemetry was not available in the searched data.
- **Not established** — insufficient evidence to support a stronger conclusion.

The investigation also evaluates telemetry limitations. For example, Event ID `1102` generated by the controlled Security log clearing was successfully visible in Elastic, while several other simulated activities were not exposed through the available telemetry. These gaps are documented as visibility limitations rather than interpreted as proof that the corresponding activities did not occur.

The final objective is to reconstruct the simulated activity timeline, correlate the available evidence, identify relevant MITRE ATT&CK techniques, document telemetry gaps, and determine whether the evidence supports a confirmed compromise or only a sequence of controlled endpoint actions.

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

## Cleanup

All controlled artifacts were removed after the investigation.

```powershell
Remove-Item "C:\Users\Public\Lab18_Stage3.txt" -Force
schtasks.exe /Delete /TN "ElasticLab18" /F
sc.exe delete ElasticLab18Svc
```

Post-cleanup validation confirmed that the scheduled task and service no longer existed.

---

