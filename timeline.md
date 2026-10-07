# Lab 18 Investigation Timeline

## Investigation Timeline

The timeline below reconstructs the controlled multi-stage endpoint activity using the timestamps available from the Windows PowerShell evidence and Elastic telemetry.

> **Important:** The timeline represents a controlled lab simulation. It does not represent a confirmed real-world attack.

---

| Time | Stage | Activity | Evidence Source | Assessment |
|---|---|---|---|---|
| 05:30:04 | Baseline | `whoami`, `hostname`, `Get-Date`, `ipconfig` | Windows PowerShell | Confirmed |
| 05:30:50 | Baseline | Location, process and service enumeration | Windows PowerShell | Confirmed |
| ~05:31 | Discovery | Windows OS information queried | Windows PowerShell | Confirmed |
| ~05:31 | Discovery | Process enumeration performed | Windows PowerShell | Confirmed |
| ~05:32 | Execution | Controlled PowerShell command executed | Windows PowerShell | Confirmed |
| 05:33 | File Creation | `Lab18_Stage3.txt` created | Windows PowerShell | Confirmed |
| ~05:33 | File Validation | Test file verified under `C:\Users\Public` | Windows PowerShell | Confirmed |
| ~05:34+ | Authentication | Invalid SMB/IPC$ authentication attempted | Windows command output | Failed authentication confirmed |
| ~05:34+ | Authentication | Local Event ID 4625 queried | Windows Security log | Not observed |
| ~05:35+ | Persistence | `ElasticLab18` scheduled task created | Windows Task Scheduler | Confirmed |
| ~05:35+ | Persistence | Scheduled task queried and shown as `Ready` | Windows Task Scheduler | Confirmed |
| ~05:35+ | Task Telemetry | TaskScheduler Operational log queried | Windows Event Log | No events returned |
| ~05:36+ | Persistence | `ElasticLab18Svc` service created | Service Control Manager | Confirmed |
| ~05:36+ | Service Validation | Service queried and shown as `STOPPED` | Service Control Manager | Confirmed |
| 05:42:36 | Defense Evasion | Windows Security log cleared | Windows Event Log | Confirmed |
| 05:42:36 | Detection | Event ID 1102 generated | Windows Event Log | Confirmed |
| 05:42:36 | Detection | Event ID 1102 ingested by Elastic | Elastic Security | Confirmed in Elastic |
| After investigation | Cleanup | Test file removed | Windows PowerShell | Confirmed |
| After investigation | Cleanup | Scheduled task deleted | Windows Task Scheduler | Confirmed |
| After investigation | Cleanup | Windows service deleted | Service Control Manager | Confirmed |

---

# Detailed Timeline

## 05:30:04 — Endpoint Baseline

```text
User:
desktop-9mmm37v\dell

Hostname:
DESKTOP-9MMM37V
```

Network configuration was collected using `ipconfig`.

The endpoint contained VMware virtual network adapters including:

```text
192.168.174.1
```

### Assessment

Baseline endpoint information successfully collected.

---

## 05:30:50 — Normal Activity Baseline

The following commands were executed:

```powershell
Get-Date
Get-Location
Get-Process | Select-Object -First 5
Get-Service | Select-Object -First 5
```

This established normal local process and service visibility before the simulated attack stages.

---

## ~05:31 — System and Process Discovery

The following discovery commands were executed:

```powershell
whoami
hostname

Get-CimInstance Win32_OperatingSystem |
Select-Object Caption, Version, LastBootUpTime

Get-Process |
Select-Object -First 10 Name, Id
```

The operating system was identified as:

```text
Microsoft Windows 11 Pro
10.0.26200
```

### Assessment

Discovery activity confirmed locally.

---

## ~05:32 — Initial PowerShell Execution

The controlled execution command was:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Elastic Lab 18 Initial Execution'"
```

Output:

```text
Elastic Lab 18 Initial Execution
```

### Assessment

PowerShell execution confirmed locally.

No malicious payload was executed.

---

## 05:33 — Controlled File Creation

The test artifact was created:

```text
C:\Users\Public\Lab18_Stage3.txt
```

Content:

```text
Elastic Lab 18 controlled test artifact
```

The file was verified locally and had a size of 41 bytes.

### Elastic Assessment

The artifact name and test text were searched in Elastic, but no matching results were returned.

---

## Authentication Test — Time Not Captured

The following controlled authentication attempt was performed:

```powershell
net use \\localhost\IPC$ /user:FakeLabUser WrongPassword
```

Windows returned:

```text
System error 1326 has occurred.
The user name or password is incorrect.
```

A local 4625 search returned no event.

Elastic also returned no 4625 Logon Type 3 event.

### Assessment

The authentication failure was confirmed by the command result.

A Windows 4625 event was not observed.

Lateral movement was not established.

---

## Scheduled Task Creation — Time Not Captured

The following task was created:

```powershell
schtasks.exe /Create /TN "ElasticLab18" /TR "cmd.exe /c echo Elastic Lab 18 Scheduled Task" /SC ONCE /ST 23:59 /F
```

The task was confirmed as:

```text
TaskName:
\ElasticLab18

Status:
Ready

Schedule:
One Time Only

Start Time:
23:59

Action:
cmd.exe /c echo Elastic Lab 18 Scheduled Task
```

The task had not executed.

### Elastic Assessment

No matching `ElasticLab18` telemetry was returned.

---

## Windows Service Creation — Time Not Captured

The service was created with:

```powershell
sc.exe create ElasticLab18Svc binPath= "cmd.exe /c exit 0" start= demand
```

The Service Control Manager returned:

```text
[SC] CreateService SUCCESS
```

The service state was:

```text
STOPPED
```

### Assessment

Service creation confirmed.

Service execution not demonstrated.

---

## 05:42:36 — Security Log Clearing

The Security log was intentionally cleared:

```powershell
wevtutil cl Security
```

A subsequent local query returned:

```text
TimeCreated:
07-10-2026 05:42:36

Event ID:
1102

Provider:
Microsoft-Windows-Eventlog
```

### Elastic Correlation

Elastic returned:

```text
@timestamp:
Oct 7, 2026 @ 05:42:36.610

host.name:
desktop-9mmm37v

user.name:
Dell

event.code:
1102
```

Message:

```text
The audit log was cleared.
```

### Assessment

This is the primary directly correlated event in the investigation.

---

# Cleanup Timeline

## Test Artifact Removal

```powershell
Remove-Item "C:\Users\Public\Lab18_Stage3.txt" -Force
```

### Result

Controlled file removed.

---

## Scheduled Task Removal

```powershell
schtasks.exe /Delete /TN "ElasticLab18" /F
```

### Result

```text
SUCCESS: The scheduled task "ElasticLab18" was successfully deleted.
```

Post-cleanup query confirmed the task no longer existed.

---

## Service Removal

```powershell
sc.exe delete ElasticLab18Svc
```

### Result

```text
[SC] DeleteService SUCCESS
```

Post-cleanup query returned error `1060`, confirming the service was no longer installed.

---

# Attack-Chain Assessment

```text
Execution
   ↓
Discovery
   ↓
File Creation
   ↓
Scheduled Task Creation
   ↓
Windows Service Creation
   ↓
Security Log Clearing
   ↓
Failed Authentication Attempt
   ↓
Cleanup
```

### Evidence Status

```text
PowerShell Execution       → Confirmed locally
Discovery                  → Confirmed locally
File Creation              → Confirmed locally
Scheduled Task Creation    → Confirmed locally
Scheduled Task Execution   → Not observed
Service Creation           → Confirmed locally
Service Execution          → Not demonstrated
Event Log Clearing         → Confirmed locally + Elastic
4625 Authentication Event  → Not observed
Lateral Movement           → Not established
```

---

# Final Timeline Assessment

The timeline demonstrates a sequence of controlled endpoint behaviors that can resemble multiple stages of an attack. Several activities were confirmed directly on the endpoint, while Elastic provided reliable visibility for Event ID 1102 but not for several other stages.

The investigation therefore distinguishes between **activity that occurred locally**, **activity visible in Elastic**, and **activity that could not be established from available telemetry**. This prevents the simulated sequence from being incorrectly presented as a confirmed compromise.
