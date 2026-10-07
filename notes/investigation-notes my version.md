# Investigation Notes 

## Host and User Context

```text
User:
desktop-9mmm37v\dell

Hostname:
DESKTOP-9MMM37V

Operating System:
Microsoft Windows 11 Pro

Version:
10.0.26200

Initial Investigation Time:
07 October 2026 05:30:04
```

Network information showed VMware virtual adapters including:

```text
192.168.174.1
```

The environment consisted of a single physical Windows endpoint.

---

# Stage 1 — Initial PowerShell Execution

## Action

A controlled PowerShell command was executed:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Elastic Lab 18 Initial Execution'"
```

## Result

The command returned:

```text
Elastic Lab 18 Initial Execution
```

## Assessment

PowerShell execution is confirmed locally.

The command itself was benign and did not establish malicious execution.

Elastic process telemetry did not provide sufficient evidence to independently correlate this specific execution.

### Classification

**Confirmed locally / not independently correlated in Elastic**

---

# Stage 2 — Discovery

The following discovery actions were performed:

```powershell
whoami
hostname
Get-CimInstance Win32_OperatingSystem |
Select-Object Caption, Version, LastBootUpTime

Get-Process |
Select-Object -First 10 Name, Id
```

Additional baseline commands included:

```powershell
Get-Date
Get-Location
Get-Process | Select-Object -First 5
Get-Service | Select-Object -First 5
```

## Observed Information

The endpoint returned:

```text
User:
desktop-9mmm37v\dell

Hostname:
DESKTOP-9MMM37V

Operating System:
Microsoft Windows 11 Pro

Version:
10.0.26200
```

The process enumeration returned normal processes including:

```text
adb
Adobe Crash Processor
AdobeCollabSync
AggregatorHost
AppActions
ApplicationFrameHost
armsvc
audiodg
bcmHostControlService
```

## Assessment

System and process discovery were confirmed locally.

No evidence from these commands alone establishes malicious intent.

### Classification

**Confirmed locally**

---

# Stage 3 — Controlled File Creation

A benign test artifact was created:

```powershell
$LabPath = "C:\Users\Public\Lab18_Stage3.txt"

"Elastic Lab 18 controlled test artifact" |
Set-Content -Path $LabPath
```

The file was then verified:

```powershell
Get-Item "C:\Users\Public\Lab18_Stage3.txt"
```

## Result

```text
Directory: C:\Users\Public

Name:
Lab18_Stage3.txt

Length:
41 bytes
```

The file was successfully created at approximately:

```text
07 October 2026 05:33
```

## Elastic Investigation

The following searches were performed:

```esql
FROM logs-*
| WHERE TO_STRING(message) LIKE "*Lab18_Stage3*"
   OR TO_STRING(message) LIKE "*Elastic Lab 18*"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code
| SORT @timestamp DESC
```

No matching results were returned.

## Assessment

The file creation is confirmed locally.

Elastic did not expose a matching message containing the test artifact name or text.

### Classification

**Confirmed locally / Elastic telemetry not observed**

---

# Stage 4 — Scheduled Task Creation

A controlled scheduled task was created:

```powershell
schtasks.exe /Create /TN "ElasticLab18" /TR "cmd.exe /c echo Elastic Lab 18 Scheduled Task" /SC ONCE /ST 23:59 /F
```

## Result

```text
SUCCESS: The scheduled task "ElasticLab18" has successfully been created.
```

The task was then queried:

```powershell
schtasks.exe /Query /TN "ElasticLab18" /FO LIST /V
```

The task was confirmed with:

```text
TaskName:
\ElasticLab18

Status:
Ready

Scheduled Task State:
Enabled

Schedule Type:
One Time Only

Start Time:
23:59:00

Task To Run:
cmd.exe /c echo Elastic Lab 18 Scheduled Task

Run As User:
Dell
```

The task had not executed during the investigation.

## Task Scheduler Operational Log

The following command was executed:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

Result:

```text
No events were found that match the specified selection criteria.
```

## Elastic Investigation

The following search was performed:

```esql
FROM logs-*
| WHERE TO_STRING(message) LIKE "*ElasticLab18*"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       message
| SORT @timestamp DESC
```

No results were returned.

## Assessment

The scheduled task creation was confirmed directly on the endpoint.

No task execution occurred during the investigation.

No Task Scheduler Operational events were returned, and the task name was not observed in Elastic message telemetry.

### Classification

**Confirmed locally / execution not observed / Elastic telemetry not observed**

---

# Stage 5 — Windows Service Creation

The expected System32 executable was first checked:

```powershell
$System32 = "$env:WINDIR\System32\cmd.exe"
Test-Path $System32
```

Result:

```text
True
```

A controlled service was then created:

```powershell
sc.exe create ElasticLab18Svc binPath= "cmd.exe /c exit 0" start= demand
```

## Result

```text
[SC] CreateService SUCCESS
```

The service was queried:

```powershell
sc.exe query ElasticLab18Svc
```

Result:

```text
SERVICE_NAME: ElasticLab18Svc
TYPE: 10 WIN32_OWN_PROCESS
STATE: 1 STOPPED
WIN32_EXIT_CODE: 1077
SERVICE_EXIT_CODE: 0
```

## Assessment

The service installation was confirmed locally.

The service remained stopped and was not used to execute a payload.

### Classification

**Confirmed locally / service execution not demonstrated**

---

# Stage 6 — Windows Security Log Clearing

Before clearing the Security log, its state was checked:

```powershell
Get-WinEvent -ListLog Security |
Select-Object LogName, RecordCount, IsEnabled
```

Result:

```text
LogName  RecordCount  IsEnabled
Security 34           True
```

The controlled log-clearing action was then performed:

```powershell
wevtutil cl Security
```

A subsequent query checked for Event ID 1102:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=1102
} -MaxEvents 1 |
Select-Object TimeCreated, Id, ProviderName, Message
```

## Local Result

```text
TimeCreated:
07-10-2026 05:42:36

Id:
1102

ProviderName:
Microsoft-Windows-Eventlog

Message:
The audit log was cleared....
```

## Elastic Result

The following ES|QL query was executed:

```esql
FROM logs-*
| WHERE event.code == "1102"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       message
| SORT @timestamp DESC
```

Elastic returned one matching document:

```text
@timestamp:
Oct 7, 2026 @ 05:42:36.610

host.name:
desktop-9mmm37v

user.name:
Dell

event.code:
1102

message:
The audit log was cleared.
```

## Assessment

This was the strongest correlated stage in the investigation.

The Security log clearing was confirmed locally and the resulting Event ID 1102 was also observed in Elastic.

### Classification

**Confirmed locally / confirmed in Elastic**

---

# Stage 7 — Failed Network Authentication

A controlled authentication attempt was performed against the local IPC$ endpoint:

```powershell
net use \\localhost\IPC$ /user:FakeLabUser WrongPassword
```

The command returned:

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

A local Event ID 4625 search was then performed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
} -MaxEvents 1 |
Select-Object TimeCreated, Id, ProviderName, Message
```

Result:

```text
Get-WinEvent:
No events were found that match the specified selection criteria.
```

Elastic was also queried for Event ID 4625 with Logon Type 3:

```esql
FROM logs-*
| WHERE event.code == "4625"
  AND winlog.event_data.LogonType == "3"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       winlog.event_data.LogonType
| SORT @timestamp DESC
```

Result:

```text
0 documents processed

No results match your search criteria
```

## Assessment

The failed authentication attempt itself is confirmed by the Windows command result.

However, no local Event ID 4625 was observed and no corresponding Elastic event was returned.

Therefore, this investigation does not claim:

- A confirmed Event ID 4625
- A confirmed Logon Type 3 event
- Successful authentication
- Lateral movement

### Classification

**Controlled authentication failure confirmed / security event not observed / lateral movement not established**

---

# Stage 8 — Cleanup

The controlled file was removed:

```powershell
Remove-Item "C:\Users\Public\Lab18_Stage3.txt" -Force
```

The scheduled task was deleted:

```powershell
schtasks.exe /Delete /TN "ElasticLab18" /F
```

Validation confirmed:

```text
ERROR: The system cannot find the file specified.
```

The service was deleted:

```powershell
sc.exe delete ElasticLab18Svc
```

Validation confirmed:

```text
[SC] EnumQueryServicesStatus:OpenService FAILED 1060

The specified service does not exist as an installed service.
```

