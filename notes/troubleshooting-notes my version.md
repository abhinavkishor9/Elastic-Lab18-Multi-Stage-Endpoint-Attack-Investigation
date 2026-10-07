# Troubleshooting Notes 

## 1. Scheduled Task Name Not Visible in Elastic

### Query

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

### Result

```text
No results match your search criteria
```

### Local Validation

The task was queried directly:

```powershell
schtasks.exe /Query /TN "ElasticLab18" /FO LIST /V
```

The task was confirmed as:

```text
TaskName:
\ElasticLab18

Status:
Ready

Scheduled Task State:
Enabled

Task To Run:
cmd.exe /c echo Elastic Lab 18 Scheduled Task
```

### Interpretation

The scheduled task definitely existed locally, but its name was not present in the Elastic message telemetry searched.

This was treated as a telemetry visibility limitation.

The absence of an Elastic result was not interpreted as evidence that the task was never created.

---

## 2. Task Scheduler Operational Log Returned No Events

### Command

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Result

```text
Get-WinEvent:
No events were found that match the specified selection criteria.
```

### Interpretation

No Task Scheduler Operational events were available through this query.

The investigation therefore relied on direct task enumeration rather than claiming Task Scheduler event visibility.

---

## 3. File Artifact Not Visible in Elastic

### Query

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

### Result

```text
No results match your search criteria
```

### Local Validation

The artifact was confirmed locally:

```text
C:\Users\Public\Lab18_Stage3.txt
```

The file contained:

```text
Elastic Lab 18 controlled test artifact
```

### Interpretation

The file was successfully created locally, but the available Elastic message telemetry did not expose the artifact name or test text.

This was classified as a visibility gap.

---

## 4. Event ID 4625 Not Available Locally

### Controlled Test

```powershell
net use \\localhost\IPC$ /user:FakeLabUser WrongPassword
```

### Result

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

### Local Event Search

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
} -MaxEvents 1 |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Result

```text
Get-WinEvent:
No events were found that match the specified selection criteria.
```

### Interpretation

The command confirmed that the authentication attempt was rejected, but an Event ID 4625 was not available through the local query.

The investigation therefore did not claim that Event ID 4625 was generated.

---

## 5. Elastic Event ID 4625 Search Returned Nothing

### Query

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

### Result

```text
0 documents processed

No results match your search criteria
```

### Interpretation

Because the local Windows query also returned no 4625 event, the investigation did not attempt to force an Elastic interpretation.

The final assessment was:

```text
Controlled authentication failure: Confirmed
Event ID 4625: Not observed
Elastic 4625 telemetry: Not observed
Lateral movement: Not established
```

---

## 6. Security Log Clearing Produced Elastic Telemetry

Unlike several other stages, Event ID 1102 was visible in both Windows and Elastic.

### Local Command

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=1102
} -MaxEvents 1 |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Local Result

```text
07-10-2026 05:42:36
1102
Microsoft-Windows-Eventlog
The audit log was cleared....
```

### Elastic Query

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

### Elastic Result

```text
Oct 7, 2026 @ 05:42:36.610
desktop-9mmm37v
Dell
1102
The audit log was cleared.
```

### Interpretation

This demonstrates that Elastic was capable of ingesting and exposing at least this Windows Security event.

Therefore, the absence of other events should be documented individually rather than assuming that all endpoint telemetry was unavailable.

---

## 7. Security Log Clearing Removed Earlier Security Evidence

Before the controlled log clearing, the Security log contained:

```text
RecordCount: 34
IsEnabled: True
```

The following command was then executed:

```powershell
wevtutil cl Security
```

After clearing, Event ID 1102 was available.

### Investigation Impact

Clearing the Security log is destructive to previously stored Security events on the endpoint.

Therefore, the investigation does not attempt to use the post-clear state to conclude that earlier authentication or privilege events never occurred.

This is an important forensic limitation.

---

## 8. Service Creation Was Confirmed Locally

### Creation

```powershell
sc.exe create ElasticLab18Svc binPath= "cmd.exe /c exit 0" start= demand
```

### Result

```text
[SC] CreateService SUCCESS
```

### Validation

```powershell
sc.exe query ElasticLab18Svc
```

Returned:

```text
SERVICE_NAME: ElasticLab18Svc
STATE: 1 STOPPED
```

### Interpretation

The service was successfully installed but remained stopped.

No claim was made that the service executed a payload.

---

## 9. Cleanup Validation

### Scheduled Task

```powershell
schtasks.exe /Delete /TN "ElasticLab18" /F
```

Result:

```text
SUCCESS: The scheduled task "ElasticLab18" was successfully deleted.
```

Validation:

```powershell
schtasks.exe /Query /TN "ElasticLab18"
```

Result:

```text
ERROR: The system cannot find the file specified.
```

### Windows Service

```powershell
sc.exe delete ElasticLab18Svc
```

Result:

```text
[SC] DeleteService SUCCESS
```

Validation:

```powershell
sc.exe query ElasticLab18Svc
```

Result:

```text
FAILED 1060

The specified service does not exist as an installed service.
```

### File

```powershell
Remove-Item "C:\Users\Public\Lab18_Stage3.txt" -Force
```

The controlled test artifact was removed.

---

