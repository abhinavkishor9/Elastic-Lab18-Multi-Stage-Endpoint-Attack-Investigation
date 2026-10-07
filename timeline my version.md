# Lab 18 Investigation Timeline

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


The investigation therefore distinguishes between **activity that occurred locally**, **activity visible in Elastic**, and **activity that could not be established from available telemetry**. This prevents the simulated sequence from being incorrectly presented as a confirmed compromise.
