# Threat Hunt Report: Zero-Day Ransomware PwnCrypt Outbreak
```
⚠️ Disclaimer: This repository and github site presents fictional threat hunting scenarios created for
educational and portfolio purposes. Any similarities to real individuals, organizations, or events are purely
coincidental. The investigation techniques, queries, and methodologies demonstrated are based on real-world
cybersecurity practices but are applied in a simulated environment. This content is intended to showcase threat
hunting skills, analytical thinking, and investigative processes for professional development. It does not
reflect or promote any actual security incidents or breache
```

## 📂 Overview
On April 12, 2025, threat intelligence reports identified a new ransomware strain named PwnCrypt, which utilizes a PowerShell-based payload to encrypt files using AES-256. It specifically targets directories such as `C:\Users\Public\Desktop` and appends a `.pwncrypt` substring to encrypted files (e.g., `hello.txt` becomes `hello.pwncrypt.txt`). In response, the CISO initiated a proactive threat hunt to determine whether the ransomware had infected any systems and to assess its delivery mechanism or potential lateral movement.

## 🔍 Hypothesis
Due to the organization’s immature security posture—including limited endpoint protection and no formal user awareness training—it is plausible that `PwnCrypt` infiltrated the network.

This hunt focused on identifying:
- Files with `.pwncrypt` in their names.
- PowerShell processes that could have executed the ransomware.
- Potential delivery methods, such as external script downloads or lateral movement patterns.

## 📥 Data Collection
Data was collected from Microsoft Defender for Endpoint (MDE), specifically:
- DeviceFileEvents: To detect file IOCs and abnormal file activity.
- DeviceProcessEvents: To trace suspicious processes occurring around the time of identified file events.

## 🧠 Data Analysis

✅ PowerShell Executions Observed
- All suspicious processes were linked to `powershell.exe` on `sjr-workstation`.
- Multiple commands used flags like `-ExecutionPolicy`, `-NoProfile`, and `-File`, which are commonly seen in script-based attacks.

✅ Execution of Malicious Script
-The following command confirms execution of a known ransomware script: `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1`

✅ Initiation Sources
- PowerShell was launched by both `cmd.exe` and `senseir.exe`.
- The use of `cmd.exe` suggests possible user or script-initiated activity.

✅ Malicious Script Files Dropped
- `pwncrypt.ps1` was the first script dropped.
- Other `.ps1` files (`eicar`, `portscan`, `exfiltratedata`) suggest chained attack simulation or further malicious activity.
- All were dropped via PowerShell, aligning with automation or attack tooling behavior.

✅ Evidence of File Encryption
- Encrypted files such as `9009_ProjectList_pwncrypt.csv` and `9998_CompanyFinancials_pwncrypt.csv` were created on the user’s Desktop.
- These files were then renamed and moved to `C:\Windows\Temp\`, consistent with ransomware behavior.
- The presence of both `FileCreated` and `FileRenamed` events within seconds reinforces the conclusion of script-based ransomware execution.

✅ Evidence of Lateral Movement?
- A network logon `LogonType: Network` to `vm000002` was observed under the user account `johndoe678` on April 12, 2025. While this confirms that the account accessed `vm000002` remotely, the source device is not recorded in the available `DeviceLogonEvents` data.

- In parallel, `sjr-workstation` initiated SMB (port 445) connections to internal IPs `10.0.0.5` and `10.0.0.10` around the same timeframe, with powershell.exe as the initiating process. However, neither of these IPs is directly linked to `vm000002` in the current logs.

- Therefore, while there are indicators suggestive of lateral movement, such as remote authentication and SMB activity from the infected machine, the available data does not definitively prove that `sjr-workstation` connected to or initiated access to `vm000002`.



## 🕵️ Investigation

### 1. KQL Query: Finding Suspicious ProcessCommandLines.
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-04-12T00:00:00Z) .. datetime(2025-04-12T23:59:59Z))
| where DeviceName contains "sjr-workstation"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "Invoke-Expression", "IEX", "wget", "curl", "Bypass", "-File", ".ps1")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/c85d2661-87a1-4289-9a48-e31ff034e3fa)

### 2. KQL Query: Scripts That Were Dropped.
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-04-12T00:00:00Z) .. datetime(2025-04-12T23:59:59Z))
| where DeviceName == "sjr-workstation"
| where FileName endswith ".ps1"
| where FolderPath has "C:\\ProgramData"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/a8b4b0c0-6117-4d46-818f-08a810d23cbd)

### 3. KQL Query: PwnCrypt Ransomware Indicators
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-04-12T00:00:00Z) .. datetime(2025-04-12T23:59:59Z))
| where DeviceName == "sjr-workstation"
| where FileName contains "pwncrypt"
| project Timestamp, FileName, FolderPath, ActionType
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/7390326b-af15-4916-af7f-c206916c7877)

### 4. KQL Queries: Checking Lateral Movement
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-04-12T00:00:00Z) .. datetime(2025-04-12T23:59:59Z))
| where DeviceName == "sjr-workstation"
| where InitiatingProcessAccountName !~ "NT AUTHORITY\\SYSTEM"
| where ProcessCommandLine has_any ("Invoke-Command", "Invoke-WmiMethod", "psexec", "wmic", "Win32_Process")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```
*No results*

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-04-12T00:00:00Z) .. datetime(2025-04-12T23:59:59Z))
| where DeviceName == "sjr-workstation"
| where LogonType in ("RemoteInteractive", "Network") // e.g., RDP or admin shares
| project Timestamp, AccountName, RemoteDeviceName, LogonType
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/3bfc1578-e804-41e5-8aad-5669781c0d33)

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-04-12T00:00:00Z) .. datetime(2025-04-12T23:59:59Z))
| where DeviceName == "sjr-workstation"
| where RemotePort == 445 // SMB
| project Timestamp, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/06ae7705-4f72-4a88-8cce-8e8d1137572c)


## 🛡️ Recommended Response Actions for SOC/IR Team
Based on confirmed execution of the PwnCrypt ransomware on `sjr-workstation` and strong indicators of potential lateral movement, the following response actions are recommended to contain, remediate, and further investigate the incident:

### ✅ Containment
- Immediately isolate `sjr-workstation` from the network to prevent further encryption or propagation.
- Disable or reset credentials for the affected user account `johndoe678` to prevent abuse of active sessions or cached tokens.

### ✅ Eradication & Remediation
- Reimage `sjr-workstation` to eliminate any persistent malware and restore system integrity.
- Remove known malicious script files (`pwncrypt.ps1`, `eicar.ps1`, `portscan.ps1`, `exfiltratedata.ps1`) if present on any other systems.
- Restore encrypted user files from a known good backup.

### ✅ Further Investigation
- Investigate `vm000002`, which received a remote network logon from `johndoe678` shortly after ransomware execution:
  - Pull DeviceProcessEvents and `DeviceFileEvents` for April 12, 2025, on `vm000002`.
  - Look for script execution, file modification, or encryption behavior.

- Continue environment-wide threat hunting for:
  - Logons using `johndoe678` on other hosts.
  - Lateral movement techniques such as `psexec`, `Invoke-Command`, or `WMI-based` execution.

### ✅ Detection & Monitoring
- Create MDE detection rules or Sentinel analytics to alert on:
  - PowerShell executions with `Invoke-WebRequest`, `-ExecutionPolicy Bypass`, and `.ps1` usage.
  - File creation events in `C:\ProgramData\` or encryption patterns like `.pwncrypt`.
  - Lateral movement behaviors using `SMB (port 445)` and `LogonType Network`.

### ✅ User Awareness & Policy Review
- Conduct targeted user training on recognizing phishing attempts and suspicious scripts.
- Review and update endpoint security configurations, ensuring enhanced logging and behavior monitoring is enabled.

## 🔄 Improvements
### ✅ Preventive Measures
- Enforce application control policies (AppLocker or WDAC) to restrict script execution from user-writable directories.
- Apply Controlled Folder Access in Microsoft Defender to protect critical folders from unauthorized modification.
- Block known delivery domains (e.g., `raw.githubusercontent.com`) if not required for business operations.

### ✅ Hunting Process Refinement
- Incorporate DeviceLogonEvents correlation across multiple endpoints earlier in the hunt to confirm or rule out lateral movement with more certainty.
- Expand hunting to include network flow data (DeviceNetworkEvents) sooner when ransomware execution is confirmed, to catch outbound connections or lateral spread attempts.
- Create pre-built KQL query templates for ransomware-related behaviors (e.g., script drop detection, suspicious command-line flags, and encryption patterns) to accelerate future investigations.
- Ensure visibility on all relevant endpoints (e.g., `vm000002`) so logs can be pulled from both the infected source and any remote systems involved.
- Log enrichment using host tagging or asset role identifiers (e.g., production vs. lab machines) would help quickly assess the business impact during a hunt.

## 📝 Summary
On April 12, 2025, a proactive threat hunt was conducted in response to reports of a new ransomware variant named PwnCrypt. The investigation focused on detecting signs of infection, identifying execution methods, and determining whether lateral movement had occurred. Evidence confirmed that the ransomware script (`pwncrypt.ps1`) was executed on `sjr-workstation`, resulting in file encryption and renaming activity. While remote logon activity and SMB traffic suggested potential lateral movement, the connection to other systems—specifically `vm000002`—could not be definitively confirmed without additional telemetry.

## ‼️ Conclusion
The hunt validated the presence of ransomware activity on sjr-workstation and uncovered strong indicators of potential lateral movement within the network. While full attribution of remote access remains inconclusive, the findings support a partial confirmation of the original hypothesis. Key gaps in script control, PowerShell policy enforcement, and monitoring coverage contributed to the exposure. Remediation actions and process improvements have been recommended to prevent future incidents and strengthen the organization’s overall detection and response capabilities.

## 🗓️ Timeline of Key Events 

| Time (UTC)            | Event                                                                                      | Source                |
|-----------------------|--------------------------------------------------------------------------------------------|------------------------|
| **12:13:22 PM**       | `pwncrypt.ps1` script dropped in `C:\ProgramData`                                          | DeviceFileEvents       |
| **12:13:29 PM**       | Encrypted files created on Desktop (e.g., `9998_CompanyFinancials_pwncrypt.csv`)           | DeviceFileEvents       |
| **12:13:29 PM**       | Encrypted files renamed and moved to `C:\Windows\Temp`                                     | DeviceFileEvents       |
| **12:40:15 PM**       | `sjr-workstation` initiated SMB connection (port 445) to `10.0.0.5` via `powershell.exe`   | DeviceNetworkEvents    |
| **12:43:58 PM**       | Another SMB connection from `sjr-workstation` to `10.0.0.10` via `powershell.exe`          | DeviceNetworkEvents    |
| **12:46:05 PM**       | Network logon (`LogonType: Network`) to `vm000002` under user `johndoe678`                 | DeviceLogonEvents      |
| **12:46:08 PM**       | RemoteInteractive logons under `johndoe678` (source device not specified)                  | DeviceLogonEvents      |



