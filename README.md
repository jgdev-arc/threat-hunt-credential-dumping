<img src="https://github.com/user-attachments/assets/9234b207-0138-4dd0-b05d-c23243f49c28" width="400"/>

# Threat Hunt Report: Credential Dumping via Mimikatz (Atomic Red Team T1003.001)  
This threat hunt investigates attempted credential dumping on a Windows endpoint using Mimikatz techniques (T1003.001), specifically through LSASS memory access with ProcDump, to simulate and detect unauthorized credential access attempts.

## Platforms and Tools Used
- **Microsoft Azure** (Virtual Machine)
- **Microsoft Defender for Endpoint** (EDR telemetry)
- **Kusto Query Language (KQL)**
- **Atomic Red Team** (Adversary simulation framework)
- **Invoke-AtomicRedTeam PowerShell module** (Used to execute Atomic Test T1003.001)
- **Sysinternals ProcDump** (Used to simulate LSASS memory dump)

---

## Scenario Overview

Credential dumping is a common technique used by threat actors to extract account login credentials from memory, particularly from the Local Security Authority Subsystem Service (LSASS) process. These credentials can then be used for lateral movement, privilege escalation, or persistence.

In this scenario, the security team simulates an attacker using the tool **ProcDump** to dump the memory of the LSASS process—mimicking the behavior of tools like **Mimikatz**. The goal is to validate whether Microsoft Defender for Endpoint (MDE) detects or blocks this credential access attempt, and to practice identifying associated telemetry and forensic evidence via threat hunting in Microsoft 365 Defender.

This scenario aligns with **MITRE ATT&CK technique T1003.001: Credential Dumping - LSASS Memory** and is based on an [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) simulation test.

---

## 🔍 IoC-Based Threat Hunting Plan

To detect signs of credential dumping via LSASS memory dumping, the following indicators of compromise (IoCs) and hunting steps were used:

- **Process Execution Monitoring**
  - Search `DeviceProcessEvents` for execution of `procdump.exe`.
  - Look for command-line arguments that include `lsass.exe` and flags like `-ma` (full memory dump).

- **File Creation**
  - Search `DeviceFileEvents` for the creation of dump files such as `lsass.dmp`, especially on user-accessible paths like `Desktop`.

- **Defender or EDR Alerts**
  - Review the `AlertEvidence` table for any detections or alerts triggered by credential dumping behavior.
  - Focus on blocked executions, real-time protection events, or any threats tied to `procdump.exe` or `lsass.exe`.

- **Image Load Monitoring**
  - (Optional) Search for sensitive system DLLs loaded into unusual processes, such as `comsvcs.dll` or `dbghelp.dll`, which may indicate memory manipulation.

These hunting steps are aligned with MITRE ATT&CK Technique **T1003.001 – Credential Dumping: LSASS Memory**, and are used to identify attempts to extract credentials from memory on Windows endpoints.

---

## Investigation Steps

### 🧪 1. Process Execution – procdump.exe Observed

On **May 27, 2025 at 11:04:10 AM**, user **labuser** on the device **vm-test-zedd** executed **procdump.exe** from the following location:

- **Executable Path:** `C:\Tools\Procdump\procdump.exe`
- **Command Line:** `procdump.exe`

Although the command was invoked, no additional parameters (such as `-ma` or `lsass.exe`) were captured in this specific event. Microsoft Defender blocked this attempt.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "vm-test-zedd"
| where FileName =~ "procdump.exe"
| project Timestamp, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```
![1](https://github.com/user-attachments/assets/7766dc86-6772-4737-8772-c9df80c37955)

---

### 🧾 2. File Creation Attempt – `lsass.dmp`

A search for any file creation events involving `lsass.dmp` on **vm-test-zedd** returned **no results**.

This suggests that while the user attempted to execute `procdump.exe`, the actual memory dump file was **not written to disk**, likely due to the **interference from Microsoft Defender**.

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "vm-test-zedd"
| where FileName endswith "lsass.dmp"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessAccountName
| order by Timestamp desc
```
![noresults](https://github.com/user-attachments/assets/00244d57-8e26-45ba-9bff-ec67cbb56108)

---

### 🧩 3. Image Load Activity – `lsasrv.dll` in procdump.exe Context

A query was run to determine if `procdump.exe` successfully loaded the sensitive DLL `lsasrv.dll`, which is commonly associated with LSASS memory access. This is often used to confirm whether an attempted LSASS dump had elevated access.

However, **no image load events were recorded** involving `lsasrv.dll` on **vm-test-zedd**, indicating that `procdump.exe` likely **did not execute far enough to interact with LSASS**, or was **blocked by Microsoft Defender** before performing this action.

**KQL Query Used:**
```kql
DeviceImageLoadEvents
| where DeviceName == "vm-test-zedd"
| where InitiatingProcessFileName =~ "procdump.exe"
| where FileName endswith "lsasrv.dll"
| project Timestamp, InitiatingProcessFileName, FileName, FolderPath, InitiatingProcessAccountName
```
![noresults](https://github.com/user-attachments/assets/87c8e512-9cb4-4d4f-9cb6-376bbb336699)

---

### 🚨 4. Alert Detection – None Triggered

A query of Microsoft Defender for Endpoint's `AlertEvidence` table revealed **no alerts** were generated during or after the execution of `procdump.exe` against `lsass.exe` on the device **vm-test-zedd**. Despite the behavior being consistent with credential dumping attempts (MITRE ATT&CK T1003.001), no automatic detection or alerting occurred. Likely due to being blocked by Microsoft Defender.

**KQL Query Used:**
```kql
AlertEvidence
| where DeviceName == "vm-test-zedd"
| where EntityType == "Process"
| where FileName has_any ("lsass.exe", "procdump.exe")
   or ProcessCommandLine has_any ("lsass", "procdump", "T1003")
| project Timestamp, DeviceName, AlertId, EntityType, EvidenceRole, FileName, ProcessCommandLine
| order by Timestamp desc
```
![noresults](https://github.com/user-attachments/assets/6b95f629-64d8-4f99-ac2a-77afe12e3a72)

---

### 🧾 5. Evidence Behind Alerts – No Correlated Results

A detailed search of the `AlertEvidence` table for any evidence related to the LSASS dump attempt returned **no results**. This indicates that while Defender logged the execution attempt of `procdump.exe`, it did not correlate additional evidence (such as file writes or process behavior) into a singular alert regarding LSASS credential dumping.

This observation suggests one of two possibilities:
- Defender's detection engine blocked the activity so early that no additional evidence was captured for alert correlation.
- Alternatively, the current alerting logic did not classify the behavior as sufficiently malicious to trigger a unified alert.

**KQL Query Used:**
```kql
AlertEvidence
| where DeviceName == "vm-test-zedd"
| where EntityType == "Process"
| where FileName has_any ("lsass.exe", "procdump.exe") 
   or ProcessCommandLine has_any ("lsass", "procdump", "T1003")
| project Timestamp, DeviceName, AlertId, EntityType, EvidenceRole, FileName, ProcessCommandLine
| order by Timestamp desc
```
![noresults](https://github.com/user-attachments/assets/6b95f629-64d8-4f99-ac2a-77afe12e3a72)

---

## 🕒 Chronological Timeline of Events – Credential Dump Attempt via ProcDump  
**Device:** `vm-test-zedd`  
**Date:** May 27, 2025  

| **Time**       | **Event**                  | **Details** |
|----------------|----------------------------|-------------|
| **11:04:10 AM** | 📁 Process Created         | User `labuser` launched `procdump.exe` from `C:\Tools\Procdump\`. <br>**Command Executed:** `procdump.exe` (no flags were passed; likely blocked before execution completed) |
| *(none)*        | 📄 Dump File Not Created   | No `lsass.dmp` or other dump file was recorded in `DeviceFileEvents`, indicating the dump action failed. |
| *(none)*        | 🚨 Alerts Not Generated    | No alert or detection was raised in `AlertEvidence` related to `lsass` or credential dumping during this attempt. |

---

## 🧾 Summary of Findings

On **May 27, 2025**, user **labuser** attempted to execute `procdump.exe` from the `C:\Tools\Procdump\` directory in an effort to dump the LSASS process memory, which is a common technique for harvesting user credentials. 

- Although `procdump.exe` was launched, no command-line arguments were passed in the telemetry, and no dump file (`lsass.dmp`) was created.
- Microsoft Defender blocked execution of the dump attempt, generating an **"Access is denied"** error during both direct and scripted attempts.
- No alerts or evidence entries were found in Microsoft Defender for Endpoint, indicating that the telemetry only captured blocked process creation without further activity.

This activity matches behavior defined in **MITRE ATT&CK T1003.001 – Credential Dumping: LSASS Memory**, though no credentials were successfully dumped.

---

## ✅ Containment and Remediation

The following actions were taken in response to this credential dumping attempt:

- **Confirmed Defender intervention**: Microsoft Defender blocked the memory dump attempt before it could execute. Real-time protection and tamper protection were observed functioning correctly.
- **Verified no dump file was created**: A check of the `DeviceFileEvents` table confirmed that no LSASS memory dump file was written to disk.
- **No remediation required**: Since the attack was blocked at execution, no persistence or further action was observed. However, continued monitoring is recommended.
- **Flagged the incident for internal review**: The attempt was logged for internal security awareness and correlation with future activity.
