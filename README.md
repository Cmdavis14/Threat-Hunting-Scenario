# 🕵️ Threat Hunting: Detecting Unauthorized TOR Browser Usage

> **Cyber Range Project**  
> Simulated Insider Threat Scenario Focused on Detecting TOR-Based Activity

---

## 📚 Overview

This project simulates a threat hunting engagement in a controlled lab environment. The objective was to detect and confirm the use of the TOR browser within a corporate network, where it was suspected to be used for bypassing security controls.

---

## 🧰 Tools & Technologies

- **Platform:** Windows 10 Virtual Machines (Azure-hosted)
- **EDR:** Microsoft Defender for Endpoint (MDE)
- **Language:** Kusto Query Language (KQL)
- **Browser Under Investigation:** TOR Browser

---

## 🎯 Scenario Description

Management received reports of employees accessing restricted content during work hours. Concurrently, network logs showed unusual encrypted traffic and connections to known TOR entry nodes. This triggered a security investigation to identify:

- Evidence of TOR browser installation
- Signs of execution or usage
- Any network traffic linked to TOR nodes

If validated, the finding would be escalated for remediation.

---

## 🧠 Detection Strategy (Indicators of Compromise)

1. **File Activity:** Search `DeviceFileEvents` for TOR-related executables.
2. **Process Creation:** Look for installation or launch commands in `DeviceProcessEvents`.
3. **Network Activity:** Identify connections using common TOR ports via `DeviceNetworkEvents`.

---

## 🔎 Investigation Steps

### 1. 🗂️ File Artifact Discovery
Searched the `DeviceFileEvents` table for TOR-related files. Identified the user `employee` downloaded the TOR browser installer and saved it to the Downloads folder.

**Query:**
```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| order by Timestamp desc
```
---
### 2. ⚙️  Silent Installation Identified
Observed the TOR browser being installed in silent mode via DeviceProcessEvents.
```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
---
### 3. 🚀 TOR Browser Launched
Confirmed execution of tor.exe and firefox.exe, verifying the user launched the TOR browser successfully.
```kql
DeviceProcessEvents
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
```
---
### 4. 🌐 Network Connections to TOR Nodes
Detected outbound connections to TOR entry nodes and common TOR ports, confirming active usage.
```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| order by Timestamp desc
```

📅 Timeline of Events
| Timestamp (UTC)        | Event                                                              |
| ---------------------- | ------------------------------------------------------------------ |
| `2024-11-08T22:14:48Z` | TOR installer downloaded by user `employee`.                       |
| `2024-11-08T22:16:47Z` | Silent install of TOR browser executed.                            |
| `2024-11-08T22:17:21Z` | TOR browser launched (`tor.exe`, `firefox.exe` processes created). |
| `2024-11-08T22:18:01Z` | Network connection to 176.198.159.33 on port 9001 established.     |
| `2024-11-08T22:18:08Z` | Additional TOR connection to 194.164.169.85 over port 443.         |
| `2024-11-08T22:18:16Z` | Local loopback connection on port 9150 initiated.                  |
| `2024-11-08T22:27:19Z` | File `tor-shopping-list.txt` created on Desktop.                   |




## ✅ Conclusion
The investigation confirmed that the user employee on the threat-hunt-lab device:

Installed the TOR browser using a silent installer

Launched and actively used the browser to access the TOR network

Created artifacts related to usage (e.g., tor-shopping-list.txt)




## 🛡️ Response Actions
The endpoint was isolated from the network

Management was notified for further action

Documentation of all findings was compiled for compliance and HR follow-up




## 📎 Related
Inspired by original TOR hunting scenario by @joshmadakor0










