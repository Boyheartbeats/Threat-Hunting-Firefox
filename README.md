# Threat Hunting Firefox Report

- [Scenario Creation]([(https://github.com/Boyheartbeats/Threat-Hunting-Firefox/blob/main/firefox-scenario.md])

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)  
- EDR Platform: Microsoft Defender for Endpoint  
- Kusto Query Language (KQL)  
- Firefox Browser  

## Scenario

Management suspects that some employees may be using unauthorized browsers (such as Firefox) to bypass network security controls. A recent security advisory noted that Firefox can be installed without administrative privileges, potentially circumventing corporate application restrictions. Additionally, IT has observed unusual browsing behavior that raised concerns.  

The goal is to detect any unauthorized Firefox usage and analyze related security incidents to mitigate potential risks. If any use of Firefox is found, notify management.  

### High-Level Firefox-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for Firefox installer and related file events (`Firefox Setup*.exe`, `firefox.exe`, `project-data.txt`, `firefox-exported-bookmarks.html`).  
- **Check `DeviceProcessEvents`** for signs of installation commands and Firefox process launches.  
- **Check `DeviceNetworkEvents`** for outbound connections initiated by `firefox.exe` to external websites.  


### 1. Searched the `DeviceFileEvents` Table

Searched for evidence of Firefox installer activity. On `dbwindowsadmin`, the user downloaded and executed `Firefox Setup 142.0.exe` from the Downloads folder. Additional file activity included the creation and deletion of `project-data.txt` and `firefox-exported-bookmarks.html` on the Desktop.  

**Query used:**
```kql
DeviceFileEvents
| where DeviceName == "dbwindowsadmin"
| where FileName matches regex @"Firefox (Setup|Installer).*\.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1297" height="443" alt="image" src="https://github.com/user-attachments/assets/7d335c19-6430-4d82-a71b-5ed734d89eb4" />


### 2. Searched the `DeviceProcessEvents` Table

Confirmed that the Firefox installer executed in silent mode using the `/S` argument. Later, `firefox.exe` was launched from the standard program path `C:\Program Files\Mozilla Firefox\firefox.exe`.  

**Query used:**
```kql
DeviceProcessEvents
| where DeviceName == "dbwindowsadmin"
| where FileName in~ ("firefox.exe") or ProcessCommandLine has "Firefox Setup"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1265" height="542" alt="image" src="https://github.com/user-attachments/assets/5061b5fc-8d88-43b7-ae5a-f26e4dc5f760" />


### 3. Searched the `DeviceNetworkEvents` Table

Generated browsing activity by visiting Wikipedia and Bing through Firefox. Outbound HTTPS connections initiated by `firefox.exe` were confirmed in the telemetry, validating that the browser was actively used.  

**Query used:**
```kql
DeviceNetworkEvents
| where DeviceName == "dbwindowsadmin"
| where InitiatingProcessFileName == "firefox.exe"
| project Timestamp, DeviceName, ActionType, RemotePort, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1200" height="923" alt="image" src="https://github.com/user-attachments/assets/fc7cf604-181b-46fa-81ab-48a7c131031e" />

### 4. File Creation Activity

Observed the creation of two Desktop files simulating potential data staging activity:  
- `project-data.txt`  
- `firefox-exported-bookmarks.html`  

**Note:** Deletion events were expected but were not observed in this dataset. File creation telemetry alone was sufficient to confirm user activity on the endpoint.  

**Query used:**
```kql
DeviceFileEvents
| where DeviceName == "dbwindowsadmin"
| where FileName in ("project-data.txt","firefox-exported-bookmarks.html")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

<img width="1196" height="439" alt="image" src="https://github.com/user-attachments/assets/bcf69d49-2e39-4a71-a179-4869d4f8ac15" />

## Chronological Event Timeline

### 1. File Download – Firefox Installer  
- **Event:** Downloaded `Firefox Setup 142.0.exe` to Downloads.  
- **Action:** File creation event logged.  
- **Path:** `C:\Users\dbwindowsadmin\Downloads\Firefox Setup 142.0.exe`  

---

### 2. Process Execution – Silent Install
- **Event:** Executed Firefox installer with `/S`.  
- **Action:** Silent installation detected in process telemetry.  
- **Command:** `"Firefox Setup 142.0.exe" /S`  
- **Path:** `C:\Users\dbwindowsadmin\Downloads\Firefox Setup 142.0.exe`  

---

### 3. Process Execution – Firefox Launch
- **Event:** `firefox.exe` launched by user `dbwindowsadmin`.  
- **Action:** Process creation event logged.  
- **Path:** `C:\Program Files\Mozilla Firefox\firefox.exe`  

---

### 4. Network Connections – Firefox Browsing
- **Event:** Outbound connections from `firefox.exe` to safe domains (e.g., `wikipedia.org`, `bing.com`).  
- **Action:** HTTPS sessions confirmed.  
- **Port(s):** TCP/443  

---

### 5. File Creation – Desktop Files
- **Timestamp:** `[Timestamp – from DeviceFileEvents]`  
- **Event:** User created two files simulating data staging:  
  - `project-data.txt`  
  - `firefox-exported-bookmarks.html`  
- **Action:** File creation events logged.  
- **Path:** `C:\Users\dbwindowsadmin\Desktop\`  

**Note:** File deletion events were expected but not observed in the telemetry.

## Summary

The user `dbwindowsadmin` on endpoint `dbwindowsadmin` installed and used an unauthorized Firefox browser.  
Evidence collected included:  

- **File download** of `Firefox Setup 142.0.exe` into the Downloads folder.  
- **Silent installation** of Firefox using the `/S` argument.  
- **Process execution** of `firefox.exe` from `C:\Program Files\Mozilla Firefox\`.  
- **Network activity** generated by Firefox connecting to external websites over HTTPS (TCP/443).  
- **File creation events** on the Desktop (`project-data.txt` and `firefox-exported-bookmarks.html`) simulating potential data staging.  

This sequence of events confirms that Firefox was successfully installed and used on the endpoint outside of sanctioned corporate policy.  

## Response Taken

Unauthorized Firefox usage was confirmed on endpoint `dbwindowsadmin`.  
The following response actions were taken:  

- The device was flagged for review by the SOC team.  
- Management was notified of the confirmed installation and use of Firefox.  
- Recommendations were made to implement policy controls to prevent unauthorized browser installations in the future (e.g., application whitelisting, endpoint restrictions).  







