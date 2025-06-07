<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/junrickmar/Threat-Hunting-Scenario-TOR-Browser-Usage/blob/master/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceEvents table for any files containing the word "tor" and found that the user named "jun-threathunt" seems to have downloaded a Tor installer. After that, several Tor-related files were copied to the desktop, and a file called "tor-shopping-list.txt" was also created there. These events begun at: 2025-06-01T23:30:36.0326577Z

**Query used to locate events:**

```kql
DeviceEvents
| where DeviceName == "jun-threathunt"
| where FileName contains "tor"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, Account = InitiatingProcessAccountName
| order by Timestamp desc

```
<img width="981" alt="Screenshot 2025-06-03 at 3 09 44 PM" src="https://github.com/user-attachments/assets/f02f2f65-aa00-4a4e-b56c-c650ff08b699" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-14.5.3.exe". Based on the the logs returned, at 2025-06-01T23:30:14.1081493Z, a computer named jun-threathunt, a user named junrick ran a program called "tor-browser-windows-x86_64-portable-14.5.3.exe" from their Downloads folder. This file is the installer for the Tor Browser, a tool often used to browse the internet anonymously. The way the program was run—using the "/S" command—means it was installed silently, without showing installation windows or requiring user interaction

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "jun-threathunt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1448" alt="Screenshot 2025-06-03 at 3 14 58 PM" src="https://github.com/user-attachments/assets/c8e7f558-2cbd-48df-9a94-321134c727ce" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user "junrick" actually opened the tor browser. There was evidence that they did open it at 2025-06-01T23:32:48.7305024Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jun-threathunt"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1637" alt="Screenshot 2025-06-03 at 3 18 06 PM" src="https://github.com/user-attachments/assets/9ec14167-957f-41ad-85a3-6124242e357e" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-06-01T23:33:02.6635945Z, just a few minutes after installing Tor, the user "junrick" successfully made a network connection using the Tor program (tor.exe) from their desktop folder. The connection was made to the IP address 148.251.41.235 on port 9001, which is commonly used by the Tor network.There were a couple other connections.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jun-threathunt"
| where InitiatingProcessAccountName == "junrick"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1628" alt="Screenshot 2025-06-03 at 3 31 18 PM" src="https://github.com/user-attachments/assets/c923ebb1-568f-4959-b5c6-711090b798c7" />

---

## Chronological Event Timeline 

**User Account:** `junrick`  
**Date:** `2025-06-02`  
**Time Zone:** `UTC`

| Time (UTC)   | Event Description |
|--------------|-------------------|
| **07:30:14** | **Installation Started**: `tor-browser-windows-x86_64-portable-14.5.3.exe` was executed with the `/S` flag (silent install).<br>**Path:** `C:\Users\junrick\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe` |
| **07:30:36** | **Shortcut Created**: `Tor Browser.lnk` was created on the Desktop, confirming the installation location.<br>**Path:** `C:\Users\junrick\Desktop\Tor Browser` |
| **07:32:48** | **Tor Browser Launched**: Initial execution of `firefox.exe` from within the Tor Browser directory.<br>**Path:** `C:\Users\junrick\Desktop\Tor Browser\Browser\firefox.exe` |
| **07:32:48** | A second `firefox.exe` process spawned, likely as part of the browser's startup routine. |
| **07:32:53** | Multiple subprocesses created by `firefox.exe`, indicating full startup and tab rendering. |
| **07:32:54** | **Tor Service Started**: `tor.exe` executed from the Tor directory, indicating the background service has started. |
| **07:32:54** | Additional `firefox.exe` processes launched, likely supporting browser functionality. |




---

## Summary

The user "junrick" on the "jun-threathunt" device initiated and completed the installation of the Tor browser. They proceeded to launch the browser, establish connections within the Tor network, and created various files related to Tor on their desktop, including a file named tor-shopping-list.txt. This sequence of activities indicates that the user actively installed, configured, and used the Tor browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `jun-threathunt` by the user `junrick`. The device was isolated, and the user's direct manager was notified.

---
