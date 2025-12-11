<img width="2000" height="1000" alt="threathunter" src="https://github.com/user-attachments/assets/3af47e17-aad3-4c6d-b89d-c3ac3a4d543d" />



## Overview

ThreatHunter is a comprehensive PowerShell toolkit designed for threat hunting, digital forensics, and incident response (DFIR). 

It provides a suite of hunt functions to detect persistence mechanisms, analyze system artifacts, search event logs, and generate detailed forensic reports - all through PowerShell on the command line.

**[Read the Wiki](../../wiki)**

---

## 🎯 Core Capabilities

| Function | Purpose |
|----------|---------|
| **Hunt-ForensicDump** | Forensic collection with interactive HTML reporting |
| **Hunt-Persistence** | Detect 60+ persistence techniques (registry, services, WMI, tasks) |
| **Hunt-Logs** | Event log analysis with caching and IOC detection |
| **Hunt-Browser** | Browser history/extension analysis with tool integration |
| **Hunt-Files** | File hunting by time, content, hashes, and ADS |
| **Hunt-Registry** | Registry search, autoruns, and Run MRU (ClickFix detection) |
| **Hunt-Services** | Service enumeration with svchost DLL resolution |
| **Hunt-Tasks** | Scheduled task analysis with privilege detection |
| **Hunt-VirusTotal** | VirusTotal API integration with auto-upload |


---

## 🔧 Installation

### Install the Module from PS Gallery
```powershell
Install-Module ThreatHunter

# If having errors installing
Install-Module ThreatHunter -Force -AllowClobber
```
### Install Module for Temporary Usage
```powershell
Install-Module ThreatHunter -Scope CurrentUser

# When Done
Uninstall-Module ThreatHunter
```

### Import the Module from File
```powershell
# Clone repository
git clone https://github.com/blwhit/ThreatHunter.git

# Import module
Import-Module .\ThreatHunter.psd1
```

---

## 🚀 Quick Examples
```powershell

# Quick forensic dump and Export EVTZ to ZIP
Hunt-ForensicDump -StartDate "3D" -LoadBrowserTool -SkipConfirmation -ExportLogs

# Hunt for persistence
Hunt-Persistence -Aggressive

# Search all event logs for IOCs
Hunt-Logs -StartDate "7D" -Search "mimikatz"

# Pull all browser history
Hunt-Browser -LoadTool -SkipConfirmation
```

---

## 📋 Requirements

- PowerShell 5.0+
- Windows 7/Server 2008 R2 or later
- Administrator privileges (recommended)

---

## ⚡ Key Features

- **Pure PowerShell** - No compiled binaries or external dependencies
- **Interactive HTML Reports** - Single-file forensic reports with dark/light themes
- **Smart Caching** - Browser and log caching for fast repeated searches
- **Multiple Outputs** - Console, CSV, PowerShell objects
- **Date Filtering** - Flexible relative and absolute date formats
- **MITRE ATT&CK** - Persistence techniques mapped to framework
- **ClickFix Detection** - Analyze Win+R commands for social engineering attacks
- **Offline Analysis** - Process exported EVTX logs and CSV files

---

## 📚 Documentation

- **[Home](../../wiki/Home)** - Module overview and quick start
- **[Hunt-ForensicDump](../../wiki/Hunt-ForensicDump)** - Master forensic collection
- **[Hunt-Persistence](../../wiki/Hunt-Persistence)** - 60+ persistence techniques
- **[Hunt-Logs](../../wiki/Hunt-Logs)** - Event log hunting
- **[Hunt-Browser](../../wiki/Hunt-Browser)** - Browser analysis
- **[Hunt-Files](../../wiki/Hunt-Files)** - File system hunting
- **[Hunt-Registry](../../wiki/Hunt-Registry)** - Registry analysis
- **[Hunt-Services](../../wiki/Hunt-Services)** - Service enumeration
- **[Hunt-Tasks](../../wiki/Hunt-Tasks)** - Scheduled task analysis
- **[Hunt-VirusTotal](../../wiki/Hunt-VirusTotal)** - VirusTotal integration


---

## 🛡️ Use Cases

- **Incident Response** - Quick triage and comprehensive data collection
- **Threat Hunting** - Proactive search for persistence and IOCs
- **Forensic Analysis** - Detailed system artifact examination

---


## 🔗 Resources

- **Wiki Documentation**: [Link](../../wiki)
- **MITRE ATT&CK**: https://attack.mitre.org
- **Issue Tracker**: [Link](../../issues)

---

**Author**: [Blake White]  
**Version**: 1.0  
**Last Updated**: December 2025
