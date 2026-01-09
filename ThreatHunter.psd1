# ThreatHunter Manifest
@{
    # Script module filename
    RootModule         = 'ThreatHunter.psm1'
    
    # Module version number
    ModuleVersion      = '1.0.1'
    
    # Module unique identifier
    GUID               = '48e59dc3-154d-4db0-a9c7-2c57dde9103b'
    
    # Author info
    Author             = 'Blake White'
    CompanyName        = 'Independent'
    Copyright          = '(c) 2025 Blake White. All rights reserved.'
    
    # Module description
    Description        = 'Enterprise-grade PowerShell DFIR module for threat hunting, persistence detection, forensic analysis, and incident response. Features 50+ persistence techniques, intelligent caching, MITRE ATT&CK mapping, browser forensics (18+ browsers), event log analysis, registry hunting, service enumeration, scheduled task inspection, and VirusTotal integration. Generates interactive HTML reports with comprehensive CSV/JSON exports.'
    
    # Minimum PowerShell version required
    PowerShellVersion  = '5.1'
    
    # Exported module functions 
    FunctionsToExport  = @(
        'Hunt-Persistence',
        'Hunt-Files',
        'Hunt-Browser',
        'Hunt-Logs',
        'Hunt-Registry',
        'Hunt-Services',
        'Hunt-Tasks',
        'Hunt-VirusTotal',
        'Hunt-ForensicDump'
    )
    
    # No cmdlets to export
    CmdletsToExport    = @()
    
    # No variables to export
    VariablesToExport  = @()
    
    # No aliases to export
    AliasesToExport    = @()
    
    # External dependencies
    RequiredModules    = @()
    
    # Required assemblies
    RequiredAssemblies = @()
    
    # Nested modules
    NestedModules      = @()
    
    # Private module data
    PrivateData        = @{
        PSData = @{
            Tags                       = @(
                'DFIR'
                'DigitalForensics'
                'IncidentResponse'
                'ThreatHunting'
                'Forensics'
                'Security'
                'SOC'
                'IR'
                'Persistence'
                'EventLogs'
                'BrowserForensics'
                'Registry'
                'WindowsServices'
                'ScheduledTasks'
                'AlternateDataStreams'
                'ADS'
                'WindowsForensics'
                'MITRE'
                'ATT&CK'
                'VirusTotal'
                'Malware'
                'Detection'
                'Investigation'
                'Windows'
                'PowerShell'
                'HTMLReport'
                'CSV'
                'JSON'
            )
            
            LicenseUri                 = 'https://opensource.org/licenses/MIT'
            
            ProjectUri                 = 'https://github.com/blwhit/ThreatHunter'
            
            ReleaseNotes               = @'
ThreatHunter v1.0.1

CORE FUNCTIONS:
- Hunt-Persistence: 50+ Windows persistence mechanism detection (MITRE ATT&CK mapped)
- Hunt-Files: File system analysis with ADS detection, signature verification, streaming hash calculations
- Hunt-Browser: Browser history extraction for 18+ browsers (Chrome, Edge, Firefox, Safari, Opera, Brave, etc.)
- Hunt-Logs: Event log analysis with intelligent caching and aggressive filesystem log search
- Hunt-Registry: Registry hunting with offline hive mounting and pattern matching
- Hunt-Services: Service enumeration with automatic DLL extraction and dependency analysis
- Hunt-Tasks: Scheduled task forensics with action parsing and hash calculations
- Hunt-VirusTotal: VirusTotal API integration for hash/file/URL threat intelligence
- Hunt-ForensicDump: Master orchestration function generating comprehensive HTML reports

KEY CAPABILITIES:
✓ PowerShell 5.1+ compatible (Windows-only, tested on Win10/Win11/Server 2016+)
✓ Interactive HTML reports with JavaScript search/filtering and dark mode
✓ Multiple export formats: HTML, JSON, CSV with Excel formula injection protection
✓ LoadFromJson mode for offline report regeneration without re-scanning
✓ Intelligent session caching for Hunt-Logs and Hunt-Browser (performance optimization)
✓ Configurable date ranges: Relative (7D, 24H, 30M) or absolute (2024-01-01)
✓ Detection modes: Auto (high-fidelity), Aggressive (more IOCs), All (everything), Insane (maximum coverage)
✓ MITRE ATT&CK technique mapping: 20+ techniques across TA0003, TA0005, TA0007, TA0009, TA0011
✓ Memory-efficient streaming for large files (no 500MB+ file loads into RAM)
✓ LNK shortcut resolution with target hash calculation
✓ Authenticode signature verification with certificate chain analysis
✓ LOLBIN (Living-off-the-land binary) detection
✓ Base64/hex/PowerShell encoding detection in file content and registry
✓ Network indicator extraction (IPs, domains, URLs) from logs and persistence
✓ Offline EVTX file analysis (no Windows Event Log service required)
✓ Registry hive mounting for dead-box forensics (NTUSER.DAT analysis)
✓ Browser extension enumeration (Chromium and Firefox) with manifest parsing
✓ Alternate Data Stream (ADS) detection and content analysis

DETECTION COVERAGE:
Persistence Techniques (50+):
- Registry Run/RunOnce keys (all hives including user profiles)
- Startup folder shortcuts (all users)
- Scheduled tasks with suspicious triggers/actions
- Windows Services (standard and svchost-hosted)
- WMI Event Subscriptions (permanent event consumers)
- AppInit DLLs, AppCert DLLs, IFEO Debuggers
- Logon/Logoff scripts (GPO and legacy)
- Windows Terminal startup profiles
- Browser extensions (malicious or suspicious)
- DLL hijacking indicators (search order vulnerabilities)
- Accessibility feature backdoors (Sticky Keys, etc.)
- And 30+ more techniques...

Browser Coverage (18+):
Chrome, Edge, Firefox, Safari, Opera, Brave, Vivaldi, Chromium, Opera GX,
Edge Dev/Beta/Canary, Chrome Dev/Beta/Canary, Yandex, Tor Browser, Waterfox,
Pale Moon, SeaMonkey, plus NirSoft BrowsingHistoryView fallback mode

SYSTEM REQUIREMENTS:
- Windows PowerShell 5.1 or PowerShell 7+ (Windows only)
- Administrator privileges recommended (required for some persistence checks and service analysis)
- .NET Framework 4.5+ (typically pre-installed on Win10+)
- Internet connectivity optional (only needed for VirusTotal API and NirSoft LoadTool downloads)
- Disk space: ~50MB for module, temporary cache files may require additional space

USAGE NOTE - UNAPPROVED VERB:
This module uses "Hunt-" prefix which is not in PowerShell's approved verb list.
This is intentional - "Hunt" is standard terminology in DFIR/threat hunting and better
conveys active investigation vs passive queries. To suppress import warnings:
    Import-Module ThreatHunter -WarningAction SilentlyContinue

DOCUMENTATION & SUPPORT:
- GitHub Repository: https://github.com/blwhit/ThreatHunter
- Wiki Documentation: https://github.com/blwhit/ThreatHunter/wiki
- Usage Examples: https://github.com/blwhit/ThreatHunter/tree/main/examples
- Issue Tracker: https://github.com/blwhit/ThreatHunter/issues
- License: MIT (https://opensource.org/licenses/MIT)

EXAMPLE USAGE:
    # Quick persistence scan
    Hunt-Persistence -Auto

    # Full forensic dump with HTML report
    Hunt-ForensicDump -Auto -OutputDir C:\Cases\Investigation01

    # Search event logs for specific IOCs
    Hunt-Logs -Search "powershell","mimikatz" -StartDate 7D

    # Browser history analysis
    Hunt-Browser -StartDate 30D -Search "evil.com" -OutputCSV C:\output.csv

    # Service enumeration with suspicious DLL detection
    Hunt-Services -Search "temp","appdata" -PassThru
'@
            
            ExternalModuleDependencies = @()
        }
    }
    
    HelpInfoURI        = 'https://github.com/blwhit/ThreatHunter/wiki'
}