# ThreatHunter Manifest
@{
    # Script module filename
    RootModule         = 'ThreatHunter.psm1'
    
    # Module version number
    ModuleVersion      = '1.0.0'
    
    # Module nique identifier
    GUID               = '48e59dc3-154d-4db0-a9c7-2c57dde9103b'
    
    # Author info
    Author             = 'Blake White'
    CompanyName        = 'Independent'
    Copyright          = '(c) 2025 Blake White. All rights reserved.'
    
    # Module description
    Description        = 'PowerShell Digital Forensics and Incident Response (DFIR) module for comprehensive threat hunting, persistence analysis, and forensic data collection.'
    
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
                'DFIR',
                'Digital-Forensics',
                'Incident-Response',
                'Threat-Hunting',
                'Forensics',
                'Security',
                'IR',
                'Hunt',
                'Persistence',
                'Event-Logs',
                'Browser-History',
                'Registry',
                'Services',
                'Tasks',
                'ScheduledTasks',
                'ADS',
                'Alternate-Data-Streams',
                'Windows-Forensics',
                'MITRE-ATTCK',
                'TA0003',
                'TA0005',
                'VirusTotal',
                'Caching',
                'Automation',
                'PowerShell-5',
                'Windows'
            )
            
            LicenseUri                 = 'https://opensource.org/licenses/MIT'
            
            ProjectUri                 = 'https://github.com/blwhit/ThreatHunter'
            
            ReleaseNotes               = @'
ThreatHunter v1.0.0 - Initial Release (2025)

FEATURES:
- Hunt-Persistence: 45+ Windows persistence mechanism detection techniques
- Hunt-Files: Advanced file system analysis with ADS detection, signature verification, and hash calculations
- Hunt-Browser: Browser history extraction supporting 15+ browsers (standard + NirSoft LoadTool mode with caching)
- Hunt-Logs: Windows Event Log analysis with intelligent caching system and custom log provider support
- Hunt-Registry: Registry key hunting with offline hive mounting and analysis
- Hunt-Services: Windows service enumeration with DLL extraction (5 fallback methods for svchost.exe)
- Hunt-Tasks: Scheduled task analysis with comprehensive hash calculations and forensic metadata
- Hunt-VirusTotal: VirusTotal API integration for hash/file/URL analysis with monitoring and CSV export
- Hunt-ForensicDump: Master function for complete forensic data collection with interactive HTML reports

CAPABILITIES:
- PowerShell 5.1+ compatible (Windows-only)
- Advanced caching system for Hunt-Logs (session-persistent, intelligent cache invalidation)
- Interactive HTML reports with search and filtering
- JSON and CSV export formats with formula injection protection
- LoadFromJson mode for report regeneration
- Configurable date ranges (relative: 7D, 24H, 30M and absolute)
- Multiple detection modes: Auto (high-fidelity), Aggressive, All, Insane
- MITRE ATT&CK technique mapping (18+ techniques across TA0003, TA0005, TA0007, TA0009, TA0011)
- Memory-efficient processing for large datasets (configurable limits)
- LNK shortcut target resolution with hash calculation
- Signature verification with detailed certificate analysis
- Living-off-the-land binary (LOLBIN) detection
- Base64/hex/PowerShell encoding detection
- Network indicator detection (IPs, domains, URLs)
- Offline EVTX analysis support
- Registry hive mounting for forensic analysis
- Browser extension enumeration (Chromium and Firefox)
- Filesystem aggressive search mode with caching

NOTE ON UNAPPROVED VERBS:
This module uses the "Hunt-" verb prefix, which is not in PowerShell's approved verb list.
This is intentional - "Hunt" is industry-standard terminology in DFIR/threat hunting contexts
and more clearly conveys active investigation operations versus passive queries.

To suppress the verb warning during import:
    Import-Module ThreatHunter -WarningAction SilentlyContinue

REQUIREMENTS:
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator privileges recommended for full functionality
- Internet connectivity optional (required for NirSoft LoadTool downloads and VirusTotal API)

INTERNAL DEPENDENCIES:
Helper functions-
- Get-FileFromCommandLine: Extracts executables from command lines (20+ patterns)
- Find-ExecutableInSystemPaths: Resolves relative paths in 9 system directories
- Get-RegistryHivesForAnalysis: Registry hive enumeration with optional mounting
- Mount-RegistryHive: Loads NTUSER.DAT files for offline analysis
- Dismount-AllRegistryHives: Cleanup for mounted hives
- Close-RegistryHandles: Forces garbage collection for registry handle release

DOCUMENTATION:
- GitHub Wiki: https://github.com/blwhit/ThreatHunter/wiki
- Examples: https://github.com/blwhit/ThreatHunter/tree/main/examples
- Issue Tracker: https://github.com/blwhit/ThreatHunter/issues
'@
            
            ExternalModuleDependencies = @()
        }
    }
    
    HelpInfoURI        = 'https://github.com/blwhit/ThreatHunter/wiki'
}