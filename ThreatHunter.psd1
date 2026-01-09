# ThreatHunter Manifest

@{
    # Script module filename
    RootModule         = 'ThreatHunter.psm1'
    
    # Module version number
    ModuleVersion      = '1.0'
    
    # Module unique identifier
    GUID               = '48e59dc3-154d-4db0-a9c7-2c57dde9103b'
    
    # Author info
    Author             = 'Blake White'
    
    # Module description
    Description        = 'A comprehensive PowerShell toolkit for threat hunting, digital forensics, and incident response (DFIR). Provides "Hunt" style functions to detect persistence mechanisms, analyze system artifacts, search event logs, and generate detailed forensic reports.'
    
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
                'ThreatHunting'
                'IncidentResponse'
                'Forensics'
                'Security'
                'Persistence'
                'EventLogs'
                'Browser'
                'Registry'
                'MITRE'
                'VirusTotal'
                'Windows'
                'PowerShell'
                'ClickFix'
                'Malware'
                'CyberSecurity'
                'SecOps'
                'EVTX'
            )
            
            LicenseUri                 = 'https://opensource.org/licenses/MIT'
            
            ProjectUri                 = 'https://github.com/blwhit/ThreatHunter'
            
            ReleaseNotes               = @'
ThreatHunter v1.0

A comprehensive PowerShell toolkit for threat hunting, digital forensics, and incident response (DFIR). Provides hunt functions to detect persistence mechanisms, analyze system artifacts, search event logs, and generate detailed forensic reports.

CORE CAPABILITIES:

Hunt-ForensicDump    - Forensic collection with interactive HTML reporting
Hunt-Persistence     - Detect 60+ persistence techniques (registry, services, WMI, tasks)
Hunt-Logs            - Event log analysis with caching and IOC detection
Hunt-Browser         - Browser history/extension analysis with tool integration
Hunt-Files           - File hunting by time, content, hashes, and ADS
Hunt-Registry        - Registry search, autoruns, and Run MRU (ClickFix detection)
Hunt-Services        - Service enumeration with svchost DLL resolution
Hunt-Tasks           - Scheduled task analysis with privilege detection
Hunt-VirusTotal      - VirusTotal API integration with auto-upload

KEY FEATURES:

- Pure PowerShell with no compiled binaries or external dependencies
- Interactive HTML reports with dark/light themes
- Smart caching for browser and log data
- Flexible date filtering (relative and absolute formats)
- MITRE ATT&CK mapping for persistence techniques
- ClickFix detection via Win+R command analysis
- Offline analysis support for exported EVTX logs and CSV files

REQUIREMENTS:

- PowerShell 5.0+
- Windows 7/Server 2008 R2 or later
- Administrator privileges recommended

QUICK EXAMPLES:

    # Quick forensic dump and export event logs to ZIP
    Hunt-ForensicDump -StartDate "3D" -LoadBrowserTool -SkipConfirmation -ExportLogs

    # Hunt for persistence
    Hunt-Persistence -Aggressive

    # Search all event logs for IOCs
    Hunt-Logs -StartDate "7D" -Search "mimikatz"

    # Pull all browser history
    Hunt-Browser -LoadTool -SkipConfirmation

DOCUMENTATION:

- Wiki: https://github.com/blwhit/ThreatHunter/wiki
- GitHub: https://github.com/blwhit/ThreatHunter
- Issues: https://github.com/blwhit/ThreatHunter/issues
'@
            
            ExternalModuleDependencies = @()
        }
    }
    
    HelpInfoURI        = 'https://github.com/blwhit/ThreatHunter/wiki'
}