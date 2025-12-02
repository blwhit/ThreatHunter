# ThreatHunter Manifest
@{
    # Script module file this manifest is for
    RootModule         = 'ThreatHunter.psm1'
    
    # Version number of this module
    ModuleVersion      = '1.0.0'
    
    # Unique identifier for this module
    GUID               = '48e59dc3-154d-4db0-a9c7-2c57dde9103b'
    
    # Author info
    Author             = 'Blake White'
    CompanyName        = 'Independent'
    Copyright          = '(c) 2025 Blake White. All rights reserved.'
    
    # Description of the module
    Description        = 'PowerShell Digital Forensics and Incident Response (DFIR) module for comprehensive threat hunting, persistence analysis, and forensic data collection.'
    
    # Minimum PowerShell version
    PowerShellVersion  = '5.1'
    
    # Exported functions - all Hunt-* functions
    FunctionsToExport  = @(
        'Hunt-Persistence',
        'Hunt-Files',
        'Hunt-Browser',
        'Hunt-Logs',
        'Hunt-Registry',
        'Hunt-Services',
        'Hunt-Tasks',
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
    
    # Required assemblies for module functionality
    RequiredAssemblies = @(
        'System.IO.Compression.FileSystem.dll',
        'System.Security.dll',
        'System.Web.dll'
    )
    
    # Optional: nested modules
    NestedModules      = @()
    
    # Private module data (metadata and PSGallery info)
    PrivateData        = @{
        PSData = @{
            # Tags for PowerShell Gallery
            Tags         = @(
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
                'ADS',
                'Alternate-Data-Streams',
                'Windows-Forensics',
                'MITRE-ATTCK'
            )
            
            # License
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            
            # Project repository
            ProjectUri   = 'https://github.com/blwhit/ThreatHunter'
            
            # Icon for PowerShell Gallery (optional)
            # IconUri    = 'https://github.com/blwhit/ThreatHunter/raw/main/icon.png'
            
            # Release notes
            ReleaseNotes = @'
ThreatHunter v1.0.0 - Initial Release (2025)

FEATURES:
- Hunt-Persistence: Comprehensive Windows persistence mechanism detection
- Hunt-Files: Advanced file system analysis with ADS detection and hash calculations
- Hunt-Browser: Browser history extraction (standard + NirSoft LoadTool mode)
- Hunt-Logs: Windows Event Log analysis with custom log provider support
- Hunt-Registry: Registry key hunting for common persistence locations
- Hunt-Services: Windows service enumeration and analysis
- Hunt-Tasks: Scheduled task analysis with hash calculations
- Hunt-ForensicDump: Master function for complete forensic data collection with interactive HTML reports

CAPABILITIES:
- PowerShell 5.1+ compatible
- Interactive HTML reports with search and filtering
- JSON and CSV export formats
- LoadFromJson mode for report regeneration
- Configurable date ranges (relative and absolute)
- Auto and Aggressive collection modes
- MITRE ATT&CK technique mapping
- Memory-efficient processing for large datasets

NOTE ON UNAPPROVED VERBS:
This module uses the "Hunt-" verb prefix, which is not in PowerShell's approved verb list.
This is intentional - "Hunt" is industry-standard terminology in DFIR/threat hunting contexts
and more clearly conveys active investigation operations versus passive queries.

To suppress the verb warning during import:
    Import-Module ThreatHunter -WarningAction SilentlyContinue

REQUIREMENTS:
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator privileges recommended for full functionality
- Internet connectivity optional (required for NirSoft LoadTool downloads)

DOCUMENTATION:
- GitHub Wiki: https://github.com/blwhit/ThreatHunter/wiki
- Examples: https://github.com/blwhit/ThreatHunter/tree/main/examples
- Issue Tracker: https://github.com/blwhit/ThreatHunter/issues
'@
            
            # Prerelease string (comment out for stable release)
            # Prerelease = 'beta'
            
            # Suppress unapproved verb warning message
            # Note: This doesn't actually suppress the warning, but documents the intention
            # Users should import with: Import-Module ThreatHunter -WarningAction SilentlyContinue
        }
    }
    
    # Help info URI
    HelpInfoURI        = 'https://github.com/blwhit/ThreatHunter/wiki'
}