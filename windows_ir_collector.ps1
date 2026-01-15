#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Incident Response Log Collector

.DESCRIPTION
    Collects forensically valuable logs and artefacts from Windows for 
    investigation and incident response purposes.

.PARAMETER OutputDir
    Directory to store collected artefacts (default: Desktop\IR_Collection_<hostname>_<timestamp>)

.PARAMETER DryRun
    Show what would be collected without copying

.PARAMETER Verbose
    Show detailed output

.PARAMETER EventLogHours
    Number of hours of event logs to collect (default: 24)

.PARAMETER SkipEventLogs
    Skip event log collection (faster)

.EXAMPLE
    .\windows_ir_collector.ps1
    Collect to default location

.EXAMPLE
    .\windows_ir_collector.ps1 -OutputDir "C:\IR\Collection"
    Collect to specific directory

.EXAMPLE
    .\windows_ir_collector.ps1 -DryRun
    Show what would be collected

.EXAMPLE
    .\windows_ir_collector.ps1 -EventLogHours 72
    Collect 72 hours of event logs

.NOTES
    Author: orchardroot
    Version: 1.0.0
    - Some artefacts require Administrator privileges
    - Run elevated for complete collection
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$OutputDir,
    
    [switch]$DryRun,
    
    [int]$EventLogHours = 24,
    
    [switch]$SkipEventLogs
)

# =============================================================================
# Configuration
# =============================================================================
$Script:Version = "1.0.0"
$Script:Hostname = $env:COMPUTERNAME
$Script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:StartTime = Get-Date

if (-not $OutputDir) {
    $OutputDir = Join-Path ([Environment]::GetFolderPath("Desktop")) "IR_Collection_${Script:Hostname}_${Script:Timestamp}"
}

$Script:OutputDir = $OutputDir
$Script:LogFile = Join-Path $OutputDir "collection.log"
$Script:ManifestFile = Join-Path $OutputDir "manifest.txt"
$Script:HashFile = Join-Path $OutputDir "hashes.sha256"
$Script:ErrorLogFile = Join-Path $OutputDir "error_collection.log"

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Log {
    param(
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level,
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colours = @{
        "INFO"  = "Green"
        "WARN"  = "Yellow"
        "ERROR" = "Red"
        "DEBUG" = "Cyan"
    }
    
    Write-Host "[$Level] " -ForegroundColor $colours[$Level] -NoNewline
    Write-Host $Message
    
    if (Test-Path $Script:LogFile) {
        "[$timestamp] [$Level] $Message" | Add-Content -Path $Script:LogFile -ErrorAction SilentlyContinue
    }
}

function Write-LogVerbose {
    param([string]$Message)
    if ($VerbosePreference -eq 'Continue') {
        Write-Log -Level "DEBUG" -Message $Message
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-Collection {
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "DRY RUN MODE - No files will be copied"
        return
    }
    
    # Create output directory
    New-Item -ItemType Directory -Path $Script:OutputDir -Force | Out-Null
    
    # Initialise log file
    @"
# Windows IR Collection Log
# Started: $(Get-Date)
# Hostname: $Script:Hostname
# User: $env:USERNAME
# Elevated: $(Test-Administrator)

"@ | Set-Content -Path $Script:LogFile
    
    # Initialise manifest
    @"
# Windows IR Collection Manifest
# Generated: $(Get-Date)

"@ | Set-Content -Path $Script:ManifestFile
    
    # Initialise hash file
    @"
# SHA256 Hashes for IR Collection
# Generated: $(Get-Date)

"@ | Set-Content -Path $Script:HashFile
    
    # Initialise error log
    @"
# Windows IR Collection Error Log
# Generated: $(Get-Date)

"@ | Set-Content -Path $Script:ErrorLogFile
    
    Write-Log -Level "INFO" -Message "Collection directory: $Script:OutputDir"
}

function Copy-Artefact {
    param(
        [string]$Source,
        [string]$DestinationSubDir,
        [string]$Description = ""
    )
    
    if (-not (Test-Path $Source)) {
        Write-LogVerbose "Not found: $Source"
        return $false
    }
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: $Source"
        return $true
    }
    
    $destDir = Join-Path $Script:OutputDir $DestinationSubDir
    New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
    
    try {
        if (Test-Path $Source -PathType Container) {
            Copy-Item -Path $Source -Destination $destDir -Recurse -Force -ErrorAction Stop
            $itemName = Split-Path $Source -Leaf
            "$DestinationSubDir\$itemName\ - $Source" | Add-Content -Path $Script:ManifestFile
            Write-LogVerbose "Collected directory: $Source"
        }
        else {
            Copy-Item -Path $Source -Destination $destDir -Force -ErrorAction Stop
            $filename = Split-Path $Source -Leaf
            "$DestinationSubDir\$filename - $Source" | Add-Content -Path $Script:ManifestFile
            Write-LogVerbose "Collected: $Source"
        }
        return $true
    }
    catch {
        $errorMsg = "Failed to copy '$Source': $_"
        Write-Log -Level "WARN" -Message $errorMsg
        $errorMsg | Add-Content -Path $Script:ErrorLogFile -ErrorAction SilentlyContinue
        return $false
    }
}

function Save-CommandOutput {
    param(
        [string]$Command,
        [string]$OutputFile,
        [string]$Description
    )
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would execute: $Command"
        return
    }
    
    $destPath = Join-Path $Script:OutputDir $OutputFile
    $destDir = Split-Path $destPath -Parent
    New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
    
    try {
        $output = Invoke-Expression $Command 2>&1
        $output | Out-File -FilePath $destPath -Encoding UTF8 -ErrorAction Stop
        "$OutputFile - $Description" | Add-Content -Path $Script:ManifestFile
        Write-LogVerbose "Executed: $Command"
    }
    catch {
        $errorMsg = "Failed to execute '$Command': $_"
        Write-Log -Level "WARN" -Message $errorMsg
        $errorMsg | Add-Content -Path $Script:ErrorLogFile -ErrorAction SilentlyContinue
    }
}

# =============================================================================
# Collection Functions
# =============================================================================

function Get-SystemInformation {
    Write-Log -Level "INFO" -Message "Collecting system information..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: System information"
        return
    }
    
    $infoFile = Join-Path $Script:OutputDir "system_info.txt"
    
    $systemInfo = @"
# Windows System Information
# Collected: $(Get-Date)

=== HOSTNAME ===
$env:COMPUTERNAME

=== OS VERSION ===
$(Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture | Out-String)

=== HARDWARE ===
$(Get-CimInstance Win32_ComputerSystem | Format-List Manufacturer, Model, TotalPhysicalMemory, NumberOfProcessors | Out-String)

=== PROCESSOR ===
$(Get-CimInstance Win32_Processor | Format-List Name, NumberOfCores, NumberOfLogicalProcessors | Out-String)

=== CURRENT USER ===
User: $env:USERNAME
Domain: $env:USERDOMAIN
$(whoami /all 2>$null)

=== LOGGED IN USERS ===
$(query user 2>$null)

=== LAST BOOT TIME ===
$(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)

=== UPTIME ===
$((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime)

=== RUNNING PROCESSES ===
$(Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 Id, ProcessName, CPU, WorkingSet, Path | Format-Table -AutoSize | Out-String)

=== SERVICES ===
$(Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-Table Name, DisplayName, Status -AutoSize | Out-String)

=== NETWORK CONNECTIONS ===
$(Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
    Format-Table -AutoSize | Out-String)

=== LISTENING PORTS ===
$(netstat -ano | Select-String "LISTENING" | Out-String)

=== MOUNTED VOLUMES ===
$(Get-Volume | Format-Table DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size -AutoSize | Out-String)

=== DISK USAGE ===
$(Get-PSDrive -PSProvider FileSystem | Format-Table Name, Used, Free -AutoSize | Out-String)

=== ENVIRONMENT VARIABLES ===
$(Get-ChildItem Env: | Format-Table Name, Value -AutoSize -Wrap | Out-String)

=== LOCAL USERS ===
$(Get-LocalUser -ErrorAction SilentlyContinue | Format-Table Name, Enabled, LastLogon, PasswordLastSet | Out-String)

=== LOCAL GROUPS ===
$(Get-LocalGroup -ErrorAction SilentlyContinue | Format-Table Name, Description | Out-String)

=== ADMINISTRATORS GROUP MEMBERS ===
$(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Format-Table Name, PrincipalSource | Out-String)

"@
    
    $systemInfo | Set-Content -Path $infoFile -Encoding UTF8
    "system_info.txt - System information" | Add-Content -Path $Script:ManifestFile
    
    Write-Log -Level "INFO" -Message "System information collected"
}

function Get-EventLogs {
    if ($SkipEventLogs) {
        Write-Log -Level "INFO" -Message "Skipping event log collection (--SkipEventLogs)"
        return
    }
    
    Write-Log -Level "INFO" -Message "Collecting event logs (last $EventLogHours hours)..."
    Write-Log -Level "INFO" -Message "This may take several minutes..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: Event logs for last $EventLogHours hours"
        return
    }
    
    $eventDir = Join-Path $Script:OutputDir "event_logs"
    New-Item -ItemType Directory -Path $eventDir -Force | Out-Null
    
    $startTime = (Get-Date).AddHours(-$EventLogHours)
    
    # Key event logs to collect
    $eventLogs = @(
        @{Name = "Security"; File = "security.evtx"; Description = "Security events (logons, audit)"},
        @{Name = "System"; File = "system.evtx"; Description = "System events"},
        @{Name = "Application"; File = "application.evtx"; Description = "Application events"},
        @{Name = "Microsoft-Windows-PowerShell/Operational"; File = "powershell_operational.evtx"; Description = "PowerShell operational"},
        @{Name = "Windows PowerShell"; File = "powershell_legacy.evtx"; Description = "PowerShell legacy"},
        @{Name = "Microsoft-Windows-Sysmon/Operational"; File = "sysmon.evtx"; Description = "Sysmon events"},
        @{Name = "Microsoft-Windows-Windows Defender/Operational"; File = "defender.evtx"; Description = "Windows Defender"},
        @{Name = "Microsoft-Windows-WMI-Activity/Operational"; File = "wmi_activity.evtx"; Description = "WMI activity"},
        @{Name = "Microsoft-Windows-TaskScheduler/Operational"; File = "taskscheduler.evtx"; Description = "Task Scheduler"},
        @{Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; File = "rdp_local.evtx"; Description = "RDP local sessions"},
        @{Name = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; File = "rdp_remote.evtx"; Description = "RDP remote connections"},
        @{Name = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"; File = "rdp_core.evtx"; Description = "RDP Core"},
        @{Name = "Microsoft-Windows-DNS-Client/Operational"; File = "dns_client.evtx"; Description = "DNS Client"},
        @{Name = "Microsoft-Windows-NTLM/Operational"; File = "ntlm.evtx"; Description = "NTLM authentication"},
        @{Name = "Microsoft-Windows-Security-Mitigations/KernelMode"; File = "security_mitigations_kernel.evtx"; Description = "Security mitigations kernel"},
        @{Name = "Microsoft-Windows-AppLocker/EXE and DLL"; File = "applocker_exe_dll.evtx"; Description = "AppLocker EXE/DLL"},
        @{Name = "Microsoft-Windows-AppLocker/MSI and Script"; File = "applocker_msi_script.evtx"; Description = "AppLocker MSI/Script"},
        @{Name = "Microsoft-Windows-CodeIntegrity/Operational"; File = "code_integrity.evtx"; Description = "Code Integrity"},
        @{Name = "Microsoft-Windows-Bits-Client/Operational"; File = "bits_client.evtx"; Description = "BITS Client"},
        @{Name = "Microsoft-Windows-WindowsUpdateClient/Operational"; File = "windows_update.evtx"; Description = "Windows Update"},
        @{Name = "Microsoft-Windows-Kernel-PnP/Device Configuration"; File = "kernel_pnp.evtx"; Description = "Device configuration (USB)"},
        @{Name = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"; File = "driver_frameworks.evtx"; Description = "Driver frameworks"}
    )
    
    foreach ($log in $eventLogs) {
        try {
            $logPath = Join-Path $eventDir $log.File
            $logExists = Get-WinEvent -ListLog $log.Name -ErrorAction SilentlyContinue
            
            if ($logExists) {
                Write-LogVerbose "Exporting: $($log.Name)"
                wevtutil epl $log.Name $logPath /q:"*[System[TimeCreated[timediff(@SystemTime) <= $($EventLogHours * 3600000)]]]" 2>$null
                
                if (Test-Path $logPath) {
                    "event_logs\$($log.File) - $($log.Description)" | Add-Content -Path $Script:ManifestFile
                }
            }
        }
        catch {
            Write-LogVerbose "Event log not available: $($log.Name)"
        }
    }
    
    # Export key security events to CSV for easier analysis
    Write-Log -Level "INFO" -Message "Exporting key security events to CSV..."
    
    $parsedDir = Join-Path $eventDir "parsed"
    New-Item -ItemType Directory -Path $parsedDir -Force | Out-Null
    
    # Logon events (4624, 4625, 4634, 4647, 4648)
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4634,4647,4648; StartTime=$startTime} -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, 
                @{N='LogonType';E={$_.Properties[8].Value}},
                @{N='TargetUserName';E={$_.Properties[5].Value}},
                @{N='TargetDomainName';E={$_.Properties[6].Value}},
                @{N='IpAddress';E={$_.Properties[18].Value}},
                @{N='ProcessName';E={$_.Properties[17].Value}} |
            Export-Csv -Path (Join-Path $parsedDir "logon_events.csv") -NoTypeInformation
    }
    catch {
        Write-LogVerbose "Could not export logon events: $_"
    }
    
    # Process creation events (4688)
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$startTime} -ErrorAction SilentlyContinue |
            Select-Object TimeCreated,
                @{N='NewProcessName';E={$_.Properties[5].Value}},
                @{N='CommandLine';E={$_.Properties[8].Value}},
                @{N='ParentProcessName';E={$_.Properties[13].Value}},
                @{N='SubjectUserName';E={$_.Properties[1].Value}} |
            Export-Csv -Path (Join-Path $parsedDir "process_creation_4688.csv") -NoTypeInformation
    }
    catch {
        Write-LogVerbose "Could not export process creation events: $_"
    }
    
    # PowerShell script block logging (4104)
    try {
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$startTime} -ErrorAction SilentlyContinue |
            Select-Object TimeCreated,
                @{N='ScriptBlockText';E={$_.Properties[2].Value}},
                @{N='ScriptBlockId';E={$_.Properties[3].Value}} |
            Export-Csv -Path (Join-Path $parsedDir "powershell_scriptblocks.csv") -NoTypeInformation
    }
    catch {
        Write-LogVerbose "Could not export PowerShell script blocks: $_"
    }
    
    # Sysmon events (if available)
    try {
        $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
        if ($sysmonLog) {
            # Process Create (Event ID 1)
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$startTime} -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [xml]$xml = $_.ToXml()
                    $data = @{}
                    $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        ProcessId = $data.ProcessId
                        Image = $data.Image
                        CommandLine = $data.CommandLine
                        ParentImage = $data.ParentImage
                        User = $data.User
                        Hashes = $data.Hashes
                    }
                } | Export-Csv -Path (Join-Path $parsedDir "sysmon_process_create.csv") -NoTypeInformation
            
            # Network Connect (Event ID 3)
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3; StartTime=$startTime} -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [xml]$xml = $_.ToXml()
                    $data = @{}
                    $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        Image = $data.Image
                        DestinationIp = $data.DestinationIp
                        DestinationPort = $data.DestinationPort
                        DestinationHostname = $data.DestinationHostname
                        User = $data.User
                    }
                } | Export-Csv -Path (Join-Path $parsedDir "sysmon_network.csv") -NoTypeInformation
            
            # File Create (Event ID 11)
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11; StartTime=$startTime} -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [xml]$xml = $_.ToXml()
                    $data = @{}
                    $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        Image = $data.Image
                        TargetFilename = $data.TargetFilename
                    }
                } | Export-Csv -Path (Join-Path $parsedDir "sysmon_file_create.csv") -NoTypeInformation
            
            # Registry Events (Event ID 12, 13, 14)
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=12,13,14; StartTime=$startTime} -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [xml]$xml = $_.ToXml()
                    $data = @{}
                    $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        EventType = $data.EventType
                        Image = $data.Image
                        TargetObject = $data.TargetObject
                        Details = $data.Details
                    }
                } | Export-Csv -Path (Join-Path $parsedDir "sysmon_registry.csv") -NoTypeInformation
        }
    }
    catch {
        Write-LogVerbose "Could not export Sysmon events: $_"
    }
    
    Write-Log -Level "INFO" -Message "Event logs collected"
}

function Get-PersistenceMechanisms {
    Write-Log -Level "INFO" -Message "Collecting persistence mechanisms..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: Persistence mechanisms"
        return
    }
    
    $persistDir = Join-Path $Script:OutputDir "persistence"
    New-Item -ItemType Directory -Path $persistDir -Force | Out-Null
    
    # Scheduled Tasks
    Write-LogVerbose "Collecting scheduled tasks..."
    $tasksDir = Join-Path $persistDir "scheduled_tasks"
    New-Item -ItemType Directory -Path $tasksDir -Force | Out-Null
    
    Get-ScheduledTask | 
        Select-Object TaskName, TaskPath, State, 
            @{N='Author';E={$_.Principal.UserId}},
            @{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "}} |
        Export-Csv -Path (Join-Path $tasksDir "scheduled_tasks.csv") -NoTypeInformation
    
    # Export task XML files
    $taskXmlDir = Join-Path $tasksDir "xml"
    New-Item -ItemType Directory -Path $taskXmlDir -Force | Out-Null
    Get-ScheduledTask | ForEach-Object {
        $safeName = ($_.TaskPath + $_.TaskName) -replace '[\\/:*?"<>|]', '_'
        Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath 2>$null | 
            Out-File -FilePath (Join-Path $taskXmlDir "$safeName.xml") -Encoding UTF8
    }
    
    # Services
    Write-LogVerbose "Collecting services..."
    Get-CimInstance Win32_Service | 
        Select-Object Name, DisplayName, State, StartMode, PathName, StartName, Description |
        Export-Csv -Path (Join-Path $persistDir "services.csv") -NoTypeInformation
    
    # Registry Run Keys
    Write-LogVerbose "Collecting registry run keys..."
    $runKeysDir = Join-Path $persistDir "registry_run_keys"
    New-Item -ItemType Directory -Path $runKeysDir -Force | Out-Null
    
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    
    $runKeyResults = @()
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $runKeyResults += [PSCustomObject]@{
                    KeyPath = $key
                    Name = $_.Name
                    Value = $_.Value
                }
            }
        }
    }
    $runKeyResults | Export-Csv -Path (Join-Path $runKeysDir "run_keys.csv") -NoTypeInformation
    
    # Startup Folders
    Write-LogVerbose "Collecting startup folders..."
    $startupDir = Join-Path $persistDir "startup_folders"
    New-Item -ItemType Directory -Path $startupDir -Force | Out-Null
    
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $destName = if ($path -match "ProgramData") { "all_users" } else { "current_user" }
            Copy-Item -Path $path -Destination (Join-Path $startupDir $destName) -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # WMI Subscriptions
    Write-LogVerbose "Collecting WMI subscriptions..."
    $wmiDir = Join-Path $persistDir "wmi_subscriptions"
    New-Item -ItemType Directory -Path $wmiDir -Force | Out-Null
    
    Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
        Export-Csv -Path (Join-Path $wmiDir "event_filters.csv") -NoTypeInformation
    
    Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Export-Csv -Path (Join-Path $wmiDir "event_consumers.csv") -NoTypeInformation
    
    Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Export-Csv -Path (Join-Path $wmiDir "filter_bindings.csv") -NoTypeInformation
    
    # COM Hijacking locations
    Write-LogVerbose "Collecting COM objects..."
    $comDir = Join-Path $persistDir "com_objects"
    New-Item -ItemType Directory -Path $comDir -Force | Out-Null
    
    $clsidPaths = @(
        "HKLM:\SOFTWARE\Classes\CLSID",
        "HKCU:\SOFTWARE\Classes\CLSID"
    )
    
    foreach ($clsidPath in $clsidPaths) {
        if (Test-Path $clsidPath) {
            $hive = if ($clsidPath -match "HKLM") { "HKLM" } else { "HKCU" }
            Get-ChildItem -Path $clsidPath -ErrorAction SilentlyContinue | ForEach-Object {
                $inprocServer = Join-Path $_.PSPath "InprocServer32"
                $localServer = Join-Path $_.PSPath "LocalServer32"
                if ((Test-Path $inprocServer) -or (Test-Path $localServer)) {
                    [PSCustomObject]@{
                        Hive = $hive
                        CLSID = $_.PSChildName
                        InprocServer32 = (Get-ItemProperty -Path $inprocServer -ErrorAction SilentlyContinue).'(default)'
                        LocalServer32 = (Get-ItemProperty -Path $localServer -ErrorAction SilentlyContinue).'(default)'
                    }
                }
            } | Export-Csv -Path (Join-Path $comDir "${hive}_clsid.csv") -NoTypeInformation -Append
        }
    }
    
    # Image File Execution Options
    Write-LogVerbose "Collecting IFEO entries..."
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) {
        Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
            $debugger = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                [PSCustomObject]@{
                    ImageName = $_.PSChildName
                    Debugger = $debugger
                }
            }
        } | Export-Csv -Path (Join-Path $persistDir "ifeo_debuggers.csv") -NoTypeInformation
    }
    
    # AppInit DLLs
    $appInitPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )
    
    $appInitResults = @()
    foreach ($path in $appInitPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $appInitResults += [PSCustomObject]@{
                Path = $path
                AppInit_DLLs = $props.AppInit_DLLs
                LoadAppInit_DLLs = $props.LoadAppInit_DLLs
            }
        }
    }
    $appInitResults | Export-Csv -Path (Join-Path $persistDir "appinit_dlls.csv") -NoTypeInformation
    
    # Drivers
    Write-LogVerbose "Collecting drivers..."
    Get-CimInstance Win32_SystemDriver | 
        Select-Object Name, DisplayName, State, StartMode, PathName |
        Export-Csv -Path (Join-Path $persistDir "drivers.csv") -NoTypeInformation
    
    # Browser Extensions paths
    Write-LogVerbose "Collecting browser extension paths..."
    $extensionsDir = Join-Path $persistDir "browser_extensions"
    New-Item -ItemType Directory -Path $extensionsDir -Force | Out-Null
    
    $chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    $edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    
    if (Test-Path $chromeExtPath) {
        Get-ChildItem -Path $chromeExtPath -Directory -ErrorAction SilentlyContinue |
            Select-Object Name, FullName, CreationTime, LastWriteTime |
            Export-Csv -Path (Join-Path $extensionsDir "chrome_extensions.csv") -NoTypeInformation
    }
    
    if (Test-Path $edgeExtPath) {
        Get-ChildItem -Path $edgeExtPath -Directory -ErrorAction SilentlyContinue |
            Select-Object Name, FullName, CreationTime, LastWriteTime |
            Export-Csv -Path (Join-Path $extensionsDir "edge_extensions.csv") -NoTypeInformation
    }
    
    "persistence\ - Persistence mechanisms" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "Persistence mechanisms collected"
}

function Get-NetworkInformation {
    Write-Log -Level "INFO" -Message "Collecting network information..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: Network configuration"
        return
    }
    
    $netDir = Join-Path $Script:OutputDir "network"
    New-Item -ItemType Directory -Path $netDir -Force | Out-Null
    
    # Network interfaces
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed |
        Export-Csv -Path (Join-Path $netDir "adapters.csv") -NoTypeInformation
    
    Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily, PrefixLength |
        Export-Csv -Path (Join-Path $netDir "ip_addresses.csv") -NoTypeInformation
    
    # IP Configuration
    ipconfig /all | Out-File -FilePath (Join-Path $netDir "ipconfig_all.txt") -Encoding UTF8
    
    # Routing table
    Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias |
        Export-Csv -Path (Join-Path $netDir "routes.csv") -NoTypeInformation
    
    route print | Out-File -FilePath (Join-Path $netDir "route_print.txt") -Encoding UTF8
    
    # ARP cache
    Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias |
        Export-Csv -Path (Join-Path $netDir "arp_cache.csv") -NoTypeInformation
    
    arp -a | Out-File -FilePath (Join-Path $netDir "arp_table.txt") -Encoding UTF8
    
    # DNS configuration
    Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses |
        Export-Csv -Path (Join-Path $netDir "dns_servers.csv") -NoTypeInformation
    
    # DNS cache
    Get-DnsClientCache -ErrorAction SilentlyContinue | 
        Select-Object Entry, RecordName, RecordType, Data, TimeToLive |
        Export-Csv -Path (Join-Path $netDir "dns_cache.csv") -NoTypeInformation
    
    ipconfig /displaydns | Out-File -FilePath (Join-Path $netDir "dns_cache_display.txt") -Encoding UTF8
    
    # Active connections
    Get-NetTCPConnection | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Export-Csv -Path (Join-Path $netDir "tcp_connections.csv") -NoTypeInformation
    
    Get-NetUDPEndpoint |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Export-Csv -Path (Join-Path $netDir "udp_endpoints.csv") -NoTypeInformation
    
    netstat -ano | Out-File -FilePath (Join-Path $netDir "netstat_ano.txt") -Encoding UTF8
    netstat -anob 2>$null | Out-File -FilePath (Join-Path $netDir "netstat_anob.txt") -Encoding UTF8
    
    # Firewall status
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Export-Csv -Path (Join-Path $netDir "firewall_profiles.csv") -NoTypeInformation
    
    # Firewall rules (enabled only to reduce size)
    Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, Direction, Action, Protocol, LocalPort, RemoteAddress |
        Export-Csv -Path (Join-Path $netDir "firewall_rules_enabled.csv") -NoTypeInformation
    
    # Hosts file
    Copy-Artefact -Source "$env:SystemRoot\System32\drivers\etc\hosts" -DestinationSubDir "network" -Description "Hosts file"
    
    # Network shares
    Get-SmbShare -ErrorAction SilentlyContinue | 
        Select-Object Name, Path, Description |
        Export-Csv -Path (Join-Path $netDir "smb_shares.csv") -NoTypeInformation
    
    net share | Out-File -FilePath (Join-Path $netDir "net_share.txt") -Encoding UTF8
    
    # SMB Sessions
    Get-SmbSession -ErrorAction SilentlyContinue |
        Select-Object ClientComputerName, ClientUserName, NumOpens |
        Export-Csv -Path (Join-Path $netDir "smb_sessions.csv") -NoTypeInformation
    
    # Saved WiFi profiles
    netsh wlan show profiles | Out-File -FilePath (Join-Path $netDir "wifi_profiles.txt") -Encoding UTF8
    
    "network\ - Network configuration" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "Network information collected"
}

function Get-BrowserArtefacts {
    Write-Log -Level "INFO" -Message "Collecting browser artefacts..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: Browser artefacts"
        return
    }
    
    $browserDir = Join-Path $Script:OutputDir "browser_artefacts"
    New-Item -ItemType Directory -Path $browserDir -Force | Out-Null
    
    # Chrome
    $chromeDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    if (Test-Path $chromeDir) {
        $chromeDest = Join-Path $browserDir "chrome"
        New-Item -ItemType Directory -Path $chromeDest -Force | Out-Null
        
        $chromeFiles = @("History", "Cookies", "Login Data", "Bookmarks", "Preferences", "Web Data", "Top Sites")
        foreach ($file in $chromeFiles) {
            $srcPath = Join-Path $chromeDir $file
            if (Test-Path $srcPath) {
                Copy-Item -Path $srcPath -Destination $chromeDest -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Parse Chrome history if sqlite3 is available
        $historyPath = Join-Path $chromeDir "History"
        if ((Test-Path $historyPath) -and (Get-Command sqlite3 -ErrorAction SilentlyContinue)) {
            $parsedDir = Join-Path $chromeDest "parsed"
            New-Item -ItemType Directory -Path $parsedDir -Force | Out-Null
            
            # Copy history to temp to avoid locking issues
            $tempHistory = Join-Path $env:TEMP "chrome_history_temp"
            Copy-Item -Path $historyPath -Destination $tempHistory -Force -ErrorAction SilentlyContinue
            
            if (Test-Path $tempHistory) {
                sqlite3 $tempHistory "SELECT datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') AS visit_time, url, title, visit_count FROM urls ORDER BY last_visit_time DESC;" 2>$null |
                    Out-File -FilePath (Join-Path $parsedDir "urls.txt") -Encoding UTF8
                
                sqlite3 $tempHistory "SELECT datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') AS start_time, current_path, tab_url, total_bytes FROM downloads ORDER BY start_time DESC;" 2>$null |
                    Out-File -FilePath (Join-Path $parsedDir "downloads.txt") -Encoding UTF8
                
                Remove-Item $tempHistory -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Edge (Chromium-based)
    $edgeDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    if (Test-Path $edgeDir) {
        $edgeDest = Join-Path $browserDir "edge"
        New-Item -ItemType Directory -Path $edgeDest -Force | Out-Null
        
        $edgeFiles = @("History", "Cookies", "Login Data", "Bookmarks", "Preferences", "Web Data")
        foreach ($file in $edgeFiles) {
            $srcPath = Join-Path $edgeDir $file
            if (Test-Path $srcPath) {
                Copy-Item -Path $srcPath -Destination $edgeDest -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Firefox
    $firefoxProfilesDir = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilesDir) {
        $firefoxDest = Join-Path $browserDir "firefox"
        New-Item -ItemType Directory -Path $firefoxDest -Force | Out-Null
        
        Get-ChildItem -Path $firefoxProfilesDir -Directory | ForEach-Object {
            $profileDest = Join-Path $firefoxDest $_.Name
            New-Item -ItemType Directory -Path $profileDest -Force | Out-Null
            
            $firefoxFiles = @("places.sqlite", "cookies.sqlite", "logins.json", "formhistory.sqlite", "extensions.json", "cert9.db")
            foreach ($file in $firefoxFiles) {
                $srcPath = Join-Path $_.FullName $file
                if (Test-Path $srcPath) {
                    Copy-Item -Path $srcPath -Destination $profileDest -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    
    # Internet Explorer / Legacy Edge
    $ieDir = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    $ieHistoryDir = "$env:LOCALAPPDATA\Microsoft\Windows\History"
    $ieCookiesDir = "$env:LOCALAPPDATA\Microsoft\Windows\INetCookies"
    
    $ieDest = Join-Path $browserDir "internet_explorer"
    New-Item -ItemType Directory -Path $ieDest -Force | Out-Null
    
    # IE Typed URLs
    $typedURLsPath = "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"
    if (Test-Path $typedURLsPath) {
        Get-ItemProperty -Path $typedURLsPath -ErrorAction SilentlyContinue |
            Out-File -FilePath (Join-Path $ieDest "typed_urls.txt") -Encoding UTF8
    }
    
    "browser_artefacts\ - Browser artefacts" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "Browser artefacts collected"
}

function Get-UserActivity {
    Write-Log -Level "INFO" -Message "Collecting user activity artefacts..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: User activity artefacts"
        return
    }
    
    $activityDir = Join-Path $Script:OutputDir "user_activity"
    New-Item -ItemType Directory -Path $activityDir -Force | Out-Null
    
    # Recent files
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        Copy-Item -Path $recentPath -Destination (Join-Path $activityDir "recent") -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Jump Lists
    $jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    $jumpListCustomPath = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
    
    if (Test-Path $jumpListPath) {
        Copy-Item -Path $jumpListPath -Destination (Join-Path $activityDir "jump_lists_auto") -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    if (Test-Path $jumpListCustomPath) {
        Copy-Item -Path $jumpListCustomPath -Destination (Join-Path $activityDir "jump_lists_custom") -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Prefetch (requires admin)
    $prefetchPath = "$env:SystemRoot\Prefetch"
    if ((Test-Path $prefetchPath) -and (Test-Administrator)) {
        $prefetchDest = Join-Path $activityDir "prefetch"
        New-Item -ItemType Directory -Path $prefetchDest -Force | Out-Null
        
        Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
            ForEach-Object {
                Copy-Item -Path $_.FullName -Destination $prefetchDest -Force -ErrorAction SilentlyContinue
            }
        
        # List prefetch files with timestamps
        Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
            Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, Length |
            Export-Csv -Path (Join-Path $activityDir "prefetch_list.csv") -NoTypeInformation
    }
    
    # SRUM (System Resource Usage Monitor) - requires admin
    $srumPath = "$env:SystemRoot\System32\sru\SRUDB.dat"
    if ((Test-Path $srumPath) -and (Test-Administrator)) {
        Copy-Item -Path $srumPath -Destination $activityDir -Force -ErrorAction SilentlyContinue
    }
    
    # BAM/DAM (Background Activity Moderator)
    $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    if (Test-Path $bamPath) {
        Get-ChildItem -Path $bamPath -ErrorAction SilentlyContinue | ForEach-Object {
            $sid = $_.PSChildName
            Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue |
                Out-File -FilePath (Join-Path $activityDir "bam_$sid.txt") -Encoding UTF8
        }
    }
    
    # Shellbags (user folder access history)
    $shellBagsPath = "HKCU:\SOFTWARE\Microsoft\Windows\Shell\BagMRU"
    if (Test-Path $shellBagsPath) {
        reg export "HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU" (Join-Path $activityDir "shellbags_bagmru.reg") 2>$null
        reg export "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags" (Join-Path $activityDir "shellbags_bags.reg") 2>$null
    }
    
    # UserAssist (program execution tracking)
    $userAssistPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    if (Test-Path $userAssistPath) {
        reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" (Join-Path $activityDir "userassist.reg") 2>$null
    }
    
    # MUI Cache
    $muiCachePath = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiCachePath) {
        Get-ItemProperty -Path $muiCachePath -ErrorAction SilentlyContinue |
            Out-File -FilePath (Join-Path $activityDir "muicache.txt") -Encoding UTF8
    }
    
    # AppCompatCache/Shimcache - requires parsing tool or raw registry
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" (Join-Path $activityDir "appcompatcache.reg") 2>$null
    
    # Amcache
    $amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
    if ((Test-Path $amcachePath) -and (Test-Administrator)) {
        Copy-Item -Path $amcachePath -Destination $activityDir -Force -ErrorAction SilentlyContinue
    }
    
    # Windows Timeline (ActivitiesCache.db)
    $timelinePath = "$env:LOCALAPPDATA\ConnectedDevicesPlatform"
    if (Test-Path $timelinePath) {
        Get-ChildItem -Path $timelinePath -Recurse -Filter "ActivitiesCache.db" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $destName = "timeline_" + ($_.Directory.Name) + ".db"
                Copy-Item -Path $_.FullName -Destination (Join-Path $activityDir $destName) -Force -ErrorAction SilentlyContinue
            }
    }
    
    # Recycle Bin metadata
    $recycleBinPath = "C:\`$Recycle.Bin"
    if ((Test-Path $recycleBinPath) -and (Test-Administrator)) {
        Get-ChildItem -Path $recycleBinPath -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object FullName, CreationTime, LastWriteTime, Length |
            Export-Csv -Path (Join-Path $activityDir "recycle_bin_contents.csv") -NoTypeInformation
    }
    
    "user_activity\ - User activity artefacts" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "User activity artefacts collected"
}

function Get-SecurityArtefacts {
    Write-Log -Level "INFO" -Message "Collecting security artefacts..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: Security artefacts"
        return
    }
    
    $securityDir = Join-Path $Script:OutputDir "security"
    New-Item -ItemType Directory -Path $securityDir -Force | Out-Null
    
    # Windows Defender status
    Get-MpComputerStatus -ErrorAction SilentlyContinue |
        Out-File -FilePath (Join-Path $securityDir "defender_status.txt") -Encoding UTF8
    
    Get-MpPreference -ErrorAction SilentlyContinue |
        Out-File -FilePath (Join-Path $securityDir "defender_preferences.txt") -Encoding UTF8
    
    # Defender threat history
    Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Export-Csv -Path (Join-Path $securityDir "defender_threat_detections.csv") -NoTypeInformation
    
    Get-MpThreat -ErrorAction SilentlyContinue |
        Export-Csv -Path (Join-Path $securityDir "defender_threats.csv") -NoTypeInformation
    
    # Defender exclusions
    $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
    if ($exclusions) {
        [PSCustomObject]@{
            ExclusionPath = $exclusions.ExclusionPath -join "; "
            ExclusionExtension = $exclusions.ExclusionExtension -join "; "
            ExclusionProcess = $exclusions.ExclusionProcess -join "; "
            ExclusionIpAddress = $exclusions.ExclusionIpAddress -join "; "
        } | Export-Csv -Path (Join-Path $securityDir "defender_exclusions.csv") -NoTypeInformation
    }
    
    # Audit policy
    auditpol /get /category:* | Out-File -FilePath (Join-Path $securityDir "audit_policy.txt") -Encoding UTF8
    
    # Security policy
    secedit /export /cfg (Join-Path $securityDir "security_policy.inf") 2>$null
    
    # Local security policy
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue |
        Out-File -FilePath (Join-Path $securityDir "lsa_settings.txt") -Encoding UTF8
    
    # Credential Guard status
    Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue |
        Out-File -FilePath (Join-Path $securityDir "device_guard_status.txt") -Encoding UTF8
    
    # BitLocker status
    Get-BitLockerVolume -ErrorAction SilentlyContinue |
        Select-Object MountPoint, EncryptionMethod, VolumeStatus, ProtectionStatus |
        Export-Csv -Path (Join-Path $securityDir "bitlocker_status.csv") -NoTypeInformation
    
    # TPM status
    Get-Tpm -ErrorAction SilentlyContinue |
        Out-File -FilePath (Join-Path $securityDir "tpm_status.txt") -Encoding UTF8
    
    # LSASS protection
    $lsassProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if ($lsassProtection) {
        "LSASS Protection (RunAsPPL): $($lsassProtection.RunAsPPL)" | Out-File -FilePath (Join-Path $securityDir "lsass_protection.txt") -Encoding UTF8
    }
    
    # CrowdStrike Falcon (if installed)
    $csAgentInfo = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent" -ErrorAction SilentlyContinue
    if ($csAgentInfo) {
        Write-LogVerbose "CrowdStrike Falcon detected"
        $csAgentInfo | Out-File -FilePath (Join-Path $securityDir "crowdstrike_service.txt") -Encoding UTF8
        
        # CrowdStrike sensor version
        $csPath = "C:\Program Files\CrowdStrike"
        if (Test-Path $csPath) {
            Get-ChildItem -Path $csPath -ErrorAction SilentlyContinue |
                Select-Object Name, LastWriteTime |
                Export-Csv -Path (Join-Path $securityDir "crowdstrike_files.csv") -NoTypeInformation
        }
    }
    
    # Certificates (personal store)
    Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint |
        Export-Csv -Path (Join-Path $securityDir "user_certificates.csv") -NoTypeInformation
    
    Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint |
        Export-Csv -Path (Join-Path $securityDir "machine_certificates.csv") -NoTypeInformation
    
    "security\ - Security artefacts" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "Security artefacts collected"
}

function Get-ShellHistory {
    Write-Log -Level "INFO" -Message "Collecting shell history..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: Shell history"
        return
    }
    
    $historyDir = Join-Path $Script:OutputDir "shell_history"
    New-Item -ItemType Directory -Path $historyDir -Force | Out-Null
    
    # PowerShell history (PSReadLine)
    $psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistoryPath) {
        Copy-Item -Path $psHistoryPath -Destination (Join-Path $historyDir "powershell_history.txt") -Force -ErrorAction SilentlyContinue
    }
    
    # PowerShell ISE history
    $pseHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\Windows PowerShell ISE Host_history.txt"
    if (Test-Path $pseHistoryPath) {
        Copy-Item -Path $pseHistoryPath -Destination (Join-Path $historyDir "powershell_ise_history.txt") -Force -ErrorAction SilentlyContinue
    }
    
    # VS Code integrated terminal history
    $vscodeHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt"
    if (Test-Path $vscodeHistoryPath) {
        Copy-Item -Path $vscodeHistoryPath -Destination (Join-Path $historyDir "vscode_powershell_history.txt") -Force -ErrorAction SilentlyContinue
    }
    
    # CMD history from registry (Run dialog)
    $runMruPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    if (Test-Path $runMruPath) {
        Get-ItemProperty -Path $runMruPath -ErrorAction SilentlyContinue |
            Out-File -FilePath (Join-Path $historyDir "run_dialog_history.txt") -Encoding UTF8
    }
    
    # Python history
    $pythonHistoryPath = "$env:USERPROFILE\.python_history"
    if (Test-Path $pythonHistoryPath) {
        Copy-Item -Path $pythonHistoryPath -Destination (Join-Path $historyDir "python_history.txt") -Force -ErrorAction SilentlyContinue
    }
    
    # WSL Bash history (if WSL is installed)
    $wslBashHistory = "$env:LOCALAPPDATA\Packages\*Ubuntu*\LocalState\rootfs\home\*\.bash_history"
    Get-ChildItem -Path $wslBashHistory -ErrorAction SilentlyContinue | ForEach-Object {
        $destName = "wsl_bash_history_" + $_.Directory.Parent.Name + ".txt"
        Copy-Item -Path $_.FullName -Destination (Join-Path $historyDir $destName) -Force -ErrorAction SilentlyContinue
    }
    
    # Git Bash history
    $gitBashHistory = "$env:USERPROFILE\.bash_history"
    if (Test-Path $gitBashHistory) {
        Copy-Item -Path $gitBashHistory -Destination (Join-Path $historyDir "git_bash_history.txt") -Force -ErrorAction SilentlyContinue
    }
    
    # MySQL history
    $mysqlHistory = "$env:USERPROFILE\.mysql_history"
    if (Test-Path $mysqlHistory) {
        Copy-Item -Path $mysqlHistory -Destination (Join-Path $historyDir "mysql_history.txt") -Force -ErrorAction SilentlyContinue
    }
    
    "shell_history\ - Shell history" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "Shell history collected"
}

function Get-ApplicationArtefacts {
    Write-Log -Level "INFO" -Message "Collecting application artefacts..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: Application artefacts"
        return
    }
    
    $appsDir = Join-Path $Script:OutputDir "applications"
    New-Item -ItemType Directory -Path $appsDir -Force | Out-Null
    
    # Installed applications (Programs and Features)
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Where-Object { $_.DisplayName } |
        Export-Csv -Path (Join-Path $appsDir "installed_programs_hklm.csv") -NoTypeInformation
    
    Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Where-Object { $_.DisplayName } |
        Export-Csv -Path (Join-Path $appsDir "installed_programs_hklm_wow64.csv") -NoTypeInformation
    
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Where-Object { $_.DisplayName } |
        Export-Csv -Path (Join-Path $appsDir "installed_programs_hkcu.csv") -NoTypeInformation
    
    # Windows Store apps
    Get-AppxPackage -ErrorAction SilentlyContinue |
        Select-Object Name, PackageFullName, Version, Publisher, InstallLocation |
        Export-Csv -Path (Join-Path $appsDir "store_apps.csv") -NoTypeInformation
    
    # List of executables in common locations
    $exePaths = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:LOCALAPPDATA\Programs"
    )
    
    foreach ($path in $exePaths) {
        if (Test-Path $path) {
            $pathName = ($path -split '\\')[-1] -replace '[^a-zA-Z0-9]', '_'
            Get-ChildItem -Path $path -Filter "*.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                Select-Object Name, FullName, CreationTime, LastWriteTime, 
                    @{N='FileVersion';E={$_.VersionInfo.FileVersion}},
                    @{N='ProductName';E={$_.VersionInfo.ProductName}} |
                Export-Csv -Path (Join-Path $appsDir "executables_$pathName.csv") -NoTypeInformation
        }
    }
    
    # Windows optional features
    Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Enabled' } |
        Select-Object FeatureName, State |
        Export-Csv -Path (Join-Path $appsDir "windows_features_enabled.csv") -NoTypeInformation
    
    # pip packages (if Python installed)
    $pipPath = Get-Command pip -ErrorAction SilentlyContinue
    if ($pipPath) {
        pip list 2>$null | Out-File -FilePath (Join-Path $appsDir "pip_packages.txt") -Encoding UTF8
    }
    
    # npm global packages (if Node.js installed)
    $npmPath = Get-Command npm -ErrorAction SilentlyContinue
    if ($npmPath) {
        npm list -g --depth=0 2>$null | Out-File -FilePath (Join-Path $appsDir "npm_global_packages.txt") -Encoding UTF8
    }
    
    # Chocolatey packages (if installed)
    $chocoPath = Get-Command choco -ErrorAction SilentlyContinue
    if ($chocoPath) {
        choco list --local-only 2>$null | Out-File -FilePath (Join-Path $appsDir "chocolatey_packages.txt") -Encoding UTF8
    }
    
    # Winget packages (if available)
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        winget list 2>$null | Out-File -FilePath (Join-Path $appsDir "winget_packages.txt") -Encoding UTF8
    }
    
    "applications\ - Application artefacts" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "Application artefacts collected"
}

function Get-ConfigurationFiles {
    Write-Log -Level "INFO" -Message "Collecting configuration files..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: Configuration files"
        return
    }
    
    $configDir = Join-Path $Script:OutputDir "config_files"
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    
    # User configuration directories
    $userConfigDir = Join-Path $configDir "user"
    New-Item -ItemType Directory -Path $userConfigDir -Force | Out-Null
    
    # SSH configuration
    $sshDir = "$env:USERPROFILE\.ssh"
    if (Test-Path $sshDir) {
        $sshDest = Join-Path $userConfigDir "ssh"
        New-Item -ItemType Directory -Path $sshDest -Force | Out-Null
        
        # Copy config files but NOT private keys
        $sshFiles = @("config", "known_hosts", "authorized_keys")
        foreach ($file in $sshFiles) {
            $srcPath = Join-Path $sshDir $file
            if (Test-Path $srcPath) {
                Copy-Item -Path $srcPath -Destination $sshDest -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Git configuration
    Copy-Artefact -Source "$env:USERPROFILE\.gitconfig" -DestinationSubDir "config_files\user" -Description "Git config"
    Copy-Artefact -Source "$env:USERPROFILE\.gitignore_global" -DestinationSubDir "config_files\user" -Description "Git global ignore"
    
    # AWS configuration (credentials contain sensitive data - be careful)
    $awsDir = "$env:USERPROFILE\.aws"
    if (Test-Path $awsDir) {
        $awsDest = Join-Path $userConfigDir "aws"
        New-Item -ItemType Directory -Path $awsDest -Force | Out-Null
        Copy-Item -Path (Join-Path $awsDir "config") -Destination $awsDest -Force -ErrorAction SilentlyContinue
        Write-Log -Level "WARN" -Message "AWS config collected (credentials file excluded for security)"
    }
    
    # Azure CLI configuration
    Copy-Artefact -Source "$env:USERPROFILE\.azure" -DestinationSubDir "config_files\user\azure" -Description "Azure CLI config"
    
    # Docker configuration
    Copy-Artefact -Source "$env:USERPROFILE\.docker\config.json" -DestinationSubDir "config_files\user" -Description "Docker config"
    
    # Kubernetes configuration
    Copy-Artefact -Source "$env:USERPROFILE\.kube\config" -DestinationSubDir "config_files\user" -Description "Kubernetes config"
    Write-Log -Level "WARN" -Message "Kubernetes config may contain sensitive credentials"
    
    # VS Code settings
    $vscodeSettings = "$env:APPDATA\Code\User\settings.json"
    if (Test-Path $vscodeSettings) {
        Copy-Item -Path $vscodeSettings -Destination (Join-Path $userConfigDir "vscode_settings.json") -Force -ErrorAction SilentlyContinue
    }
    
    # System configuration
    $sysConfigDir = Join-Path $configDir "system"
    New-Item -ItemType Directory -Path $sysConfigDir -Force | Out-Null
    
    # System hosts file (already collected in network, but include here too)
    Copy-Artefact -Source "$env:SystemRoot\System32\drivers\etc\hosts" -DestinationSubDir "config_files\system" -Description "Hosts file"
    Copy-Artefact -Source "$env:SystemRoot\System32\drivers\etc\services" -DestinationSubDir "config_files\system" -Description "Services file"
    Copy-Artefact -Source "$env:SystemRoot\System32\drivers\etc\protocol" -DestinationSubDir "config_files\system" -Description "Protocol file"
    
    # Group Policy
    if (Test-Administrator) {
        gpresult /h (Join-Path $sysConfigDir "gpresult.html") 2>$null
        gpresult /r | Out-File -FilePath (Join-Path $sysConfigDir "gpresult_summary.txt") -Encoding UTF8
    }
    
    # System environment variables
    [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine) |
        Out-File -FilePath (Join-Path $sysConfigDir "system_env_vars.txt") -Encoding UTF8
    
    # Windows Firewall configuration export
    netsh advfirewall export (Join-Path $sysConfigDir "firewall_config.wfw") 2>$null
    
    "config_files\ - Configuration files" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "Configuration files collected"
}

function Get-USNJournal {
    Write-Log -Level "INFO" -Message "Collecting USN Journal information..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: USN Journal"
        return
    }
    
    if (-not (Test-Administrator)) {
        Write-Log -Level "WARN" -Message "USN Journal collection requires Administrator privileges - skipping"
        return
    }
    
    $usnDir = Join-Path $Script:OutputDir "usn_journal"
    New-Item -ItemType Directory -Path $usnDir -Force | Out-Null
    
    # Get USN Journal info
    fsutil usn queryjournal C: 2>$null | Out-File -FilePath (Join-Path $usnDir "usn_journal_info.txt") -Encoding UTF8
    
    # Export recent USN entries (this can be large, so we limit it)
    # Note: For full USN journal parsing, you'd need a tool like MFTECmd or similar
    Write-Log -Level "INFO" -Message "USN Journal info collected (full journal requires specialised tools)"
}

function Get-MFT {
    Write-Log -Level "INFO" -Message "Checking MFT accessibility..."
    
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "Would collect: MFT information"
        return
    }
    
    if (-not (Test-Administrator)) {
        Write-Log -Level "WARN" -Message "MFT collection requires Administrator privileges - skipping"
        return
    }
    
    $mftDir = Join-Path $Script:OutputDir "mft"
    New-Item -ItemType Directory -Path $mftDir -Force | Out-Null
    
    # Note: Actual MFT extraction requires specialised tools like RawCopy or FTK Imager
    # We'll just document the MFT location and provide metadata
    
    $mftInfo = @"
MFT Information
===============
The Master File Table (MFT) is located at: C:\`$MFT

To extract the MFT for forensic analysis, use one of these tools:
- RawCopy (https://github.com/jschicht/RawCopy)
- FTK Imager (AccessData)
- Eric Zimmerman's MFTECmd (https://ericzimmerman.github.io/)
- KAPE (Kroll Artifact Parser and Extractor)

Volume Information:
$(fsutil volume diskfree C: 2>$null)

File System Information:
$(fsutil fsinfo ntfsinfo C: 2>$null)
"@
    
    $mftInfo | Out-File -FilePath (Join-Path $mftDir "mft_info.txt") -Encoding UTF8
    
    "mft\ - MFT information" | Add-Content -Path $Script:ManifestFile
    Write-Log -Level "INFO" -Message "MFT information collected"
}

function New-Hashes {
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "DRY RUN: Would generate SHA256 hashes"
        return
    }
    
    Write-Log -Level "INFO" -Message "Generating SHA256 hashes for collected files..."
    
    $excludeFiles = @(
        (Split-Path $Script:HashFile -Leaf),
        (Split-Path $Script:LogFile -Leaf),
        (Split-Path $Script:ManifestFile -Leaf),
        (Split-Path $Script:ErrorLogFile -Leaf)
    )
    
    Get-ChildItem -Path $Script:OutputDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $excludeFiles -notcontains $_.Name } |
        ForEach-Object {
            try {
                $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction Stop
                "$($hash.Hash)  $($_.FullName -replace [regex]::Escape($Script:OutputDir), '.')" | 
                    Add-Content -Path $Script:HashFile -ErrorAction SilentlyContinue
            }
            catch {
                Write-LogVerbose "Failed to hash: $($_.FullName)"
            }
        }
    
    # Hash the manifest and log files
    @($Script:ManifestFile, $Script:LogFile, $Script:ErrorLogFile) | ForEach-Object {
        if (Test-Path $_) {
            try {
                $hash = Get-FileHash -Path $_ -Algorithm SHA256 -ErrorAction Stop
                "$($hash.Hash)  $($_ -replace [regex]::Escape($Script:OutputDir), '.')" | 
                    Add-Content -Path $Script:HashFile -ErrorAction SilentlyContinue
            }
            catch {
                Write-LogVerbose "Failed to hash: $_"
            }
        }
    }
    
    Write-Log -Level "INFO" -Message "SHA256 hashes generated in $Script:HashFile"
}

function Compress-Collection {
    if ($DryRun) {
        Write-Log -Level "INFO" -Message "DRY RUN: Would compress collection to .zip"
        return
    }
    
    Write-Log -Level "INFO" -Message "Compressing collection..."
    
    $archivePath = "$Script:OutputDir.zip"
    
    try {
        Compress-Archive -Path $Script:OutputDir -DestinationPath $archivePath -CompressionLevel Optimal -Force
        Write-Log -Level "INFO" -Message "Collection compressed to: $archivePath"
        
        # Generate hash of archive
        $archiveHash = Get-FileHash -Path $archivePath -Algorithm SHA256
        "$($archiveHash.Hash)  $(Split-Path $archivePath -Leaf)" | 
            Out-File -FilePath "$archivePath.sha256" -Encoding UTF8
        
        Write-Log -Level "INFO" -Message "Archive hash: $archivePath.sha256"
    }
    catch {
        Write-Log -Level "WARN" -Message "Failed to compress collection: $_"
    }
}

# =============================================================================
# Main Execution
# =============================================================================

function Main {
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "  Windows IR Log Collector v$Script:Version" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check privileges
    if (-not (Test-Administrator)) {
        Write-Log -Level "WARN" -Message "Not running as Administrator. Some artefacts may not be collected."
        Write-Log -Level "WARN" -Message "Re-run with elevated privileges for complete collection."
    }
    
    # Initialise collection
    Initialize-Collection
    
    # Run collections
    Get-SystemInformation
    Get-EventLogs
    Get-PersistenceMechanisms
    Get-NetworkInformation
    Get-BrowserArtefacts
    Get-UserActivity
    Get-SecurityArtefacts
    Get-ShellHistory
    Get-ApplicationArtefacts
    Get-ConfigurationFiles
    Get-USNJournal
    Get-MFT
    
    # Finalise
    New-Hashes
    Compress-Collection
    
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "  Collection Complete" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not $DryRun) {
        Write-Log -Level "INFO" -Message "Output directory: $Script:OutputDir"
        Write-Log -Level "INFO" -Message "Compressed archive: $Script:OutputDir.zip"
        Write-Log -Level "INFO" -Message "Manifest: $Script:ManifestFile"
        Write-Log -Level "INFO" -Message "Hashes: $Script:HashFile"
        
        # Show size
        $size = (Get-ChildItem -Path $Script:OutputDir -Recurse -ErrorAction SilentlyContinue | 
            Measure-Object -Property Length -Sum).Sum
        $sizeFormatted = "{0:N2} MB" -f ($size / 1MB)
        Write-Log -Level "INFO" -Message "Total size: $sizeFormatted"
        
        # Show duration
        $duration = (Get-Date) - $Script:StartTime
        Write-Log -Level "INFO" -Message "Duration: $($duration.ToString('hh\:mm\:ss'))"
    }
    
    Write-Host ""
}

# Execute main function
Main
