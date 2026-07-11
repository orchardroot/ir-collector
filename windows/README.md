# windows-ir-collector

Windows incident response triage collector. Gathers forensically valuable artefacts from Windows systems for investigation and threat hunting.

## Overview

A PowerShell-based collection tool that rapidly extracts key artefacts from Windows endpoints during incident response. Designed to be deployed quickly, run with minimal dependencies, and produce a portable evidence package ready for analysis.

## Features

- **System Information** — OS details, hardware, installed software, environment
- **Event Logs** — Security, System, Application, PowerShell, Sysmon, Windows Defender
- **Persistence Mechanisms** — Registry run keys, scheduled tasks, services, startup items, WMI subscriptions
- **Network Configuration** — Connections, ARP cache, DNS cache, firewall rules, routing tables
- **Browser Artefacts** — Chrome, Firefox, Edge history, downloads, extensions
- **User Activity** — Recent files, jump lists, shellbags, UserAssist, RDP history
- **Security Artefacts** — Windows Defender logs, AMSI, Credential Guard status
- **Shell History** — PowerShell, CMD, WSL bash history
- **Application Artefacts** — Office MRU, Outlook, Sticky Notes, clipboard
- **Configuration Files** — SSH, Git, AWS, Azure, Kubernetes configs
- **Filesystem Metadata** — USN Journal info, MFT location details

All collected files are hashed (SHA256) and a manifest is generated for chain of custody.

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges recommended (some artefacts require elevation)

## Usage

```powershell
# Basic collection (default output to Desktop)
.\windows_ir_collector.ps1

# Specify output directory
.\windows_ir_collector.ps1 -OutputDir "C:\IR\Collection"

# Dry run - show what would be collected
.\windows_ir_collector.ps1 -DryRun

# Collect 72 hours of event logs (default is 24)
.\windows_ir_collector.ps1 -EventLogHours 72

# Skip event log collection (faster)
.\windows_ir_collector.ps1 -SkipEventLogs

# Verbose output
.\windows_ir_collector.ps1 -Verbose
```

## Output Structure

```
IR_Collection_<hostname>_<timestamp>/
├── system_info/           # OS, hardware, processes, services
├── event_logs/            # Exported .evtx files
├── persistence/           # Registry exports, scheduled tasks
├── network/               # Connections, configs, firewall
├── browser_data/          # Chrome, Firefox, Edge artefacts
├── user_activity/         # Recent files, jump lists, shellbags
├── security/              # Defender, AMSI, security config
├── shell_history/         # PowerShell, CMD, WSL history
├── application_data/      # Office, Outlook, app artefacts
├── config_files/          # SSH, Git, cloud provider configs
├── usn_journal/           # USN Journal metadata
├── mft/                   # MFT location and volume info
├── collection.log         # Collection log
├── manifest.txt           # File manifest
├── hashes.sha256          # SHA256 hashes of all collected files
└── error_collection.log   # Any errors during collection
```

A compressed `.zip` archive is automatically created alongside the collection directory.

## Artefacts Collected

| Category | Artefacts |
|----------|-----------|
| Event Logs | Security, System, Application, PowerShell, Sysmon, WinRM, TaskScheduler, Defender |
| Persistence | Run/RunOnce keys, Services, Scheduled Tasks, Startup folders, WMI subscriptions |
| Network | netstat, arp cache, DNS cache, route table, hosts file, firewall rules |
| Browser | History, downloads, extensions (Chrome, Firefox, Edge) |
| User Activity | Recent files, Jump Lists, Shellbags, UserAssist, LNK files |
| Security | Defender exclusions, AMSI providers, LSA protection status |
| Shell History | PSReadLine, ConsoleHost_history, CMD doskey, WSL bash_history |
| Configs | SSH keys/config, Git config, AWS/Azure/GCP credentials, kubeconfig |

## Notes

- Some artefacts require Administrator privileges; the tool will warn and skip inaccessible items when run unprivileged
- Browser artefacts are collected from all user profiles where accessible
- Sensitive configurations (SSH keys, cloud credentials) are collected and flagged with warnings
- For full MFT extraction, use dedicated tools like KAPE, MFTECmd, or RawCopy
- Event log time window is configurable via `-EventLogHours` parameter

## Companion Tools

For macOS collection, see [mac-ir-collector](https://github.com/orchardroot/mac-ir-collector).

## Author

**Orchardroot**  
[github.com/orchardroot](https://github.com/orchardroot)

## Licence

MIT — see [LICENCE](LICENCE) for details.
