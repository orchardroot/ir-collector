# ir-collector

Cross-platform **incident-response triage collectors**: two standalone scripts — one Bash, one PowerShell — that rapidly gather the forensically useful logs and artefacts from an endpoint and package them into a hashed, portable evidence archive.

I run a SOC. When a box looks wrong at 02:00, the thing I want is *everything that matters, off the host, hashed, in one archive, in minutes* — before anyone reboots it, before the attacker notices, and before I have to argue with a forensic suite's licence server. These scripts are that. No installer, no agent, no dependencies beyond what the OS ships with. Copy one file on, run it, copy one archive off.

| Platform | Script | Language |
|----------|--------|----------|
| macOS | [`macos/mac_ir_collector.sh`](macos/mac_ir_collector.sh) | Bash |
| Windows | [`windows/windows_ir_collector.ps1`](windows/windows_ir_collector.ps1) | PowerShell |

Both produce an `IR_Collection_<hostname>_<timestamp>/` directory containing a `manifest.txt`, SHA256 `hashes.sha256` for chain of custody, a `collection.log` and an `error_collection.log`, then compress the lot into a single archive.

---

## macOS — `mac_ir_collector.sh`

Collects `/var/log`, Apple unified logs (targeted at auth/sudo/SSH/kernel/XProtect/Gatekeeper/Endpoint Security, plus CrowdStrike Falcon and Google Santa), BSM audit logs, persistence (LaunchDaemons/Agents, cron, login hooks, kexts, system extensions), network state, browser artefacts (Safari/Chrome/Firefox/Edge, raw + parsed), user activity (KnowledgeC, recent items), security databases (TCC, quarantine, XProtect, Gatekeeper), shell history, config/credential dirs, and diagnostic reports.

```bash
sudo ./macos/mac_ir_collector.sh [OUTPUT_DIR] [OPTIONS]
```

| Option | Meaning |
|--------|---------|
| `-n, --dry-run` | Show what would be collected without copying |
| `-v, --verbose` | Detailed output |
| `-u, --unified-hours N` | Hours of unified logs to collect (default 24) |
| `--no-unified` | Skip unified logs (much faster) |
| `-h, --help` | Help |

Requires macOS 10.12+; run with `sudo` for a complete collection.

## Windows — `windows_ir_collector.ps1`

Gathers system info, event logs (Security/System/Application/PowerShell/Sysmon/Defender), persistence (run keys, scheduled tasks, services, startup, WMI subscriptions), network state, browser artefacts (Chrome/Firefox/Edge), user activity (recent files, jump lists, shellbags, UserAssist, RDP history), security artefacts (Defender, AMSI, Credential Guard), shell history (PowerShell/CMD/WSL), application artefacts (Office MRU, Outlook), config/credential files, and filesystem metadata (USN Journal, MFT location).

```powershell
.\windows\windows_ir_collector.ps1                              # default output to Desktop
.\windows\windows_ir_collector.ps1 -OutputDir "C:\IR\Collection"
.\windows\windows_ir_collector.ps1 -DryRun
.\windows\windows_ir_collector.ps1 -EventLogHours 72
.\windows\windows_ir_collector.ps1 -SkipEventLogs
```

Requires Windows 10/11 or Server 2016+, PowerShell 5.1+; Administrator recommended.

---

## Things I'd want to know before running it on my own estate

- **Elevation.** Some artefacts need root/Administrator. Both scripts warn and skip what they can't read when run unprivileged, and log the details to `error_collection.log` — you get a partial collection, not a failure.
- **Sensitive data — this is the important one.** Both collectors deliberately gather credential material: SSH keys, `.aws`, `.kube`, cloud creds, `.gnupg`, browser databases. That is the point of triage, and it also means the resulting archive is now the most sensitive file on your network. Treat it like evidence: encrypt it in transit, store it somewhere access-controlled, and record who has had it.
- **Dry-run first** on a new build of anything. `-n` / `-DryRun` shows you exactly what would be touched.
- **MFT.** The Windows collector records where the MFT is; for a full extraction use a dedicated tool (KAPE, MFTECmd, RawCopy). This is a triage script, not a full-disk imager, and it doesn't pretend otherwise.

## History

This repository combines the previously separate `mac-ir-collector` and `win-ir-collector` projects; the original commit history of both is preserved under `macos/` and `windows/`.

## Licence

MIT — see [LICENSE](LICENSE). Use it, fork it, adapt it to your estate; if you improve it, a PR would be lovely.

---

*orchardroot — made in Cheshire, under the supervision of two cats.*
