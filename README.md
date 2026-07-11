# ir-collector

Cross-platform **incident-response triage collectors**. Two standalone scripts that
rapidly gather forensically valuable logs and artefacts from an endpoint during an
investigation and package them into a hashed, portable evidence archive.

| Platform | Script | Language |
|----------|--------|----------|
| macOS | [`macos/mac_ir_collector.sh`](macos/mac_ir_collector.sh) | Bash |
| Windows | [`windows/windows_ir_collector.ps1`](windows/windows_ir_collector.ps1) | PowerShell |

Both produce an `IR_Collection_<hostname>_<timestamp>/` directory with a `manifest.txt`,
SHA256 `hashes.sha256` for chain of custody, a `collection.log`, and an
`error_collection.log`, then compress it to a single archive.

---

## macOS — `mac_ir_collector.sh`

Collects `/var/log`, Apple unified logs (targeted at auth/sudo/SSH/kernel/XProtect/
Gatekeeper/Endpoint Security, plus CrowdStrike Falcon and Google Santa), BSM audit
logs, persistence (LaunchDaemons/Agents, cron, login hooks, kexts, system extensions),
network state, browser artefacts (Safari/Chrome/Firefox/Edge, raw + parsed), user
activity (KnowledgeC, recent items), security databases (TCC, quarantine, XProtect,
Gatekeeper), shell history, config/credential dirs, and diagnostic reports.

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

Gathers system info, event logs (Security/System/Application/PowerShell/Sysmon/
Defender), persistence (run keys, scheduled tasks, services, startup, WMI
subscriptions), network state, browser artefacts (Chrome/Firefox/Edge), user activity
(recent files, jump lists, shellbags, UserAssist, RDP history), security artefacts
(Defender, AMSI, Credential Guard), shell history (PowerShell/CMD/WSL), application
artefacts (Office MRU, Outlook), config/credential files, and filesystem metadata
(USN Journal, MFT location).

```powershell
# Basic collection (default output to Desktop)
.\windows\windows_ir_collector.ps1

.\windows\windows_ir_collector.ps1 -OutputDir "C:\IR\Collection"
.\windows\windows_ir_collector.ps1 -DryRun
.\windows\windows_ir_collector.ps1 -EventLogHours 72
.\windows\windows_ir_collector.ps1 -SkipEventLogs
```

Requires Windows 10/11 or Server 2016+, PowerShell 5.1+; Administrator recommended.

---

## Notes

- Some artefacts require elevation; both scripts warn and skip inaccessible items when
  run unprivileged, logging details to `error_collection.log`.
- **Sensitive data:** both collectors gather credential material (SSH keys, `.aws`,
  `.kube`, cloud creds, `.gnupg`). Handle the resulting archive securely.
- For full MFT extraction on Windows use dedicated tools (KAPE, MFTECmd, RawCopy).

## History

This repository combines the previously separate `mac-ir-collector` and
`win-ir-collector` projects; the original commit history of both is preserved here
under `macos/` and `windows/`.

## Author

**Orchardroot** — [github.com/orchardroot](https://github.com/orchardroot)

## Licence

MIT — see [LICENSE](LICENSE).
