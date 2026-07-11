#!/bin/bash

# =============================================================================
# macOS Incident Response Log Collector
# =============================================================================
# Collects forensically valuable logs and artifacts from macOS for 
# investigation and incident response purposes.
#
# Author: orchardroot
# Version: 1.1.0
# =============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_VERSION="1.1.0"
HOSTNAME=$(hostname -s)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${1:-$HOME/Desktop/IR_Collection_${HOSTNAME}_${TIMESTAMP}}"
LOG_FILE="$OUTPUT_DIR/collection.log"
MANIFEST_FILE="$OUTPUT_DIR/manifest.txt"
HASH_FILE="$OUTPUT_DIR/hashes.sha256"
ERROR_LOG_FILE="$OUTPUT_DIR/error_collection.log"

DRY_RUN=false
VERBOSE=false
COLLECT_UNIFIED_LOGS=true
UNIFIED_LOG_HOURS=24

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

# --- Functions ---

usage() {
    cat << EOF
macOS Incident Response Log Collector v${SCRIPT_VERSION}

Usage: $0 [OUTPUT_DIR] [OPTIONS]

Collects forensically valuable logs and artifacts from macOS for 
investigation and incident response purposes.

ARGUMENTS:
  OUTPUT_DIR          Directory to store collected artifacts
                      (default: ~/Desktop/IR_Collection_<hostname>_<timestamp>)

OPTIONS:
  -n, --dry-run       Show what would be collected without copying
  -v, --verbose       Show detailed output
  -u, --unified-hours Number of hours of unified logs to collect (default: 24)
  --no-unified        Skip unified log collection (faster)
  -h, --help          Display this help message

EXAMPLES:
  $0                              Collect to default location
  $0 /tmp/ir_collection           Collect to specific directory
  $0 -n                           Dry run - show what would be collected
  $0 -u 72                        Collect 72 hours of unified logs
  $0 --no-unified                 Skip unified logs (much faster)

NOTES:
  - Some artifacts require sudo privileges
  - Run with sudo for complete collection
  - Unified log export can take several minutes

OUTPUT STRUCTURE:
  IR_Collection_<hostname>_<timestamp>/
  ├── collection.log          # Collection activity log
  ├── error_collection.log    # Log of commands that encountered errors
  ├── manifest.txt            # List of all collected files
  ├── hashes.sha256           # SHA256 hashes for integrity
  ├── system_info.txt         # Basic system information
  ├── system_logs/            # /var/log contents
  ├── unified_logs/           # Exported unified logs
  ├── audit_logs/             # BSM audit logs
  ├── user_logs/              # ~/Library/Logs
  ├── diagnostic_reports/     # Crash reports
  ├── persistence/            # LaunchAgents, LaunchDaemons, etc.
  ├── network/                # Network configuration and logs
  ├── browser_artifacts/      # Browser history databases and parsed output
  ├── user_activity/          # KnowledgeC, recent items, etc.
  ├── security_databases/     # TCC, quarantine events
  ├── shell_history/          # Bash/zsh history files
  ├── config_files/           # System and user configuration files
  └── applications/           # Installed applications list

EOF
}

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)  colour="$GREEN" ;;
        WARN)  colour="$YELLOW" ;;
        ERROR) colour="$RED" ;;
        DEBUG) colour="$BLUE" ;;
        *)     colour="$NC" ;;
    esac
    
    echo -e "${colour}[${level}]${NC} ${message}"
    
    if [ -f "$LOG_FILE" ]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        log "DEBUG" "$1"
    fi
}

check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        log "WARN" "Not running as root. Some artifacts may not be collected."
        log "WARN" "Re-run with sudo for complete collection."
        return 1
    fi
    return 0
}

check_process_running() {
    local process_name="$1"
    pgrep -x "$process_name" > /dev/null 2>&1
}

init_collection() {
    if [ "$DRY_RUN" = true ]; then
        log "INFO" "DRY RUN MODE - No files will be copied"
        return 0
    fi
    
    mkdir -p "$OUTPUT_DIR"
    
    # Initialise log file
    echo "# macOS IR Collection Log" > "$LOG_FILE"
    echo "# Started: $(date)" >> "$LOG_FILE"
    echo "# Hostname: $HOSTNAME" >> "$LOG_FILE"
    echo "# User: $(whoami)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Initialise manifest
    echo "# macOS IR Collection Manifest" > "$MANIFEST_FILE"
    echo "# Generated: $(date)" >> "$MANIFEST_FILE"
    echo "" >> "$MANIFEST_FILE"
    
    # Initialise hash file
    echo "# SHA256 Hashes for IR Collection" > "$HASH_FILE"
    echo "# Generated: $(date)" >> "$HASH_FILE"
    echo "" >> "$HASH_FILE"

    # Initialise error log file
    echo "# macOS IR Collection Error Log" > "$ERROR_LOG_FILE"
    echo "# Generated: $(date)" >> "$ERROR_LOG_FILE"
    echo "" >> "$ERROR_LOG_FILE"
    
    log "INFO" "Collection directory: $OUTPUT_DIR"
}

collect_file() {
    local src="$1"
    local dest_dir="$2"
    local description="${3:-}"
    
    if [ ! -e "$src" ]; then
        log_verbose "Not found: $src"
        return 1
    fi
    
    if [ "$DRY_RUN" = true ]; then
        log "INFO" "Would collect: $src"
        return 0
    fi
    
    mkdir -p "$OUTPUT_DIR/$dest_dir"
    
    if [ -f "$src" ]; then
        cp -p "$src" "$OUTPUT_DIR/$dest_dir/" 2>> "$ERROR_LOG_FILE"
        if [ $? -eq 0 ]; then
            local filename
            filename=$(basename "$src")
            echo "$dest_dir/$filename - $src" >> "$MANIFEST_FILE"
            log_verbose "Collected: $src"
            return 0
        else
            log "WARN" "Failed to copy file '$src' to '$OUTPUT_DIR/$dest_dir/'. Check '$ERROR_LOG_FILE' for details."
            return 1
        fi
    elif [ -d "$src" ]; then
        cp -Rp "$src" "$OUTPUT_DIR/$dest_dir/" 2>> "$ERROR_LOG_FILE"
        if [ $? -eq 0 ]; then
            local dirname
            dirname=$(basename "$src")
            echo "$dest_dir/$dirname/ - $src" >> "$MANIFEST_FILE"
            log_verbose "Collected directory: $src"
            return 0
        else
            log "WARN" "Failed to copy directory '$src' to '$OUTPUT_DIR/$dest_dir/'. Check '$ERROR_LOG_FILE' for details."
            return 1
        fi
    fi
}

collect_with_find() {
    local search_path="$1"
    local pattern="$2"
    local dest_dir="$3"
    local max_depth="${4:-}"
    
    if [ ! -d "$search_path" ]; then
        log_verbose "Search path not found: $search_path"
        return 1
    fi
    
    local find_cmd="find \"$search_path\""
    [ -n "$max_depth" ] && find_cmd="$find_cmd -maxdepth $max_depth"
    find_cmd="$find_cmd -name \"$pattern\" -type f 2>> \"$ERROR_LOG_FILE\""
    
    local count=0
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            collect_file "$file" "$dest_dir"
            ((count++))
        fi
    done < <(eval "$find_cmd")
    
    log_verbose "Found $count files matching '$pattern' in $search_path"
}

# --- Collection Functions ---

collect_system_info() {
    log "INFO" "Collecting system information..."
    
    if [ "$DRY_RUN" = true ]; then
        log "INFO" "Would collect: System information"
        return 0
    fi
    
    local info_file="$OUTPUT_DIR/system_info.txt"
    
    {
        echo "# macOS System Information"
        echo "# Collected: $(date)"
        echo ""
        echo "=== HOSTNAME ==="
        hostname
        echo ""
        echo "=== OS VERSION ==="
        sw_vers
        echo ""
        echo "=== HARDWARE ==="
        system_profiler SPHardwareDataType 2>> "$ERROR_LOG_FILE"
        echo ""
        echo "=== CURRENT USER ==="
        whoami
        id
        echo ""
        echo "=== LOGGED IN USERS ==="
        who
        echo ""
        echo "=== LAST LOGINS ==="
        last -20
        echo ""
        echo "=== UPTIME ==="
        uptime
        echo ""
        echo "=== RUNNING PROCESSES ==="
        ps aux
        echo ""
        echo "=== NETWORK CONNECTIONS ==="
        netstat -an 2>> "$ERROR_LOG_FILE" || echo "netstat command failed"
        echo ""
        echo "=== LISTENING PORTS ==="
        lsof -i -P -n 2>> "$ERROR_LOG_FILE" | head -100
        echo ""
        echo "=== MOUNTED VOLUMES ==="
        mount
        echo ""
        echo "=== DISK USAGE ==="
        df -h
        echo ""
        echo "=== ENVIRONMENT VARIABLES ==="
        env
        echo ""
    } > "$info_file"
    
    log "INFO" "System information collected"
}

collect_system_logs() {
    log "INFO" "Collecting system logs from /var/log..."
    
    # Key system logs
    collect_file "/var/log/system.log" "system_logs" "Main system log"
    collect_file "/var/log/install.log" "system_logs" "Installation log"
    collect_file "/var/log/wifi.log" "system_logs" "WiFi log"
    collect_file "/var/log/appfirewall.log" "system_logs" "Application firewall log"
    collect_file "/var/log/fsck_apfs.log" "system_logs" "APFS filesystem check log"
    collect_file "/var/log/fsck_hfs.log" "system_logs" "HFS filesystem check log"
    
    # ASL logs (legacy but still useful)
    if [ -d "/var/log/asl" ]; then
        collect_file "/var/log/asl" "system_logs/asl" "Apple System Logs"
    fi
    
    # DiagnosticMessages
    if [ -d "/var/log/DiagnosticMessages" ]; then
        collect_file "/var/log/DiagnosticMessages" "system_logs/diagnostic_messages" "Diagnostic messages"
    fi
    
    # Collect any .log files in /var/log
    collect_with_find "/var/log" "*.log" "system_logs" 1
    
    log "INFO" "System logs collected"
}

collect_unified_logs() {
    if [ "$COLLECT_UNIFIED_LOGS" = false ]; then
        log "INFO" "Skipping unified log collection (--no-unified)"
        return 0
    fi
    
    log "INFO" "Collecting unified logs (last ${UNIFIED_LOG_HOURS} hours)..."
    log "INFO" "This may take several minutes..."
    
    if [ "$DRY_RUN" = true ]; then
        log "INFO" "Would collect: Unified logs for last ${UNIFIED_LOG_HOURS} hours"
        return 0
    fi
    
    mkdir -p "$OUTPUT_DIR/unified_logs"
    
    local start_time
    start_time=$(date -v-${UNIFIED_LOG_HOURS}H '+%Y-%m-%d %H:%M:%S')
    
    # Export unified logs to text format
    log show --start "$start_time" --style syslog > "$OUTPUT_DIR/unified_logs/unified_log_syslog.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect unified syslog. Check $ERROR_LOG_FILE."
    
    # Export with JSON format for easier parsing
    log show --start "$start_time" --style json > "$OUTPUT_DIR/unified_logs/unified_log.json" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect unified JSON log. Check $ERROR_LOG_FILE."
    
    # Collect specific subsystems of interest
    log "INFO" "Collecting security-relevant unified log subsystems..."
    
    # Authentication events
    log show --start "$start_time" --predicate 'subsystem == "com.apple.opendirectoryd"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/opendirectoryd.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect opendirectoryd logs. Check $ERROR_LOG_FILE."
    
    # Authorization events
    log show --start "$start_time" --predicate 'subsystem == "com.apple.Authorization"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/authorization.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect authorization logs. Check $ERROR_LOG_FILE."
    
    # Endpoint Security events
    log show --start "$start_time" --predicate 'subsystem == "com.apple.endpointsecurity"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/endpoint_security.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect endpoint security logs. Check $ERROR_LOG_FILE."
    
    # XProtect events
    log show --start "$start_time" --predicate 'subsystem == "com.apple.XProtect"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/xprotect.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect XProtect logs. Check $ERROR_LOG_FILE."
    
    # Gatekeeper events
    log show --start "$start_time" --predicate 'subsystem == "com.apple.syspolicy"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/gatekeeper.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect Gatekeeper logs. Check $ERROR_LOG_FILE."
    
    # SSH events
    log show --start "$start_time" --predicate 'process == "sshd"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/sshd.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect sshd logs. Check $ERROR_LOG_FILE."
    
    # Sudo events
    log show --start "$start_time" --predicate 'process == "sudo"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/sudo.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect sudo logs. Check $ERROR_LOG_FILE."
    
    # Login window events
    log show --start "$start_time" --predicate 'subsystem == "com.apple.loginwindow"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/loginwindow.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect loginwindow logs. Check $ERROR_LOG_FILE."
    
    # Kernel events
    log show --start "$start_time" --predicate 'sender == "kernel"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/kernel.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect kernel logs. Check $ERROR_LOG_FILE."
    
    # Santa (if installed)
    log show --start "$start_time" --predicate 'subsystem == "com.google.santa"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/santa.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect Santa logs. Check $ERROR_LOG_FILE."
    
    # CrowdStrike (if installed)
    log show --start "$start_time" --predicate 'subsystem CONTAINS "crowdstrike"' --style syslog \
        > "$OUTPUT_DIR/unified_logs/crowdstrike.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect CrowdStrike logs. Check $ERROR_LOG_FILE."
    
    echo "unified_logs/ - Unified log export" >> "$MANIFEST_FILE"
    log "INFO" "Unified logs collected"
}

collect_audit_logs() {
    log "INFO" "Collecting BSM audit logs..."
    
    # OpenBSM audit logs
    if [ -d "/var/audit" ]; then
        collect_file "/var/audit" "audit_logs" "BSM audit logs"
    fi
    
    # Audit control configuration
    collect_file "/etc/security/audit_control" "audit_logs" "Audit configuration"
    collect_file "/etc/security/audit_class" "audit_logs" "Audit class definitions"
    collect_file "/etc/security/audit_event" "audit_logs" "Audit event definitions"
    
    log "INFO" "Audit logs collected"
}

collect_user_logs() {
    log "INFO" "Collecting user logs..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # User library logs
    if [ -d "$user_home/Library/Logs" ]; then
        collect_file "$user_home/Library/Logs" "user_logs" "User library logs"
    fi
    
    log "INFO" "User logs collected"
}

collect_diagnostic_reports() {
    log "INFO" "Collecting diagnostic/crash reports..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # System diagnostic reports
    collect_file "/Library/Logs/DiagnosticReports" "diagnostic_reports/system" "System crash reports"
    
    # User diagnostic reports
    collect_file "$user_home/Library/Logs/DiagnosticReports" "diagnostic_reports/user" "User crash reports"
    
    # Spin reports
    collect_file "/Library/Logs/Spin Reports" "diagnostic_reports/spin" "System spin reports"
    
    log "INFO" "Diagnostic reports collected"
}

collect_persistence_mechanisms() {
    log "INFO" "Collecting persistence mechanisms..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # System LaunchDaemons
    collect_file "/Library/LaunchDaemons" "persistence/system_launch_daemons" "System LaunchDaemons"
    
    # System LaunchAgents
    collect_file "/Library/LaunchAgents" "persistence/system_launch_agents" "System LaunchAgents"
    
    # User LaunchAgents
    collect_file "$user_home/Library/LaunchAgents" "persistence/user_launch_agents" "User LaunchAgents"
    
    # Apple LaunchDaemons (for comparison/baseline)
    collect_file "/System/Library/LaunchDaemons" "persistence/apple_launch_daemons" "Apple LaunchDaemons"
    
    # Apple LaunchAgents
    collect_file "/System/Library/LaunchAgents" "persistence/apple_launch_agents" "Apple LaunchAgents"
    
    # Cron jobs
    collect_file "/var/at/tabs" "persistence/cron" "System cron tabs"
    collect_file "/etc/crontab" "persistence/cron" "System crontab"
    collect_file "/usr/lib/cron/tabs" "persistence/cron" "User cron tabs"
    
    # Periodic scripts
    collect_file "/etc/periodic" "persistence/periodic" "Periodic scripts"
    
    # Login/logout hooks
    if [ "$DRY_RUN" = false ]; then
        mkdir -p "$OUTPUT_DIR/persistence/hooks"
        defaults read com.apple.loginwindow LoginHook > "$OUTPUT_DIR/persistence/hooks/login_hook.txt" 2>> "$ERROR_LOG_FILE" || log_verbose "No LoginHook configured"
        defaults read com.apple.loginwindow LogoutHook > "$OUTPUT_DIR/persistence/hooks/logout_hook.txt" 2>> "$ERROR_LOG_FILE" || log_verbose "No LogoutHook configured"
    fi
    
    # Startup items (legacy)
    collect_file "/Library/StartupItems" "persistence/startup_items" "Startup items"
    
    # Authorization plugins
    collect_file "/Library/Security/SecurityAgentPlugins" "persistence/auth_plugins" "Authorization plugins"
    
    # Kernel extensions
    collect_file "/Library/Extensions" "persistence/kernel_extensions" "Third-party kernel extensions"
    
    # System extensions
    if [ "$DRY_RUN" = false ]; then
        mkdir -p "$OUTPUT_DIR/persistence/system_extensions"
        systemextensionsctl list > "$OUTPUT_DIR/persistence/system_extensions/list.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to list system extensions. Check $ERROR_LOG_FILE."
    fi
    
    # Login items (user)
    collect_file "$user_home/Library/Application Support/com.apple.backgroundtaskmanagementagent" \
        "persistence/login_items" "Background task management"
    
    log "INFO" "Persistence mechanisms collected"
}

collect_network_info() {
    log "INFO" "Collecting network information..."
    
    if [ "$DRY_RUN" = true ]; then
        log "INFO" "Would collect: Network configuration and logs"
        return 0
    fi
    
    mkdir -p "$OUTPUT_DIR/network"
    
    # Network interfaces
    ifconfig -a > "$OUTPUT_DIR/network/interfaces.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect network interfaces. Check $ERROR_LOG_FILE."
    
    # Routing table
    netstat -rn > "$OUTPUT_DIR/network/routes.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect routing table. Check $ERROR_LOG_FILE."
    
    # ARP cache
    arp -a > "$OUTPUT_DIR/network/arp_cache.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect ARP cache. Check $ERROR_LOG_FILE."
    
    # DNS configuration
    scutil --dns > "$OUTPUT_DIR/network/dns_config.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect DNS config via scutil. Check $ERROR_LOG_FILE."
    cat /etc/resolv.conf > "$OUTPUT_DIR/network/resolv_conf.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect /etc/resolv.conf. Check $ERROR_LOG_FILE."
    
    # Active connections (lsof) - provides process info and open files
    lsof -i -P -n > "$OUTPUT_DIR/network/active_connections_lsof.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect active connections via lsof. Check $ERROR_LOG_FILE."
    
    # Active connections (netstat for comprehensive list)
    netstat -f inet -an > "$OUTPUT_DIR/network/active_connections_netstat.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to collect active connections via netstat. Check $ERROR_LOG_FILE."
    
    # Firewall status and rules (using valid macOS socketfilterfw flags)
    {
        echo "=== Firewall Global State ==="
        /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>> "$ERROR_LOG_FILE"
        echo ""
        echo "=== Firewall Block All ==="
        /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>> "$ERROR_LOG_FILE"
        echo ""
        echo "=== Firewall Allow Signed ==="
        /usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned 2>> "$ERROR_LOG_FILE"
        echo ""
        echo "=== Firewall Stealth Mode ==="
        /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>> "$ERROR_LOG_FILE"
        echo ""
        echo "=== Firewall Logging ==="
        /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>> "$ERROR_LOG_FILE"
        echo ""
        echo "=== Firewall Applications ==="
        /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>> "$ERROR_LOG_FILE"
    } > "$OUTPUT_DIR/network/firewall_status.txt" || log "WARN" "Failed to collect firewall status. Check $ERROR_LOG_FILE."
    
    # Known networks
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    collect_file "$user_home/Library/Preferences/com.apple.wifi.known-networks.plist" \
        "network" "Known WiFi networks"
    
    # Hosts file
    collect_file "/etc/hosts" "network" "Hosts file"
    
    echo "network/ - Network configuration" >> "$MANIFEST_FILE"
    log "INFO" "Network information collected"
}

# Function to dump Chrome history from SQLite database
dump_chrome_history() {
    local user_home="$1"
    local output_base_dir="$2"
    local chrome_dir="$user_home/Library/Application Support/Google/Chrome/Default"
    local history_db="$chrome_dir/History"
    local output_dir="$output_base_dir/browser_artifacts/chrome_parsed"

    if [ ! -f "$history_db" ]; then
        log_verbose "Chrome History database not found at $history_db"
        return 1
    fi

    # Check if Chrome is running - warn but continue (we have the raw copy)
    if check_process_running "Google Chrome"; then
        log "WARN" "Chrome is running. SQLite queries may return incomplete results. Raw database has been copied."
    fi

    log "INFO" "Parsing Chrome history from $history_db..."
    mkdir -p "$output_dir"

    # Dump URLs
    sqlite3 "$history_db" "SELECT datetime(last_visit_time / 1000000 + strftime('%s', '1601-01-01'), 'unixepoch', 'localtime') AS 'Last Visit Time', url, title, visit_count FROM urls ORDER BY last_visit_time DESC;" > "$output_dir/chrome_urls.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to parse Chrome URLs. Check $ERROR_LOG_FILE."

    # Dump Downloads
    sqlite3 "$history_db" "SELECT datetime(start_time / 1000000 + strftime('%s', '1601-01-01'), 'unixepoch', 'localtime') AS 'Start Time', current_path, target_path, tab_url, total_bytes FROM downloads ORDER BY start_time DESC;" > "$output_dir/chrome_downloads.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to parse Chrome downloads. Check $ERROR_LOG_FILE."

    # Dump Search Terms
    sqlite3 "$history_db" "SELECT keyword_search_terms.term, urls.url, datetime(urls.last_visit_time / 1000000 + strftime('%s', '1601-01-01'), 'unixepoch', 'localtime') AS 'Last Visit' FROM keyword_search_terms JOIN urls ON keyword_search_terms.url_id = urls.id ORDER BY urls.last_visit_time DESC;" > "$output_dir/chrome_search_terms.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to parse Chrome search terms. Check $ERROR_LOG_FILE."

    log "INFO" "Chrome history parsed to $output_dir"
    echo "browser_artifacts/chrome_parsed/ - Parsed Chrome history" >> "$MANIFEST_FILE"
}

# Function to dump Firefox history from SQLite databases
dump_firefox_history() {
    local user_home="$1"
    local output_base_dir="$2"
    local firefox_profiles_dir="$user_home/Library/Application Support/Firefox/Profiles"
    local output_parent_dir="$output_base_dir/browser_artifacts/firefox_parsed"

    if [ ! -d "$firefox_profiles_dir" ]; then
        log_verbose "Firefox Profiles directory not found at $firefox_profiles_dir"
        return 1
    fi

    # Check if Firefox is running - warn but continue (we have the raw copy)
    if check_process_running "firefox"; then
        log "WARN" "Firefox is running. SQLite queries may return incomplete results. Raw database has been copied."
    fi

    log "INFO" "Parsing Firefox history..."
    mkdir -p "$output_parent_dir"

    for profile_dir in "$firefox_profiles_dir"/*/; do
        if [ -d "$profile_dir" ]; then
            local profile_name
            profile_name=$(basename "$profile_dir")
            local places_db="${profile_dir}places.sqlite"

            local output_dir="$output_parent_dir/$profile_name"
            mkdir -p "$output_dir"

            if [ -f "$places_db" ]; then
                log "INFO" "Parsing Firefox history for profile '$profile_name'..."
                
                # Dump URLs and visit times
                sqlite3 "$places_db" "SELECT datetime(moz_places.last_visit_date / 1000000, 'unixepoch', 'localtime') AS 'Last Visit Time', moz_places.url, moz_places.title, moz_places.visit_count FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY moz_places.last_visit_date DESC;" > "$output_dir/firefox_urls.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to parse Firefox URLs for profile $profile_name. Check $ERROR_LOG_FILE."
                
                # Dump bookmarks
                sqlite3 "$places_db" "SELECT datetime(moz_bookmarks.dateAdded / 1000000, 'unixepoch', 'localtime') AS 'Date Added', moz_bookmarks.title, moz_places.url FROM moz_bookmarks JOIN moz_places ON moz_bookmarks.fk = moz_places.id WHERE moz_bookmarks.type = 1 ORDER BY moz_bookmarks.dateAdded DESC;" > "$output_dir/firefox_bookmarks.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to parse Firefox bookmarks for profile $profile_name. Check $ERROR_LOG_FILE."
                
                # Dump annotations (if any exist)
                sqlite3 "$places_db" "SELECT datetime(moz_annos.dateAdded / 1000000, 'unixepoch', 'localtime') AS 'Date', moz_annos.content, moz_places.url FROM moz_annos JOIN moz_places ON moz_annos.place_id = moz_places.id ORDER BY moz_annos.dateAdded DESC;" > "$output_dir/firefox_annotations.txt" 2>> "$ERROR_LOG_FILE" || log_verbose "No Firefox annotations for profile $profile_name"

                echo "browser_artifacts/firefox_parsed/$profile_name/ - Parsed Firefox history for profile $profile_name" >> "$MANIFEST_FILE"
            else
                log_verbose "Firefox places.sqlite not found for profile $profile_name at $places_db"
            fi
        fi
    done
    log "INFO" "Firefox history parsed to $output_parent_dir"
}

collect_browser_artifacts() {
    log "INFO" "Collecting browser artifacts..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # Safari
    collect_file "$user_home/Library/Safari/History.db" "browser_artifacts/safari" "Safari history"
    collect_file "$user_home/Library/Safari/Downloads.plist" "browser_artifacts/safari" "Safari downloads"
    collect_file "$user_home/Library/Safari/Bookmarks.plist" "browser_artifacts/safari" "Safari bookmarks"
    collect_file "$user_home/Library/Safari/LastSession.plist" "browser_artifacts/safari" "Safari last session"
    collect_file "$user_home/Library/Safari/TopSites.plist" "browser_artifacts/safari" "Safari top sites"
    collect_file "$user_home/Library/Safari/Extensions" "browser_artifacts/safari" "Safari extensions"
    
    # Chrome - collect raw files first
    local chrome_dir="$user_home/Library/Application Support/Google/Chrome/Default"
    if [ -d "$chrome_dir" ]; then
        collect_file "$chrome_dir/History" "browser_artifacts/chrome" "Chrome history"
        collect_file "$chrome_dir/Login Data" "browser_artifacts/chrome" "Chrome login data"
        collect_file "$chrome_dir/Cookies" "browser_artifacts/chrome" "Chrome cookies"
        collect_file "$chrome_dir/Bookmarks" "browser_artifacts/chrome" "Chrome bookmarks"
        collect_file "$chrome_dir/Preferences" "browser_artifacts/chrome" "Chrome preferences"
        collect_file "$chrome_dir/Extensions" "browser_artifacts/chrome" "Chrome extensions"
        # Parse history if not dry run
        if [ "$DRY_RUN" = false ]; then
            dump_chrome_history "$user_home" "$OUTPUT_DIR"
        fi
    fi
    
    # Firefox - collect raw files first
    local firefox_profiles="$user_home/Library/Application Support/Firefox/Profiles"
    if [ -d "$firefox_profiles" ]; then
        for profile_dir in "$firefox_profiles"/*/; do
            if [ -d "$profile_dir" ]; then
                local profile_name
                profile_name=$(basename "$profile_dir")
                collect_file "${profile_dir}places.sqlite" "browser_artifacts/firefox/$profile_name" "Firefox history/bookmarks"
                collect_file "${profile_dir}cookies.sqlite" "browser_artifacts/firefox/$profile_name" "Firefox cookies"
                collect_file "${profile_dir}logins.json" "browser_artifacts/firefox/$profile_name" "Firefox logins"
                collect_file "${profile_dir}extensions.json" "browser_artifacts/firefox/$profile_name" "Firefox extensions"
                collect_file "${profile_dir}formhistory.sqlite" "browser_artifacts/firefox/$profile_name" "Firefox form history"
            fi
        done
        # Parse history if not dry run
        if [ "$DRY_RUN" = false ]; then
            dump_firefox_history "$user_home" "$OUTPUT_DIR"
        fi
    fi
    
    # Edge
    local edge_dir="$user_home/Library/Application Support/Microsoft Edge/Default"
    if [ -d "$edge_dir" ]; then
        collect_file "$edge_dir/History" "browser_artifacts/edge" "Edge history"
        collect_file "$edge_dir/Cookies" "browser_artifacts/edge" "Edge cookies"
        collect_file "$edge_dir/Bookmarks" "browser_artifacts/edge" "Edge bookmarks"
    fi
    
    log "INFO" "Browser artifacts collected"
}

collect_user_activity() {
    log "INFO" "Collecting user activity artifacts..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # KnowledgeC database (user activity tracking)
    collect_file "$user_home/Library/Application Support/Knowledge/knowledgeC.db" \
        "user_activity" "KnowledgeC database"
    
    # Recent items
    collect_file "$user_home/Library/Application Support/com.apple.sharedfilelist" \
        "user_activity/recent_items" "Recent items"
    
    # Finder preferences (recent folders, etc.)
    collect_file "$user_home/Library/Preferences/com.apple.finder.plist" \
        "user_activity" "Finder preferences"
    
    # Dock (recent apps)
    collect_file "$user_home/Library/Preferences/com.apple.dock.plist" \
        "user_activity" "Dock preferences"
    
    # Notification center
    collect_file "$user_home/Library/Application Support/NotificationCenter" \
        "user_activity/notifications" "Notification center"
    
    # Spotlight shortcuts
    collect_file "$user_home/Library/Application Support/com.apple.spotlight.Shortcuts" \
        "user_activity" "Spotlight shortcuts"
    
    log "INFO" "User activity artifacts collected"
}

collect_security_databases() {
    log "INFO" "Collecting security databases..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # TCC (Transparency, Consent, and Control) database
    collect_file "$user_home/Library/Application Support/com.apple.TCC/TCC.db" \
        "security_databases" "User TCC database"
    collect_file "/Library/Application Support/com.apple.TCC/TCC.db" \
        "security_databases" "System TCC database"
    
    # Quarantine events database
    collect_file "$user_home/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" \
        "security_databases" "Quarantine events"
    
    # Gatekeeper configuration
    collect_file "/var/db/SystemPolicy-prefs.plist" \
        "security_databases" "Gatekeeper preferences"
    
    # XProtect data
    collect_file "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara" \
        "security_databases" "XProtect YARA rules"
    collect_file "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist" \
        "security_databases" "XProtect definitions"
    
    # MRT (Malware Removal Tool) data
    collect_file "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Resources" \
        "security_databases/mrt" "MRT resources"
    
    log "INFO" "Security databases collected"
}

collect_shell_history() {
    log "INFO" "Collecting shell history..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # Bash history
    collect_file "$user_home/.bash_history" "shell_history" "Bash history"
    
    # Zsh history
    collect_file "$user_home/.zsh_history" "shell_history" "Zsh history"
    
    # Fish history
    collect_file "$user_home/.local/share/fish/fish_history" "shell_history" "Fish history"
    
    # Python history
    collect_file "$user_home/.python_history" "shell_history" "Python history"
    
    # MySQL history
    collect_file "$user_home/.mysql_history" "shell_history" "MySQL history"
    
    # SQLite history
    collect_file "$user_home/.sqlite_history" "shell_history" "SQLite history"
    
    # Less history
    collect_file "$user_home/.lesshst" "shell_history" "Less history"
    
    log "INFO" "Shell history collected"
}

collect_application_artifacts() {
    log "INFO" "Collecting application artifacts..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # Installed applications list
    if [ "$DRY_RUN" = false ]; then
        mkdir -p "$OUTPUT_DIR/applications"
        ls -la /Applications > "$OUTPUT_DIR/applications/applications_list.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to list /Applications. Check $ERROR_LOG_FILE."
        ls -la "$user_home/Applications" >> "$OUTPUT_DIR/applications/applications_list.txt" 2>> "$ERROR_LOG_FILE" || log_verbose "No user Applications folder"
        
        # Homebrew packages (if installed)
        if command -v brew &> /dev/null; then
            brew list > "$OUTPUT_DIR/applications/homebrew_packages.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to list Homebrew packages. Check $ERROR_LOG_FILE."
            brew list --cask > "$OUTPUT_DIR/applications/homebrew_casks.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to list Homebrew casks. Check $ERROR_LOG_FILE."
        fi
        
        # pip packages (if installed)
        if command -v pip3 &> /dev/null; then
            pip3 list > "$OUTPUT_DIR/applications/pip_packages.txt" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to list pip3 packages. Check $ERROR_LOG_FILE."
        fi
    fi
    
    # Terminal preferences
    collect_file "$user_home/Library/Preferences/com.apple.Terminal.plist" \
        "applications" "Terminal preferences"
    
    # iTerm2 preferences
    collect_file "$user_home/Library/Preferences/com.googlecode.iterm2.plist" \
        "applications" "iTerm2 preferences"
    
    log "INFO" "Application artifacts collected"
}

collect_config_files() {
    log "INFO" "Collecting configuration files..."
    
    local user_home
    user_home=$(eval echo ~"${SUDO_USER:-$USER}")
    
    # User shell configuration files
    collect_file "$user_home/.bash_profile" "config_files/user" "User Bash profile"
    collect_file "$user_home/.bashrc" "config_files/user" "User Bashrc"
    collect_file "$user_home/.zshrc" "config_files/user" "User Zshrc"
    collect_file "$user_home/.zprofile" "config_files/user" "User Zsh profile"
    collect_file "$user_home/.profile" "config_files/user" "User profile"
    collect_file "$user_home/.cshrc" "config_files/user" "User Cshrc"
    collect_file "$user_home/.tcshrc" "config_files/user" "User Tcshrc"
    collect_file "$user_home/.login" "config_files/user" "User Login script"
    
    # User application configuration
    collect_file "$user_home/.gitconfig" "config_files/user" "User Git configuration"
    collect_file "$user_home/.vimrc" "config_files/user" "User Vim configuration"
    collect_file "$user_home/.inputrc" "config_files/user" "User Inputrc"
    
    # User SSH configuration (not private keys)
    collect_file "$user_home/.ssh/known_hosts" "config_files/user_ssh" "User SSH known hosts"
    collect_file "$user_home/.ssh/config" "config_files/user_ssh" "User SSH config"
    collect_file "$user_home/.ssh/authorized_keys" "config_files/user_ssh" "User SSH authorized keys"
    
    # User directories with potential credentials - log warning
    log "WARN" "Collecting credential directories (.gnupg, .aws, .kube) - these may contain sensitive keys"
    collect_file "$user_home/.config" "config_files/user_dirs" "User .config directory"
    collect_file "$user_home/.gnupg" "config_files/user_dirs" "User GnuPG directory"
    collect_file "$user_home/.aws" "config_files/user_dirs" "User AWS configuration directory"
    collect_file "$user_home/.kube" "config_files/user_dirs" "User Kubernetes configuration directory"
    
    # System-wide configuration files
    collect_file "/etc/hosts" "config_files/system" "System Hosts file"
    collect_file "/etc/profile" "config_files/system" "System profile"
    collect_file "/etc/shells" "config_files/system" "System shells"
    collect_file "/etc/bashrc" "config_files/system" "System Bashrc"
    collect_file "/etc/zshrc" "config_files/system" "System Zshrc"
    collect_file "/etc/paths" "config_files/system" "System paths"
    collect_file "/etc/sudoers" "config_files/system" "System Sudoers"
    collect_file "/etc/sysctl.conf" "config_files/system" "System sysctl configuration"
    collect_file "/etc/ssh/sshd_config" "config_files/system_ssh" "System SSHD config"
    
    # System directories
    collect_file "/etc/pam.d" "config_files/system_dirs" "System PAM directory"
    collect_file "/etc/security" "config_files/system_dirs" "System security directory"

    log "INFO" "Configuration files collected"
}

generate_hashes() {
    if [ "$DRY_RUN" = true ]; then
        log "INFO" "DRY RUN: Would generate SHA256 hashes"
        return 0
    fi
    
    log "INFO" "Generating SHA256 hashes for collected files..."
    
    # Exclude control files from initial hashing
    local hash_file_basename
    hash_file_basename=$(basename "$HASH_FILE")
    local log_file_basename
    log_file_basename=$(basename "$LOG_FILE")
    local manifest_file_basename
    manifest_file_basename=$(basename "$MANIFEST_FILE")
    local error_log_basename
    error_log_basename=$(basename "$ERROR_LOG_FILE")

    find "$OUTPUT_DIR" -type f \
        ! -name "$hash_file_basename" \
        ! -name "$log_file_basename" \
        ! -name "$manifest_file_basename" \
        ! -name "$error_log_basename" \
        -print0 | while IFS= read -r -d '' file; do
        shasum -a 256 "$file" >> "$HASH_FILE" 2>/dev/null || log_verbose "Failed to hash file: $file"
    done
    
    # Hash the manifest file itself after all other files are processed
    if [ -f "$MANIFEST_FILE" ]; then
        shasum -a 256 "$MANIFEST_FILE" >> "$HASH_FILE" 2>/dev/null || log_verbose "Failed to hash manifest file"
    fi
    
    # Hash the collection log file
    if [ -f "$LOG_FILE" ]; then
        shasum -a 256 "$LOG_FILE" >> "$HASH_FILE" 2>/dev/null || log_verbose "Failed to hash log file"
    fi
    
    # Hash the error log file
    if [ -f "$ERROR_LOG_FILE" ]; then
        shasum -a 256 "$ERROR_LOG_FILE" >> "$HASH_FILE" 2>/dev/null || log_verbose "Failed to hash error log file"
    fi
    
    log "INFO" "SHA256 hashes generated in $HASH_FILE"
}

compress_collection() {
    if [ "$DRY_RUN" = true ]; then
        log "INFO" "DRY RUN: Would compress collection to .tar.gz"
        return 0
    fi
    
    log "INFO" "Compressing collection..."
    
    local parent_dir
    local dir_name
    parent_dir=$(dirname "$OUTPUT_DIR")
    dir_name=$(basename "$OUTPUT_DIR")
    
    tar -czf "${OUTPUT_DIR}.tar.gz" -C "$parent_dir" "$dir_name" 2>> "$ERROR_LOG_FILE"
    
    if [ $? -eq 0 ]; then
        log "INFO" "Collection compressed to: ${OUTPUT_DIR}.tar.gz"
        
        # Generate hash of archive
        shasum -a 256 "${OUTPUT_DIR}.tar.gz" > "${OUTPUT_DIR}.tar.gz.sha256" 2>> "$ERROR_LOG_FILE" || log "WARN" "Failed to hash archive. Check $ERROR_LOG_FILE."
        log "INFO" "Archive hash: ${OUTPUT_DIR}.tar.gz.sha256"
    else
        log "WARN" "Failed to compress collection. Check $ERROR_LOG_FILE."
    fi
}

# --- Main ---

main() {
    echo ""
    echo "======================================"
    echo "  macOS IR Log Collector v${SCRIPT_VERSION}"
    echo "======================================"
    echo ""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -n|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -u|--unified-hours)
                UNIFIED_LOG_HOURS="$2"
                shift 2
                ;;
            --no-unified)
                COLLECT_UNIFIED_LOGS=false
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                OUTPUT_DIR="$1"
                shift
                ;;
        esac
    done
    
    # Check privileges
    check_sudo
    
    # Initialise collection
    init_collection
    
    # Run collections
    collect_system_info
    collect_system_logs
    collect_unified_logs
    collect_audit_logs
    collect_user_logs
    collect_diagnostic_reports
    collect_persistence_mechanisms
    collect_network_info
    collect_browser_artifacts
    collect_user_activity
    collect_security_databases
    collect_shell_history
    collect_application_artifacts
    collect_config_files
    
    # Finalise
    generate_hashes
    compress_collection
    
    echo ""
    echo "======================================"
    echo "  Collection Complete"
    echo "======================================"
    echo ""
    
    if [ "$DRY_RUN" = false ]; then
        log "INFO" "Output directory: $OUTPUT_DIR"
        log "INFO" "Compressed archive: ${OUTPUT_DIR}.tar.gz"
        log "INFO" "Manifest: $MANIFEST_FILE"
        log "INFO" "Hashes: $HASH_FILE"
        
        # Show size
        local size
        size=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)
        log "INFO" "Total size: $size"
    fi
    
    echo ""
}

main "$@"
