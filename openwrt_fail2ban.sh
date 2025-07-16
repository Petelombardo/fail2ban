#!/bin/bash

# OpenWRT Fail2Ban - SSH Brute Force Protection
# Adapted for OpenWRT/dropbear from EdgeOS fail2ban script

VERSION="1.0"
SCRIPT_NAME="$(basename "$0")"

# Configuration
ATTEMPTS=10;    # NUMBER OF ATTEMPTS IN A GIVEN INTERVAL
INTERVAL=600;   # INTERVAL (IN SECONDS) TO WATCH FOR FAILED ATTEMPTS - HISTORICALLY FROM CURRENT TIME
PERMBAN=100;    # AFTER THIS NUM OF FAILED ATTEMPTS, BAN UNTIL LOG ROTATES
BLOCKSECS=3600; # AFTER THIS TIME (IN SECONDS), UNBLOCK A BLOCKED IP

# Colors for output (with better terminal detection for OpenWRT)
USE_COLORS=0
if [ -t 1 ] && [ "${TERM:-}" != "dumb" ] && command -v tput >/dev/null 2>&1; then
    if tput colors >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null)" -ge 8 ]; then
        USE_COLORS=1
    fi
fi

# Force color mode if explicitly requested
if [ "${FORCE_COLOR:-}" = "1" ]; then
    USE_COLORS=1
fi

if [ "$USE_COLORS" -eq 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    PURPLE=''
    CYAN=''
    WHITE=''
    BOLD=''
    NC=''
fi

# Global variables
BLOCKED_ALREADY=""
BLOCKED_NOW=""
SKIPPED=""
EXPIRED_BLOCK=""
NOW=`date '+%s'`
VERBOSE=0
QUIET=0

# OpenWRT specific paths
IPLIST_LOG="/tmp/ip-list.log"
BANNED_LOG="/tmp/banned.log"
THISRUN_FILE="/tmp/this-run"
LASTRUN_FILE="/tmp/last-run"

# Functions
show_help() {
    cat << EOF
${BOLD}OpenWRT Fail2Ban v${VERSION}${NC}
SSH brute force protection for OpenWRT routers

${BOLD}USAGE:${NC}
    $SCRIPT_NAME [OPTIONS]

${BOLD}OPTIONS:${NC}
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output
    -q, --quiet     Quiet mode (minimal output)
    -s, --status    Show current status only
    -u, --unblock   Unblock expired IPs and exit
    -r, --remove    Remove specific IP from blocks (use with IP address)
    -c, --config    Show current configuration
    --color         Force color output (if terminal doesn't auto-detect)
    --no-color      Disable color output
    --version       Show version information

${BOLD}CONFIGURATION:${NC}
    Attempts threshold: ${ATTEMPTS}
    Time window:        ${INTERVAL}s ($(($INTERVAL/60)) minutes)
    Block duration:     ${BLOCKSECS}s ($(($BLOCKSECS/3600)) hour)
    Permanent ban:      ${PERMBAN} attempts

${BOLD}FILES:${NC}
    IP tracking:        ${IPLIST_LOG}
    Ban history:        ${BANNED_LOG}

${BOLD}EXAMPLES:${NC}
    $SCRIPT_NAME                        # Run fail2ban check
    $SCRIPT_NAME -v                     # Run with verbose output
    $SCRIPT_NAME -s                     # Show status only
    $SCRIPT_NAME -u                     # Unblock expired IPs
    $SCRIPT_NAME -r 45.148.10.215       # Manually unblock specific IP
    $SCRIPT_NAME --color                # Force colors if not detected

${BOLD}NOTE:${NC}
    If colors appear as escape codes, use --no-color option.
    IPs with >${PERMBAN} attempts are permanently banned and require manual removal.

EOF
}

show_version() {
    echo "${BOLD}OpenWRT Fail2Ban v${VERSION}${NC}"
    echo "SSH brute force protection for OpenWRT routers"
}

show_config() {
    if [ "$USE_COLORS" -eq 1 ]; then
        cat << EOF
${BOLD}${BLUE}Current Configuration:${NC}
┌─────────────────────────────────────┐
│ ${WHITE}Attempts threshold:${NC} ${YELLOW}${ATTEMPTS}${NC}
│ ${WHITE}Time window:${NC}        ${YELLOW}${INTERVAL}s${NC} ($(($INTERVAL/60)) min)
│ ${WHITE}Block duration:${NC}     ${YELLOW}${BLOCKSECS}s${NC} ($(($BLOCKSECS/3600)) hour)
│ ${WHITE}Permanent ban:${NC}      ${YELLOW}${PERMBAN}${NC} attempts
└─────────────────────────────────────┘

${BOLD}${BLUE}File Locations:${NC}
┌─────────────────────────────────────┐
│ ${WHITE}IP tracking:${NC}        ${CYAN}${IPLIST_LOG}${NC}
│ ${WHITE}Ban history:${NC}        ${CYAN}${BANNED_LOG}${NC}
└─────────────────────────────────────┘
EOF
    else
        cat << EOF
Current Configuration:
+-------------------------------------+
| Attempts threshold: ${ATTEMPTS}
| Time window:        ${INTERVAL}s ($(($INTERVAL/60)) min)
| Block duration:     ${BLOCKSECS}s ($(($BLOCKSECS/3600)) hour)
| Permanent ban:      ${PERMBAN} attempts
+-------------------------------------+

File Locations:
+-------------------------------------+
| IP tracking:        ${IPLIST_LOG}
| Ban history:        ${BANNED_LOG}
+-------------------------------------+
EOF
    fi
}

print_header() {
    local title="$1"
    printf "\n"
    if [ "$USE_COLORS" -eq 1 ]; then
        printf "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}\n"
        printf "${BOLD}${BLUE}║${NC} ${WHITE}%-76s${NC} ${BOLD}${BLUE}║${NC}\n" "$title"
        printf "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}\n"
    else
        printf "================================================================================\n"
        printf " %-76s \n" "$title"
        printf "================================================================================\n"
    fi
}

print_section() {
    local title="$1"
    printf "\n"
    if [ "$USE_COLORS" -eq 1 ]; then
        printf "${BOLD}${CYAN}▶ %s${NC}\n" "$title"
        printf "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}\n"
    else
        printf "▶ %s\n" "$title"
        printf "────────────────────────────────────────────────────────────────────────────────\n"
    fi
}

log_message() {
    local level="$1"
    local message="$2"
    
    if [ "$QUIET" -eq 0 ]; then
        case "$level" in
            "INFO")  printf "${BLUE}[INFO]${NC}  %s\n" "$message" ;;
            "WARN")  printf "${YELLOW}[WARN]${NC}  %s\n" "$message" ;;
            "ERROR") printf "${RED}[ERROR]${NC} %s\n" "$message" ;;
            "SUCCESS") printf "${GREEN}[OK]${NC}    %s\n" "$message" ;;
            "DEBUG") [ "$VERBOSE" -eq 1 ] && printf "${PURPLE}[DEBUG]${NC} %s\n" "$message" ;;
        esac
    fi
}

progress_indicator() {
    local current="$1"
    local total="$2"
    local desc="$3"
    
    if [ "$QUIET" -eq 0 ] && [ "$VERBOSE" -eq 1 ] && [ "$USE_COLORS" -eq 1 ]; then
        local percent=$((current * 100 / total))
        local filled=$((percent / 5))
        local empty=$((20 - filled))
        
        printf "\r${CYAN}[%-20s]${NC} %3d%% %s" \
            "$(printf "%*s" $filled | tr ' ' '█')$(printf "%*s" $empty)" \
            "$percent" \
            "$desc"
    elif [ "$QUIET" -eq 0 ] && [ "$VERBOSE" -eq 1 ]; then
        # Simple progress without colors
        local percent=$((current * 100 / total))
        printf "\rProcessing... %d%% (%d/%d) %s" "$percent" "$current" "$total" "$desc"
    fi
}

isip() {
    ISIP=0
    local testip=$1
    if [ $(echo $testip | sed 's/[^.]//g' | awk '{print length; }' 2> /dev/null) -eq 3 ]; then
        # Additional validation for proper IP format
        if echo $testip | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
            ISIP=1
        fi
    fi
}

fail2ban() {
    IP=$IP
    EXISTS=`iptables -n -L | grep $IP | wc -l`
    IS_LOCAL=`echo $IP | grep -E '^10\.|^192\.168|^127\.|^172\.(1[6-9]|2[0-9]|3[01])\.' | wc -l`
    
    if [ $EXISTS -gt 0 ]; then
        BLOCKED_ALREADY+=",$IP:$COUNT"
        log_message "DEBUG" "IP $IP is already blocked"
    elif [ $IS_LOCAL -eq 1 ]; then
        SKIPPED+=",$IP:$COUNT"
        log_message "DEBUG" "Skipping local IP $IP"
    else
        if [ ! "$IP" == "" ]; then
            BLOCKED_NOW+=",$IP:$COUNT"
            iptables -I INPUT 1 -j DROP -s $IP
            echo "`date`:$IP:$NEWCOUNT:$COUNT:BLOCKED" >> $BANNED_LOG
            log_message "WARN" "Blocked IP $IP after $COUNT failed attempts"
        fi
    fi
}

updateList() {
    NOW=`date '+%s'`
    sed -i "s/:$IP:$LASTCOUNT:.*$/:$IP:$COUNT:$NOW/" $IPLIST_LOG
}

updateTime() {
    NOW=`date '+%s'`
    sed -i "s/:$IP:$LASTCOUNT:.*$/:$IP:$LASTCOUNT:$NOW/" $IPLIST_LOG
}

showList() {
    local description="$1"
    local list="$2"
    local color="$3"
    
    if [ ! "$list" == "" ] && [ ! "$list" == "," ]; then
        printf "\n"
        printf "${BOLD}${color}%s:${NC}\n" "$description"
        local count=0
        # Remove leading comma and split properly
        local clean_list=$(echo "$list" | sed 's/^,//')
        echo "$clean_list" | tr ',' '\n' | while read item; do
            if [ ! "$item" == "" ]; then
                BIP=$(echo "$item" | sed -e 's/:.*$//')
                BCOUNT=$(echo "$item" | sed -e 's/^.*://')
                if [ ! "$BIP" == "" ]; then
                    printf "  ${WHITE}%-15s${NC} ${YELLOW}%s${NC} attempts\n" "$BIP" "$BCOUNT"
                    count=$((count + 1))
                fi
            fi
        done
        # Count items properly
        local total_count=$(echo "$clean_list" | tr ',' '\n' | grep -c ':' 2>/dev/null || echo 0)
        printf "  ${PURPLE}Total: %d IPs${NC}\n" "$total_count"
    fi
}

checkExpired() {
    log_message "INFO" "Checking for expired blocks..."
    # Get list of currently blocked IPs from iptables
    BLOCKED=$(iptables -L INPUT -n | grep "^DROP" | grep "0.0.0.0/0" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $i != "0.0.0.0/0") print $i}')
    local expired_count=0
    local orphaned_count=0
    
    for blocked_ip in $BLOCKED; do
        # Skip if not a valid IP
        isip "$blocked_ip"
        if [ $ISIP -eq 0 ]; then
            continue
        fi
        
        # Check if this IP exists in our tracking log
        tracking_entry=$(grep ":$blocked_ip:" $IPLIST_LOG 2>/dev/null | tail -1)
        
        if [ -z "$tracking_entry" ]; then
            # Orphaned block - IP is blocked but not in tracking log
            # This happens when logs/tracking get cleaned up but iptables rule remains
            LINE=`iptables -L INPUT -n --line-numbers | grep "$blocked_ip" | head -1 | cut -d' ' -f1`
            if [ ! "$LINE" == "" ]; then
                log_message "WARN" "Removing orphaned block for $blocked_ip (no tracking record found)"
                echo "$(date):$blocked_ip:UNBLOCKED:ORPHANED" >> $BANNED_LOG
                EXPIRED_BLOCK+=",$blocked_ip"
                iptables -D INPUT $LINE
                orphaned_count=$((orphaned_count + 1))
            fi
        else
            # Normal expiration check for tracked IPs
            IP=`echo $tracking_entry | cut -d':' -f2`
            COUNT=`echo $tracking_entry | cut -d':' -f3`
            LASTACTION=`echo $tracking_entry | cut -d':' -f4`
            
            if [ $((NOW-LASTACTION)) -gt $BLOCKSECS ] && [ ! "$IP" == "" ] && [ $COUNT -lt $PERMBAN ]; then
                LINE=`iptables -L INPUT -n --line-numbers | grep "$IP" | head -1 | cut -d' ' -f1`
                if [ ! "$LINE" == "" ]; then
                    local block_duration=$((NOW-LASTACTION))
                    log_message "SUCCESS" "Unblocked $IP (was blocked for ${block_duration}s)"
                    echo "$(date):$IP:UNBLOCKED" >> $BANNED_LOG
                    EXPIRED_BLOCK+=",$IP"
                    iptables -D INPUT $LINE
                    expired_count=$((expired_count + 1))
                fi
            fi
        fi
    done
    
    if [ $expired_count -eq 0 ] && [ $orphaned_count -eq 0 ]; then
        log_message "INFO" "No expired or orphaned blocks found"
    else
        [ $expired_count -gt 0 ] && log_message "SUCCESS" "Unblocked $expired_count expired IPs"
        [ $orphaned_count -gt 0 ] && log_message "SUCCESS" "Removed $orphaned_count orphaned blocks"
    fi
}

show_status() {
    print_section "Current System Status"
    
    # Count current blocks - look for DROP rules with 0.0.0.0/0 destination (our rules)
    local current_blocks=$(iptables -L INPUT -n | grep "^DROP" | grep "0.0.0.0/0" | wc -l)
    local tracking_ips=$([ -f "$IPLIST_LOG" ] && wc -l < "$IPLIST_LOG" || echo 0)
    local total_bans=$([ -f "$BANNED_LOG" ] && grep ":BLOCKED" "$BANNED_LOG" | wc -l || echo 0)
    
    printf "${WHITE}Active blocks:${NC}     ${RED}%d${NC}\n" "$current_blocks"
    printf "${WHITE}Tracking IPs:${NC}     ${YELLOW}%d${NC}\n" "$tracking_ips"
    printf "${WHITE}Total bans:${NC}       ${PURPLE}%d${NC}\n" "$total_bans"
    
    if [ $current_blocks -gt 0 ]; then
        printf "\n"
        printf "${BOLD}${RED}Currently Blocked IPs:${NC}\n"
        # Extract IPs from DROP rules and check their status
        iptables -L INPUT -n --line-numbers | grep DROP | grep "0.0.0.0/0" | while read line; do
            # Extract the IP address (not 0.0.0.0/0) from the line
            local ip=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $i != "0.0.0.0/0") print $i}' | head -1)
            local rule_num=$(echo "$line" | awk '{print $1}')
            if [ ! -z "$ip" ]; then
                # Check if this is a permanent ban
                local tracking_entry=$(grep ":$ip:" $IPLIST_LOG 2>/dev/null | tail -1)
                if [ ! -z "$tracking_entry" ]; then
                    local count=$(echo "$tracking_entry" | cut -d':' -f3)
                    local timestamp=$(echo "$tracking_entry" | cut -d':' -f4)
                    local age_seconds=$((NOW - timestamp))
                    local age_hours=$((age_seconds / 3600))
                    
                    if [ $count -ge $PERMBAN ]; then
                        printf "  ${WHITE}%-15s${NC} (rule %s) ${RED}PERMANENT${NC} (%d attempts)\n" "$ip" "$rule_num" "$count"
                    else
                        printf "  ${WHITE}%-15s${NC} (rule %s) %dh old (%d attempts)\n" "$ip" "$rule_num" "$age_hours" "$count"
                    fi
                else
                    printf "  ${WHITE}%-15s${NC} (rule %s) ${YELLOW}ORPHANED${NC}\n" "$ip" "$rule_num"
                fi
            fi
        done
        
        printf "\n${YELLOW}Note: Use '${SCRIPT_NAME} -r <IP>' to manually remove permanent/orphaned blocks${NC}\n"
    fi
    
    # Show recent activity
    if [ -f "$BANNED_LOG" ]; then
        printf "\n"
        printf "${BOLD}${YELLOW}Recent Activity (last 10):${NC}\n"
        tail -10 "$BANNED_LOG" | while read line; do
            if [ ! -z "$line" ]; then
                printf "  ${CYAN}%s${NC}\n" "$line"
            fi
        done
    fi
}

cleanup_files() {
    log_message "INFO" "Performing file cleanup..."
    
    # CLEANUP - KEEP ONLY RECENT DATA AND REMOVE DUPLICATES
    if [ -f $IPLIST_LOG ]; then
        # Get entries from last 3 days and remove duplicates (keep most recent per IP)
        grep -E "^$(date +%Y%m%d):|^$(date -d '1 day ago' +%Y%m%d):|^$(date -d '2 days ago' +%Y%m%d):" $IPLIST_LOG 2>/dev/null | \
        awk -F: '{
            # For each IP, keep only the entry with the highest timestamp
            key = $2;  # IP address
            if (key != "" && ($4 > max_time[key] || max_time[key] == "")) {
                max_time[key] = $4;
                entry[key] = $0;
            }
        }
        END {
            for (ip in entry) {
                print entry[ip];
            }
        }' | sort > ${IPLIST_LOG}.new
        
        mv ${IPLIST_LOG}.new $IPLIST_LOG
    fi
    
    # Rotate banned.log if it gets too large (>100KB)
    if [ -f $BANNED_LOG ] && [ $(stat -c%s $BANNED_LOG 2>/dev/null || echo 0) -gt 102400 ]; then
        tail -500 $BANNED_LOG > ${BANNED_LOG}.new && mv ${BANNED_LOG}.new $BANNED_LOG
        echo "$(date):LOG:ROTATED" >> $BANNED_LOG
        log_message "INFO" "Rotated ban log (was >100KB)"
    fi
    
    log_message "SUCCESS" "File cleanup completed"
}

process_logs() {
    print_section "Processing Authentication Logs"
    
    # Check if we should run (basic change detection)
    if [ -f $THISRUN_FILE ]; then
        mv $THISRUN_FILE $LASTRUN_FILE
    else
        touch $LASTRUN_FILE
    fi
    
    # Get current log size for change detection
    logread | wc -l > $THISRUN_FILE
    CHANGE=$(diff $LASTRUN_FILE $THISRUN_FILE 2>/dev/null | wc -l)
    if [ $CHANGE -eq 0 ]; then
        log_message "INFO" "No new log entries since last run"
        return 1
    fi
    
    log_message "INFO" "Found $CHANGE new log entries to process"
    
    # Parse dropbear logs for failed password attempts
    IPLIST=`logread | grep "Bad password attempt" | grep -oE 'from [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed 's/from //' | sort | uniq -c | sed -e 's/^ *//' | sed -e 's/ /:/' | sed -e "s/^\(.*\)$/$(date +%Y%m%d):\1/"`
    
    if [ -z "$IPLIST" ]; then
        log_message "INFO" "No failed login attempts found"
        return 1
    fi
    
    local total_ips=$(echo "$IPLIST" | wc -l)
    local current_ip=0
    
    log_message "INFO" "Processing $total_ips unique IPs with failed attempts"
    
    for i in `echo "$IPLIST"`; do
        current_ip=$((current_ip + 1))
        progress_indicator $current_ip $total_ips "Processing IPs..."
        
        COUNT=`echo $i | cut -d':' -f2`
        IP=`echo $i | cut -d':' -f3`
        DATE=`echo $i | cut -d':' -f1`
        isip $IP
        
        if [ $ISIP -eq 0 ]; then
            continue
        fi
        
        LASTCOUNT=`grep ":$IP:" $IPLIST_LOG 2>/dev/null | cut -d':' -f3`
        ELAPSED=`grep ":$IP:" $IPLIST_LOG 2>/dev/null | cut -d':' -f4 | sed -e 's/\n//g'`
        
        if [ ! "$ELAPSED" == "" ]; then
            ELAPSED=$((NOW-ELAPSED))
        else
            ELAPSED=0
        fi
        
        if [ "$COUNT" == "" ]; then
            COUNT=0
        fi
        if [ "$LASTCOUNT" == "" ]; then
            LASTCOUNT=0
        fi
        
        # Handle circular buffer reset - if current count < stored count, 
        # the log buffer has rotated and old entries are gone
        if [ $COUNT -lt $LASTCOUNT ]; then
            log_message "DEBUG" "Circular buffer reset detected for $IP ($COUNT < $LASTCOUNT) - resetting counter"
            LASTCOUNT=0
            # Remove any old entries for this IP and add new one
            grep -v ":$IP:" $IPLIST_LOG > ${IPLIST_LOG}.tmp 2>/dev/null || touch ${IPLIST_LOG}.tmp
            echo "$DATE:$IP:$COUNT:$NOW" >> ${IPLIST_LOG}.tmp
            mv ${IPLIST_LOG}.tmp $IPLIST_LOG
            ELAPSED=0  # Reset elapsed time since we're starting fresh
        fi
        
        NEWCOUNT=$((COUNT-LASTCOUNT))
        
        # Add new IPs to tracking
        if [ "$LASTCOUNT" == "" ] || [ $LASTCOUNT -eq 0 ]; then
            echo "$DATE:$IP:$COUNT:$NOW" >> $IPLIST_LOG
            log_message "DEBUG" "Added $IP to tracking log with $COUNT attempts"
        fi
        
        log_message "DEBUG" "IP:$IP NEWCOUNT:$NEWCOUNT LASTCOUNT:$LASTCOUNT COUNT:$COUNT ELAPSED:$ELAPSED"
        
        # Decide whether to ban
        if [ $NEWCOUNT -ge $ATTEMPTS ] && [ $ISIP -eq 1 ] && ( [ $ELAPSED -le $INTERVAL ] || [ $COUNT -gt $PERMBAN ] ); then
            if [ $LASTCOUNT -ne 0 ]; then
                log_message "DEBUG" "Updating IP:$IP with NEWCOUNT:$NEWCOUNT (threshold: $ATTEMPTS attempts in $INTERVAL seconds)"
                updateList
            fi
            fail2ban
        elif [ $NEWCOUNT -ge $ATTEMPTS ] && [ $ISIP -eq 1 ]; then
            log_message "DEBUG" "Updating timestamp for IP $IP; +$NEWCOUNT attempts since last update (outside time window)"
            updateTime
        fi
    done
    
    if [ "$VERBOSE" -eq 1 ]; then
        printf "\n" # Clear progress line
    fi
    
    return 0
}

main() {
    # Create necessary files if they don't exist
    [ ! -f $IPLIST_LOG ] && touch $IPLIST_LOG
    [ ! -f $BANNED_LOG ] && touch $BANNED_LOG
    
    if [ "$QUIET" -eq 0 ]; then
        print_header "OpenWRT Fail2Ban v${VERSION} - $(date '+%Y-%m-%d %H:%M:%S')"
    fi
    
    cleanup_files
    
    if process_logs; then
        checkExpired
        
        # Show results
        print_section "Execution Summary"
        
        # Count items properly by removing leading commas and counting colons
        local blocked_count=0
        local already_blocked_count=0
        local skipped_count=0
        local expired_count=0
        
        if [ ! "$BLOCKED_NOW" == "" ]; then
            blocked_count=$(echo "$BLOCKED_NOW" | sed 's/^,//' | tr ',' '\n' | grep -c ':' 2>/dev/null || echo 0)
        fi
        if [ ! "$BLOCKED_ALREADY" == "" ]; then
            already_blocked_count=$(echo "$BLOCKED_ALREADY" | sed 's/^,//' | tr ',' '\n' | grep -c ':' 2>/dev/null || echo 0)
        fi
        if [ ! "$SKIPPED" == "" ]; then
            skipped_count=$(echo "$SKIPPED" | sed 's/^,//' | tr ',' '\n' | grep -c ':' 2>/dev/null || echo 0)
        fi
        if [ ! "$EXPIRED_BLOCK" == "" ]; then
            expired_count=$(echo "$EXPIRED_BLOCK" | sed 's/^,//' | tr ',' '\n' | grep -c ':' 2>/dev/null || echo 0)
        fi
        
        printf "${WHITE}New blocks:${NC}       ${RED}%d${NC}\n" "$blocked_count"
        printf "${WHITE}Already blocked:${NC}  ${YELLOW}%d${NC}\n" "$already_blocked_count"
        printf "${WHITE}Skipped (local):${NC}  ${BLUE}%d${NC}\n" "$skipped_count"
        printf "${WHITE}Unblocked:${NC}        ${GREEN}%d${NC}\n" "$expired_count"
        
        showList "🚫 Newly Blocked" "$BLOCKED_NOW" "$RED"
        showList "⚠️  Already Blocked" "$BLOCKED_ALREADY" "$YELLOW"
        showList "🏠 Skipped (Local IPs)" "$SKIPPED" "$BLUE"
        showList "✅ Unblocked (Expired)" "$EXPIRED_BLOCK" "$GREEN"
        
        if [ "$BLOCKED_NOW" != "" ] || [ "$EXPIRED_BLOCK" != "" ]; then
            print_section "Current iptables DROP Rules"
            # Show our DROP rules (with 0.0.0.0/0 destination)
            iptables -L INPUT -n --line-numbers | grep DROP | grep "0.0.0.0/0" | while read line; do
                printf "  ${CYAN}%s${NC}\n" "$line"
            done
        fi
    else
        checkExpired
    fi
    
    if [ "$QUIET" -eq 0 ]; then
        printf "\n"
        log_message "SUCCESS" "Fail2ban execution completed"
    fi
}

# Parse command line arguments
REMOVE_IP=""
while [ $# -gt 0 ]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        -s|--status)
            show_status
            exit 0
            ;;
        -u|--unblock)
            print_header "Unblocking Expired IPs"
            [ ! -f $IPLIST_LOG ] && touch $IPLIST_LOG
            checkExpired
            exit 0
            ;;
        -r|--remove)
            if [ -z "$2" ]; then
                printf "${RED}Error: -r/--remove requires an IP address${NC}\n" >&2
                printf "Example: %s -r 192.168.1.100${NC}\n" "$SCRIPT_NAME" >&2
                exit 1
            fi
            REMOVE_IP="$2"
            shift 2
            ;;
        -c|--config)
            show_config
            exit 0
            ;;
        --color)
            USE_COLORS=1
            RED='\033[0;31m'
            GREEN='\033[0;32m'
            YELLOW='\033[1;33m'
            BLUE='\033[0;34m'
            PURPLE='\033[0;35m'
            CYAN='\033[0;36m'
            WHITE='\033[1;37m'
            BOLD='\033[1m'
            NC='\033[0m'
            shift
            ;;
        --no-color)
            USE_COLORS=0
            RED=''
            GREEN=''
            YELLOW=''
            BLUE=''
            PURPLE=''
            CYAN=''
            WHITE=''
            BOLD=''
            NC=''
            shift
            ;;
        --version)
            show_version
            exit 0
            ;;
        *)
            printf "${RED}Error: Unknown option '%s'${NC}\n" "$1" >&2
            printf "Use '%s --help' for usage information.\n" "$SCRIPT_NAME" >&2
            exit 1
            ;;
    esac
done

# Handle manual IP removal
if [ ! -z "$REMOVE_IP" ]; then
    print_header "Manually Removing IP: $REMOVE_IP"
    
    # Validate IP format
    isip "$REMOVE_IP"
    if [ $ISIP -eq 0 ]; then
        log_message "ERROR" "Invalid IP address format: $REMOVE_IP"
        exit 1
    fi
    
    # Check if IP is currently blocked
    if iptables -L INPUT -n | grep -q "$REMOVE_IP"; then
        LINE=`iptables -L INPUT -n --line-numbers | grep "$REMOVE_IP" | head -1 | cut -d' ' -f1`
        if [ ! -z "$LINE" ]; then
            iptables -D INPUT $LINE
            log_message "SUCCESS" "Removed iptables rule for $REMOVE_IP"
            echo "$(date):$REMOVE_IP:UNBLOCKED:MANUAL" >> $BANNED_LOG
        fi
    else
        log_message "WARN" "IP $REMOVE_IP is not currently blocked in iptables"
    fi
    
    # Remove from tracking log
    if grep -q ":$REMOVE_IP:" $IPLIST_LOG 2>/dev/null; then
        grep -v ":$REMOVE_IP:" $IPLIST_LOG > ${IPLIST_LOG}.tmp
        mv ${IPLIST_LOG}.tmp $IPLIST_LOG
        log_message "SUCCESS" "Removed $REMOVE_IP from tracking log"
    else
        log_message "WARN" "IP $REMOVE_IP was not found in tracking log"
    fi
    
    log_message "SUCCESS" "Manual removal of $REMOVE_IP completed"
    exit 0
fi

# Run main function
main