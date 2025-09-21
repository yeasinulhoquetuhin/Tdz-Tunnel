#!/bin/bash

# ==================================================
# Tdz Tunnel - Ultimate VPN Solution
# Developer: Yeasinul Hoque Tuhin
# Contact: tuhinbro.website
# ==================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Log functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "Root access required! Use: ${CYAN}sudo ./install.sh${NC}"
    exit 1
fi

# Banner
echo -e "${GREEN}"
echo "=================================================="
echo "            Tdz Tunnel Auto Installer"
echo "           Developer: Yeasinul Hoque Tuhin"
echo "=================================================="
echo -e "${NC}"

# Update system
log_info "Updating system packages..."
apt install -y curl wget sudo git unzip jq certbot python3-certbot-nginx bc

# Get domain from user
read -p "Enter your domain name: " DOMAIN
if [ -z "$DOMAIN" ]; then
    log_error "Domain name is required!"
    exit 1
fi

# Verify domain
log_info "Verifying domain: ${CYAN}$DOMAIN${NC}"
if ! ping -c 1 $DOMAIN &> /dev/null; then
    log_error "Domain not reachable! Please configure DNS first."
    exit 1
fi

# Get server location and ISP info
get_server_info() {
    IP=$(curl -s ifconfig.me)
    LOCATION=$(curl -s ipinfo.io/$IP | jq -r '.country + ", " + .city')
    ISP=$(curl -s ipinfo.io/$IP | jq -r '.org' | cut -d' ' -f2-)
    echo "$LOCATION" > /root/tdz-server-location.txt
    echo "$ISP" > /root/tdz-server-isp.txt
}

get_server_info

# Install Xray
log_info "Installing Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate SSL certificate
log_info "Generating SSL certificate for ${CYAN}$DOMAIN${NC}"
certbot certonly --standalone --agree-tos --non-interactive --email admin@$DOMAIN -d $DOMAIN

# Generate UUIDs
UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
UUID_TROJAN=$(cat /proc/sys/kernel/random/uuid)

# Create Xray config with ALL protocols
log_info "Creating Xray configuration..."
cat > /usr/local/etc/xray/config.json << EOF
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "flow": "xtls-rprx-vision",
                        "email": "vless-tls@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ],
                    "alpn": ["h2", "http/1.1"]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 80,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "email": "vless-ntls@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/TuhinDroidZone",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"
            }
        },
        {
            "port": 8443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-tls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/TuhinDroidZone",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 8080,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-ntls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/TuhinDroidZone",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            }
        },
        {
            "port": 2095,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-tls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 2096,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-grpc@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "Tuhin-Internet-Service"
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ]
}
EOF

# Restart Xray
systemctl restart xray
systemctl enable xray

# Configure firewall
log_info "Configuring firewall..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
ufw allow 8080/tcp
ufw allow 2095/tcp
ufw allow 2096/tcp
ufw --force enable

# Create user management system
mkdir -p /etc/tdz
cat > /etc/tdz/user-manager.sh << 'EOF'
#!/bin/bash

USER_DB="/etc/tdz/users.json"

initialize_db() {
    if [ ! -f "$USER_DB" ]; then
        echo '{"users": []}' > "$USER_DB"
    fi
}

create_user() {
    local protocol=$1
    local remark=$2
    local expiry_days=$3
    
    case $protocol in
        "vless")
            uuid=$(cat /proc/sys/kernel/random/uuid)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"vless\", \"uuid\": \"$uuid\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$uuid"
            ;;
        "vmess")
            uuid=$(cat /proc/sys/kernel/random/uuid)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"vmess\", \"uuid\": \"$uuid\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$uuid"
            ;;
        "trojan")
            password=$(cat /proc/sys/kernel/random/uuid | cut -d'-' -f1)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"trojan\", \"password\": \"$password\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$password"
            ;;
    esac
}

list_users() {
    jq -r '.users[] | "\(.protocol) - \(.remark) - Expiry: \(.expiry_date)"' "$USER_DB"
}

get_user_info() {
    local protocol=$1
    local remark=$2
    jq -r ".users[] | select(.protocol == \"$protocol\" and .remark == \"$remark\")" "$USER_DB"
}
EOF

chmod +x /etc/tdz/user-manager.sh

# Create advanced control script with interactive dashboard
cat > /usr/local/bin/tdz << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

CONFIG_FILE="/root/tdz-config.txt"
SERVER_LOCATION=$(cat /root/tdz-server-location.txt 2>/dev/null || echo "Singapore")
SERVER_ISP=$(cat /root/tdz-server-isp.txt 2>/dev/null || echo "Digital Ocean")
USER_DB="/etc/tdz/users.json"
source /etc/tdz/user-manager.sh

initialize_db

show_dashboard() {
    while true; do
        clear
        echo -e "${GREEN}"
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║                   Tdz Tunnel Dashboard                   ║"
        echo "║               Developer: Yeasinul Hoque Tuhin            ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        # Server status
        echo -e "${BLUE}🖥️  SERVER STATUS:${NC}"
        if systemctl is-active --quiet xray; then
            echo -e "   Xray Service: ${GREEN}● Running${NC}"
        else
            echo -e "   Xray Service: ${RED}● Stopped${NC}"
        fi
        
        # User count
        USER_COUNT=$(jq '.users | length' "$USER_DB")
        echo -e "   Total Users: ${CYAN}$USER_COUNT${NC}"
        
        # System info
        echo -e "   CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
        echo -e "   Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
        echo -e "   Disk Usage: $(df -h / | awk 'NR==2{print $5}')"
        
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}📊 MAIN MENU:${NC}"
        echo -e "   ${GREEN}1${NC}. User Management"
        echo -e "   ${GREEN}2${NC}. Protocol Configuration" 
        echo -e "   ${GREEN}3${NC}. Server Information"
        echo -e "   ${GREEN}4${NC}. Service Control"
        echo -e "   ${GREEN}5${NC}. View Logs"
        echo -e "   ${GREEN}6${NC}. Backup & Restore"
        echo -e "   ${GREEN}7${NC}. Uninstall"
        echo -e "   ${GREEN}0${NC}. Exit"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
        
        read -p "Select an option [0-7]: " main_choice

        case $main_choice in
            1) user_management ;;
            2) protocol_management ;;
            3) server_information ;;
            4) service_control ;;
            5) view_logs ;;
            6) backup_restore ;;
            7) uninstall_tdz ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

user_management() {
    while true; do
        clear
        echo -e "${GREEN}"
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║                   User Management                        ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        echo -e "${BLUE}👥 USER OPTIONS:${NC}"
        echo -e "   ${GREEN}1${NC}. Create New User"
        echo -e "   ${GREEN}2${NC}. List All Users"
        echo -e "   ${GREEN}3${NC}. Delete User"
        echo -e "   ${GREEN}4${NC}. View User Details"
        echo -e "   ${GREEN}5${NC}. Generate User Links"
        echo -e "   ${GREEN}6${NC}. Back to Main Menu"
        
        read -p "Select an option [1-6]: " user_choice

        case $user_choice in
            1) create_user_menu ;;
            2) list_users_menu ;;
            3) delete_user_menu ;;
            4) view_user_details ;;
            5) generate_links_menu ;;
            6) return ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

create_user_menu() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Create New User                        ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}Select Protocol:${NC}"
    echo -e "   ${GREEN}1${NC}. VLESS"
    echo -e "   ${GREEN}2${NC}. VMESS"
    echo -e "   ${GREEN}3${NC}. Trojan"
    echo -e "   ${GREEN}4${NC}. Back"
    
    read -p "Select protocol [1-4]: " proto_choice
    
    case $proto_choice in
        1) protocol="vless" ;;
        2) protocol="vmess" ;;
        3) protocol="trojan" ;;
        4) return ;;
        *) echo -e "${RED}Invalid choice!${NC}"; sleep 1; return ;;
    esac
    
    read -p "Enter remark name: " remark
    read -p "Enter expiry days: " expiry_days
    
    if [ "$protocol" = "vless" ] || [ "$protocol" = "vmess" ]; then
        user_id=$(create_user "$protocol" "$remark" "$expiry_days")
        expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
        show_user_result "$protocol" "$remark" "$user_id" "$expiry_date"
    else
        password=$(create_user "$protocol" "$remark" "$expiry_days")
        expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
        show_user_result "$protocol" "$remark" "$password" "$expiry_date"
    fi
    
    read -p "Press Enter to continue..."
}

show_user_result() {
    local protocol=$1
    local remark=$2
    local user_id=$3
    local expiry_date=$4
    
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   User Created Successfully!             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BLUE}📋 USER DETAILS:${NC}"
    echo -e "   Protocol: ${CYAN}$protocol${NC}"
    echo -e "   Remark: ${CYAN}$remark${NC}"
    echo -e "   Expiry Date: ${YELLOW}$expiry_date${NC}"
    
    if [ "$protocol" = "vless" ] || [ "$protocol" = "vmess" ]; then
        echo -e "   UUID: ${MAGENTA}$user_id${NC}"
    else
        echo -e "   Password: ${MAGENTA}$user_id${NC}"
    fi
    
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}🔗 CONFIGURATION LINKS:${NC}"
    generate_links "$protocol" "$user_id" "$remark"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
}

list_users_menu() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   All Users                              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    if [ ! -s "$USER_DB" ] || [ "$(jq '.users | length' "$USER_DB")" -eq 0 ]; then
        echo -e "${YELLOW}No users found.${NC}"
    else
        jq -r '.users[] | "\(.protocol) - \(.remark) - Expiry: \(.expiry_date)"' "$USER_DB"
    fi
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

delete_user_menu() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Delete User                            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    if [ ! -s "$USER_DB" ] || [ "$(jq '.users | length' "$USER_DB")" -eq 0 ]; then
        echo -e "${YELLOW}No users found.${NC}"
        sleep 1
        return
    fi
    
    echo -e "${YELLOW}Current Users:${NC}"
    jq -r '.users[] | "\(.remark) (\(.protocol))"' "$USER_DB"
    echo ""
    read -p "Enter remark name to delete: " del_remark
    
    # Remove user from database
    tmp=$(mktemp)
    jq --arg remark "$del_remark" '.users |= map(select(.remark != $remark))' "$USER_DB" > "$tmp" && mv "$tmp" "$USER_DB"
    
    echo -e "${GREEN}User '$del_remark' deleted successfully!${NC}"
    sleep 1
}

generate_links_menu() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Generate Links                         ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    if [ ! -s "$USER_DB" ] || [ "$(jq '.users | length' "$USER_DB")" -eq 0 ]; then
        echo -e "${YELLOW}No users found.${NC}"
        sleep 1
        return
    fi
    
    echo -e "${YELLOW}Select User:${NC}"
    jq -r '.users[] | "\(.remark) (\(.protocol))"' "$USER_DB"
    echo ""
    read -p "Enter remark name: " gen_remark
    
    user_info=$(jq -r --arg remark "$gen_remark" '.users[] | select(.remark == $remark)' "$USER_DB")
    if [ -z "$user_info" ]; then
        echo -e "${RED}User not found!${NC}"
        sleep 1
        return
    fi
    
    protocol=$(echo "$user_info" | jq -r '.protocol')
    user_id=$(echo "$user_info" | jq -r '.uuid // .password')
    
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Configuration Links                    ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    generate_links "$protocol" "$user_id" "$gen_remark"
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

generate_links() {
    local protocol=$1
    local user_id=$2
    local remark=$3
    local domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    
    case $protocol in
        "vless")
            echo -e "${BLUE}VLESS Links:${NC}"
            echo -e "${CYAN}vless://$user_id@$domain:443?type=tcp&security=tls&flow=xtls-rprx-vision#$remark${NC}"
            echo -e "${CYAN}vless://$user_id@$domain:80?type=ws&path=/TuhinDroidZone&host=$domain#$remark${NC}"
            ;;
        "vmess")
            echo -e "${BLUE}VMESS Links:${NC}"
            vmess_config=$(jq -n --arg id "$user_id" --arg add "$domain" --arg ps "$remark" \
                '{v: "2", ps: $ps, add: $add, port: "8443", id: $id, aid: "0", net: "ws", type: "none", path: "/TuhinDroidZone", tls: "tls"}')
            echo -e "${CYAN}vmess://$(echo "$vmess_config" | base64 -w 0)${NC}"
            ;;
        "trojan")
            echo -e "${BLUE}Trojan Links:${NC}"
            echo -e "${CYAN}trojan://$user_id@$domain:2095?security=tls&type=tcp#$remark${NC}"
            echo -e "${CYAN}trojan://$user_id@$domain:2096?security=tls&type=grpc&serviceName=Tuhin-Internet-Service#$remark${NC}"
            ;;
    esac
}

protocol_management() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Protocol Management                    ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BLUE}🌐 ACTIVE PROTOCOLS:${NC}"
    echo -e "   ${GREEN}●${NC} VLESS (TCP-TLS) - Port 443"
    echo -e "   ${GREEN}●${NC} VLESS (WS-NTLS) - Port 80"
    echo -e "   ${GREEN}●${NC} VMESS (WS-TLS) - Port 8443"
    echo -e "   ${GREEN}●${NC} VMESS (WS-NTLS) - Port 8080"
    echo -e "   ${GREEN}●${NC} Trojan (TCP-TLS) - Port 2095"
    echo -e "   ${GREEN}●${NC} Trojan (gRPC-TLS) - Port 2096"
    
    echo -e "\n${BLUE}📊 CONFIGURATION:${NC}"
    echo -e "   WebSocket Path: ${CYAN}/TuhinDroidZone${NC}"
    echo -e "   gRPC Service: ${CYAN}Tuhin-Internet-Service${NC}"
    echo -e "   Domain: ${CYAN}$domain${NC}"
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

server_information() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Server Information                     ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BLUE}🖥️  SYSTEM INFO:${NC}"
    echo -e "   Hostname: $(hostname)"
    echo -e "   OS: $(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | head -n1)"
    echo -e "   Kernel: $(uname -r)"
    echo -e "   Uptime: $(uptime -p | sed 's/up //')"
    
    echo -e "\n${BLUE}📡 NETWORK INFO:${NC}"
    echo -e "   Public IP: $(curl -s ifconfig.me)"
    echo -e "   Location: ${SERVER_LOCATION}"
    echo -e "   ISP: ${SERVER_ISP}"
    
    echo -e "\n${BLUE}📈 RESOURCE USAGE:${NC}"
    echo -e "   CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
    echo -e "   Memory: $(free -m | awk 'NR==2{printf "%s/%s MB (%.2f%%)", $3, $2, $3*100/$2}')"
    echo -e "   Disk: $(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')"
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

service_control() {
    while true; do
        clear
        echo -e "${GREEN}"
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║                   Service Control                        ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        echo -e "${BLUE}🛠️  SERVICE STATUS:${NC}"
        if systemctl is-active --quiet xray; then
            echo -e "   Xray: ${GREEN}● Running${NC}"
        else
            echo -e "   Xray: ${RED}● Stopped${NC}"
        fi
        
        echo -e "\n${BLUE}⚙️  OPTIONS:${NC}"
        echo -e "   ${GREEN}1${NC}. Start Xray"
        echo -e "   ${GREEN}2${NC}. Stop Xray"
        echo -e "   ${GREEN}3${NC}. Restart Xray"
        echo -e "   ${GREEN}4${NC}. Check Status"
        echo -e "   ${GREEN}5${NC}. View Logs"
        echo -e "   ${GREEN}6${NC}. Back to Main Menu"
        
        read -p "Select an option [1-6]: " service_choice

        case $service_choice in
            1) systemctl start xray; echo -e "${GREEN}Xray started!${NC}"; sleep 1 ;;
            2) systemctl stop xray; echo -e "${YELLOW}Xray stopped!${NC}"; sleep 1 ;;
            3) systemctl restart xray; echo -e "${GREEN}Xray restarted!${NC}"; sleep 1 ;;
            4) clear; systemctl status xray --no-pager -l; echo -e "\n${GREEN}Press Enter to continue...${NC}"; read ;;
            5) view_logs ;;
            6) return ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

view_logs() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   View Logs                              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BLUE}📋 LOG FILES:${NC}"
    echo -e "   ${GREEN}1${NC}. Xray Access Log"
    echo -e "   ${GREEN}2${NC}. Xray Error Log"
    echo -e "   ${GREEN}3${NC}. System Log"
    echo -e "   ${GREEN}4${NC}. Back"
    
    read -p "Select log file [1-4]: " log_choice

    case $log_choice in
        1) tail -50 /var/log/tdz/access.log 2>/dev/null || echo "No access log found" ;;
        2) tail -50 /var/log/tdz/error.log 2>/dev/null || echo "No error log found" ;;
        3) journalctl -u xray -n 20 --no-pager ;;
        4) return ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 1; return ;;
    esac
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

backup_restore() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Backup & Restore                       ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BLUE}💾 OPTIONS:${NC}"
    echo -e "   ${GREEN}1${NC}. Backup Configuration"
    echo -e "   ${GREEN}2${NC}. Restore Configuration"
    echo -e "   ${GREEN}3${NC}. Back to Main Menu"
    
    read -p "Select an option [1-3]: " backup_choice

    case $backup_choice in
        1)
            BACKUP_DIR="/root/tdz-backup-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$BACKUP_DIR"
            cp -r /etc/tdz/ "$BACKUP_DIR/"
            cp /usr/local/etc/xray/config.json "$BACKUP_DIR/"
            echo -e "${GREEN}Backup created at: $BACKUP_DIR${NC}"
            ;;
        2)
            read -p "Enter backup directory path: " restore_dir
            if [ -d "$restore_dir" ]; then
                cp -r "$restore_dir"/* /etc/tdz/
                cp "$restore_dir/config.json" /usr/local/etc/xray/
                systemctl restart xray
                echo -e "${GREEN}Configuration restored!${NC}"
            else
                echo -e "${RED}Backup directory not found!${NC}"
            fi
            ;;
        3) return ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
    esac
    sleep 2
}

uninstall_tdz() {
    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   Uninstall Tdz Tunnel                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Are you sure you want to uninstall? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Uninstalling Tdz Tunnel...${NC}"
        
        systemctl stop xray
        systemctl disable xray
        rm -rf /usr/local/bin/tdz
        rm -rf /usr/local/etc/xray
        rm -rf /etc/tdz
        rm -f /root/tdz-config.txt
        rm -f /root/tdz-server-*
        rm -rf /var/log/tdz
        
        echo -e "${GREEN}Tdz Tunnel uninstalled successfully!${NC}"
    else
        echo -e "${GREEN}Uninstall cancelled.${NC}"
    fi
    echo -e "${NC}"
    exit 0
}

# Start the dashboard
if [ $# -eq 0 ]; then
    show_dashboard
else
    case $1 in
        "1") user_management ;;
        "2") protocol_management ;;
        "3") server_information ;;
        "4") service_control ;;
        "5") view_logs ;;
        "6") backup_restore ;;
        "7") uninstall_tdz ;;
        *) show_dashboard ;;
    esac
fi
EOF

chmod +x /usr/local/bin/tdz

# Save config
cat > /root/tdz-config.txt << EOF
Domain: $DOMAIN
VLESS UUID: $UUID_VLESS
VMESS UUID: $UUID_VMESS
Trojan Password: $UUID_TROJAN
Installation Date: $(date)
Server Location: $SERVER_LOCATION
Server ISP: $SERVER_ISP
WS Path: /TuhinDroidZone
gRPC Service Name: Tuhin-Internet-Service
EOF

# Initialize user database
mkdir -p /etc/tdz
echo '{"users": []}' > /etc/tdz/users.json

# Create log directory
mkdir -p /var/log/tdz

# Completion message
log_success "Installation completed!"
echo -e "${GREEN}"
echo "=================================================="
echo "           Tdz Tunnel Setup Complete!"
echo "=================================================="
echo -e "${NC}"
echo "Dashboard: ${CYAN}tdz${NC}"
echo "User Management: ${CYAN}tdz -> 1${NC}"
echo "Server Info: ${CYAN}tdz -> 3${NC}"
echo "Service Control: ${CYAN}tdz -> 4${NC}"
echo ""
echo "Config saved to: ${CYAN}/root/tdz-config.txt${NC}"
echo "User database: ${CYAN}/etc/tdz/users.json${NC}"require_root

# ---------- Update system and install prerequisites ----------
log_info "Updating system packages..."
apt update && apt upgrade -y
apt install -y curl wget sudo git unzip jq certbot python3-certbot-nginx bc

# ---------- Get domain from user ----------
read -p "Enter your domain name: " DOMAIN
if [ -z "$DOMAIN" ]; then
    log_error "Domain name is required!"
fi

# ---------- Verify domain ----------
log_info "Verifying domain: ${CYAN}$DOMAIN${NC}"
if ! ping -c 1 "$DOMAIN" &>/dev/null; then
    log_error "Domain not reachable! Please configure DNS first."
fi

# ---------- Get server location and ISP info ----------
get_server_info() {
    IP=$(curl -s ifconfig.me)
    LOCATION=$(curl -s ipinfo.io/"$IP" | jq -r '.country + ", " + .city')
    ISP=$(curl -s ipinfo.io/"$IP" | jq -r '.org')
    echo "$LOCATION" > /root/tdz-server-location.txt
    echo "$ISP" > /root/tdz-server-isp.txt
}
get_server_info

# ---------- Install Xray ----------
log_info "Installing Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# ---------- Generate SSL certificate ----------
log_info "Generating SSL certificate for ${CYAN}$DOMAIN${NC}"
certbot certonly --standalone --agree-tos --non-interactive --email admin@"$DOMAIN" -d "$DOMAIN"

# ---------- Generate UUIDs and custom IDs ----------
UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
UUID_TROJAN=$(cat /proc/sys/kernel/random/uuid)
CUSTOM_ID="TuhinDroidZone$(date +%m%d)"

# ---------- Create Xray config with ALL protocols ----------
log_info "Creating Xray configuration..."
cat > /usr/local/etc/xray/config.json << EOF
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "flow": "xtls-rprx-vision",
                        "email": "vless-user@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ],
                    "alpn": ["h2", "http/1.1"]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 80,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "email": "vless-ntls@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/@TuhinBroh",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 8443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-user@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/tdz-vmess",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 8080,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-ntls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/tdz-vmess-ntls",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            }
        },
        {
            "port": 2083,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-user@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 2087,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-grpc@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "Tuhin-Internet-Service"
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ],
    "stats": {},
    "policy": {
        "levels": {
            "0": {
                "statsUserUplink": true,
                "statsUserDownlink": true
            }
        }
    },
    "api": {
        "tag": "api",
        "services": ["StatsService"]
    }
}
EOF

# ---------- Restart Xray ----------
systemctl restart xray
systemctl enable xray

# ---------- Configure firewall ----------
log_info "Configuring firewall..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
ufw allow 8080/tcp
ufw allow 2083/tcp
ufw allow 2087/tcp
ufw --force enable

# ---------- Create bandwidth monitoring ----------
create_bandwidth_monitor() {
    cat > /usr/local/bin/bandwidth-monitor << 'EOF'
#!/bin/bash
echo "Bandwidth Usage:"
echo "=================================================="
if [ -f "/usr/local/etc/xray/access.log" ]; then
    echo "Total Data Used: $(du -h /usr/local/etc/xray/access.log | cut -f1)"
else
    echo "Log file not found. Bandwidth monitoring will start soon."
fi
echo "=================================================="
EOF
    chmod +x /usr/local/bin/bandwidth-monitor
}
create_bandwidth_monitor

# ---------- Create user management system ----------
mkdir -p /etc/tdz
cat > /etc/tdz/user-manager.sh << 'EOF'
#!/bin/bash

USER_DB="/etc/tdz/users.json"

initialize_db() {
    if [ ! -f "$USER_DB" ]; then
        echo '{"users": []}' > "$USER_DB"
    fi
}

create_user() {
    local protocol=$1
    local remark=$2
    local expiry_days=$3
    
    case $protocol in
        "vless")
            uuid=$(cat /proc/sys/kernel/random/uuid)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"vless\", \"uuid\": \"$uuid\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$uuid"
            ;;
        "vmess")
            uuid=$(cat /proc/sys/kernel/random/uuid)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"vmess\", \"uuid\": \"$uuid\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$uuid"
            ;;
        "trojan")
            password=$(cat /proc/sys/kernel/random/uuid | cut -d'-' -f1)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"trojan\", \"password\": \"$password\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$password"
            ;;
    esac
}

list_users() {
    jq -r '.users[] | "\(.protocol) - \(.remark) - Expiry: \(.expiry_date)"' "$USER_DB"
}

get_user_info() {
    local protocol=$1
    local remark=$2
    jq -r ".users[] | select(.protocol == \"$protocol\" and .remark == \"$remark\")" "$USER_DB"
}
EOF
chmod +x /etc/tdz/user-manager.sh

# ---------- Create enhanced control script with beautiful dashboard ----------
cat > /usr/local/bin/tdz << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

CONFIG_FILE="/root/tdz-config.txt"
USER_DB="/etc/tdz/users.json"
SERVER_LOCATION=$(cat /root/tdz-server-location.txt 2>/dev/null || echo "Singapore")
SERVER_ISP=$(cat /root/tdz-server-isp.txt 2>/dev/null || echo "Digital Ocean")
source /etc/tdz/user-manager.sh

initialize_db

# Function to display VLESS config
show_vless_config() {
    local remark=$1
    local uuid=$2
    local expiry_date=$3
    
    domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Tdz Tunnel - VLESS Account               ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "Remarks      : ${CYAN}$remark${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$domain${NC}"
    echo -e "Port TLS     : ${BLUE}443${NC}"
    echo -e "Port N-TLS   : ${BLUE}80${NC}"
    echo -e "UUID         : ${MAGENTA}$uuid${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}Auto${NC}"
    echo -e "Network      : ${YELLOW}Websocket/gRPC${NC}"
    echo -e "Service Name : ${CYAN}Tuhin-Internet-Service${NC}"
    echo -e "Path WS      : ${GREEN}/@TuhinBroh${NC}"
    echo -e "Expired On   : ${RED}$expiry_date${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            VLESS gRPC TLS Configuration            ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}vless://$uuid@$domain:443?type=grpc&encryption=none&serviceName=Tuhin-Internet-Service&security=tls&sni=$domain&fp=chrome&alpn=h2,http/1.1#$remark${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            VLESS WS NO TLS Configuration           ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}vless://$uuid@$domain:80?type=ws&encryption=none&path=/@TuhinBroh&host=$domain&security=none#$remark${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
}

# Function to display VMess config
show_vmess_config() {
    local remark=$1
    local uuid=$2
    local expiry_date=$3
    
    domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    
    vmess_config=$(cat << EOV
{
  "v": "2",
  "ps": "$remark",
  "add": "$domain",
  "port": "8443",
  "id": "$uuid",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "$domain",
  "path": "/tdz-vmess",
  "tls": "tls"
}
EOV
    )
    
    vmess_config_ntls=$(cat << EOV
{
  "v": "2",
  "ps": "$remark-NTLS",
  "add": "$domain",
  "port": "8080",
  "id": "$uuid",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "$domain",
  "path": "/tdz-vmess-ntls",
  "tls": "none"
}
EOV
    )
    
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Tdz Tunnel - VMESS Account               ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "Remarks      : ${CYAN}$remark${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$domain${NC}"
    echo -e "Port TLS     : ${BLUE}8443${NC}"
    echo -e "Port N-TLS   : ${BLUE}8080${NC}"
    echo -e "UUID         : ${MAGENTA}$uuid${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}Auto${NC}"
    echo -e "Network      : ${YELLOW}Websocket${NC}"
    echo -e "Path TLS     : ${GREEN}/tdz-vmess${NC}"
    echo -e "Path N-TLS   : ${GREEN}/tdz-vmess-ntls${NC}"
    echo -e "Expired On   : ${RED}$expiry_date${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            VMESS WS TLS Configuration              ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}vmess://$(echo "$vmess_config" | base64 -w 0)${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            VMESS WS NO TLS Configuration           ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}vmess://$(echo "$vmess_config_ntls" | base64 -w 0)${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
}

# Function to display Trojan config
show_trojan_config() {
    local remark=$1
    local password=$2
    local expiry_date=$3
    
    domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Tdz Tunnel - Trojan Account              ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "Remarks      : ${CYAN}$remark${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$domain${NC}"
    echo -e "Port TCP     : ${BLUE}2083${NC}"
    echo -e "Port gRPC    : ${BLUE}2087${NC}"
    echo -e "Password     : ${MAGENTA}$password${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}TLS${NC}"
    echo -e "Network      : ${YELLOW}TCP/gRPC${NC}"
    echo -e "Service Name : ${CYAN}Tuhin-Internet-Service${NC}"
    echo -e "Expired On   : ${RED}$expiry_date${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Trojan TCP TLS Configuration            ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}trojan://$password@$domain:2083?security=tls&type=tcp&headerType=none&sni=$domain#$remark${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Trojan gRPC TLS Configuration           ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}trojan://$password@$domain:2087?security=tls&type=grpc&serviceName=Tuhin-Internet-Service&sni=$domain#$remark${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
}

# Function to create user with menu
create_user_menu() {
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Create New User                          ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}1. VLESS User${NC}"
    echo -e "${CYAN}2. VMESS User${NC}"
    echo -e "${CYAN}3. Trojan User${NC}"
    echo -e "${CYAN}4. Back to Main Menu${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    read -p "Select protocol [1-4]: " proto_choice
    
    case $proto_choice in
        1) protocol="vless" ;;
        2) protocol="vmess" ;;
        3) protocol="trojan" ;;
        4) return ;;
        *) echo -e "${RED}Invalid choice!${NC}"; sleep 1; create_user_menu; return ;;
    esac
    
    read -p "Enter remark name: " remark
    read -p "Enter expiry days: " expiry_days
    
    if [ "$protocol" = "vless" ] || [ "$protocol" = "vmess" ]; then
        user_id=$(create_user "$protocol" "$remark" "$expiry_days")
        expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
        
        if [ "$protocol" = "vless" ]; then
            show_vless_config "$remark" "$user_id" "$expiry_date"
        else
            show_vmess_config "$remark" "$user_id" "$expiry_date"
        fi
    else
        password=$(create_user "$protocol" "$remark" "$expiry_days")
        expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
        show_trojan_config "$remark" "$password" "$expiry_date"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to list users
list_users_menu() {
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Current Users                            ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    list_users
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    read -p "Press Enter to continue..."
}

# Function to show server status
show_status() {
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Server Status                            ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    systemctl status xray --no-pager -l
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    read -p "Press Enter to continue..."
}

# Function to show bandwidth
show_bandwidth() {
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Bandwidth Usage                          ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    /usr/local/bin/bandwidth-monitor
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    read -p "Press Enter to continue..."
}

# Function to restart services
restart_services() {
    systemctl restart xray
    echo -e "${GREEN}Services restarted successfully!${NC}"
    sleep 1
}

# Function to change domain
change_domain() {
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Change Domain                            ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    read -p "Enter new domain name: " new_domain
    sed -i "s/Domain: .*/Domain: $new_domain/" "$CONFIG_FILE"
    echo -e "${GREEN}Domain changed to $new_domain${NC}"
    sleep 1
}

# Function to show VPS info
vps_info() {
    clear
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            VPS Information                          ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "CPU: $(nproc) cores"
    echo -e "RAM: $(free -h | grep Mem | awk '{print $2}')"
    echo -e "Disk: $(df -h / | grep / | awk '{print $2}')"
    echo -e "Location: $SERVER_LOCATION"
    echo -e "ISP: $SERVER_ISP"
    echo -e "IP: $(curl -s ifconfig.me)"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    read -p "Press Enter to continue..."
}

# Function to uninstall Tdz Tunnel
uninstall_tdz() {
    clear
    echo -e "${RED}════════════════════════════════════════════════════${NC}"
    echo -e "${RED}            Uninstall Tdz Tunnel                     ${NC}"
    echo -e "${RED}════════════════════════════════════════════════════${NC}"
    read -p "Are you sure you want to uninstall? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        systemctl stop xray
        systemctl disable xray
        rm -rf /usr/local/bin/tdz
        rm -rf /usr/local/etc/xray
        rm -rf /etc/tdz
        rm -f /root/tdz-config.txt
        rm -f /root/tdz-server-location.txt
        rm -f /root/tdz-server-isp.txt
        echo -e "${GREEN}Tdz Tunnel uninstalled successfully!${NC}"
    fi
    echo -e "${NC}"
    exit 0
}

# Enhanced main menu
show_main_menu() {
    while true; do
        clear
        echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}        Tdz Tunnel Control Panel v1.0                ${NC}"
        echo -e "${GREEN}        Developer: Yeasinul Hoque Tuhin             ${NC}"
        echo -e "${GREEN}        Website: tuhinbro.website                   ${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}1. Create New User${NC}"
        echo -e "${CYAN}2. List All Users${NC}"
        echo -e "${CYAN}3. Show VLESS Config${NC}"
        echo -e "${CYAN}4. Show VMESS Config${NC}"
        echo -e "${CYAN}5. Show Trojan Config${NC}"
        echo -e "${CYAN}6. Server Status${NC}"
        echo -e "${CYAN}7. Bandwidth Monitoring${NC}"
        echo -e "${CYAN}8. Restart Services${NC}"
        echo -e "${CYAN}9. Change Domain${NC}"
        echo -e "${CYAN}10. VPS Information${NC}"
        echo -e "${CYAN}11. Uninstall Tdz Tunnel${NC}"
        echo -e "${CYAN}0. Exit${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
        read -p "Select an option [0-11]: " main_choice

        case $main_choice in
            1) create_user_menu ;;
            2) list_users_menu ;;
            3) show_vless_config "TUSFZ" "$(grep "VLESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)" "25/09/2025" ;;
            4) show_vmess_config "TUSFZ-VMESS" "$(grep "VMESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)" "25/09/2025" ;;
            5) show_trojan_config "TUSFZ-TROJAN" "$(grep "Trojan Password:" "$CONFIG_FILE" | cut -d' ' -f4)" "25/09/2025" ;;
            6) show_status ;;
            7) show_bandwidth ;;
            8) restart_services ;;
            9) change_domain ;;
            10) vps_info ;;
            11) uninstall_tdz ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# Start the menu
if [ $# -eq 0 ]; then
    show_main_menu
else
    case $1 in
        "1") create_user_menu ;;
        "2") list_users_menu ;;
        "3") show_vless_config "TUSFZ" "$(grep "VLESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)" "25/09/2025" ;;
        "4") show_vmess_config "TUSFZ-VMESS" "$(grep "VMESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)" "25/09/2025" ;;
        "5") show_trojan_config "TUSFZ-TROJAN" "$(grep "Trojan Password:" "$CONFIG_FILE" | cut -d' ' -f4)" "25/09/2025" ;;
        "6") show_status ;;
        "7") show_bandwidth ;;
        "8") restart_services ;;
        "9") change_domain ;;
        "10") vps_info ;;
        "11") uninstall_tdz ;;
        *) show_main_menu ;;
    esac
fi
EOF
chmod +x /usr/local/bin/tdz

# ---------- Save config ----------
cat > /root/tdz-config.txt << EOF
Domain: $DOMAIN
VLESS UUID: $UUID_VLESS
VMESS UUID: $UUID_VMESS
Trojan Password: $UUID_TROJAN
Custom ID: $CUSTOM_ID
Installation Date: $(date)
Server Location: $SERVER_LOCATION
Server ISP: $SERVER_ISP
EOF

# ---------- Initialize user database ----------
mkdir -p /etc/tdz
echo '{"users": []}' > /etc/tdz/users.json

# ---------- Completion message ----------
log_success "Installation completed!"
echo -e "${GREEN}"
echo "=================================================="
echo "           Tdz Tunnel Setup Complete!"
echo "=================================================="
echo -e "${NC}"
echo "Control Panel: ${CYAN}tdz${NC}"
echo "Create User: ${CYAN}tdz 1${NC}"
echo "List Users: ${CYAN}tdz 2${NC}"
echo "Show VLESS: ${CYAN}tdz 3${NC}"
echo "Show VMESS: ${CYAN}tdz 4${NC}"
echo "Show Trojan: ${CYAN}tdz 5${NC}"
echo ""
echo "Config saved to: ${CYAN}/root/tdz-config.txt${NC}"
echo "User database: ${CYAN}/etc/tdz/users.json${NC}"
# ---------- Interactive prompts (with defaults) ----------
read -rp "Enter domain to use for TLS (leave empty to skip certbot and use self-signed): " DOMAIN
if [ -z "$DOMAIN" ]; then
  msg "No domain provided — TLS via certbot will be skipped. We'll create a self-signed cert (not recommended for production)."
  USE_CERTBOT=0
else
  USE_CERTBOT=1
fi

read -rp "Enter websocket path (default: $DEFAULT_WS_PATH): " WS_PATH
WS_PATH=${WS_PATH:-$DEFAULT_WS_PATH}
# normalize leading slash
if [[ "$WS_PATH" != /* ]]; then WS_PATH="/$WS_PATH"; fi

read -rp "Enter systemd service name (default: $DEFAULT_SERVICE_NAME): " SERVICE_NAME
SERVICE_NAME=${SERVICE_NAME:-$DEFAULT_SERVICE_NAME}

msg "Using domain: ${DOMAIN:-(none)}"
msg "Using websocket path: $WS_PATH"
msg "Service name: $SERVICE_NAME"

sleep 1

# ---------- Install prerequisites ----------
msg "Installing prerequisites..."
apt-get update -y
apt-get install -y curl wget gnupg2 apt-transport-https lsb-release ca-certificates unzip jq socat openssl cron sudo software-properties-common

if [ "$USE_CERTBOT" -eq 1 ]; then
  apt-get install -y certbot
fi

# ---------- Install Xray (official) ----------
msg "Installing Xray-core..."
# Attempt official installer for reliability
bash <(curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) || err "Xray install failed"

if ! command -v xray >/dev/null 2>&1; then
  err "xray binary not found after install"
fi

# ---------- TLS: certbot or self-signed ----------
CERT_FULLCHAIN=""
CERT_PRIVKEY=""
if [ "$USE_CERTBOT" -eq 1 ]; then
  msg "Obtaining TLS certificate for $DOMAIN using certbot (standalone). Make sure port 80 is free."
  systemctl stop nginx apache2 2>/dev/null || true
  if certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"; then
    CERT_FULLCHAIN="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    CERT_PRIVKEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    msg "Obtained certs: $CERT_FULLCHAIN"
  else
    msg "certbot failed — falling back to self-signed certificate"
    USE_CERTBOT=0
  fi
fi

if [ "$USE_CERTBOT" -eq 0 ]; then
  msg "Creating self-signed certificate for $DOMAIN (or for host)"
  HOST_CN=${DOMAIN:-"$(hostname -f 2>/dev/null || echo "localhost")"}
  mkdir -p /etc/tdz/certs
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/tdz/certs/tdz.key -out /etc/tdz/certs/tdz.crt -subj "/CN=$HOST_CN"
  CERT_FULLCHAIN="/etc/tdz/certs/tdz.crt"
  CERT_PRIVKEY="/etc/tdz/certs/tdz.key"
  msg "Self-signed cert created at $CERT_FULLCHAIN"
fi

# ---------- Generate Xray config ----------
msg "Generating Xray config at $XRAY_CONFIG ..."
cat > "$XRAY_CONFIG" <<EOF
{
  "log": {"access": "/var/log/tdz/access.log", "error": "/var/log/tdz/error.log", "loglevel": "warning"},
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": {"path": "$WS_PATH"},
        "tlsSettings": {"certificates": [{"certificateFile": "$CERT_FULLCHAIN","keyFile": "$CERT_PRIVKEY"}]}
      }
    },
    {
      "port": 8443,
      "protocol": "vmess",
      "settings": {"clients": []},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "$WS_PATH"}}
    },
    {
      "port": 2083,
      "protocol": "trojan",
      "settings": {"clients": []},
      "streamSettings": {"network": "tcp"}
    }
  ],
  "outbounds": [
    {"protocol": "freedom","settings": {}},
    {"protocol": "blackhole","settings": {}, "tag": "blocked"}
  ],
  "policy": {"levels": {"0": {"uplinkOnly": 0, "downlinkOnly": 0}}},
  "transport": {}
}
EOF

# set correct permissions
chown -R root:root "$XRAY_DIR"
chmod -R 644 "$XRAY_CONFIG"

# ---------- Systemd service with custom name & description ----------
msg "Creating systemd service: /etc/systemd/system/$SERVICE_NAME"
cat >/etc/systemd/system/$SERVICE_NAME <<EOL
[Unit]
Description=Tuhin - Internet Service
After=network.target nss-lookup.target

[Service]
User=root
ExecStart=/usr/local/bin/xray -config $XRAY_CONFIG
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME" || true

# ---------- Users DB and management CLI ----------
if [ ! -f "$USERS_DB" ]; then
  echo '{"users":[]}' > "$USERS_DB"
fi

msg "Installing management CLI at $TDZ_BIN"
cat > "$TDZ_BIN" <<'TDZ'
#!/usr/bin/env bash
# tdz - account manager for Tdz Tunnel
TDZ_DIR="/etc/tdz"
XRAY_CFG="/etc/xray/tdz_config.json"
USERS_DB="$TDZ_DIR/users.json"

require_root(){ [ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; } }
require_root

usage(){ cat <<USAGE
Usage: tdz <command>
Commands:
  add <name> [--id UUID] [--path PATH] [--limit MB] [--expiry DAYS]
  delete <id_or_name>
  list
  show <id_or_name>
  genlinks <id_or_name_or_id>
  help
USAGE
}

rand_uuid(){ if command -v uuidgen >/dev/null 2>&1; then uuidgen; else cat /proc/sys/kernel/random/uuid; fi }

add_user(){
  NAME="$1"; shift
  ID=""; CUSTOM_PATH=""; LIMIT=0; EXP=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --id) ID="$2"; shift 2;;
      --path) CUSTOM_PATH="$2"; shift 2;;
      --limit) LIMIT="$2"; shift 2;;
      --expiry) EXP="$2"; shift 2;;
      *) shift;;
    esac
  done
  [ -n "$ID" ] || ID=$(rand_uuid)
  [ -n "$CUSTOM_PATH" ] || CUSTOM_PATH="/TuhinDroidZone"
  CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  USER_OBJ=$(jq -n --arg id "$ID" --arg name "$NAME" --arg created "$CREATED" --arg path "$CUSTOM_PATH" --argjson limit $LIMIT --argjson exp $EXP '{id:$id, name:$name, created:$created, path:$path, limit:$limit, expiry_days:$exp, disabled:false}')
  tmp=$(mktemp)
  jq ".users += [$USER_OBJ]" "$USERS_DB" > "$tmp" && mv "$tmp" "$USERS_DB"

  # inject into xray config
  tmp2=$(mktemp)
  jq --arg id "$ID" --arg email "$NAME" --arg path "$CUSTOM_PATH" '
  .inbounds[0].settings.clients += [{"id":$id, "email":$email}] |
  .inbounds[1].settings.clients += [{"id":$id, "email":$email, "alterId":0}] |
  .inbounds[2].settings.clients += [{"password":$id, "email":$email}]' "$XRAY_CFG" > "$tmp2" && mv "$tmp2" "$XRAY_CFG"

  systemctl restart tuhin-internet.service >/dev/null 2>&1 || true
  echo "Added user: $NAME (id: $ID)"
  echo "Run: tdz genlinks $ID to get client links"
}

delete_user(){
  KEY="$1"
  tmp=$(mktemp)
  jq --arg key "$KEY" '.users |= map(select(.id != $key and .name != $key))' "$USERS_DB" > "$tmp" && mv "$tmp" "$USERS_DB"

  tmp2=$(mktemp)
  jq --arg key "$KEY" '
  .inbounds[0].settings.clients |= map(select(.id != $key and .email != $key)) |
  .inbounds[1].settings.clients |= map(select(.id != $key and .email != $key)) |
  .inbounds[2].settings.clients |= map(select(.password != $key and .email != $key))' "$XRAY_CFG" > "$tmp2" && mv "$tmp2" "$XRAY_CFG"

  systemctl restart tuhin-internet.service >/dev/null 2>&1 || true
  echo "Deleted: $KEY"
}

list_users(){
  jq -r '.users[] | "- id:\t" + .id + "\tname:\t" + .name + "\tpath:\t" + .path + "\tcreated:\t" + .created + "\tlimit(MB):\t" + (.limit|tostring) + "\texpiry_days:\t" + (.expiry_days|tostring) + "\tdisabled:\t" + (.disabled|tostring)' "$USERS_DB"
}

show_user(){
  KEY="$1"
  jq -r --arg key "$KEY" '.users[] | select(.id==$key or .name==$key) | to_entries[] | "\(.key): \(.value)"' "$USERS_DB"
}

genlinks(){
  KEY="$1"
  USER=$(jq -r --arg key "$KEY" '.users[] | select(.id==$key or .name==$key) | @base64' "$USERS_DB" | head -n1 || true)
  if [ -z "$USER" ]; then echo "User not found"; exit 1; fi
  _u() { echo "$1" | base64 -d | jq -r ".${2}"; }
  ID=$(_u "$USER" id)
  NAME=$(_u "$USER" name)
  PATH=$(_u "$USER" path)
  DOMAIN=$(jq -r '. | "'"'${HOSTNAME}'"' ' /etc/tdz/ 2>/dev/null || echo "$(hostname -f)")
  # read domain from config TLS settings if present
  CFG_DOMAIN="$(jq -r '.inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile' /etc/xray/tdz_config.json 2>/dev/null || true)"
  if [ -n "$CFG_DOMAIN" ]; then DOMAIN="$CFG_DOMAIN"; fi
  VLESS_PORT=$(jq -r '.inbounds[0].port' /etc/xray/tdz_config.json)
  VMESS_PORT=$(jq -r '.inbounds[1].port' /etc/xray/tdz_config.json)
  TROJAN_PORT=$(jq -r '.inbounds[2].port' /etc/xray/tdz_config.json)

  echo "=== Client links for $NAME ==="
  VLESS_LINK="vless://${ID}@${DOMAIN}:${VLESS_PORT}?path=${PATH}&security=tls&type=ws#${NAME}-vless"
  echo "VLESS (WS+TLS): $VLESS_LINK"

  VMESS_JSON=$(jq -n --arg id "$ID" --arg host "$DOMAIN" --arg path "$PATH" '{v: "2", ps: "'"'${NAME}-vmess'"'", add: $host, port: '"$VMESS_PORT"', id: $id, aid: "0", net: "ws", type: "none", host: "", path: $path, tls: "tls"}')
  VMESS_B64=$(echo -n "$VMESS_JSON" | base64 -w0)
  echo "VMESS (base64): vmess://$VMESS_B64"

  TROJAN_LINK="trojan://${ID}@${DOMAIN}:${TROJAN_PORT}#${NAME}-trojan"
  echo "TROJAN: $TROJAN_LINK"
}

case "${1:-help}" in
  add) shift; add_user "$@" ;;
  delete) shift; delete_user "$1" ;;
  list) list_users ;;
  show) shift; show_user "$1" ;;
  genlinks) shift; genlinks "$1" ;;
  help|*) usage ;;
esac
TDZ

chmod +x "$TDZ_BIN"

# ---------- Expiry checker cron ----------
msg "Installing expiry checker cron (runs every 10 minutes)"
cat >/etc/cron.d/tdz-expiry <<CRON
*/10 * * * * root $EXPIRY_CHECKER >/var/log/tdz/expiry.log 2>&1
CRON

cat > "$EXPIRY_CHECKER" <<'CHECK'
#!/usr/bin/env bash
USERS_DB="/etc/tdz/users.json"
XRAY_CFG="/etc/xray/tdz_config.json"
[ -f "$USERS_DB" ] || exit 0
for u in $(jq -c '.users[]' "$USERS_DB"); do
  id=$(echo "$u" | jq -r '.id')
  name=$(echo "$u" | jq -r '.name')
  created=$(echo "$u" | jq -r '.created')
  expiry_days=$(echo "$u" | jq -r '.expiry_days')
  if [ "$expiry_days" -gt 0 ]; then
    created_epoch=$(date -d "$created" +%s)
    now_epoch=$(date -u +%s)
    expire_epoch=$((created_epoch + expiry_days*86400))
    if [ $now_epoch -ge $expire_epoch ]; then
      tmp=$(mktemp)
      jq --arg id "$id" '.users |= map(if .id==$id then .disabled=true else . end)' "$USERS_DB" > "$tmp" && mv "$tmp" "$USERS_DB"
      tmp2=$(mktemp)
      jq --arg key "$id" '
      .inbounds[0].settings.clients |= map(select(.id != $key)) |
      .inbounds[1].settings.clients |= map(select(.id != $key)) |
      .inbounds[2].settings.clients |= map(select(.password != $key))' "$XRAY_CFG" > "$tmp2" && mv "$tmp2" "$XRAY_CFG"
      systemctl restart tuhin-internet.service || true
      echo "Disabled expired user: $name ($id)"
    fi
  fi
done
CHECK
chmod +x "$EXPIRY_CHECKER"

# ---------- Final checks ----------
msg "Restarting service and checking status..."
systemctl restart "$SERVICE_NAME" || true
sleep 2
systemctl status "$SERVICE_NAME" --no-pager || true

cat <<FIN

INSTALLATION COMPLETE ✅
Files & helpers:
 - Xray config: $XRAY_CONFIG
 - Users DB: $USERS_DB
 - CLI manager: $TDZ_BIN (use: tdz add, tdz list, tdz genlinks ...)
 - Service: systemctl (name: $SERVICE_NAME, Description: "Tuhin - Internet Service")
 - Logs: /var/log/tdz/

Notes & next steps:
 - If you used a real domain, certbot was used to obtain TLS. If certbot failed, a self-signed cert was created.
 - To add a user with custom UUID and custom WS path:
     sudo tdz add "username" --id 123e4567-e89b-12d3-a456-426614174000 --path /TuhinDroidZone --expiry 30
 - To list users:
     sudo tdz list
 - To generate client links:
     sudo tdz genlinks username_or_id

I tried to make this robust, but I cannot *guarantee* clients will connect in every environment (ports, firewall, NAT, provider blocks). If a client cannot connect:
 - Check ports 80/443/8443/2083 are open in both VPS firewall (ufw/iptables) and cloud provider security group.
 - Ensure DNS for your domain points to the VPS public IP.
 - Check logs: tail -n 200 /var/log/tdz/error.log
 - Check service: systemctl status $SERVICE_NAME

If you want, I can now:
 - Add automatic Let's Encrypt renewal hooks (certbot renew deploy-hook to restart service)
 - Implement per-user traffic quota using Xray stats API
 - Add a simple web panel to view users & usage

Developer: Yeasinul Hoque Tuhin
Website: tuhinbro.website

FIN

exit 0
--------- Install Xray core (official binary) ---------

install_xray(){ msg "Installing Xray-core (latest)..." XRAY_VER="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)" ARCH="$(dpkg --print-architecture)" case "$ARCH" in amd64) ARCH_TAG="linux-64";; arm64|aarch64) ARCH_TAG="linux-arm64";; armhf|armv7l) ARCH_TAG="linux-armv7";; ) ARCH_TAG="linux-64";; esac TMPDIR=$(mktemp -d) cd "$TMPDIR" curl -sL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-${XRAY_VER}-${ARCH_TAG}.zip" -o xray.zip || { msg "Release download failed, trying Xray official installer..." bash <(curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) || err "xray install failed" return } apt-get install -y unzip unzip xray.zip install -m 755 xray /usr/local/bin/xray mkdir -p /usr/local/share/xray cp geosite.dat geosite.dat. /usr/local/share/xray/ 2>/dev/null || true cp geoip.dat geoip.dat.* /usr/local/share/xray/ 2>/dev/null || true cd - >/dev/null rm -rf "$TMPDIR"

systemd service

cat >/etc/systemd/system/xray.service <<'EOF' [Unit] Description=Xray Service (tdz) After=network.target nss-lookup.target

[Service] User=root ExecStart=/usr/local/bin/xray -config /etc/xray/tdz_config.json Restart=on-failure

[Install] WantedBy=multi-user.target EOF systemctl daemon-reload }

--------- Default Xray config (VLESS WS/TCP, VMess, Trojan) ---------

generate_config(){ msg "Generating Xray configuration..." cat > "$XRAY_CONFIG" <<EOF { "log": {"access": "/var/log/tdz/access.log", "error": "/var/log/tdz/error.log", "loglevel": "warning"}, "inbounds": [ { "port": 443, "protocol": "vless", "settings": {"clients": []}, "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"alpn": ["h2","http/1.1"]}} }, { "port": 8443, "protocol": "vmess", "settings": {"clients": []}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/tdz-ws"}} }, { "port": 2083, "protocol": "trojan", "settings": {"clients": []}, "streamSettings": {"network": "tcp"} } ], "outbounds": [ {"protocol": "freedom","settings": {}}, {"protocol": "blackhole","settings": {}, "tag": "blocked"} ], "policy": {"levels": {"0": {"uplinkOnly": 0, "downlinkOnly": 0}}}, "transport": {} } EOF

default users DB

if [ ! -f "$USERS_DB" ]; then echo '{"users":[]}' > "$USERS_DB" fi }

--------- Management CLI that manipulates config & users DB ---------

install_manager(){ msg "Installing management CLI at $TDZ_BIN" cat > "$TDZ_BIN" <<'TDZ' #!/usr/bin/env bash

tdz - simple Xray account manager for Tdz Tunnel

TDZ_DIR="/etc/tdz" XRAY_CFG="/etc/xray/tdz_config.json" USERS_DB="$TDZ_DIR/users.json"

jq_cmd() { jq -r "$@"; } require_root(){ [ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; } } require_root

usage(){ cat <<USAGE Usage: tdz <command> [args] Commands: add <name> [--id UUID] [--limit MB] [--expiry DAYS]    Add new account (prints links) delete <id_or_email>                                   Delete account list                                                   List accounts show <id_or_email>                                     Show account details genlinks <id_or_email>                                 Print client links help USAGE }

rand_uuid(){ if command -v uuidgen >/dev/null 2>&1; then uuidgen; else cat /proc/sys/kernel/random/uuid; fi }

add_user(){ NAME="$1"; shift ID=""; LIMIT=0; EXP=0 while [ "$#" -gt 0 ]; do case "$1" in --id) ID="$2"; shift 2;; --limit) LIMIT="$2"; shift 2;; --expiry) EXP="$2"; shift 2;; *) shift;; esac done [ -n "$ID" ] || ID=$(rand_uuid) CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ) USER=$(jq -n --arg id "$ID" --arg name "$NAME" --arg created "$CREATED" --argjson limit $LIMIT --argjson exp $EXP '{id:$id, name:$name, created:$created, limit:$limit, expiry_days:$exp, disabled:false}') tmp=$(mktemp) jq ".users += [$USER]" "$USERS_DB" > "$tmp" && mv "$tmp" "$USERS_DB"

inject into xray config: add to each inbound clients list

for proto in "vless" "vmess" "trojan"; do case $proto in vless) jq --arg id "$ID" --arg email "$NAME" '.inbounds[0].settings.clients += [{"id":$id, "email":$email}]' "$XRAY_CFG" > "$tmp" && mv "$tmp" "$XRAY_CFG" ;; vmess) # vmess client format: id, alterId not used in v4 jq --arg id "$ID" --arg email "$NAME" '.inbounds[1].settings.clients += [{"id":$id, "email":$email, "alterId":0}]' "$XRAY_CFG" > "$tmp" && mv "$tmp" "$XRAY_CFG" ;; trojan) jq --arg id "$ID" --arg email "$NAME" '.inbounds[2].settings.clients += [{"password":$id, "email":$email}]' "$XRAY_CFG" > "$tmp" && mv "$tmp" "$XRAY_CFG" ;; esac done

systemctl restart xray || true echo "Added user: $NAME (id: $ID)" echo "Run: tdz genlinks $ID to get client config/links" }

delete_user(){ KEY="$1" tmp=$(mktemp)

remove from users DB

jq --arg key "$KEY" '.users |= map(select(.id != $key and .name != $key))' "$USERS_DB" > "$tmp" && mv "$tmp" "$USERS_DB"

remove from xray config clients

jq --arg key "$KEY" ' .inbounds[0].settings.clients |= map(select(.id != $key and .email != $key)) | .inbounds[1].settings.clients |= map(select(.id != $key and .email != $key)) | .inbounds[2].settings.clients |= map(select(.password != $key and .email != $key))' "$XRAY_CFG" > "$tmp" && mv "$tmp" "$XRAY_CFG"

systemctl restart xray || true echo "Deleted: $KEY" }

list_users(){ jq -r '.users[] | "- id:\t" + .id + "\tname:\t" + .name + "\tcreated:\t" + .created + "\tlimit(MB):\t" + (.limit|tostring) + "\texpiry_days:\t" + (.expiry_days|tostring)' "$USERS_DB" }

show_user(){ KEY="$1" jq -r --arg key "$KEY" '.users[] | select(.id==$key or .name==$key) | to_entries[] | "(.key): (.value)"' "$USERS_DB" }

genlinks(){ KEY="$1"

find user

USER=$(jq -r --arg key "$KEY" '.users[] | select(.id==$key or .name==$key) | @base64' "$USERS_DB" | head -n1 || true) if [ -z "$USER" ]; then echo "User not found"; exit 1; fi _u() { echo "$1" | base64 -d | jq -r ".${2}"; } ID=$(_u "$USER" id) NAME=$(_u "$USER" name) DOMAIN=$(jq -r '. | "'"'${DOMAIN}'"' ' /etc/tdz/ 2>/dev/null || echo "$HOSTNAME")

ports from config

VLESS_PORT=$(jq -r '.inbounds[0].port' "$XRAY_CFG") VMESS_PORT=$(jq -r '.inbounds[1].port' "$XRAY_CFG") TROJAN_PORT=$(jq -r '.inbounds[2].port' "$XRAY_CFG")

echo "=== Client links for $NAME ==="

VLESS ws+tls

VLESS_LINK="vless://${ID}@${DOMAIN}:${VLESS_PORT}?path=/tdz-ws&security=tls&type=ws#${NAME}-vless" echo "VLESS (WS+TLS): $VLESS_LINK"

VMESS JSON -> base64

VMESS_JSON=$(jq -n --arg id "$ID" --arg host "$DOMAIN" --arg path "/tdz-ws" '{v: "2", ps: "'"'${NAME}-vmess'"'", add: $host, port: '$VMESS_PORT', id: $id, aid: "0", net: "ws", type: "none", host: "", path: $path, tls: ""}') VMESS_B64=$(echo -n "$VMESS_JSON" | base64 -w0) echo "VMESS (base64): vmess://$VMESS_B64"

TROJAN

TROJAN_LINK="trojan://${ID}@${DOMAIN}:${TROJAN_PORT}#${NAME}-trojan" echo "TROJAN: $TROJAN_LINK" }

Main dispatcher

case "${1:-help}" in add) shift; add_user "$@" ;; delete) shift; delete_user "$1" ;; list) list_users ;; show) shift; show_user "$1" ;; genlinks) shift; genlinks "$1" ;; help|*) usage ;; esac TDZ chmod +x "$TDZ_BIN" }

--------- Expiry cron (disables users after expiry_days) ---------

install_expiry_cron(){ msg "Installing expiry checker cron (runs every 10 minutes)" cat >/etc/cron.d/tdz-expiry <<'CRON' */10 * * * * root /usr/local/bin/tdz-expiry-check >/var/log/tdz/expiry.log 2>&1 CRON

cat > /usr/local/bin/tdz-expiry-check <<'CHECK' #!/usr/bin/env bash USERS_DB="/etc/tdz/users.json" XRAY_CFG="/etc/xray/tdz_config.json" [ -f "$USERS_DB" ] || exit 0 for u in $(jq -c '.users[]' "$USERS_DB"); do id=$(echo "$u" | jq -r '.id') name=$(echo "$u" | jq -r '.name') created=$(echo "$u" | jq -r '.created') expiry_days=$(echo "$u" | jq -r '.expiry_days') if [ "$expiry_days" -gt 0 ]; then created_epoch=$(date -d "$created" +%s) now_epoch=$(date -u +%s) expire_epoch=$((created_epoch + expiry_days*86400)) if [ $now_epoch -ge $expire_epoch ]; then # disable user: remove from config and mark in DB tmp=$(mktemp) jq --arg id "$id" '.users |= map(if .id==$id then .disabled=true else . end)' "$USERS_DB" > "$tmp" && mv "$tmp" "$USERS_DB" tmp2=$(mktemp) jq --arg key "$id" ' .inbounds[0].settings.clients |= map(select(.id != $key)) | .inbounds[1].settings.clients |= map(select(.id != $key)) | .inbounds[2].settings.clients |= map(select(.password != $key))' "$XRAY_CFG" > "$tmp2" && mv "$tmp2" "$XRAY_CFG" systemctl restart xray || true echo "Disabled expired user: $name ($id)" fi fi done CHECK chmod +x /usr/local/bin/tdz-expiry-check }

--------- Final instructions and optional steps ---------

post_install_notes(){ cat <<'NOTES'

Tdz Tunnel 설치 শেষ হয়েছে!

관리 명령어 (root로 실행): tdz add <name> [--id UUID] [--limit MB] [--expiry DAYS] tdz delete <id_or_email> tdz list tdz genlinks <id_or_email>

Important notes / limitations:

This installer provides a working Xray config and a simple management CLI.

Traffic quota enforcement (bytes per user) is NOT fully implemented by default. To implement quotas you can: • Use Xray's stats API (enable and query per-user traffic) and disable accounts when quota exceeded (cron + jq). • Use system-level monitoring like vnstat or iptables accounting + cron to disable users when they exceed limit. • Use tc/nftables to shape per-IP bandwidth (requires mapping user -> IP).


Security & TLS:

This template assumes you'll provide TLS certificates (recommended: use certbot to obtain real certs for $DOMAIN) Example: apt-get install -y certbot && certbot certonly --standalone -d $DOMAIN Then update tdz_config.json tlsSettings to point to the cert and key files.


Customization:

Ports, paths, and protocols are controlled in /etc/xray/tdz_config.json

Users are recorded in /etc/tdz/users.json


If you want, I can extend the script to:

Automatically obtain and renew Let's Encrypt certs

Implement per-user traffic quotas using Xray's stats API

Add a simple web panel (static) to list users and usage


Enjoy — Developer: Yeasinul Hoque Tuhin

NOTES }

--------- Run installation steps ---------

install_prereq install_xray generate_config install_manager install_expiry_cron systemctl enable --now xray || true post_install_notes

exit 0


# Update system
log_info "Updating system packages..."
apt update && apt upgrade -y
apt install -y curl wget sudo git unzip jq certbot python3-certbot-nginx bc

# Get domain from user
read -p "Enter your domain name: " DOMAIN
if [ -z "$DOMAIN" ]; then
    log_error "Domain name is required!"
    exit 1
fi

# Verify domain
log_info "Verifying domain: ${CYAN}$DOMAIN${NC}"
if ! ping -c 1 $DOMAIN &> /dev/null; then
    log_error "Domain not reachable! Please configure DNS first."
    exit 1
fi

# Get server location and ISP info
get_server_info() {
    IP=$(curl -s ifconfig.me)
    LOCATION=$(curl -s ipinfo.io/$IP | jq -r '.country + ", " + .city')
    ISP=$(curl -s ipinfo.io/$IP | jq -r '.org' | cut -d' ' -f2-)
    echo "$LOCATION" > /root/tdz-server-location.txt
    echo "$ISP" > /root/tdz-server-isp.txt
}

get_server_info

# Install Xray
log_info "Installing Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate SSL certificate
log_info "Generating SSL certificate for ${CYAN}$DOMAIN${NC}"
certbot certonly --standalone --agree-tos --non-interactive --email admin@$DOMAIN -d $DOMAIN

# Generate UUIDs
UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
UUID_TROJAN=$(cat /proc/sys/kernel/random/uuid)

# Create Xray config with ALL protocols and proper settings
log_info "Creating Xray configuration..."
cat > /usr/local/etc/xray/config.json << EOF
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "flow": "xtls-rprx-vision",
                        "email": "vless-tls@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ],
                    "alpn": ["h2", "http/1.1"]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 80,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "email": "vless-ntls@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/TuhinDroidZone",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 8443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-tls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/TuhinDroidZone",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 8080,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-ntls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/TuhinDroidZone",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            }
        },
        {
            "port": 2095,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-tls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 2096,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-grpc@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "Tuhin-Internet-Service"
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ]
}
EOF

# Restart Xray
systemctl restart xray
systemctl enable xray

# Configure firewall
log_info "Configuring firewall..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
ufw allow 8080/tcp
ufw allow 2095/tcp
ufw allow 2096/tcp
ufw --force enable

# Create user management system
mkdir -p /etc/tdz
cat > /etc/tdz/user-manager.sh << 'EOF'
#!/bin/bash

USER_DB="/etc/tdz/users.json"

initialize_db() {
    if [ ! -f "$USER_DB" ]; then
        echo '{"users": []}' > "$USER_DB"
    fi
}

create_user() {
    local protocol=$1
    local remark=$2
    local expiry_days=$3
    
    case $protocol in
        "vless")
            uuid=$(cat /proc/sys/kernel/random/uuid)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"vless\", \"uuid\": \"$uuid\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$uuid"
            ;;
        "vmess")
            uuid=$(cat /proc/sys/kernel/random/uuid)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"vmess\", \"uuid\": \"$uuid\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$uuid"
            ;;
        "trojan")
            password=$(cat /proc/sys/kernel/random/uuid | cut -d'-' -f1)
            expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
            jq ".users += [{\"protocol\": \"trojan\", \"password\": \"$password\", \"remark\": \"$remark\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > /tmp/tdz_temp.json && mv /tmp/tdz_temp.json "$USER_DB"
            echo "$password"
            ;;
    esac
}

list_users() {
    jq -r '.users[] | "\(.protocol) - \(.remark) - Expiry: \(.expiry_date)"' "$USER_DB"
}

get_user_info() {
    local protocol=$1
    local remark=$2
    jq -r ".users[] | select(.protocol == \"$protocol\" and .remark == \"$remark\")" "$USER_DB"
}
EOF

chmod +x /etc/tdz/user-manager.sh

# Create advanced control script with REAL configuration
cat > /usr/local/bin/tdz << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

CONFIG_FILE="/root/tdz-config.txt"
SERVER_LOCATION=$(cat /root/tdz-server-location.txt 2>/dev/null || echo "Singapore")
SERVER_ISP=$(cat /root/tdz-server-isp.txt 2>/dev/null || echo "Digital Ocean")
USER_DB="/etc/tdz/users.json"
source /etc/tdz/user-manager.sh

initialize_db

show_vless_config() {
    local remark=$1
    local uuid=$2
    local expiry_date=$3
    
    domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    
    clear
    echo -e "${GREEN}"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo "               VLESS ACCOUNT"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo -e "${NC}"
    echo -e "Remarks      : ${CYAN}$remark${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$domain${NC}"
    echo -e "Port TLS     : ${BLUE}443${NC}"
    echo -e "Port N-TLS   : ${BLUE}80${NC}"
    echo -e "Uid          : ${MAGENTA}$uuid${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}Auto${NC}"
    echo -e "Network      : ${YELLOW}Websocket/gRPC${NC}"
    echo -e "Service Name : ${CYAN}Tuhin-Internet-Service${NC}"
    echo -e "Path ws      : ${GREEN}/TuhinDroidZone${NC}"
    echo -e "Expired On   : ${RED}$expiry_date${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          VLESS gRPC TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}vless://$uuid@$domain:443?type=grpc&encryption=none&serviceName=Tuhin-Internet-Service&security=tls&sni=$domain&fp=chrome&alpn=h2,http/1.1#$remark${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          VLESS WS NO TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}vless://$uuid@$domain:80?type=ws&encryption=none&path=/TuhinDroidZone&host=$domain&security=none#$remark${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
}

show_vmess_config() {
    local remark=$1
    local uuid=$2
    local expiry_date=$3
    
    domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    
    # Create VMESS configuration
    vmess_config=$(cat << EOF
{
  "v": "2",
  "ps": "$remark",
  "add": "$domain",
  "port": "8443",
  "id": "$uuid",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "$domain",
  "path": "/TuhinDroidZone",
  "tls": "tls"
}
EOF
    )
    
    vmess_config_ntls=$(cat << EOF
{
  "v": "2",
  "ps": "$remark-NTLS",
  "add": "$domain",
  "port": "8080",
  "id": "$uuid",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "$domain",
  "path": "/TuhinDroidZone",
  "tls": "none"
}
EOF
    )
    
    clear
    echo -e "${GREEN}"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo "               VMESS ACCOUNT"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo -e "${NC}"
    echo -e "Remarks      : ${CYAN}$remark${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$domain${NC}"
    echo -e "Port TLS     : ${BLUE}8443${NC}"
    echo -e "Port N-TLS   : ${BLUE}8080${NC}"
    echo -e "Uid          : ${MAGENTA}$uuid${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}Auto${NC}"
    echo -e "Network      : ${YELLOW}Websocket${NC}"
    echo -e "Path         : ${GREEN}/TuhinDroidZone${NC}"
    echo -e "Expired On   : ${RED}$expiry_date${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          VMESS WS TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}vmess://$(echo "$vmess_config" | base64 -w 0)${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          VMESS WS NO TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}vmess://$(echo "$vmess_config_ntls" | base64 -w 0)${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
}

show_trojan_config() {
    local remark=$1
    local password=$2
    local expiry_date=$3
    
    domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    
    clear
    echo -e "${GREEN}"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo "               TROJAN ACCOUNT"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo -e "${NC}"
    echo -e "Remarks      : ${CYAN}$remark${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$domain${NC}"
    echo -e "Port TCP     : ${BLUE}2095${NC}"
    echo -e "Port gRPC    : ${BLUE}2096${NC}"
    echo -e "Password     : ${MAGENTA}$password${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}TLS${NC}"
    echo -e "Network      : ${YELLOW}TCP/gRPC${NC}"
    echo -e "Service Name : ${CYAN}Tuhin-Internet-Service${NC}"
    echo -e "Expired On   : ${RED}$expiry_date${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          TROJAN TCP TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}trojan://$password@$domain:2095?security=tls&type=tcp&headerType=none&sni=$domain#$remark${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          TROJAN gRPC TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}trojan://$password@$domain:2096?security=tls&type=grpc&serviceName=Tuhin-Internet-Service&sni=$domain#$remark${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
}

create_user_menu() {
    clear
    echo -e "${GREEN}"
    echo "=================================================="
    echo "               Create New User"
    echo "=================================================="
    echo -e "${NC}"
    echo "1. VLESS User"
    echo "2. VMESS User"
    echo "3. Trojan User"
    echo "4. Back to Main Menu"
    echo -e "${GREEN}==================================================${NC}"
    read -p "Select protocol [1-4]: " proto_choice
    
    case $proto_choice in
        1) protocol="vless" ;;
        2) protocol="vmess" ;;
        3) protocol="trojan" ;;
        4) return ;;
        *) echo "Invalid choice!"; sleep 1; create_user_menu; return ;;
    esac
    
    read -p "Enter remark name: " remark
    read -p "Enter expiry days: " expiry_days
    
    if [ "$protocol" = "vless" ] || [ "$protocol" = "vmess" ]; then
        user_id=$(create_user "$protocol" "$remark" "$expiry_days")
        expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
        
        if [ "$protocol" = "vless" ]; then
            show_vless_config "$remark" "$user_id" "$expiry_date"
        else
            show_vmess_config "$remark" "$user_id" "$expiry_date"
        fi
    else
        password=$(create_user "$protocol" "$remark" "$expiry_days")
        expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
        show_trojan_config "$remark" "$password" "$expiry_date"
    fi
    
    read -p "Press Enter to continue..."
}

list_users_menu() {
    clear
    echo -e "${GREEN}"
    echo "=================================================="
    echo "               Current Users"
    echo "=================================================="
    echo -e "${NC}"
    list_users
    echo -e "${GREEN}==================================================${NC}"
    read -p "Press Enter to continue..."
}

show_main_menu() {
    while true; do
        clear
        echo -e "${GREEN}"
        echo "=================================================="
        echo "           Tdz Tunnel Control Panel"
        echo "           Developer: Yeasinul Hoque Tuhin"
        echo "=================================================="
        echo -e "${NC}"
        echo "1. Create New User"
        echo "2. List All Users"
        echo "3. Server Status"
        echo "4. Restart Services"
        echo "5. VPS Information"
        echo "6. Uninstall Tdz Tunnel"
        echo "0. Exit"
        echo -e "${GREEN}==================================================${NC}"
        read -p "Select an option [0-6]: " main_choice

        case $main_choice in
            1) create_user_menu ;;
            2) list_users_menu ;;
            3) systemctl status xray --no-pager -l; read -p "Press Enter to continue..." ;;
            4) systemctl restart xray; echo "Services restarted!"; sleep 1 ;;
            5) echo "VPS Info: $SERVER_LOCATION - $SERVER_ISP"; read -p "Press Enter to continue..." ;;
            6) uninstall_tdz ;;
            0) exit 0 ;;
            *) echo "Invalid option!"; sleep 1 ;;
        esac
    done
}

uninstall_tdz() {
    echo -e "${RED}"
    read -p "Are you sure you want to uninstall? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        systemctl stop xray
        systemctl disable xray
        rm -rf /usr/local/bin/tdz
        rm -rf /usr/local/etc/xray
        rm -rf /etc/tdz
        rm -f /root/tdz-config.txt
        rm -f /root/tdz-server-location.txt
        rm -f /root/tdz-server-isp.txt
        echo "Tdz Tunnel uninstalled successfully!"
    fi
    echo -e "${NC}"
    exit 0
}

# Start the menu
if [ $# -eq 0 ]; then
    show_main_menu
else
    case $1 in
        "1") create_user_menu ;;
        "2") list_users_menu ;;
        "3") systemctl status xray --no-pager -l ;;
        "4") systemctl restart xray ;;
        "5") echo "VPS Info: $SERVER_LOCATION - $SERVER_ISP" ;;
        "6") uninstall_tdz ;;
        *) show_main_menu ;;
    esac
fi
EOF

chmod +x /usr/local/bin/tdz

# Save config
cat > /root/tdz-config.txt << EOF
Domain: $DOMAIN
VLESS UUID: $UUID_VLESS
VMESS UUID: $UUID_VMESS
Trojan Password: $UUID_TROJAN
Installation Date: $(date)
Server Location: $SERVER_LOCATION
Server ISP: $SERVER_ISP
WS Path: /TuhinDroidZone
gRPC Service Name: Tuhin-Internet-Service
EOF

# Initialize user database
mkdir -p /etc/tdz
echo '{"users": []}' > /etc/tdz/users.json

# Completion message
log_success "Installation completed!"
echo -e "${GREEN}"
echo "=================================================="
echo "           Tdz Tunnel Setup Complete!"
echo "=================================================="
echo -e "${NC}"
echo "Control Panel: ${CYAN}tdz${NC}"
echo "Create User: ${CYAN}tdz 1${NC}"
echo "List Users: ${CYAN}tdz 2${NC}"
echo ""
echo "Config saved to: ${CYAN}/root/tdz-config.txt${NC}"
echo "User database: ${CYAN}/etc/tdz/users.json${NC}"
# Update system
log_info "Updating system packages..."
apt update && apt upgrade -y
apt install -y curl wget sudo git unzip jq certbot python3-certbot-nginx bc

# Get domain from user
read -p "Enter your domain name: " DOMAIN
if [ -z "$DOMAIN" ]; then
    log_error "Domain name is required!"
    exit 1
fi

# Verify domain
log_info "Verifying domain: ${CYAN}$DOMAIN${NC}"
if ! ping -c 1 $DOMAIN &> /dev/null; then
    log_error "Domain not reachable! Please configure DNS first."
    exit 1
fi

# Get server location and ISP info
get_server_info() {
    IP=$(curl -s ifconfig.me)
    LOCATION=$(curl -s ipinfo.io/$IP | jq -r '.country + ", " + .city')
    ISP=$(curl -s ipinfo.io/$IP | jq -r '.org')
    echo "$LOCATION" > /root/tdz-server-location.txt
    echo "$ISP" > /root/tdz-server-isp.txt
}

get_server_info

# Install Xray
log_info "Installing Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate SSL certificate
log_info "Generating SSL certificate for ${CYAN}$DOMAIN${NC}"
certbot certonly --standalone --agree-tos --non-interactive --email admin@$DOMAIN -d $DOMAIN

# Generate UUIDs and custom IDs
UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
UUID_TROJAN=$(cat /proc/sys/kernel/random/uuid)
CUSTOM_ID="TuhinDroidZone$(date +%m%d)"

# Create Xray config with ALL protocols
log_info "Creating Xray configuration..."
cat > /usr/local/etc/xray/config.json << EOF
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "flow": "xtls-rprx-vision",
                        "email": "vless-tls@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ],
                    "alpn": ["h2", "http/1.1"]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 80,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "email": "vless-ntls@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/@TuhinBroh",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 8443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-tls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/tdz-vmess",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 8080,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-ntls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/tdz-vmess-ntls",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            }
        },
        {
            "port": 2083,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-tls@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 2087,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-grpc@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "Tuhin-Internet-Service"
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ]
}
EOF

# Restart Xray
systemctl restart xray
systemctl enable xray

# Configure firewall
log_info "Configuring firewall..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
ufw allow 8080/tcp
ufw allow 2083/tcp
ufw allow 2087/tcp
ufw --force enable

# Create advanced control script
cat > /usr/local/bin/tdz << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

CONFIG_FILE="/root/tdz-config.txt"
SERVER_LOCATION=$(cat /root/tdz-server-location.txt 2>/dev/null || echo "Singapore")
SERVER_ISP=$(cat /root/tdz-server-isp.txt 2>/dev/null || echo "Digital Ocean")

show_vless_result() {
    clear
    echo -e "${GREEN}"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo "               VLESS ACCOUNT"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo -e "${NC}"
    echo -e "Remarks      : ${CYAN}TUSFZ${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)${NC}"
    echo -e "Port TLS     : ${BLUE}443${NC}"
    echo -e "Port N-TLS   : ${BLUE}80${NC}"
    echo -e "Uid          : ${MAGENTA}$(grep "VLESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}Auto${NC}"
    echo -e "Network      : ${YELLOW}Websocket/gRPC${NC}"
    echo -e "Service Name : ${CYAN}Tuhin - Internet Service${NC}"
    echo -e "Path ws      : ${GREEN}/@TuhinBroh${NC}"
    echo -e "Expired On   : ${RED}25/09/2025${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          VLESS gRPC TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}vless://$(grep "VLESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)@$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2):443?type=grpc&encryption=none&serviceName=Tuhin-Internet-Service&security=tls&sni=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)&fp=chrome&alpn=h2,http/1.1#TUSFZ${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          VLESS WS NO TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}vless://$(grep "VLESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)@$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2):80?type=ws&encryption=none&path=/@TuhinBroh&host=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)&security=none#TUSFZ${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
}

show_vmess_result() {
    clear
    echo -e "${GREEN}"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo "               VMESS ACCOUNT"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo -e "${NC}"
    echo -e "Remarks      : ${CYAN}TUSFZ-VMESS${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)${NC}"
    echo -e "Port TLS     : ${BLUE}8443${NC}"
    echo -e "Port N-TLS   : ${BLUE}8080${NC}"
    echo -e "Uid          : ${MAGENTA}$(grep "VMESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}Auto${NC}"
    echo -e "Network      : ${YELLOW}Websocket${NC}"
    echo -e "Path TLS     : ${GREEN}/tdz-vmess${NC}"
    echo -e "Path N-TLS   : ${GREEN}/tdz-vmess-ntls${NC}"
    echo -e "Expired On   : ${RED}25/09/2025${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          VMESS WS TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlRVU0ZaIiwNCiAgImFkZCI6ICIkKGRvbWFpbikiLA0KICAicG9ydCI6ICI4NDQzIiwNCiAgImlkIjogIiQodXVpZCkiLA0KICAiYWlkIjogIjAiLA0KICAibmV0IjogIndzIiwNCiAgInR5cGUiOiAibm9uZSIsDQogICJob3N0IjogIiQoZG9tYWluKSIsDQogICJwYXRoIjogIi90ZHotdm1lc3MiLA0KICAidGxzIjogInRscyINCn0=${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          VMESS WS NO TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlRVU0ZaIiwNCiAgImFkZCI6ICIkKGRvbWFpbikiLA0KICAicG9ydCI6ICI4MDgwIiwNCiAgImlkIjogIiQodXVpZCkiLA0KICAiYWlkIjogIjAiLA0KICAibmV0IjogIndzIiwNCiAgInR5cGUiOiAibm9uZSIsDQogICJob3N0IjogIiQoZG9tYWluKSIsDQogICJwYXRoIjogIi90ZHotdm1lc3MtbnRscyIsDQogICJ0bHMiOiAibm9uZSINCn0=${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
}

show_trojan_result() {
    clear
    echo -e "${GREEN}"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo "               TROJAN ACCOUNT"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo -e "${NC}"
    echo -e "Remarks      : ${CYAN}TUSFZ-TROJAN${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)${NC}"
    echo -e "Port TCP     : ${BLUE}2083${NC}"
    echo -e "Port gRPC    : ${BLUE}2087${NC}"
    echo -e "Password     : ${MAGENTA}$(grep "Trojan Password:" "$CONFIG_FILE" | cut -d' ' -f4)${NC}"
    echo -e "Encryption   : ${CYAN}Auto${NC}"
    echo -e "Security     : ${CYAN}TLS${NC}"
    echo -e "Network      : ${YELLOW}TCP/gRPC${NC}"
    echo -e "Service Name : ${CYAN}Tuhin-Internet-Service${NC}"
    echo -e "Expired On   : ${RED}25/09/2025${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          TROJAN TCP TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}trojan://$(grep "Trojan Password:" "$CONFIG_FILE" | cut -d' ' -f4)@$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2):2083?security=tls&type=tcp&headerType=none&sni=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)#TUSFZ-TROJAN${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "          TROJAN gRPC TLS"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${CYAN}trojan://$(grep "Trojan Password:" "$CONFIG_FILE" | cut -d' ' -f4)@$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2):2087?security=tls&type=grpc&serviceName=Tuhin-Internet-Service&sni=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)#TUSFZ-TROJAN${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
    echo -e "${GREEN}————————————————————————————————————${NC}"
}

show_main_menu() {
    clear
    echo -e "${GREEN}"
    echo "=================================================="
    echo "           Tdz Tunnel Control Panel"
    echo "           Developer: Yeasinul Hoque Tuhin"
    echo "=================================================="
    echo -e "${NC}"
    echo "1. Show VLESS Config"
    echo "2. Show VMESS Config" 
    echo "3. Show Trojan Config"
    echo "4. Server Status"
    echo "5. Restart Services"
    echo "6. VPS Information"
    echo "7. Uninstall Tdz Tunnel"
    echo "0. Exit"
    echo -e "${GREEN}==================================================${NC}"
    read -p "Select an option [0-7]: " main_choice

    case $main_choice in
        1) show_vless_result; read -p "Press Enter to continue..."; show_main_menu ;;
        2) show_vmess_result; read -p "Press Enter to continue..."; show_main_menu ;;
        3) show_trojan_result; read -p "Press Enter to continue..."; show_main_menu ;;
        4) systemctl status xray --no-pager -l; read -p "Press Enter to continue..."; show_main_menu ;;
        5) systemctl restart xray; echo "Services restarted!"; sleep 1; show_main_menu ;;
        6) echo "VPS Info: $SERVER_LOCATION - $SERVER_ISP"; read -p "Press Enter to continue..."; show_main_menu ;;
        7) uninstall_tdz ;;
        0) exit 0 ;;
        *) echo "Invalid option!"; sleep 1; show_main_menu ;;
    esac
}

uninstall_tdz() {
    echo -e "${RED}"
    read -p "Are you sure you want to uninstall? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        systemctl stop xray
        systemctl disable xray
        rm -rf /usr/local/bin/tdz
        rm -rf /usr/local/etc/xray
        rm -f /root/tdz-config.txt
        rm -f /root/tdz-server-location.txt
        rm -f /root/tdz-server-isp.txt
        echo "Tdz Tunnel uninstalled successfully!"
    fi
    echo -e "${NC}"
    exit 0
}

# Start the menu
if [ $# -eq 0 ]; then
    show_main_menu
else
    case $1 in
        "1") show_vless_result ;;
        "2") show_vmess_result ;;
        "3") show_trojan_result ;;
        "4") systemctl status xray --no-pager -l ;;
        "5") systemctl restart xray ;;
        "6") echo "VPS Info: $SERVER_LOCATION - $SERVER_ISP" ;;
        "7") uninstall_tdz ;;
        *) show_main_menu ;;
    esac
fi
EOF

chmod +x /usr/local/bin/tdz

# Save config
cat > /root/tdz-config.txt << EOF
Domain: $DOMAIN
VLESS UUID: $UUID_VLESS
VMESS UUID: $UUID_VMESS
Trojan Password: $UUID_TROJAN
Custom ID: $CUSTOM_ID
Installation Date: $(date)
Server Location: $SERVER_LOCATION
Server ISP: $SERVER_ISP
EOF

# Completion message
log_success "Installation completed!"
echo -e "${GREEN}"
echo "=================================================="
echo "           Tdz Tunnel Setup Complete!"
echo "=================================================="
echo -e "${NC}"
echo "Control Panel: ${CYAN}tdz${NC}"
echo "Show VLESS: ${CYAN}tdz 1${NC}"
echo "Show VMESS: ${CYAN}tdz 2${NC}"
echo "Show Trojan: ${CYAN}tdz 3${NC}"
echo ""
echo "Config saved to: ${CYAN}/root/tdz-config.txt${NC}"
# Update system
log_info "Updating system packages..."
apt update && apt upgrade -y
apt install -y curl wget sudo git unzip jq certbot python3-certbot-nginx bc

# Get domain from user
read -p "Enter your domain name: " DOMAIN
if [ -z "$DOMAIN" ]; then
    log_error "Domain name is required!"
    exit 1
fi

# Verify domain
log_info "Verifying domain: ${CYAN}$DOMAIN${NC}"
if ! ping -c 1 $DOMAIN &> /dev/null; then
    log_error "Domain not reachable! Please configure DNS first."
    exit 1
fi

# Get server location and ISP info
get_server_info() {
    IP=$(curl -s ifconfig.me)
    LOCATION=$(curl -s ipinfo.io/$IP | jq -r '.country + ", " + .city')
    ISP=$(curl -s ipinfo.io/$IP | jq -r '.org')
    echo "$LOCATION" > /root/tdz-server-location.txt
    echo "$ISP" > /root/tdz-server-isp.txt
}

get_server_info

# Install Xray
log_info "Installing Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate SSL certificate
log_info "Generating SSL certificate for ${CYAN}$DOMAIN${NC}"
certbot certonly --standalone --agree-tos --non-interactive --email admin@$DOMAIN -d $DOMAIN

# Generate UUIDs and custom IDs
UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
UUID_TROJAN=$(cat /proc/sys/kernel/random/uuid)
CUSTOM_ID="TuhinDroidZone$(date +%m%d)"

# Create Xray config with both TLS and NTLS
log_info "Creating Xray configuration..."
cat > /usr/local/etc/xray/config.json << EOF
{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "flow": "xtls-rprx-vision",
                        "email": "vless-user@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ],
                    "alpn": ["h2", "http/1.1"]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 80,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VLESS",
                        "email": "vless-ntls@$DOMAIN"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/@TuhinBroh",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "none"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 8443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0,
                        "email": "vmess-user@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/tdz-vmess",
                    "headers": {
                        "Host": "$DOMAIN"
                    }
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "port": 2083,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN",
                        "email": "trojan-user@$DOMAIN"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "Tuhin-Internet-Service"
                },
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ],
    "stats": {},
    "policy": {
        "levels": {
            "0": {
                "statsUserUplink": true,
                "statsUserDownlink": true
            }
        }
    },
    "api": {
        "tag": "api",
        "services": ["StatsService"]
    }
}
EOF

# Restart Xray
systemctl restart xray
systemctl enable xray

# Configure firewall
log_info "Configuring firewall..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
ufw allow 2083/tcp
ufw --force enable

# Create bandwidth monitoring
create_bandwidth_monitor() {
    cat > /usr/local/bin/bandwidth-monitor << 'EOF'
#!/bin/bash
echo "Bandwidth Usage:"
echo "=================================================="
if [ -f "/usr/local/etc/xray/access.log" ]; then
    echo "Total Data Used: $(du -h /usr/local/etc/xray/access.log | cut -f1)"
else
    echo "Log file not found. Bandwidth monitoring will start soon."
fi
echo "=================================================="
EOF
    chmod +x /usr/local/bin/bandwidth-monitor
}

create_bandwidth_monitor

# Create advanced control script with professional results
cat > /usr/local/bin/tdz << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

CONFIG_FILE="/root/tdz-config.txt"
USER_DB="/root/tdz-users.json"
SERVER_LOCATION=$(cat /root/tdz-server-location.txt 2>/dev/null || echo "Singapore")
SERVER_ISP=$(cat /root/tdz-server-isp.txt 2>/dev/null || echo "Digital Ocean")

# Initialize user database if not exists
if [ ! -f "$USER_DB" ]; then
    echo '{"users": []}' > "$USER_DB"
fi

show_professional_result() {
    local protocol=$1
    local user_id=$2
    local custom_id=$3
    local expiry_date=$4
    
    clear
    echo -e "${GREEN}"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo "               ${protocol^^} ACCOUNT"
    echo "————————————————————————————————————"
    echo "————————————————————————————————————"
    echo -e "${NC}"
    echo -e "Remarks      : ${CYAN}TUSFZ${NC}"
    echo -e "Location     : ${YELLOW}$SERVER_LOCATION${NC}"
    echo -e "ISP          : ${YELLOW}$SERVER_ISP${NC}"
    echo -e "Domain       : ${GREEN}$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)${NC}"
    
    if [ "$protocol" = "vless" ]; then
        echo -e "Port TLS     : ${BLUE}443${NC}"
        echo -e "Port N-TLS   : ${BLUE}80${NC}"
        echo -e "Uid          : ${MAGENTA}$custom_id${NC}"
        echo -e "Encryption   : ${CYAN}Auto${NC}"
        echo -e "Security     : ${CYAN}Auto${NC}"
        echo -e "Network      : ${YELLOW}Websocket/gRPC${NC}"
        echo -e "Service Name : ${CYAN}Tuhin - Internet Service${NC}"
        echo -e "Path ws      : ${GREEN}/@TuhinBroh${NC}"
        echo -e "Expired On   : ${RED}$expiry_date${NC}"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "          ${protocol^^} gRPC TLS"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "${CYAN}vless://$custom_id@$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2):443?type=grpc&encryption=none&serviceName=Tuhin+-+Internet+Service&authority=&security=tls&sni=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)&fp=chrome&alpn=h2%2Chttp%2F1.1#TUSFZ${NC}"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "          ${protocol^^} WS NO TLS"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "${CYAN}vless://$custom_id@$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2):80?type=ws&encryption=none&path=%2F%40TuhinBroh&host=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)&security=none#TUSFZ${NC}"
        echo -e "${GREEN}————————————————————————————————————${NC}"
        echo -e "${GREEN}————————————————————————————————————${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

show_main_menu() {
    clear
    echo -e "${GREEN}"
    echo "=================================================="
    echo "           Tdz Tunnel Control Panel"
    echo "           Developer: Yeasinul Hoque Tuhin"
    echo "=================================================="
    echo -e "${NC}"
    echo "1. VLESS Management"
    echo "2. VMESS Management" 
    echo "3. Trojan Management"
    echo "4. Server Status & Info"
    echo "5. Bandwidth Monitoring"
    echo "6. Restart Services"
    echo "7. Change Domain"
    echo "8. VPS Information"
    echo "9. Uninstall Tdz Tunnel"
    echo "0. Exit"
    echo -e "${GREEN}==================================================${NC}"
    read -p "Select an option [0-9]: " main_choice

    case $main_choice in
        1) vless_management ;;
        2) vmess_management ;;
        3) trojan_management ;;
        4) show_status ;;
        5) show_bandwidth ;;
        6) restart_services ;;
        7) change_domain ;;
        8) vps_info ;;
        9) uninstall_tdz ;;
        0) exit 0 ;;
        *) echo "Invalid option!"; sleep 1; show_main_menu ;;
    esac
}

vless_management() {
    clear
    echo -e "${GREEN}"
    echo "=================================================="
    echo "               VLESS Management"
    echo "=================================================="
    echo -e "${NC}"
    echo "1. Create VLESS User"
    echo "2. Delete VLESS User"
    echo "3. List VLESS Users"
    echo "4. Show VLESS Config"
    echo "5. Back to Main Menu"
    echo -e "${GREEN}==================================================${NC}"
    read -p "Select an option [1-5]: " vless_choice

    case $vless_choice in
        1) create_vless_user ;;
        2) delete_vless_user ;;
        3) list_vless_users ;;
        4) show_vless_config ;;
        5) show_main_menu ;;
        *) echo "Invalid option!"; sleep 1; vless_management ;;
    esac
}

create_vless_user() {
    echo -e "${YELLOW}"
    read -p "Enter custom user ID: " custom_id
    read -p "Enter data limit (GB): " data_limit
    read -p "Enter expiry days: " expiry_days
    
    expiry_date=$(date -d "+$expiry_days days" +"%d/%m/%Y")
    uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # Add to user database
    jq ".users += [{\"id\": \"$uuid\", \"custom_id\": \"$custom_id\", \"protocol\": \"vless\", \"data_limit\": \"$data_limit\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > tmp.json && mv tmp.json "$USER_DB"
    
    show_professional_result "vless" "$uuid" "$custom_id" "$expiry_date"
}

show_vless_config() {
    domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    uuid=$(grep "VLESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)
    show_professional_result "vless" "$uuid" "TuhinDroidZone" "25/09/2025"
}

show_status() {
    echo -e "${GREEN}"
    echo "Server Status:"
    echo "=================================================="
    systemctl status xray --no-pager -l
    echo -e "${NC}"
    read -p "Press Enter to continue..."
    show_main_menu
}

show_bandwidth() {
    /usr/local/bin/bandwidth-monitor
    read -p "Press Enter to continue..."
    show_main_menu
}

restart_services() {
    systemctl restart xray
    echo -e "${GREEN}Services restarted successfully!${NC}"
    sleep 1
    show_main_menu
}

change_domain() {
    echo -e "${YELLOW}"
    read -p "Enter new domain name: " new_domain
    sed -i "s/Domain: .*/Domain: $new_domain/" "$CONFIG_FILE"
    echo -e "${GREEN}Domain changed to $new_domain${NC}"
    sleep 1
    show_main_menu
}

vps_info() {
    echo -e "${GREEN}"
    echo "VPS Information:"
    echo "=================================================="
    echo "CPU: $(nproc) cores"
    echo "RAM: $(free -h | grep Mem | awk '{print $2}')"
    echo "Disk: $(df -h / | grep / | awk '{print $2}')"
    echo "Location: $SERVER_LOCATION"
    echo "ISP: $SERVER_ISP"
    echo "IP: $(curl -s ifconfig.me)"
    echo -e "${NC}"
    read -p "Press Enter to continue..."
    show_main_menu
}

uninstall_tdz() {
    echo -e "${RED}"
    read -p "Are you sure you want to uninstall? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        systemctl stop xray
        systemctl disable xray
        rm -rf /usr/local/bin/tdz
        rm -rf /usr/local/tdz
        rm -rf /usr/local/etc/xray
        rm -f /root/tdz-config.txt
        rm -f /root/tdz-users.json
        rm -f /root/tdz-server-location.txt
        rm -f /root/tdz-server-isp.txt
        echo "Tdz Tunnel uninstalled successfully!"
    fi
    echo -e "${NC}"
    exit 0
}

# Start the menu
if [ $# -eq 0 ]; then
    show_main_menu
else
    case $1 in
        "1") vless_management ;;
        "2") vmess_management ;;
        "3") trojan_management ;;
        "4") show_status ;;
        "5") show_bandwidth ;;
        "6") restart_services ;;
        "7") change_domain ;;
        "8") vps_info ;;
        "9") uninstall_tdz ;;
        *) show_main_menu ;;
    esac
fi
EOF

chmod +x /usr/local/bin/tdz

# Save config
cat > /root/tdz-config.txt << EOF
Domain: $DOMAIN
VLESS UUID: $UUID_VLESS
VMESS UUID: $UUID_VMESS
Trojan Password: $UUID_TROJAN
Custom ID: $CUSTOM_ID
Installation Date: $(date)
Server Location: $SERVER_LOCATION
Server ISP: $SERVER_ISP
EOF

# Create user database
echo '{"users": []}' > /root/tdz-users.json

# Completion message
log_success "Installation completed!"
echo -e "${GREEN}"
echo "=================================================="
echo "           Tdz Tunnel Setup Complete!"
echo "=================================================="
echo -e "${NC}"
echo "Control Panel: ${CYAN}tdz${NC}"
echo "Main Menu: ${CYAN}tdz${NC}"
echo "Direct Access: ${CYAN}tdz 1${NC} (VLESS Management)"
echo ""
echo "Config saved to: ${CYAN}/root/tdz-config.txt${NC}"
echo "User database: ${CYAN}/root/tdz-users.json${NC}"
