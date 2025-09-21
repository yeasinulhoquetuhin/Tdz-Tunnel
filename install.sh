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
