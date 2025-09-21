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
apt install -y curl wget sudo git unzip jq certbot python3-certbot-nginx

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

# Create Xray config
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
                        "flow": "xtls-rprx-vision"
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
                    ]
                }
            }
        },
        {
            "port": 8443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID_VMESS",
                        "alterId": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/tdz-vmess"
                }
            }
        },
        {
            "port": 2083,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$UUID_TROJAN"
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
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
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
ufw allow 2083/tcp
ufw --force enable

# Create advanced control script
log_info "Creating advanced control panel..."
cat > /usr/local/bin/tdz << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_FILE="/root/tdz-config.txt"
USER_DB="/root/tdz-users.json"

# Initialize user database if not exists
if [ ! -f "$USER_DB" ]; then
    echo '{"users": []}' > "$USER_DB"
fi

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
    echo "4. Server Status"
    echo "5. Restart Services"
    echo "6. Uninstall Tdz Tunnel"
    echo "7. Exit"
    echo -e "${GREEN}==================================================${NC}"
    read -p "Select an option [1-7]: " main_choice

    case $main_choice in
        1) vless_management ;;
        2) vmess_management ;;
        3) trojan_management ;;
        4) show_status ;;
        5) restart_services ;;
        6) uninstall_tdz ;;
        7) exit 0 ;;
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
    
    expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
    uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # Add to user database
    jq ".users += [{\"id\": \"$uuid\", \"custom_id\": \"$custom_id\", \"protocol\": \"vless\", \"data_limit\": \"$data_limit\", \"expiry_date\": \"$expiry_date\", \"created\": \"$(date)\"}]" "$USER_DB" > tmp.json && mv tmp.json "$USER_DB"
    
    echo -e "${GREEN}"
    echo "VLESS User Created Successfully!"
    echo "UUID: $uuid"
    echo "Custom ID: $custom_id"
    echo "Data Limit: ${data_limit}GB"
    echo "Expiry Date: $expiry_date"
    echo -e "${NC}"
    sleep 2
    vless_management
}

delete_vless_user() {
    echo -e "${YELLOW}"
    echo "Current VLESS Users:"
    jq -r '.users[] | select(.protocol == "vless") | "\(.custom_id) (\(.id))"' "$USER_DB"
    echo -e "${NC}"
    read -p "Enter custom ID to delete: " del_id
    
    jq "del(.users[] | select(.custom_id == \"$del_id\"))" "$USER_DB" > tmp.json && mv tmp.json "$USER_DB"
    
    echo -e "${GREEN}User $del_id deleted successfully!${NC}"
    sleep 1
    vless_management
}

list_vless_users() {
    echo -e "${GREEN}"
    echo "VLESS Users List:"
    echo "=================================================="
    jq -r '.users[] | select(.protocol == "vless") | "Custom ID: \(.custom_id)\nUUID: \(.id)\nData Limit: \(.data_limit)GB\nExpiry: \(.expiry_date)\nCreated: \(.created)\n"' "$USER_DB"
    echo -e "${NC}"
    read -p "Press Enter to continue..."
    vless_management
}

show_vless_config() {
    domain=$(grep "Domain:" "$CONFIG_FILE" | cut -d' ' -f2)
    echo -e "${GREEN}"
    echo "VLESS Configuration:"
    echo "=================================================="
    echo "Address: $domain"
    echo "Port: 443"
    echo "UUID: $(grep "VLESS UUID:" "$CONFIG_FILE" | cut -d' ' -f4)"
    echo "Flow: xtls-rprx-vision"
    echo "Security: tls"
    echo -e "${NC}"
    read -p "Press Enter to continue..."
    vless_management
}

# Similar functions for VMESS and Trojan
vmess_management() {
    clear
    echo -e "${GREEN}"
    echo "=================================================="
    echo "               VMESS Management"
    echo "=================================================="
    echo -e "${NC}"
    echo "1. Create VMESS User"
    echo "2. Delete VMESS User"
    echo "3. List VMESS Users"
    echo "4. Show VMESS Config"
    echo "5. Back to Main Menu"
    echo -e "${GREEN}==================================================${NC}"
    read -p "Select an option [1-5]: " vmess_choice
    # Implement similar to vless_management
}

trojan_management() {
    clear
    echo -e "${GREEN}"
    echo "=================================================="
    echo "               Trojan Management"
    echo "=================================================="
    echo -e "${NC}"
    echo "1. Create Trojan User"
    echo "2. Delete Trojan User"
    echo "3. List Trojan Users"
    echo "4. Show Trojan Config"
    echo "5. Back to Main Menu"
    echo -e "${GREEN}==================================================${NC}"
    read -p "Select an option [1-5]: " trojan_choice
    # Implement similar to vless_management
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

restart_services() {
    systemctl restart xray
    echo -e "${GREEN}Services restarted successfully!${NC}"
    sleep 1
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
        "5") restart_services ;;
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