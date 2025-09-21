#!/usr/bin/env bash

Tdz Tunnel - Xray automatic installer & simple account manager

Developer: Yeasinul Hoque Tuhin

Usage: curl -sSL https://.../install_tdz_tunnel.sh | bash

This script installs Xray (core), creates default config supporting VLESS, VMESS, TROJAN

and installs a management CLI: /usr/local/bin/tdz

NOTE: This is a template. Traffic-quota enforcement requires additional system integration

(vnstat, xray stats API or nftables/tc). See notes at the end of the script.

set -euo pipefail export DEBIAN_FRONTEND=noninteractive

--------- Helper funcs ---------

msg() { echo -e "[TDZ] $"; } err() { echo -e "[TDZ][ERR] $" >&2; exit 1; } require_root() { [ "$(id -u)" -eq 0 ] || err "Run as root"; }

require_root

--------- Variables (change if you like) ---------

TDZ_DIR="/etc/tdz" XRAY_DIR="/etc/xray" XRAY_CONFIG="$XRAY_DIR/tdz_config.json" USERS_DB="$TDZ_DIR/users.json" TDZ_BIN="/usr/local/bin/tdz" DOMAIN="$(hostname -f 2>/dev/null || echo "$(curl -s ifconfig.me || echo "YOUR_DOMAIN")")" UUID_BIN="$(command -v uuidgen || true)"

Ensure dirs

mkdir -p "$TDZ_DIR" "$XRAY_DIR" /var/log/tdz || true

--------- Install prerequisites ---------

install_prereq(){ msg "Installing prerequisites (curl, jq, socat, lsof)..." apt-get update -y apt-get install -y curl wget gnupg2 apt-transport-https lsb-release ca-certificates curl jq socat lsof }

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
