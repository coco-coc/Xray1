#!/bin/bash

# 全局颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
NC="\033[0m"

# 信息前缀
INFO="${GREEN}[信息]${NC}"
ERROR="${RED}[错误]${NC}"
WARNING="${YELLOW}[警告]${NC}"

# 检测系统类型
detect_os() {
    if [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif grep -q "Ubuntu" /etc/os-release; then
        echo "ubuntu"
    elif grep -q "Debian" /etc/os-release; then
        echo "debian"
    elif grep -q "CentOS" /etc/os-release || grep -q "Red Hat" /etc/os-release || grep -q "AlmaLinux" /etc/os-release; then
        echo "centos"
    else
        echo "unknown"
    fi
}

OS_TYPE=$(detect_os)

# 路径配置
XRAY_BIN="/usr/local/bin/xray"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_FILE="/usr/local/etc/xray/config.json"
HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_CONFIG_DIR="/etc/hysteria"
HYSTERIA_CONFIG_FILE="/etc/hysteria/config.yaml"
ANYTLS_BIN="/usr/local/bin/anytls-server"

# 颜色输出函数
red() { echo -e "${RED}$1${NC}"; }
green() { echo -e "${GREEN}$1${NC}"; }
yellow() { echo -e "${YELLOW}$1${NC}"; }
blue() { echo -e "${BLUE}$1${NC}"; }
cyan() { echo -e "${CYAN}$1${NC}"; }

# ============================== Xray 安装部分 ==============================
install_xray() {
    rm -f /var/log/xray*.log

    yellow "检测系统类型：$OS_TYPE"
    yellow "开始安装依赖..."
    install_deps

    # 选择协议
    PROTOCOL=""
    while [[ -z "$PROTOCOL" ]]; do
        yellow "请选择协议："
        select protocol in "vmess" "trojan" "vless" "shadowsocks" "socks"; do
            if [[ -n "$protocol" ]]; then
                PROTOCOL=$protocol
                break
            else
                red "无效选择，请重新输入"
            fi
        done
    done

    # VLESS 传输类型
    VLESS_TYPE=""
    if [[ "$PROTOCOL" == "vless" ]]; then
        while [[ -z "$VLESS_TYPE" ]]; do
            yellow "请选择VLESS传输类型："
            select vless_type in "WebSocket+TLS" "Reality"; do
                if [[ -n "$vless_type" ]]; then
                    VLESS_TYPE=$vless_type
                    break
                else
                    red "无效选择，请重新输入"
                fi
            done
        done
    fi

    DEST_SERVER=""
    if [[ "$PROTOCOL" == "vless" && "$VLESS_TYPE" == "Reality" ]]; then
        read -p "请输入伪装域名[默认: www.microsoft.com]: " dest_server_input
        DEST_SERVER=${dest_server_input:-"www.microsoft.com"}
    fi

    DOMAIN=""
    WS_PATH=""
    if [[ "$PROTOCOL" != "shadowsocks" && "$PROTOCOL" != "socks" && ! ( "$PROTOCOL" == "vless" && "$VLESS_TYPE" == "Reality" ) ]]; then
        read -p "请输入域名（已解析到本机IP）：" DOMAIN
        read -p "请输入WebSocket路径（默认/）：" WS_PATH
        [[ -z "$WS_PATH" ]] && WS_PATH="/"
    fi

    CERT_PATH=""
    KEY_PATH=""
    if [[ "$PROTOCOL" != "shadowsocks" && "$PROTOCOL" != "socks" && ! ( "$PROTOCOL" == "vless" && "$VLESS_TYPE" == "Reality" ) ]]; then
        setup_certificates
    fi

    PASSWORD=""
    UUID=""
    SS_METHOD=""
    SOCKS_USER=""
    SOCKS_PASSWORD=""
    TROJAN_PASSWORD=""

    if [[ "$PROTOCOL" == "trojan" ]]; then
        read -p "请输入Trojan密码（默认随机生成）：" PASSWORD
        [[ -z "$PASSWORD" ]] && PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        green "Trojan 密码已生成：$PASSWORD"
        TROJAN_PASSWORD="$PASSWORD"
    elif [[ "$PROTOCOL" == "shadowsocks" ]]; then
        read -p "请输入Shadowsocks密码（默认随机生成）：" PASSWORD
        [[ -z "$PASSWORD" ]] && PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        green "Shadowsocks 密码已生成：$PASSWORD"

        while [[ -z "$SS_METHOD" ]]; do
            yellow "请选择加密方式："
            select method in "aes-256-gcm" "chacha20-poly1305" "aes-128-gcm" "none"; do
                if [[ -n "$method" ]]; then
                    SS_METHOD=$method
                    break
                else
                    red "无效选择，请重新输入"
                fi
            done
        done
        [[ "$SS_METHOD" == "none" ]] && SS_METHOD="plain"
    elif [[ "$PROTOCOL" == "socks" ]]; then
        read -p "请输入Socks用户名（默认随机生成）：" SOCKS_USER
        [[ -z "$SOCKS_USER" ]] && SOCKS_USER=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
        read -p "请输入Socks密码（默认随机生成）：" SOCKS_PASSWORD
        [[ -z "$SOCKS_PASSWORD" ]] && SOCKS_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        green "Socks 用户名: $SOCKS_USER"
        green "Socks 密码: $SOCKS_PASSWORD"
    else
        UUID=$(cat /proc/sys/kernel/random/uuid)
        green "UUID 已生成：$UUID"
    fi

    # 确保 Xray 二进制文件存在
    if [[ ! -f "$XRAY_BIN" ]]; then
        download_xray
    fi

    PRIVATE_KEY=""
    PUBLIC_KEY=""
    if [[ "$PROTOCOL" == "vless" && "$VLESS_TYPE" == "Reality" ]]; then
        yellow "正在生成Reality密钥对..."
        local keys_output
        keys_output=$($XRAY_BIN x25519 2>&1)
        if [[ $? -ne 0 ]]; then
            red "生成密钥对失败，请检查Xray是否正常"
            exit 1
        fi

        # 兼容多种输出格式：PrivateKey/secret, PublicKey/Hash32/public key
        PRIVATE_KEY=$(echo "$keys_output" | grep -iE '^\s*(PrivateKey|secret)\s*:' | head -1 | awk -F ':' '{print $2}' | tr -d '[:space:]')
        PUBLIC_KEY=$(echo "$keys_output" | grep -iE '^\s*Hash32\s*:' | head -1 | awk -F ':' '{print $2}' | tr -d '[:space:]')
        if [[ -z "$PUBLIC_KEY" ]]; then
            PUBLIC_KEY=$(echo "$keys_output" | grep -iE '^\s*(PublicKey|public key)\s*:' | head -1 | awk -F ':' '{print $2}' | tr -d '[:space:]')
        fi

        if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
            red "无法解析密钥对，请手动运行 $XRAY_BIN x25519 检查输出格式"
            red "当前输出："
            echo "$keys_output"
            exit 1
        fi

        green "private_key: $PRIVATE_KEY"
        green "public_key: $PUBLIC_KEY"
    fi

    read -p "请输入监听端口（默认443）：" IN_PORT
    [[ -z "$IN_PORT" ]] && IN_PORT=443
    if [[ "$IN_PORT" != "443" ]] && [[ "$PROTOCOL" != "shadowsocks" && "$PROTOCOL" != "socks" ]]; then
        yellow "建议使用443端口以提高兼容性"
    fi

    mkdir -p "$XRAY_CONFIG_DIR"
    generate_config
    setup_service
    generate_links

    yellow "访问日志：/var/log/xray-access.log"
    yellow "错误日志：/var/log/xray-error.log"
    green "Xray 服务配置完成！"
    read -p "按回车键返回主菜单..."
}

download_xray() {
    yellow "正在从 GitHub 下载最新版 Xray..."
    local ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="64" ;;
        aarch64) ARCH="arm64-v8a" ;;
        armv7l) ARCH="arm32-v7a" ;;
        *) red "不支持的系统架构: $ARCH"; exit 1 ;;
    esac

    local BASE_URL="https://git.1314k.tk/https://github.com/XTLS/Xray-core/releases/latest/download"
    local DOWNLOAD_URL="${BASE_URL}/Xray-linux-${ARCH}.zip"
    local TEMP_DIR=$(mktemp -d)
    local ZIP_FILE="${TEMP_DIR}/xray.zip"

    echo "下载链接: $DOWNLOAD_URL"
    if ! wget -q --show-progress -O "$ZIP_FILE" "$DOWNLOAD_URL"; then
        red "Xray 下载失败，请检查网络连接"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    if ! unzip -o -d "$TEMP_DIR" "$ZIP_FILE"; then
        red "解压失败"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    if [[ -f "${TEMP_DIR}/xray" ]]; then
        cp "${TEMP_DIR}/xray" "$XRAY_BIN"
    else
        red "解压后未找到 xray 可执行文件"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    chmod +x "$XRAY_BIN"

    # 复制 geo 数据文件到配置目录
    [[ -f "${TEMP_DIR}/geoip.dat" ]] && cp "${TEMP_DIR}/geoip.dat" "$XRAY_CONFIG_DIR/"
    [[ -f "${TEMP_DIR}/geosite.dat" ]] && cp "${TEMP_DIR}/geosite.dat" "$XRAY_CONFIG_DIR/"

    rm -rf "$TEMP_DIR"
    green "Xray 安装成功！二进制文件: $XRAY_BIN"
}

install_deps() {
    case "$OS_TYPE" in
        "alpine")
            apk update
            DEPS="curl wget unzip openrc openssl"
            for pkg in $DEPS; do
                if ! apk info -e $pkg &>/dev/null; then
                    yellow "安装 $pkg..."
                    apk add $pkg
                else
                    green "$pkg 已安装"
                fi
            done
            if ! command -v nc &>/dev/null; then
                yellow "安装 netcat 工具..."
                if apk info -e netcat-openbsd &>/dev/null; then
                    apk add netcat-openbsd
                elif apk info -e nmap-ncat &>/dev/null; then
                    apk add nmap-ncat
                else
                    yellow "未找到 netcat 包，跳过（端口检测功能可能受限）"
                fi
            else
                green "nc 已安装"
            fi
            ;;
        "debian"|"ubuntu")
            apt update
            DEPS="curl wget unzip netcat-openbsd openssl"
            for pkg in $DEPS; do
                if ! dpkg -s $pkg &>/dev/null; then
                    yellow "安装 $pkg..."
                    apt install -y $pkg
                else
                    green "$pkg 已安装"
                fi
            done
            ;;
        "centos")
            if grep -q "CentOS Linux 7" /etc/os-release; then
                sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
                sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
                yum clean all
            fi
            if ! rpm -q epel-release >/dev/null; then
                yellow "安装EPEL仓库..."
                yum install -y epel-release
            fi
            DEPS="curl wget unzip nc openssl"
            for pkg in $DEPS; do
                if ! rpm -q $pkg >/dev/null; then
                    yellow "安装 $pkg..."
                    yum install -y $pkg
                else
                    green "$pkg 已安装"
                fi
            done
            ;;
        *)
            red "不支持的系统类型！"
            exit 1
            ;;
    esac
}

setup_service() {
    case "$OS_TYPE" in
        "alpine")
            cat << EOF > /etc/init.d/xray
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="$XRAY_BIN"
command_args="-config $XRAY_CONFIG_FILE"
pidfile="/run/xray.pid"
respawn_delay=5
rc_ulimit="-n 30000"
output_log="/var/log/xray.log"
error_log="/var/log/xray.error.log"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -f \$output_log -m 0644
    checkpath -f \$error_log -m 0644
}

start() {
    ebegin "Starting xray service"
    start-stop-daemon --start \\
        --exec \$command \\
        --pidfile \$pidfile \\
        --background \\
        --make-pidfile \\
        -- \\
        \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping xray service"
    start-stop-daemon --stop \\
        --exec \$command \\
        --pidfile \$pidfile
    eend \$?
}
EOF
            chmod +x /etc/init.d/xray
            mkdir -p /var/log
            touch /var/log/xray.log
            rc-update add xray default
            service xray restart
            ;;
        "debian"|"ubuntu"|"centos")
            cat << EOF > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=$XRAY_BIN -config $XRAY_CONFIG_FILE
Restart=always
User=root
LimitNOFILE=30000
StandardOutput=file:/var/log/xray.log
StandardError=file:/var/log/xray.error.log

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable xray
            systemctl restart xray
            ;;
    esac
}

setup_certificates() {
    while true; do
        read -p "请选择：1.已上传证书文件，输入证书路径；2.未上传证书，直接输入证书内容.(默认选择1)： " is_path
        [[ -z $is_path ]] && is_path=1

        if [[ $is_path == 1 ]]; then
            while true; do
                read -p "请输入.crt结尾的证书绝对路径：" cert
                until [[ -f "$cert" ]]; do
                    red "找不到文件！请检查输入路径！"
                    read -p "请输入.crt结尾的证书绝对路径：" cert
                done

                read -p "请输入.key结尾的证书绝对路径：" key
                until [[ -f "$key" ]]; do
                    red "找不到文件！请检查输入路径！"
                    read -p "请输入.key结尾的证书绝对路径：" key
                done

                cert_md5=$(openssl x509 -noout -modulus -in "$cert" 2>/dev/null | openssl md5 | cut -d' ' -f2)
                key_md5=$(openssl rsa -noout -modulus -in "$key" 2>/dev/null | openssl md5 | cut -d' ' -f2)

                if [[ "$cert_md5" == "$key_md5" ]]; then
                    CERT_PATH="$cert"
                    KEY_PATH="$key"
                    green "√ 证书验证通过"
                    break 2
                else
                    red "证书与私钥不匹配！请重新输入"
                fi
            done
        else
            mkdir -p "$XRAY_CONFIG_DIR"
            chmod 700 "$XRAY_CONFIG_DIR"

            while true; do
                yellow "请输入证书内容（输入空行结束）："
                cert_txt=""
                while IFS= read -r line; do
                    [[ -z "$line" ]] && break
                    cert_txt+="$line\n"
                done
                echo -e "$cert_txt" | sed '/^$/d' > "$XRAY_CONFIG_DIR/domain.crt"
                yellow "证书被保存在：$XRAY_CONFIG_DIR/domain.crt"

                yellow "请输入对应的key内容（输入空行结束）："
                key_txt=""
                while IFS= read -r line; do
                    [[ -z "$line" ]] && break
                    key_txt+="$line\n"
                done
                echo -e "$key_txt" | sed '/^$/d' > "$XRAY_CONFIG_DIR/domain.key"
                yellow "证书被保存在：$XRAY_CONFIG_DIR/domain.key"

                cert_md5=$(openssl x509 -noout -modulus -in "$XRAY_CONFIG_DIR/domain.crt" 2>/dev/null | openssl md5 | cut -d' ' -f2)
                key_md5=$(openssl rsa -noout -modulus -in "$XRAY_CONFIG_DIR/domain.key" 2>/dev/null | openssl md5 | cut -d' ' -f2)

                if [[ "$cert_md5" == "$key_md5" ]]; then
                    CERT_PATH="$XRAY_CONFIG_DIR/domain.crt"
                    KEY_PATH="$XRAY_CONFIG_DIR/domain.key"
                    green "√ 证书验证通过"
                    break 2
                else
                    red "证书与私钥不匹配！请重新输入"
                    read -p "是否重新输入？(y/n, 默认y): " retry
                    [[ -z "$retry" ]] && retry="y"
                    [[ "$retry" != "y" ]] && { red "证书验证失败，安装中止！"; exit 1; }
                fi
            done
        fi
    done
}

generate_config() {
    local LISTEN_IPV6='"listen": "::",'
    local DOMAIN_STRATEGY='"domainStrategy": "UseIP"'

    case "$PROTOCOL" in
        "vmess")
            cat << EOF > "$XRAY_CONFIG_FILE"
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray-access.log",
        "error": "/var/log/xray-error.log"
    },
    "inbounds": [{
        $LISTEN_IPV6
        "port": $IN_PORT,
        "protocol": "$PROTOCOL",
        "settings": {
            "clients": [{ "id": "$UUID", "alterId": 0, "security": "auto" }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": "$WS_PATH",
                "headers": { "Host": "$DOMAIN" }
            },
            "tlsSettings": {
                "certificates": [{
                    "certificateFile": "$CERT_PATH",
                    "keyFile": "$KEY_PATH"
                }],
                "serverName": "$DOMAIN"
            }
        }
    }],
    "outbounds": [{
        "protocol": "freedom",
        "settings": {
            $DOMAIN_STRATEGY
        }
    }]
}
EOF
            ;;
        "trojan")
            cat << EOF > "$XRAY_CONFIG_FILE"
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray-access.log",
        "error": "/var/log/xray-error.log"
    },
    "inbounds": [{
        $LISTEN_IPV6
        "port": $IN_PORT,
        "protocol": "$PROTOCOL",
        "settings": {
            "clients": [{ "password": "$TROJAN_PASSWORD" }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": "$WS_PATH",
                "headers": { "Host": "$DOMAIN" }
            },
            "tlsSettings": {
                "certificates": [{
                    "certificateFile": "$CERT_PATH",
                    "keyFile": "$KEY_PATH"
                }],
                "serverName": "$DOMAIN"
            }
        }
    }],
    "outbounds": [{
        "protocol": "freedom",
        "settings": {
            $DOMAIN_STRATEGY
        }
    }]
}
EOF
            ;;
        "vless")
            if [[ "$VLESS_TYPE" == "Reality" ]]; then
                # 修复：shortIds 至少需要一个值，常用空字符串 ""
                cat << EOF > "$XRAY_CONFIG_FILE"
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray-access.log",
        "error": "/var/log/xray-error.log"
    },
    "inbounds": [{
        $LISTEN_IPV6
        "port": $IN_PORT,
        "protocol": "$PROTOCOL",
        "settings": {
            "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": true,
                "dest": "$DEST_SERVER:443",
                "xver": 0,
                "serverNames": [
                    "$DEST_SERVER"
                ],
                "privateKey": "$PRIVATE_KEY",
                "minClientVer": "",
                "maxClientVer": "",
                "maxTimeDiff": 0,
                "shortIds": [""]
            },
            "packetEncoding": "xudp"
        }
    }],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {
                $DOMAIN_STRATEGY
            },
            "streamSettings": {
                "packetEncoding": "xudp"
            }
        }
    ]
}
EOF
            else
                cat << EOF > "$XRAY_CONFIG_FILE"
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray-access.log",
        "error": "/var/log/xray-error.log"
    },
    "inbounds": [{
        $LISTEN_IPV6
        "port": $IN_PORT,
        "protocol": "$PROTOCOL",
        "settings": {
            "clients": [{ "id": "$UUID" }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": "$WS_PATH",
                "headers": { "Host": "$DOMAIN" }
            },
            "tlsSettings": {
                "certificates": [{
                    "certificateFile": "$CERT_PATH",
                    "keyFile": "$KEY_PATH"
                }],
                "serverName": "$DOMAIN"
            }
        }
    }],
    "outbounds": [{
        "protocol": "freedom",
        "settings": {
            $DOMAIN_STRATEGY
        }
    }]
}
EOF
            fi
            ;;
        "shadowsocks")
            cat << EOF > "$XRAY_CONFIG_FILE"
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray-access.log",
        "error": "/var/log/xray-error.log"
    },
    "inbounds": [{
        $LISTEN_IPV6
        "port": $IN_PORT,
        "protocol": "shadowsocks",
        "settings": {
            "method": "$SS_METHOD",
            "password": "$PASSWORD",
            "network": "tcp,udp"
        }
    }],
    "outbounds": [{
        "protocol": "freedom",
        "settings": {
            $DOMAIN_STRATEGY
        }
    }]
}
EOF
            ;;
        "socks")
            cat << EOF > "$XRAY_CONFIG_FILE"
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray-access.log",
        "error": "/var/log/xray-error.log"
    },
    "inbounds": [{
        $LISTEN_IPV6
        "port": $IN_PORT,
        "protocol": "socks",
        "settings": {
            "auth": "password",
            "accounts": [
                {
                    "user": "$SOCKS_USER",
                    "pass": "$SOCKS_PASSWORD"
                }
            ],
            "udp": true,
            "ip": "127.0.0.1"
        }
    }],
    "outbounds": [{
        "protocol": "freedom",
        "settings": {
            $DOMAIN_STRATEGY
        }
    }]
}
EOF
            ;;
    esac
}

get_public_ip() {
    local ipv6_ip ipv4_ip
    ipv6_ip=$(curl -s -m 5 -6 icanhazip.com 2>/dev/null || curl -s -m 5 -6 ifconfig.me 2>/dev/null)
    if [ -n "$ipv6_ip" ] && [[ "$ipv6_ip" == *":"* ]]; then
        echo "[$ipv6_ip]"
        return
    fi
    ipv4_ip=$(curl -s -m 5 -4 icanhazip.com 2>/dev/null || curl -s -m 5 -4 ifconfig.me 2>/dev/null || curl -s -m 5 -4 api.ipify.org 2>/dev/null)
    if [ -n "$ipv4_ip" ] && [[ "$ipv4_ip" != *":"* ]]; then
        echo "$ipv4_ip"
        return
    fi
    hostname -I | awk '{print $1}'
}

generate_links() {
    local SERVER_IP=$(get_public_ip)

    blue "\n=============== 客户端配置链接 ================"
    case "$PROTOCOL" in
        "vmess")
            local VMESS_JSON="{\"v\":\"2\",\"ps\":\"Xray_VMess\",\"add\":\"$DOMAIN\",\"port\":\"$IN_PORT\",\"id\":\"$UUID\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"$WS_PATH\",\"tls\":\"tls\",\"sni\":\"$DOMAIN\"}"
            local VMESS_LINK="vmess://$(echo -n "$VMESS_JSON" | base64 -w 0)"
            green "VMess 链接：\n$VMESS_LINK"
            ;;
        "trojan")
            local TROJAN_LINK="trojan://${TROJAN_PASSWORD}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_Trojan"
            green "Trojan 链接：\n$TROJAN_LINK"
            ;;
        "vless")
            if [[ "$VLESS_TYPE" == "Reality" ]]; then
                # 修复：添加 sid= 参数，与短 ID 空字符串对应
                local VLESS_LINK="vless://${UUID}@${SERVER_IP}:${IN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DEST_SERVER}&fp=chrome&pbk=${PUBLIC_KEY}&sid=&type=tcp&headerType=none&packetEncoding=xudp#Vless-Reality"
                green "VLESS (Reality) 链接：\n$VLESS_LINK"
            else
                local VLESS_LINK="vless://${UUID}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_VLESS"
                green "VLESS 链接：\n$VLESS_LINK"
            fi
            ;;
        "shadowsocks")
            local SS_LINK="ss://$(echo -n "${SS_METHOD}:${PASSWORD}" | base64 -w 0)@${SERVER_IP}:${IN_PORT}#Xray_Shadowsocks"
            green "Shadowsocks 链接：\n$SS_LINK"
            ;;
        "socks")
            blue "\n=============== Socks5 客户端配置 ================"
            green "服务器地址: ${SERVER_IP}"
            green "端口: $IN_PORT"
            green "用户名: $SOCKS_USER"
            green "密码: $SOCKS_PASSWORD"
            blue "================================================\n"
            ;;
    esac
    blue "================================================\n"
}

# ============================== Hysteria2 安装部分 ==============================
install_hysteria2() {
    generate_uuid() {
        local bytes=$(od -x -N 16 /dev/urandom | head -1 | awk '{OFS=""; $1=""; print}')
        local byte7=${bytes:12:4}
        byte7=$((0x${byte7} & 0x0fff | 0x4000))
        byte7=$(printf "%04x" $byte7)
        local byte9=${bytes:20:4}
        byte9=$((0x${byte9} & 0x3fff | 0x8000))
        byte9=$(printf "%04x" $byte9)
        echo "${bytes:0:8}-${bytes:8:4}-${byte7}-${byte9}-${bytes:24:12}" | tr '[:upper:]' '[:lower:]'
    }

    get_server_address() {
        local ipv6_ip ipv4_ip
        ipv6_ip=$(curl -s -m 5 -6 icanhazip.com 2>/dev/null || curl -s -m 5 -6 ifconfig.me 2>/dev/null)
        if [ -n "$ipv6_ip" ] && [[ "$ipv6_ip" == *":"* ]]; then
            echo "[$ipv6_ip]"
            return
        fi
        ipv4_ip=$(curl -s -m 5 -4 icanhazip.com 2>/dev/null || curl -s -m 5 -4 ifconfig.me 2>/dev/null || curl -s -m 5 -4 api.ipify.org 2>/dev/null)
        if [ -n "$ipv4_ip" ] && [[ "$ipv4_ip" != *":"* ]]; then
            echo "$ipv4_ip"
            return
        fi
        hostname -I | awk '{print $1}'
    }

    install_hysteria_deps() {
        case "$OS_TYPE" in
            "alpine")
                apk update
                DEPS="wget curl git openssl openrc lsof coreutils libcap"
                for pkg in $DEPS; do
                    apk info -e $pkg &>/dev/null || apk add $pkg
                done
                ;;
            "ubuntu"|"debian")
                apt update
                DEPS="wget curl git openssl lsof coreutils libcap2-bin"
                for pkg in $DEPS; do
                    dpkg -s $pkg &>/dev/null || apt install -y $pkg
                done
                ;;
            "centos")
                grep -q "CentOS Linux 7" /etc/os-release && {
                    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
                    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
                    yum clean all
                }
                rpm -q epel-release || yum install -y epel-release
                DEPS="wget curl git openssl lsof coreutils libcap"
                for pkg in $DEPS; do
                    rpm -q $pkg &>/dev/null || yum install -y $pkg
                done
                ;;
        esac
    }

    echo -e "${YELLOW}Hysteria 2 安装脚本${NC}"
    install_hysteria_deps
    green "依赖包安装成功。"

    local TLS_TYPE DOMAIN SNI ACME_EMAIL CERT_PATH KEY_PATH MASQUERADE_URL
    DEFAULT_MASQUERADE_URL="https://www.bing.com"
    DEFAULT_ACME_EMAIL="$(head /dev/urandom | tr -dc a-z | head -c 8)@gmail.com"

    echo ""
    yellow "请选择 TLS 验证方式:"
    echo "1. 自定义证书 (已有证书或自签名)"
    echo "2. ACME HTTP 验证 (需要域名指向本机IP)"
    read -p "请选择 [1-2, 默认 1]: " TLS_TYPE
    TLS_TYPE=${TLS_TYPE:-1}

    case $TLS_TYPE in
        1)
            read -p "请输入证书 .crt 绝对路径 (回车生成自签名): " USER_CERT_PATH
            if [ -z "$USER_CERT_PATH" ]; then
                read -p "伪装域名 (默认 www.bing.com): " SELF_SIGN_SNI
                SELF_SIGN_SNI=${SELF_SIGN_SNI:-"www.bing.com"}
                SNI="$SELF_SIGN_SNI"
                mkdir -p "$HYSTERIA_CONFIG_DIR/certs"
                CERT_PATH="$HYSTERIA_CONFIG_DIR/certs/server.crt"
                KEY_PATH="$HYSTERIA_CONFIG_DIR/certs/server.key"
                openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                    -keyout "$KEY_PATH" -out "$CERT_PATH" \
                    -subj "/CN=$SNI" -days 36500 || { red "自签名生成失败"; exit 1; }
                green "自签名证书已生成"
            else
                read -p "请输入私钥 .key 绝对路径: " USER_KEY_PATH
                CERT_PATH=$(realpath "$USER_CERT_PATH")
                KEY_PATH=$(realpath "$USER_KEY_PATH")
                [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ] && { red "文件不存在"; exit 1; }
                SNI=$(openssl x509 -noout -subject -in "$CERT_PATH" 2>/dev/null | grep -o 'CN=[^,]*' | cut -d= -f2 | tr -d ' ')
                [ -z "$SNI" ] && { read -p "无法自动提取CN，请输入SNI: " SNI; [[ -z "$SNI" ]] && { red "SNI不能为空"; exit 1; }; }
            fi
            ;;
        2)
            read -p "域名: " DOMAIN
            [[ -z "$DOMAIN" ]] && { red "域名不能为空"; exit 1; }
            read -p "ACME邮箱 (默认 $DEFAULT_ACME_EMAIL): " ACME_EMAIL
            ACME_EMAIL=${ACME_EMAIL:-$DEFAULT_ACME_EMAIL}
            SNI="$DOMAIN"
            lsof -i:80 &>/dev/null && yellow "80端口被占用，ACME可能失败"
            ;;
        *) red "无效选项"; exit 1 ;;
    esac

    read -p "端口 (留空随机): " PORT
    if [ -z "$PORT" ]; then
        PORT=$((RANDOM % 30001 + 20000))
        while lsof -i :$PORT &>/dev/null; do PORT=$((RANDOM % 30001 + 20000)); done
        green "随机端口: $PORT"
    fi

    RANDOM_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
    read -p "密码 (回车随机): " PASSWORD
    PASSWORD=${PASSWORD:-$RANDOM_PASSWORD}
    green "密码: $PASSWORD"

    read -p "伪装URL (默认 $DEFAULT_MASQUERADE_URL): " MASQUERADE_URL
    MASQUERADE_URL=${MASQUERADE_URL:-$DEFAULT_MASQUERADE_URL}

    SERVER_PUBLIC_ADDRESS=$(get_server_address)
    mkdir -p "$HYSTERIA_CONFIG_DIR"

    ARCH=$(uname -m)
    case $ARCH in
        x86_64) HYSTERIA_ARCH="amd64" ;;
        aarch64) HYSTERIA_ARCH="arm64" ;;
        armv7l) HYSTERIA_ARCH="arm" ;;
        *) red "架构不支持"; exit 1 ;;
    esac

    wget -qO "$HYSTERIA_BIN" "https://download.hysteria.network/app/latest/hysteria-linux-${HYSTERIA_ARCH}" || { red "下载失败"; exit 1; }
    chmod +x "$HYSTERIA_BIN"

    [ "$TLS_TYPE" -eq 2 ] && { command -v setcap &>/dev/null && setcap 'cap_net_bind_service=+ep' "$HYSTERIA_BIN"; }

    cat > "$HYSTERIA_CONFIG_FILE" << EOF
listen: :$PORT
auth:
  type: password
  password: $PASSWORD
masquerade:
  type: proxy
  proxy:
    url: $MASQUERADE_URL
    rewriteHost: true
EOF

    if [ "$TLS_TYPE" -eq 1 ]; then
        cat >> "$HYSTERIA_CONFIG_FILE" << EOF
tls:
  cert: $CERT_PATH
  key: $KEY_PATH
EOF
        LINK_SNI="$SNI"
        LINK_INSECURE=1
    else
        cat >> "$HYSTERIA_CONFIG_FILE" << EOF
acme:
  domains:
    - $DOMAIN
  email: $ACME_EMAIL
EOF
        LINK_SNI="$DOMAIN"
        LINK_INSECURE=0
    fi

    case "$OS_TYPE" in
        "alpine")
            cat << EOF > /etc/init.d/hysteria
#!/sbin/openrc-run
name="hysteria"
command="$HYSTERIA_BIN"
command_args="server --config $HYSTERIA_CONFIG_FILE"
pidfile="/var/run/\${name}.pid"
respawn_delay=5
output_log="/var/log/hysteria.log"
error_log="/var/log/hysteria.error.log"
depend() { need net; after firewall; }
start_pre() { checkpath -f \$output_log -m 0644; checkpath -f \$error_log -m 0644; }
start() { ebegin "Starting \$name"; start-stop-daemon --start --exec \$command --pidfile \$pidfile --background --make-pidfile -- -- \$command_args; eend \$?; }
stop() { ebegin "Stopping \$name"; start-stop-daemon --stop --exec \$command --pidfile \$pidfile; eend \$?; }
EOF
            chmod +x /etc/init.d/hysteria
            rc-update add hysteria default
            service hysteria restart
            ;;
        "ubuntu"|"debian"|"centos")
            cat << EOF > /etc/systemd/system/hysteria.service
[Unit]
Description=Hysteria Service
After=network.target
[Service]
ExecStart=$HYSTERIA_BIN server --config $HYSTERIA_CONFIG_FILE
Restart=always
User=root
LimitNOFILE=infinity
StandardOutput=file:/var/log/hysteria.log
StandardError=file:/var/log/hysteria.error.log
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable hysteria
            systemctl restart hysteria
            ;;
    esac

    sleep 3
    LINK_ADDRESS=$([ "$TLS_TYPE" -eq 2 ] && echo "$DOMAIN" || echo "$SERVER_PUBLIC_ADDRESS")
    SUBSCRIPTION_LINK="hysteria2://${PASSWORD}@${LINK_ADDRESS}:${PORT}/?sni=${LINK_SNI}&insecure=${LINK_INSECURE}&alpn=h3#Hysteria-${LINK_SNI}"

    green "Hysteria2 安装完成！"
    echo "订阅链接: $SUBSCRIPTION_LINK"
    read -p "按回车键返回主菜单..."
}

# ============================== AnyTLS-Go 安装 ==============================
install_anytls_go() {
    ANYTLS_VERSION="v0.0.8"
    BASE_URL="https://github.com/anytls/anytls-go/releases/download"
    SERVICE_NAME="anytls-server"

    rm -f /var/log/anytls*.log
    yellow "安装依赖..."
    install_deps

    read -p "端口 (默认8443): " PORT
    PORT=${PORT:-8443}

    RANDOM_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
    read -p "密码 (回车随机): " PASSWORD
    PASSWORD=${PASSWORD:-$RANDOM_PASSWORD}
    green "密码: $PASSWORD"

    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ANYTLS_ARCH="amd64" ;;
        aarch64|arm64) ANYTLS_ARCH="arm64" ;;
        *) red "架构不支持"; exit 1 ;;
    esac

    TEMP_DIR=$(mktemp -d)
    FILENAME="anytls_${ANYTLS_VERSION#v}_linux_${ANYTLS_ARCH}.zip"
    wget -q -O "${TEMP_DIR}/${FILENAME}" "${BASE_URL}/${ANYTLS_VERSION}/${FILENAME}" || { red "下载失败"; rm -rf "$TEMP_DIR"; exit 1; }
    unzip -q -d "$TEMP_DIR" "${TEMP_DIR}/${FILENAME}" || { red "解压失败"; rm -rf "$TEMP_DIR"; exit 1; }
    [ ! -f "${TEMP_DIR}/${SERVICE_NAME}" ] && { red "找不到二进制"; rm -rf "$TEMP_DIR"; exit 1; }
    mv "${TEMP_DIR}/${SERVICE_NAME}" "$ANYTLS_BIN"
    chmod +x "$ANYTLS_BIN"
    rm -rf "$TEMP_DIR"

    case "$OS_TYPE" in
        "alpine")
            cat << EOF > /etc/init.d/${SERVICE_NAME}
#!/sbin/openrc-run
name="${SERVICE_NAME}"
command="$ANYTLS_BIN"
command_args="-l :${PORT} -p \"${PASSWORD}\""
pidfile="/var/run/\${name}.pid"
respawn_delay=5
output_log="/var/log/anytls.log"
error_log="/var/log/anytls.error.log"
depend() { need net; after firewall; }
start_pre() { checkpath -f \$output_log -m 0644; checkpath -f \$error_log -m 0644; }
start() { ebegin "Starting \$name"; start-stop-daemon --start --exec \$command --background --make-pidfile --pidfile \$pidfile -- -- \$command_args; eend \$?; }
stop() { ebegin "Stopping \$name"; start-stop-daemon --stop --pidfile \$pidfile; eend \$?; }
EOF
            chmod +x /etc/init.d/${SERVICE_NAME}
            rc-update add ${SERVICE_NAME} default
            service ${SERVICE_NAME} restart
            ;;
        "ubuntu"|"debian"|"centos")
            cat << EOF > /etc/systemd/system/${SERVICE_NAME}.service
[Unit]
Description=AnyTLS-Go Service
After=network.target
[Service]
ExecStart=$ANYTLS_BIN -l :${PORT} -p "${PASSWORD}"
Restart=always
User=root
LimitNOFILE=30000
StandardOutput=file:/var/log/anytls.log
StandardError=file:/var/log/anytls.error.log
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable ${SERVICE_NAME}
            systemctl restart ${SERVICE_NAME}
            ;;
    esac

    SERVER_IP=$(get_public_ip)
    ANYTLS_LINK="anytls://${PASSWORD}@${SERVER_IP}:${PORT}#Anytls-Go"
    green "AnyTLS-Go 安装完成！"
    echo "客户端链接: $ANYTLS_LINK"
    read -p "按回车键返回主菜单..."
}

# ============================== 卸载、链接查看、服务控制、端口修改 ==============================
uninstall_xray() {
    [ ! -f "$XRAY_BIN" ] && { red "未安装 Xray"; sleep 2; return; }
    case "$OS_TYPE" in
        "alpine") service xray stop; rc-update del xray; rm -f /etc/init.d/xray ;;
        *) systemctl stop xray; systemctl disable xray; rm -f /etc/systemd/system/xray.service ;;
    esac
    rm -f "$XRAY_BIN"
    rm -rf "$XRAY_CONFIG_DIR"
    rm -f /var/log/xray*.log
    green "Xray 已卸载"
    sleep 2
}

uninstall_hysteria2() {
    [ ! -f "$HYSTERIA_BIN" ] && { red "未安装 Hysteria2"; sleep 2; return; }
    case "$OS_TYPE" in
        "alpine") service hysteria stop; rc-update del hysteria; rm -f /etc/init.d/hysteria ;;
        *) systemctl stop hysteria; systemctl disable hysteria; rm -f /etc/systemd/system/hysteria.service ;;
    esac
    rm -f "$HYSTERIA_BIN"
    rm -rf "$HYSTERIA_CONFIG_DIR"
    rm -f /var/log/hysteria*.log
    green "Hysteria2 已卸载"
    sleep 2
}

uninstall_anytls_go() {
    [ ! -f "$ANYTLS_BIN" ] && { red "未安装 AnyTLS-Go"; sleep 2; return; }
    case "$OS_TYPE" in
        "alpine") service anytls-server stop; rc-update del anytls-server; rm -f /etc/init.d/anytls-server ;;
        *) systemctl stop anytls-server; systemctl disable anytls-server; rm -f /etc/systemd/system/anytls-server.service ;;
    esac
    rm -f "$ANYTLS_BIN"
    rm -f /var/log/anytls*.log
    green "AnyTLS-Go 已卸载"
    sleep 2
}

show_xray_links() {
    [ ! -f "$XRAY_CONFIG_FILE" ] && { red "配置文件不存在"; sleep 2; return; }
    yellow "此功能请通过安装时生成的链接查看，或查看配置文件自行拼接。"
    read -p "按回车键返回..."
}

show_hysteria_links() { yellow "功能暂略"; read -p ""; }
show_anytls_links() { yellow "功能暂略"; read -p ""; }

start_xray() { [ -f "$XRAY_BIN" ] && { case "$OS_TYPE" in "alpine") service xray start;; *) systemctl start xray;; esac; green "Xray 已启动"; } || red "未安装"; sleep 2; }
stop_xray() { [ -f "$XRAY_BIN" ] && { case "$OS_TYPE" in "alpine") service xray stop;; *) systemctl stop xray;; esac; yellow "Xray 已停止"; } || red "未安装"; sleep 2; }
restart_xray() { [ -f "$XRAY_BIN" ] && { case "$OS_TYPE" in "alpine") service xray restart;; *) systemctl restart xray;; esac; cyan "Xray 已重启"; } || red "未安装"; sleep 2; }

start_hysteria2() { [ -f "$HYSTERIA_BIN" ] && { case "$OS_TYPE" in "alpine") service hysteria start;; *) systemctl start hysteria;; esac; green "Hysteria2 已启动"; } || red "未安装"; sleep 2; }
stop_hysteria2() { [ -f "$HYSTERIA_BIN" ] && { case "$OS_TYPE" in "alpine") service hysteria stop;; *) systemctl stop hysteria;; esac; yellow "Hysteria2 已停止"; } || red "未安装"; sleep 2; }
restart_hysteria2() { [ -f "$HYSTERIA_BIN" ] && { case "$OS_TYPE" in "alpine") service hysteria restart;; *) systemctl restart hysteria;; esac; cyan "Hysteria2 已重启"; } || red "未安装"; sleep 2; }

start_anytls_go() { [ -f "$ANYTLS_BIN" ] && { case "$OS_TYPE" in "alpine") service anytls-server start;; *) systemctl start anytls-server;; esac; green "AnyTLS-Go 已启动"; } || red "未安装"; sleep 2; }
stop_anytls_go() { [ -f "$ANYTLS_BIN" ] && { case "$OS_TYPE" in "alpine") service anytls-server stop;; *) systemctl stop anytls-server;; esac; yellow "AnyTLS-Go 已停止"; } || red "未安装"; sleep 2; }
restart_anytls_go() { [ -f "$ANYTLS_BIN" ] && { case "$OS_TYPE" in "alpine") service anytls-server restart;; *) systemctl restart anytls-server;; esac; cyan "AnyTLS-Go 已重启"; } || red "未安装"; sleep 2; }

change_port() {
    echo "1. Xray  2. Hysteria2  3. AnyTLS-Go"
    read -p "选择: " choice
    case $choice in
        1) [ -f "$XRAY_CONFIG_FILE" ] && { read -p "新端口: " port; sed -i "s/\"port\": [0-9]*/\"port\": $port/" "$XRAY_CONFIG_FILE"; restart_xray; } || red "Xray未安装" ;;
        2) [ -f "$HYSTERIA_CONFIG_FILE" ] && { read -p "新端口: " port; sed -i "s/listen: :[0-9]*/listen: :$port/" "$HYSTERIA_CONFIG_FILE"; restart_hysteria2; } || red "Hysteria2未安装" ;;
        3) [ -f "$ANYTLS_BIN" ] && { read -p "新端口: " port; sed -i "s/-l :[0-9]*/-l :$port/" /etc/init.d/anytls-server /etc/systemd/system/anytls-server.service 2>/dev/null; restart_anytls_go; } || red "AnyTLS未安装" ;;
    esac
    sleep 2
}

# ============================== 主菜单 ==============================
show_menu() {
    clear
    echo -e "${CYAN}=============================================="
    echo " 代理协议安装管理脚本"
    echo " 支持系统: Alpine/Ubuntu/Debian/CentOS"
    echo "=============================================="
    echo -e "${NC} 安装与更新"
    echo "=============================================="
    echo -e "${YELLOW}1. 安装 Xray${NC}"
    echo -e "${YELLOW}2. 安装 Hysteria 2${NC}"
    echo -e "${YELLOW}3. 安装 AnyTLS-Go${NC}"
    echo "=============================================="
    echo " 卸载服务"
    echo "=============================================="
    echo -e "${YELLOW}4. 卸载 Xray${NC}"
    echo -e "${YELLOW}5. 卸载 Hysteria 2${NC}"
    echo -e "${YELLOW}6. 卸载 AnyTLS-Go${NC}"
    echo "=============================================="
    echo " 配置管理"
    echo "=============================================="
    echo -e "${YELLOW}7. 查看 Xray 链接${NC}"
    echo -e "${YELLOW}8. 查看 Hysteria2 链接${NC}"
    echo -e "${YELLOW}9. 查看 AnyTLS-Go 链接${NC}"
    echo -e "${YELLOW}10. 修改端口${NC}"
    echo "=============================================="
    echo " 服务控制"
    echo "=============================================="
    echo -e "${YELLOW}11-13. Xray 启停重启${NC}"
    echo -e "${YELLOW}14-16. Hysteria2 启停重启${NC}"
    echo -e "${YELLOW}17-19. AnyTLS-Go 启停重启${NC}"
    echo "=============================================="
    echo -e "${YELLOW}0. 退出${NC}"
    echo -e "${CYAN}=============================================="

    # 状态显示
    [ -f "$XRAY_BIN" ] && echo -e " Xray: ${GREEN}已安装${NC}" || echo -e " Xray: ${RED}未安装${NC}"
    [ -f "$HYSTERIA_BIN" ] && echo -e " Hysteria2: ${GREEN}已安装${NC}" || echo -e " Hysteria2: ${RED}未安装${NC}"
    [ -f "$ANYTLS_BIN" ] && echo -e " AnyTLS-Go: ${GREEN}已安装${NC}" || echo -e " AnyTLS-Go: ${RED}未安装${NC}"

    read -p "请选择操作 [0-19]: " choice
    case $choice in
        1) install_xray ;;
        2) install_hysteria2 ;;
        3) install_anytls_go ;;
        4) uninstall_xray ;;
        5) uninstall_hysteria2 ;;
        6) uninstall_anytls_go ;;
        7) show_xray_links ;;
        8) show_hysteria_links ;;
        9) show_anytls_links ;;
        10) change_port ;;
        11) start_xray ;;
        12) stop_xray ;;
        13) restart_xray ;;
        14) start_hysteria2 ;;
        15) stop_hysteria2 ;;
        16) restart_hysteria2 ;;
        17) start_anytls_go ;;
        18) stop_anytls_go ;;
        19) restart_anytls_go ;;
        0) exit 0 ;;
        *) red "无效选择"; sleep 1 ;;
    esac
    show_menu
}

show_menu