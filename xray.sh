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

# 颜色输出函数
red() { echo -e "${RED}$1${NC}"; }
green() { echo -e "${GREEN}$1${NC}"; }
yellow() { echo -e "${YELLOW}$1${NC}"; }
blue() { echo -e "${BLUE}$1${NC}"; }
cyan() { echo -e "${CYAN}$1${NC}"; }

# ============================== Xray 安装部分 ==============================
install_xray() {
    # 清理旧日志
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

    # 如果是VLESS协议，选择传输类型
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

    # Reality模式输入伪装域名
    DEST_SERVER=""
    if [[ "$PROTOCOL" == "vless" && "$VLESS_TYPE" == "Reality" ]]; then
        read -p "请输入伪装域名[默认: www.microsoft.com]: " dest_server_input
        DEST_SERVER=${dest_server_input:-"www.microsoft.com"}
    fi

    # 输入域名和路径（Shadowsocks、Socks和Reality不需要）
    DOMAIN=""
    WS_PATH=""
    if [[ "$PROTOCOL" != "shadowsocks" && "$PROTOCOL" != "socks" && ! ( "$PROTOCOL" == "vless" && "$VLESS_TYPE" == "Reality" ) ]]; then
        read -p "请输入域名（已解析到本机IP）：" DOMAIN
        read -p "请输入WebSocket路径（默认/）：" WS_PATH
        [[ -z "$WS_PATH" ]] && WS_PATH="/"
    fi

    # 配置证书（Shadowsocks、Socks和Reality不需要证书）
    CERT_PATH=""
    KEY_PATH=""
    if [[ "$PROTOCOL" != "shadowsocks" && "$PROTOCOL" != "socks" && ! ( "$PROTOCOL" == "vless" && "$VLESS_TYPE" == "Reality" ) ]]; then
        setup_certificates
    fi

    # 生成认证信息
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

    # 确保 Xray 二进制文件存在（统一在此下载）
    if [[ ! -f "/usr/local/bin/xray" ]]; then
        download_xray
    fi

    # 生成Reality密钥对 (已移除短ID)
    if [[ "$PROTOCOL" == "vless" && "$VLESS_TYPE" == "Reality" ]]; then
        yellow "正在生成Reality密钥对..."
        local keys_output
        keys_output=$(/usr/local/bin/xray x25519 2>&1)
        if [[ $? -ne 0 ]]; then
            red "生成密钥对失败，请检查Xray是否正常"
            exit 1
        fi

        # 从所有可能的行中提取私钥（不区分大小写，冒号分隔）
        PRIVATE_KEY=$(echo "$keys_output" | grep -iE '^\s*(PrivateKey|secret)\s*:' | head -1 | awk -F ':' '{print $2}' | tr -d '[:space:]')
        
        # 提取公钥：优先 Hash32 行，其次 PublicKey 行，再次 public key 行
        PUBLIC_KEY=$(echo "$keys_output" | grep -iE '^\s*Hash32\s*:' | head -1 | awk -F ':' '{print $2}' | tr -d '[:space:]')
        if [[ -z "$PUBLIC_KEY" ]]; then
            PUBLIC_KEY=$(echo "$keys_output" | grep -iE '^\s*(PublicKey|public key)\s*:' | head -1 | awk -F ':' '{print $2}' | tr -d '[:space:]')
        fi

        if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
            red "无法解析密钥对，请手动运行 /usr/local/bin/xray x25519 检查输出格式"
            exit 1
        fi

        green "private_key: $PRIVATE_KEY"
        green "public_key: $PUBLIC_KEY"
        green "短ID(ShortId): 已配置为免短ID"
    fi

    # 端口配置
    read -p "请输入监听端口（默认443）：" IN_PORT
    [[ -z "$IN_PORT" ]] && IN_PORT=443
    if [[ "$IN_PORT" != "443" ]] && [[ "$PROTOCOL" != "shadowsocks" && "$PROTOCOL" != "socks" ]]; then
        yellow "建议使用443端口以提高兼容性"
    fi

    # 生成配置文件
    generate_config

    # 配置服务
    setup_service

    # 生成客户端链接
    generate_links

    # 显示日志路径
    yellow "访问日志：/var/log/xray-access.log"
    yellow "错误日志：/var/log/xray-error.log"
    green "Xray 服务配置完成！"

    # 添加暂停以便用户查看链接
    read -p "按回车键返回主菜单..."
}

# 下载 Xray 统一函数
download_xray() {
    yellow "正在从 GitHub 下载最新版 Xray..."
    local ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="64" ;;
        aarch64) ARCH="arm64-v8a" ;;
        armv7l) ARCH="arm32-v7a" ;;
        *) red "不支持的系统架构: $ARCH"; exit 1 ;;
    esac

    # 使用加速代理防止某些地区下载慢
    local BASE_URL="https://git.1314k.tk/https://github.com/XTLS/Xray-core/releases/latest/download"
    local DOWNLOAD_URL="${BASE_URL}/Xray-linux-${ARCH}.zip"
    local LATEST_FILE="Xray-linux-${ARCH}.zip"

    echo "下载链接: $DOWNLOAD_URL"
    if ! wget -O "$LATEST_FILE" "$DOWNLOAD_URL"; then
        red "Xray 下载失败，请检查网络连接"
        exit 1
    fi

    mkdir -p /tmp/xray_temp
    unzip -o -d /tmp/xray_temp "$LATEST_FILE"
    if [[ -f "/tmp/xray_temp/xray" ]]; then
        mv /tmp/xray_temp/xray /usr/local/bin/xray
        chmod +x /usr/local/bin/xray
        green "Xray 安装成功！"
    else
        red "解压后未找到 xray 可执行文件"
        rm -rf /tmp/xray_temp "$LATEST_FILE"
        exit 1
    fi
    rm -rf /tmp/xray_temp "$LATEST_FILE"
}

# Xray依赖安装（带检测）- 修复Alpine nc-openbsd问题
install_deps() {
    case "$OS_TYPE" in
        "alpine")
            apk update
            # 修复: Alpine 中 netcat 包名是 netcat-openbsd 或 nmap-ncat
            DEPS="curl wget unzip openrc openssl"
            for pkg in $DEPS; do
                if ! apk info -e $pkg &>/dev/null; then
                    yellow "安装 $pkg..."
                    apk add $pkg
                else
                    green "$pkg 已安装"
                fi
            done

            # 安装 nc 命令（优先 netcat-openbsd，其次 nmap-ncat）
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
            # CentOS 7 镜像源修复
            if grep -q "CentOS Linux 7" /etc/os-release; then
                echo "修复 CentOS 7 镜像源..."
                sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
                sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
                yum clean all
            fi

            # 安装EPEL仓库
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

# Xray服务管理配置
setup_service() {
    case "$OS_TYPE" in
        "alpine")
            cat << 'EOF' > /etc/init.d/xray
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/usr/local/bin/xray"
command_args="-config /usr/local/etc/xray/config.json"
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
    checkpath -f $output_log -m 0644
    checkpath -f $error_log -m 0644
}

start() {
    ebegin "Starting xray service"
    start-stop-daemon --start \
        --exec $command \
        --pidfile $pidfile \
        --background \
        --make-pidfile \
        -- \
        $command_args
    eend $?
}

stop() {
    ebegin "Stopping xray service"
    start-stop-daemon --stop \
        --exec $command \
        --pidfile $pidfile
    eend $?
}
EOF
            chmod +x /etc/init.d/xray
            mkdir -p /var/log
            touch /var/log/xray.log
            rc-update add xray default
            service xray restart
            ;;
        "debian"|"ubuntu"|"centos")
            cat << 'EOF' > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=/usr/local/bin/xray -config /usr/local/etc/xray/config.json
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

# Xray证书配置 - 增强版（带循环验证）
setup_certificates() {
    mkdir -p /usr/local/etc/xray
    chmod 700 /usr/local/etc/xray
    
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
            while true; do
                yellow "请输入证书内容（输入空行结束）："
                cert_txt=""
                while IFS= read -r line; do
                    if [[ -z "$line" ]]; then
                        break
                    fi
                    cert_txt+="$line\n"
                done
                echo -e "$cert_txt" | sed '/^$/d' > /usr/local/etc/xray/domain.crt
                yellow "证书被保存在：/usr/local/etc/xray/domain.crt"

                yellow "请输入对应的key内容（输入空行结束）："
                key_txt=""
                while IFS= read -r line; do
                    if [[ -z "$line" ]]; then
                        break
                    fi
                    key_txt+="$line\n"
                done
                echo -e "$key_txt" | sed '/^$/d' > /usr/local/etc/xray/domain.key
                yellow "证书被保存在：/usr/local/etc/xray/domain.key"

                cert_md5=$(openssl x509 -noout -modulus -in /usr/local/etc/xray/domain.crt 2>/dev/null | openssl md5 | cut -d' ' -f2)
                key_md5=$(openssl rsa -noout -modulus -in /usr/local/etc/xray/domain.key 2>/dev/null | openssl md5 | cut -d' ' -f2)

                if [[ "$cert_md5" == "$key_md5" ]]; then
                    CERT_PATH="/usr/local/etc/xray/domain.crt"
                    KEY_PATH="/usr/local/etc/xray/domain.key"
                    green "√ 证书验证通过"
                    break 2
                else
                    red "证书与私钥不匹配！请重新输入"
                    read -p "是否重新输入？(y/n, 默认y): " retry
                    [[ -z "$retry" ]] && retry="y"
                    if [[ "$retry" != "y" ]]; then
                        red "证书验证失败，安装中止！"
                        exit 1
                    fi
                fi
            done
        fi
    done
}

# Xray生成协议配置
generate_config() {
    mkdir -p /usr/local/etc/xray
    
    local LISTEN_IPV6='"listen": "::",'
    local DOMAIN_STRATEGY='"domainStrategy": "UseIP"'

    case "$PROTOCOL" in
        "vmess")
            local CLIENT_CONFIG="\"id\": \"$UUID\", \"alterId\": 0, \"security\": \"auto\""
            local TLS_SETTINGS="\"tlsSettings\": {
                \"certificates\": [{
                    \"certificateFile\": \"$CERT_PATH\",
                    \"keyFile\": \"$KEY_PATH\"
                }],
                \"serverName\": \"$DOMAIN\"
            }"
            cat << EOF > /usr/local/etc/xray/config.json
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
            "clients": [{ $CLIENT_CONFIG }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": "$WS_PATH",
                "headers": { "Host": "$DOMAIN" }
            },
            $TLS_SETTINGS
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
            local CLIENT_CONFIG="\"password\": \"$TROJAN_PASSWORD\""
            local TLS_SETTINGS="\"tlsSettings\": {
                \"certificates\": [{
                    \"certificateFile\": \"$CERT_PATH\",
                    \"keyFile\": \"$KEY_PATH\"
                }],
                \"serverName\": \"$DOMAIN\"
            }"
            cat << EOF > /usr/local/etc/xray/config.json
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
            "clients": [{ $CLIENT_CONFIG }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": "$WS_PATH",
                "headers": { "Host": "$DOMAIN" }
            },
            $TLS_SETTINGS
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
                local CLIENT_CONFIG="\"id\": \"$UUID\", \"flow\": \"xtls-rprx-vision\""
                cat << EOF > /usr/local/etc/xray/config.json
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
            "clients": [{ $CLIENT_CONFIG }],
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
                "shortIds": [
                    ""
                ]
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
                local CLIENT_CONFIG="\"id\": \"$UUID\""
                local TLS_SETTINGS="\"tlsSettings\": {
                    \"certificates\": [{
                        \"certificateFile\": \"$CERT_PATH\",
                        \"keyFile\": \"$KEY_PATH\"
                    }],
                    \"serverName\": \"$DOMAIN\"
                }"
                cat << EOF > /usr/local/etc/xray/config.json
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
            "clients": [{ $CLIENT_CONFIG }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": "$WS_PATH",
                "headers": { "Host": "$DOMAIN" }
            },
            $TLS_SETTINGS
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
            cat << EOF > /usr/local/etc/xray/config.json
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
            cat << EOF > /usr/local/etc/xray/config.json
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

# 获取公网IP函数
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

# Xray生成客户端链接 - 增强版
generate_links() {
    local SERVER_IP=$(get_public_ip)

    blue "\n=============== 客户端配置链接 ================"
    case "$PROTOCOL" in
        "vmess")
            local VMESS_JSON=$(cat <<EOF
{
    "v": "2",
    "ps": "Xray_VMess",
    "add": "$DOMAIN",
    "port": "$IN_PORT",
    "id": "$UUID",
    "aid": "0",
    "scy": "auto",
    "net": "ws",
    "type": "none",
    "host": "$DOMAIN",
    "path": "$WS_PATH",
    "tls": "tls",
    "sni": "$DOMAIN"
}
EOF
            )
            local VMESS_LINK="vmess://$(echo "$VMESS_JSON" | base64 -w 0)"
            green "VMess 链接：\n$VMESS_LINK"
            ;;
        "trojan")
            local TROJAN_LINK="trojan://${TROJAN_PASSWORD}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_Trojan"
            green "Trojan 链接：\n$TROJAN_LINK"
            ;;
        "vless")
            if [[ "$VLESS_TYPE" == "Reality" ]]; then
                local VLESS_LINK="vless://${UUID}@${SERVER_IP}:${IN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DEST_SERVER}&fp=chrome&pbk=${PUBLIC_KEY}&type=tcp&headerType=none&packetEncoding=xudp#Vless-Reality"
                green "VLESS (Reality with XUDP) 链接：\n$VLESS_LINK"
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
            green "UDP支持: 是"
            green "加密: 无（请确保在安全环境下使用）"
            blue "================================================\n"
            ;;
    esac
    blue "================================================\n"
}

# ============================== Hysteria2 安装部分 ==============================
install_hysteria2() {
    # 生成符合RFC 4122标准的UUIDv4函数
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

    # 获取服务器公网地址并格式化
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

    # 安装依赖（带检测）
    install_hysteria_deps() {
        case "$OS_TYPE" in
            "alpine")
                apk update
                DEPS="wget curl git openssl openrc lsof coreutils libcap"
                for pkg in $DEPS; do
                    if ! apk info -e $pkg &>/dev/null; then
                        yellow "安装 $pkg..."
                        apk add $pkg
                    else
                        green "$pkg 已安装"
                    fi
                done
                ;;
            "ubuntu"|"debian")
                apt update
                DEPS="wget curl git openssl lsof coreutils libcap2-bin"
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
                DEPS="wget curl git openssl lsof coreutils libcap"
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

    echo -e "${YELLOW}Hysteria 2 安装脚本${NC}"
    echo "---------------------------------------"

    install_hysteria_deps
    green "依赖包安装成功。"

    local TLS_TYPE DOMAIN SNI ACME_EMAIL CERT_PATH KEY_PATH MASQUERADE_URL
    DEFAULT_MASQUERADE_URL="https://www.bing.com"
    DEFAULT_ACME_EMAIL="$(head /dev/urandom | tr -dc a-z | head -c 8)@gmail.com"

    echo ""
    echo -e "${YELLOW}请选择 TLS 验证方式:${NC}"
    echo "1. 自定义证书 (适用于已有证书或生成自签名证书)"
    echo "2. ACME HTTP 验证 (需要域名指向本机IP，且本机80端口可用)"
    read -p "请选择 [1-2, 默认 1]: " TLS_TYPE
    TLS_TYPE=${TLS_TYPE:-1}

    case $TLS_TYPE in
        1)
            read -p "请输入证书 (.crt) 文件绝对路径 (回车则生成自签名证书): " USER_CERT_PATH
            if [ -z "$USER_CERT_PATH" ]; then
                read -p "请输入用于自签名证书的伪装域名 (默认 www.bing.com): " SELF_SIGN_SNI
                SELF_SIGN_SNI=${SELF_SIGN_SNI:-"www.bing.com"}
                SNI="$SELF_SIGN_SNI"
                mkdir -p /etc/hysteria/certs
                CERT_PATH="/etc/hysteria/certs/server.crt"
                KEY_PATH="/etc/hysteria/certs/server.key"
                echo "正在生成自签名证书..."
                if ! openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                    -keyout "$KEY_PATH" -out "$CERT_PATH" \
                    -subj "/CN=$SNI" -days 36500; then
                    red "自签名证书生成失败！"
                    exit 1
                fi
                green "自签名证书已生成: $CERT_PATH, $KEY_PATH"
            else
                read -p "请输入私钥 (.key) 文件绝对路径: " USER_KEY_PATH
                CERT_PATH=$(realpath "$USER_CERT_PATH")
                KEY_PATH=$(realpath "$USER_KEY_PATH")
                if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
                    red "证书或私钥文件不存在！"
                    exit 1
                fi
                SNI=$(openssl x509 -noout -subject -in "$CERT_PATH" 2>/dev/null | grep -o 'CN=[^,]*' | cut -d= -f2 | tr -d ' ')
                if [ -z "$SNI" ]; then
                    read -p "无法从证书自动提取CN(域名)，请输入您希望使用的SNI: " MANUAL_SNI
                    [[ -z "$MANUAL_SNI" ]] && { red "SNI 不能为空！"; exit 1; }
                    SNI="$MANUAL_SNI"
                else
                    echo "从证书中提取到的 SNI (CN): $SNI"
                fi
            fi
            ;;
        2)
            read -p "请输入您的域名 (例如: example.com): " DOMAIN
            [[ -z "$DOMAIN" ]] && { red "域名不能为空！"; exit 1; }
            read -p "请输入用于 ACME 证书申请的邮箱 (回车默认 $DEFAULT_ACME_EMAIL): " INPUT_ACME_EMAIL
            ACME_EMAIL=${INPUT_ACME_EMAIL:-$DEFAULT_ACME_EMAIL}
            [[ -z "$ACME_EMAIL" ]] && { red "邮箱不能为空！"; exit 1; }
            SNI=$DOMAIN
            echo "检查 80 端口占用情况..."
            if lsof -i:80 -sTCP:LISTEN -P -n &>/dev/null; then
                yellow "警告: 检测到 80 端口已被占用。Hysteria 将尝试使用此端口进行 ACME 验证。"
                PID_80=$(lsof -t -i:80 -sTCP:LISTEN)
                [ -n "$PID_80" ] && echo "占用80端口的进程 PID(s): $PID_80"
            else
                echo "80 端口未被占用，可用于 ACME HTTP 验证。"
            fi
            ;;
        *)
            red "无效选项"; exit 1
            ;;
    esac

    read -p "请输入 Hysteria 端口 (留空则生成随机端口): " PORT
    if [[ -z "$PORT" ]]; then
        PORT=$((RANDOM % 30001 + 20000))
        while lsof -i :$PORT >/dev/null 2>&1 || netstat -an | grep -q ":$PORT "; do
            PORT=$((RANDOM % 30001 + 20000))
        done
        green "已生成随机端口: $PORT"
    fi

    RANDOM_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
    read -p "请输入 Hysteria 密码 (回车则使用随机密码): " PASSWORD
    PASSWORD=${PASSWORD:-$RANDOM_PASSWORD}
    if [[ "$PASSWORD" == "$RANDOM_PASSWORD" ]]; then
        green "使用随机密码: $PASSWORD"
    fi

    read -p "请输入伪装访问的目标URL (默认 $DEFAULT_MASQUERADE_URL): " MASQUERADE_URL
    MASQUERADE_URL=${MASQUERADE_URL:-$DEFAULT_MASQUERADE_URL}

    SERVER_PUBLIC_ADDRESS=$(get_server_address)

    mkdir -p /etc/hysteria
    HYSTERIA_BIN="/usr/local/bin/hysteria"
    echo -e "${YELLOW}正在下载 Hysteria 最新版...${NC}"
    ARCH=$(uname -m)
    case ${ARCH} in
        x86_64) HYSTERIA_ARCH="amd64";;
        aarch64) HYSTERIA_ARCH="arm64";;
        armv7l) HYSTERIA_ARCH="arm";;
        *) red "不支持的系统架构: ${ARCH}"; exit 1;;
    esac

    if ! wget -qO "$HYSTERIA_BIN" "https://download.hysteria.network/app/latest/hysteria-linux-${HYSTERIA_ARCH}"; then
        red "下载 Hysteria 失败，请检查网络。"
        exit 1
    fi
    chmod +x "$HYSTERIA_BIN"

    if [ "$TLS_TYPE" -eq 2 ]; then
        if command -v setcap &>/dev/null; then
            setcap 'cap_net_bind_service=+ep' "$HYSTERIA_BIN" || yellow "setcap 失败，可能影响 ACME 验证。"
        else
            yellow "setcap 未找到，跳过权限设置。"
        fi
    fi

    cat > /etc/hysteria/config.yaml << EOF
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

    if [[ "$TLS_TYPE" -eq 1 ]]; then
        cat >> /etc/hysteria/config.yaml << EOF
tls:
  cert: $CERT_PATH
  key: $KEY_PATH
EOF
        LINK_SNI="$SNI"
        LINK_INSECURE=1
        yellow "注意: 使用自定义证书时，客户端需要设置 'insecure: true'"
    else
        cat >> /etc/hysteria/config.yaml << EOF
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
            cat << 'EOF' > /etc/init.d/hysteria
#!/sbin/openrc-run
name="hysteria"
description="Hysteria Service"
command="/usr/local/bin/hysteria"
command_args="server --config /etc/hysteria/config.yaml"
pidfile="/var/run/${name}.pid"
respawn_delay=5
output_log="/var/log/hysteria.log"
error_log="/var/log/hysteria.error.log"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -f $output_log -m 0644
    checkpath -f $error_log -m 0644
}

start() {
    ebegin "Starting $name"
    start-stop-daemon --start \
        --exec $command \
        --pidfile $pidfile \
        --background \
        --make-pidfile \
        -- \
        $command_args
    eend $?
}

stop() {
    ebegin "Stopping $name"
    start-stop-daemon --stop \
        --exec $command \
        --pidfile $pidfile
    eend $?
}
EOF
            chmod +x /etc/init.d/hysteria
            rc-update add hysteria default >/dev/null
            service hysteria stop >/dev/null 2>&1
            service hysteria start
            ;;
        "ubuntu"|"debian"|"centos")
            cat << 'EOF' > /etc/systemd/system/hysteria.service
[Unit]
Description=Hysteria VPN Service
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
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
            systemctl stop hysteria >/dev/null 2>&1
            systemctl start hysteria
            ;;
    esac

    sleep 3
    case "$OS_TYPE" in
        "alpine")
            if rc-service hysteria status | grep -q "started"; then
                green "Hysteria 服务已成功启动！"
            else
                red "Hysteria 服务状态异常。请检查日志:"
                echo "  tail -n 20 /var/log/hysteria.log"
            fi
            ;;
        "ubuntu"|"debian"|"centos")
            if systemctl is-active --quiet hysteria; then
                green "Hysteria 服务已成功启动！"
            else
                red "Hysteria 服务状态异常。"
                systemctl status hysteria
            fi
            ;;
    esac

    if [ "$TLS_TYPE" -eq 2 ]; then
        LINK_ADDRESS="$DOMAIN"
    else
        LINK_ADDRESS="$SERVER_PUBLIC_ADDRESS"
        [[ -z "$LINK_ADDRESS" ]] && LINK_ADDRESS="$SNI"
    fi

    SUBSCRIPTION_LINK="hysteria2://${PASSWORD}@${LINK_ADDRESS}:${PORT}/?sni=${LINK_SNI}&insecure=${LINK_INSECURE}&alpn=h3#Hysteria-${LINK_SNI}"

    echo ""
    echo "------------------------------------------------------------------------"
    green "Hysteria 2 安装和配置完成！"
    echo "------------------------------------------------------------------------"
    echo "服务器地址: ${LINK_ADDRESS}"
    echo "端口: $PORT"
    echo "密码: $PASSWORD"
    echo "SNI / 伪装域名: $LINK_SNI"
    echo "伪装目标站点: $MASQUERADE_URL"
    echo "TLS 模式: $([ "$TLS_TYPE" -eq 1 ] && echo "自定义证书" || echo "ACME HTTP")"
    [ "$TLS_TYPE" -eq 1 ] && echo "证书路径: $CERT_PATH" && echo "私钥路径: $KEY_PATH"
    [ "$TLS_TYPE" -eq 2 ] && echo "ACME 邮箱: $ACME_EMAIL"
    echo "客户端 insecure (0=false, 1=true): $LINK_INSECURE"
    echo "------------------------------------------------------------------------"
    yellow "订阅链接 (Hysteria V2):"
    echo "$SUBSCRIPTION_LINK"
    echo "------------------------------------------------------------------------"
    echo "管理命令："
    case "$OS_TYPE" in
        "alpine") echo " service hysteria start/stop/restart/status" ;;
        *) echo " systemctl start/stop/restart/status hysteria" ;;
    esac
    echo "配置文件: /etc/hysteria/config.yaml"
    echo "日志: /var/log/hysteria.log"
    echo "一键卸载："
    case "$OS_TYPE" in
        "alpine") echo " service hysteria stop ; rc-update del hysteria ; rm /etc/init.d/hysteria ; rm /usr/local/bin/hysteria ; rm -rf /etc/hysteria" ;;
        *) echo " systemctl stop hysteria ; systemctl disable hysteria ; rm /etc/systemd/system/hysteria.service ; rm /usr/local/bin/hysteria ; rm -rf /etc/hysteria" ;;
    esac
    echo "------------------------------------------------------------------------"
    read -p "按回车键返回主菜单..."
}

# ============================== AnyTLS-Go 安装部分 ==============================
install_anytls_go() {
    ANYTLS_VERSION="v0.0.8"
    BASE_URL="https://github.com/anytls/anytls-go/releases/download"
    INSTALL_DIR="/usr/local/bin"
    BINARY_NAME="anytls-server"
    SERVICE_NAME="anytls-server"

    rm -f /var/log/anytls*.log
    yellow "检测系统类型：$OS_TYPE"
    yellow "开始安装依赖..."
    install_deps

    read -p "请输入监听端口（默认8443）：" PORT
    [[ -z "$PORT" ]] && PORT=8443

    RANDOM_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
    read -p "请输入 AnyTLS 服务端密码 (回车则使用随机密码): " PASSWORD
    PASSWORD=${PASSWORD:-$RANDOM_PASSWORD}
    green "密码: $PASSWORD"

    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ANYTLS_ARCH="amd64";;
        aarch64|arm64) ANYTLS_ARCH="arm64";;
        *) red "不支持的系统架构: ${ARCH}"; exit 1;;
    esac
    green "检测到系统架构: $ANYTLS_ARCH"

    FILENAME="anytls_${ANYTLS_VERSION#v}_linux_${ANYTLS_ARCH}.zip"
    DOWNLOAD_URL="${BASE_URL}/${ANYTLS_VERSION}/${FILENAME}"
    TEMP_DIR=$(mktemp -d)

    yellow "正在下载 AnyTLS-Go..."
    if ! wget -q -O "${TEMP_DIR}/${FILENAME}" "$DOWNLOAD_URL"; then
        red "下载 AnyTLS-Go 失败。"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    yellow "正在解压文件..."
    if ! unzip -q -d "$TEMP_DIR" "${TEMP_DIR}/${FILENAME}"; then
        red "解压 AnyTLS-Go 失败。"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    if [ ! -f "${TEMP_DIR}/${BINARY_NAME}" ]; then
        red "解压后未找到 ${BINARY_NAME}。"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    mv "${TEMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    rm -rf "$TEMP_DIR"

    case "$OS_TYPE" in
        "alpine")
            cat << EOF > /etc/init.d/${SERVICE_NAME}
#!/sbin/openrc-run
name="${SERVICE_NAME}"
description="AnyTLS-Go Service"
command="${INSTALL_DIR}/${BINARY_NAME}"
command_args="-l :${PORT} -p \"${PASSWORD}\""
pidfile="/var/run/\${name}.pid"
respawn_delay=5
output_log="/var/log/anytls.log"
error_log="/var/log/anytls.error.log"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -f \$output_log -m 0644
    checkpath -f \$error_log -m 0644
}

start() {
    ebegin "Starting \$name"
    start-stop-daemon --start \\
        --exec \$command \\
        --background \\
        --make-pidfile --pidfile \$pidfile \\
        -- \\
        \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping \$name"
    start-stop-daemon --stop --pidfile \$pidfile
    eend \$?
}
EOF
            chmod +x "/etc/init.d/${SERVICE_NAME}"
            rc-update add ${SERVICE_NAME} default >/dev/null
            service ${SERVICE_NAME} restart
            ;;
        "ubuntu"|"debian"|"centos")
            cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=AnyTLS-Go Service
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -l :${PORT} -p "${PASSWORD}"
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

    echo ""
    echo "------------------------------------------------------------------------"
    green "AnyTLS-Go 服务安装完成！"
    echo "------------------------------------------------------------------------"
    echo "服务器地址: ${SERVER_IP}"
    echo "端口: $PORT"
    echo "密码: $PASSWORD"
    echo "------------------------------------------------------------------------"
    yellow "客户端链接:"
    echo "$ANYTLS_LINK"
    echo "------------------------------------------------------------------------"
    echo "管理命令："
    case "$OS_TYPE" in
        "alpine") echo " service ${SERVICE_NAME} start/stop/restart/status" ;;
        *) echo " systemctl start/stop/restart/status ${SERVICE_NAME}" ;;
    esac
    echo "日志文件: /var/log/anytls.log"
    echo "一键卸载命令："
    case "$OS_TYPE" in
        "alpine") echo " service ${SERVICE_NAME} stop ; rc-update del ${SERVICE_NAME} ; rm /etc/init.d/${SERVICE_NAME} ; rm ${INSTALL_DIR}/${BINARY_NAME}" ;;
        *) echo " systemctl stop ${SERVICE_NAME} ; systemctl disable ${SERVICE_NAME} ; rm /etc/systemd/system/${SERVICE_NAME}.service ; rm ${INSTALL_DIR}/${BINARY_NAME}" ;;
    esac
    echo "------------------------------------------------------------------------"
    read -p "按回车键返回主菜单..."
}

# ============================== 卸载功能 ==============================
uninstall_xray() {
    if [ ! -f "/usr/local/bin/xray" ]; then
        red "未找到 Xray 安装文件，可能未安装 Xray 服务！"
        sleep 2
        return
    fi
    yellow "开始卸载 Xray..."
    case "$OS_TYPE" in
        "alpine")
            service xray stop >/dev/null 2>&1
            rc-update del xray >/dev/null 2>&1
            rm -f /etc/init.d/xray
            ;;
        "debian"|"ubuntu"|"centos")
            systemctl stop xray >/dev/null 2>&1
            systemctl disable xray >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service
            systemctl daemon-reload
            ;;
    esac
    rm -f /usr/local/bin/xray
    rm -rf /usr/local/etc/xray
    rm -f /var/log/xray*.log
    green "Xray 已成功卸载！"
    sleep 2
}

uninstall_hysteria2() {
    if [ ! -f "/usr/local/bin/hysteria" ]; then
        red "未找到 Hysteria2 安装文件，可能未安装 Hysteria2 服务！"
        sleep 2
        return
    fi
    yellow "开始卸载 Hysteria2..."
    case "$OS_TYPE" in
        "alpine")
            service hysteria stop >/dev/null 2>&1
            rc-update del hysteria >/dev/null 2>&1
            rm -f /etc/init.d/hysteria
            ;;
        "ubuntu"|"debian"|"centos")
            systemctl stop hysteria >/dev/null 2>&1
            systemctl disable hysteria >/dev/null 2>&1
            rm -f /etc/systemd/system/hysteria.service
            systemctl daemon-reload
            ;;
    esac
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria
    rm -f /var/log/hysteria*.log
    green "Hysteria2 已成功卸载！"
    sleep 2
}

uninstall_anytls_go() {
    SERVICE_NAME="anytls-server"
    BINARY_PATH="/usr/local/bin/anytls-server"
    if [ ! -f "$BINARY_PATH" ]; then
        red "未找到 AnyTLS-Go 安装文件，可能未安装 AnyTLS-Go 服务！"
        sleep 2
        return
    fi
    yellow "开始卸载 AnyTLS-Go..."
    case "$OS_TYPE" in
        "alpine")
            service $SERVICE_NAME stop >/dev/null 2>&1
            rc-update del $SERVICE_NAME >/dev/null 2>&1
            rm -f /etc/init.d/$SERVICE_NAME
            ;;
        "ubuntu"|"debian"|"centos")
            systemctl stop $SERVICE_NAME >/dev/null 2>&1
            systemctl disable $SERVICE_NAME >/dev/null 2>&1
            rm -f /etc/systemd/system/${SERVICE_NAME}.service
            systemctl daemon-reload
            ;;
    esac
    rm -f $BINARY_PATH
    rm -f /var/log/anytls*.log
    green "AnyTLS-Go 已成功卸载！"
    sleep 2
}

# ============================== 显示客户端链接 ==============================
show_xray_links() {
    if [ ! -f "/usr/local/etc/xray/config.json" ]; then
        red "未找到 Xray 配置文件，请先安装 Xray！"
        sleep 2
        return
    fi

    PROTOCOL=$(grep -A10 'inbounds' /usr/local/etc/xray/config.json | grep '"protocol":' | head -1 | awk -F'"' '{print $4}')
    SERVER_IP=$(get_public_ip)

    case "$PROTOCOL" in
        "vmess"|"vless"|"trojan")
            DOMAIN=$(grep -A10 'tlsSettings' /usr/local/etc/xray/config.json | grep '"serverName":' | head -1 | awk -F'"' '{print $4}')
            WS_PATH=$(grep -A10 'wsSettings' /usr/local/etc/xray/config.json | grep '"path":' | head -1 | awk -F'"' '{print $4}')
            IN_PORT=$(grep '"port":' /usr/local/etc/xray/config.json | head -1 | awk '{print $2}' | tr -d ',')

            if [ -z "$DOMAIN" ]; then
                DOMAIN=$SERVER_IP
            fi

            case "$PROTOCOL" in
                "vmess")
                    UUID=$(grep -A10 'clients' /usr/local/etc/xray/config.json | grep '"id":' | head -1 | awk -F'"' '{print $4}')
                    VMESS_JSON=$(cat <<EOF
{
    "v": "2",
    "ps": "Xray_VMess",
    "add": "$DOMAIN",
    "port": "$IN_PORT",
    "id": "$UUID",
    "aid": "0",
    "scy": "auto",
    "net": "ws",
    "type": "none",
    "host": "$DOMAIN",
    "path": "$WS_PATH",
    "tls": "tls",
    "sni": "$DOMAIN"
}
EOF
                    )
                    VMESS_LINK="vmess://$(echo "$VMESS_JSON" | base64 -w 0)"
                    blue "\n=============== VMess 客户端链接 ================"
                    green "$VMESS_LINK"
                    ;;
                "trojan")
                    PASSWORD=$(grep -A10 '"protocol": "trojan"' /usr/local/etc/xray/config.json | grep -A5 '"clients"' | grep '"password"' | head -1 | awk -F'"' '{print $4}')
                    if [ -z "$PASSWORD" ]; then
                        PASSWORD=$(grep -A10 'trojan' /usr/local/etc/xray/config.json | grep '"password"' | head -1 | awk -F'"' '{print $4}')
                    fi
                    if [ -z "$PASSWORD" ]; then
                        red "无法提取Trojan密码，请检查配置文件"
                    else
                        TROJAN_LINK="trojan://${PASSWORD}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_Trojan"
                        blue "\n=============== Trojan 客户端链接 ================"
                        green "$TROJAN_LINK"
                    fi
                    ;;
                "vless")
                    UUID=$(grep -A10 'clients' /usr/local/etc/xray/config.json | grep '"id":' | head -1 | awk -F'"' '{print $4}')
                    if grep -q '"security": "reality"' /usr/local/etc/xray/config.json; then
                        DEST_SERVER=$(grep -A10 'realitySettings' /usr/local/etc/xray/config.json | grep 'dest' | awk -F'"' '{print $4}' | cut -d: -f1)
                        PRIVATE_KEY=$(grep -A10 'realitySettings' /usr/local/etc/xray/config.json | grep 'privateKey' | awk -F'"' '{print $4}')
                        
                        # 重新生成公钥用于显示（需要Xray存在）
                        if [[ -f "/usr/local/bin/xray" ]]; then
                            PUBLIC_KEY=$(/usr/local/bin/xray x25519 -i "$PRIVATE_KEY" 2>/dev/null | grep 'Public key' | awk -F ': ' '{print $2}')
                            if [[ -z "$PUBLIC_KEY" ]]; then
                                PUBLIC_KEY="无法获取公钥，请查看安装时的输出"
                            fi
                        else
                            PUBLIC_KEY="Xray二进制不存在，无法计算公钥"
                        fi
                        # 去除了短ID(&sid=)的分享链接
                        VLESS_LINK="vless://${UUID}@${SERVER_IP}:${IN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DEST_SERVER}&fp=chrome&pbk=${PUBLIC_KEY}&type=tcp&headerType=none&packetEncoding=xudp#Vless-Reality"
                        blue "\n=============== VLESS (Reality) 客户端链接 ================"
                        green "$VLESS_LINK"
                    else
                        VLESS_LINK="vless://${UUID}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_VLESS"
                        blue "\n=============== VLESS 客户端链接 ================"
                        green "$VLESS_LINK"
                    fi
                    ;;
            esac
            ;;
        "shadowsocks")
            IN_PORT=$(grep '"port":' /usr/local/etc/xray/config.json | head -1 | awk '{print $2}' | tr -d ',')
            METHOD=$(grep '"method":' /usr/local/etc/xray/config.json | awk -F'"' '{print $4}')
            PASSWORD=$(grep '"password":' /usr/local/etc/xray/config.json | awk -F'"' '{print $4}')
            SS_LINK="ss://$(echo -n "${METHOD}:${PASSWORD}" | base64 -w 0)@${SERVER_IP}:${IN_PORT}#Xray_Shadowsocks"
            blue "\n=============== Shadowsocks 客户端链接 ================"
            green "$SS_LINK"
            ;;
        "socks")
            IN_PORT=$(grep '"port":' /usr/local/etc/xray/config.json | head -1 | awk '{print $2}' | tr -d ',')
            SOCKS_USER=$(grep -A10 'socks' /usr/local/etc/xray/config.json | grep '"user":' | awk -F'"' '{print $4}')
            SOCKS_PASSWORD=$(grep -A10 'socks' /usr/local/etc/xray/config.json | grep '"pass":' | awk -F'"' '{print $4}')
            blue "\n=============== Socks5 客户端配置 ================"
            green "服务器地址: ${SERVER_IP}"
            green "端口: $IN_PORT"
            green "用户名: $SOCKS_USER"
            green "密码: $SOCKS_PASSWORD"
            green "UDP支持: 是"
            green "加密: 无（请确保在安全环境下使用）"
            blue "================================================\n"
            ;;
        *)
            red "未知协议类型: $PROTOCOL"
            ;;
    esac
    echo -e "${YELLOW}==============================================${NC}"
    read -p "按回车键返回..."
}

show_hysteria_links() {
    if [ ! -f "/etc/hysteria/config.yaml" ]; then
        red "未找到 Hysteria2 配置文件，请先安装 Hysteria2！"
        sleep 2
        return
    fi

    PORT=$(grep 'listen:' /etc/hysteria/config.yaml | awk '{print $2}' | tr -d ':')
    PASSWORD=$(grep 'password:' /etc/hysteria/config.yaml | awk '{print $2}')
    MASQUERADE_URL=$(grep 'url:' /etc/hysteria/config.yaml | awk '{print $2}')

    if grep -q 'acme:' /etc/hysteria/config.yaml; then
        TLS_TYPE=2
        DOMAIN=$(grep 'domains:' -A1 /etc/hysteria/config.yaml | tail -1 | awk '{print $2}' | tr -d '- ')
        LINK_SNI="$DOMAIN"
        LINK_INSECURE=0
    else
        TLS_TYPE=1
        CERT_PATH=$(grep 'cert:' /etc/hysteria/config.yaml | awk '{print $2}')
        if [ -f "$CERT_PATH" ]; then
            LINK_SNI=$(openssl x509 -noout -subject -in "$CERT_PATH" 2>/dev/null | grep -o 'CN=[^,]*' | cut -d= -f2 | tr -d ' ')
        fi
        LINK_SNI=${LINK_SNI:-"your_domain.com"}
        LINK_INSECURE=1
    fi

    SERVER_PUBLIC_ADDRESS=$(get_public_ip)
    if [ "$TLS_TYPE" -eq 2 ]; then
        LINK_ADDRESS="$DOMAIN"
    else
        LINK_ADDRESS="$SERVER_PUBLIC_ADDRESS"
    fi

    SUBSCRIPTION_LINK="hysteria2://${PASSWORD}@${LINK_ADDRESS}:${PORT}/?sni=${LINK_SNI}&insecure=${LINK_INSECURE}&alpn=h3#Hysteria-${LINK_SNI}"

    blue "\n=============== Hysteria2 客户端链接 ================"
    green "$SUBSCRIPTION_LINK"
    echo -e "${YELLOW}==============================================${NC}"
    read -p "按回车键返回..."
}

show_anytls_links() {
    SERVICE_NAME="anytls-server"
    BINARY_PATH="/usr/local/bin/anytls-server"
    if [ ! -f "$BINARY_PATH" ]; then
        red "未找到 AnyTLS-Go 安装文件，请先安装 AnyTLS-Go！"
        sleep 2
        return
    fi

    case "$OS_TYPE" in
        "alpine")
            PORT=$(grep 'command_args=' /etc/init.d/$SERVICE_NAME | grep -oE -- '-l :[0-9]+' | awk -F':' '{print $2}')
            PASSWORD=$(grep 'command_args=' /etc/init.d/$SERVICE_NAME | grep -oE -- '-p "[^"]+"' | awk -F'"' '{print $2}')
            ;;
        "ubuntu"|"debian"|"centos")
            PORT=$(grep 'ExecStart
