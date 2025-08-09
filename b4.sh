#! /bin/sh

B4_SHARE_DIR="/opt/etc/share/b4"

B4_LATEST_RELEASE_URL="https://github.com/DanielLavrushin/asuswrt-merlin-xrayui/releases/latest/download/"

install() {
    mkdir -p $B4_SHARE_DIR

    local arch=$(uname -m)

    local asset_name=""
    case "$arch" in
    x86_64)
        asset_name="b4-linux-64.zip"
        ;;
    i686 | i386)
        asset_name="b4-linux-386.zip"
        ;;
    armv5* | armv6* | armv7*)
        asset_name="b4-linux-arm5.zip"
        ;;
    aarch64 | arm64)
        asset_name="b4-linux-arm64.zip"
        ;;
    mips)
        asset_name="b4-linux-mips.zip"
        ;;
    mipsle)
        asset_name="b4-linux-mipsle.zip"
        ;;
    mips64)
        asset_name="b4-linux-mips64.zip"
        ;;
    mips64le)
        asset_name="b4-linux-mips64le.zip"
        ;;
    *)
        echo "Unsupported architecture: $arch"
        return 1
        ;;
    esac

    local tmp_zip="/tmp/b4.zip"
    rm -rf "$tmp_zip"

    local asset_url="$B4_LATEST_RELEASE_URL$asset_name"
    curl -L "$asset_url" -o "$tmp_zip"
    unzip -o "$tmp_zip" -d "$B4_SHARE_DIR"
}

firewall_start_v6() {
    if [ $IPV6 -eq 0 ]; then
        return 0
    fi

    ip6tables -t mangle -N B4 >/dev/null 2>&1
    _iptables ip6tables -A B4 -t mangle -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables ip6tables -A B4 -t mangle -p udp -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:8 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables ip6tables -A POSTROUTING -t mangle -j B4
    _iptables ip6tables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
}

firewall_stop_v6() {
    if [ $IPV6 -eq 0 ]; then
        return 0
    fi

    _iptables ip6tables -D B4 -t mangle -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables ip6tables -D B4 -t mangle -p udp -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:8 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables ip6tables -D POSTROUTING -t mangle -j B4
    _iptables ip6tables -D OUTPUT -m mark --mark 32768/32768 -j ACCEPT
    ip6tables -t mangle -X B4 >/dev/null 2>&1
}

firewall_start_v4() {
    iptables -t mangle -N B4 >/dev/null 2>&1
    _iptables iptables -A B4 -t mangle -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables iptables -A B4 -t mangle -p udp -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:8 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables iptables -A POSTROUTING -t mangle -j B4
    _iptables iptables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
}

firewall_stop_v4() {
    _iptables iptables -D B4 -t mangle -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables iptables -D B4 -t mangle -p udp -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:8 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables iptables -D POSTROUTING -t mangle -j B4
    _iptables iptables -D OUTPUT -m mark --mark 32768/32768 -j ACCEPT
    iptables -t mangle -X B4 >/dev/null 2>&1
}
