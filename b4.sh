#! /bin/sh
ENABLED=yes
PROCS=b4
PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ARGS="--threads 4 --sni-domains-file ./domains.txt"
B4_SHARE_DIR="/opt/share/b4"
B4_LATEST_RELEASE_URL="https://github.com/daniellavrushin/b4/releases/latest/download/"
IPV6="${IPV6:-0}"

install() {
    echo "Installing B4..."
    mkdir -p $B4_SHARE_DIR
    local arch=$(uname -m)
    local asset_name=""
    case "$arch" in
    x86_64) asset_name="b4-linux-64.tar.gz" ;;
    i686 | i386) asset_name="b4-linux-386.tar.gz" ;;
    armv5* | armv6* | armv7*) asset_name="b4-linux-arm5.tar.gz" ;;
    aarch64 | arm64) asset_name="b4-linux-arm64.tar.gz" ;;
    mips) asset_name="b4-linux-mips.tar.gz" ;;
    mipsle) asset_name="b4-linux-mipsle.tar.gz" ;;
    mips64) asset_name="b4-linux-mips64.tar.gz" ;;
    mips64le) asset_name="b4-linux-mips64le.tar.gz" ;;
    *)
        echo "Unsupported architecture: $arch"
        return 1
        ;;
    esac
    local tmp_zip="/tmp/b4.tar.gz"
    rm -rf "$tmp_zip"
    if [ $IPV6 -eq 0 ]; then
        ARGS="$ARGS --no-ipv6"
    fi
    local asset_url="$B4_LATEST_RELEASE_URL$asset_name"
    echo "Downloading $asset_url..."
    curl -L "$asset_url" -o "$tmp_zip"
    tar -xzf "$tmp_zip" -C "$B4_SHARE_DIR"
    rm -f "$tmp_zip"
    chmod +x "$B4_SHARE_DIR/b4"
}

start() {
    echo "Starting B4..."
    "$B4_SHARE_DIR/b4" $ARGS >/dev/null 2>&1 &
    firewall_start_v4
    firewall_start_v6
    system_config
}

stop() {
    echo "Stopping B4..."
    firewall_stop_v4
    firewall_stop_v6
    killall $PROCS 2>/dev/null
}

restart() {
    stop
    start
}

firewall_start_v4() {
    iptables -t mangle -N B4 >/dev/null 2>&1
    iptables -t mangle -F B4 >/dev/null 2>&1
    iptables -t mangle -A B4 -m connmark --mark 32768/32768 -j RETURN
    iptables -t mangle -A B4 -p udp --dport 443 -m length --length 0:1199 -j RETURN
    iptables -t mangle -A B4 -p tcp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
    iptables -t mangle -A B4 -p udp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
    iptables -t mangle -A B4 -j CONNMARK --save-mark
    iptables -t mangle -A B4 -m mark --mark 32768/32768 -j RETURN
    iptables -t mangle -C PREROUTING -j B4 2>/dev/null || iptables -t mangle -I PREROUTING -j B4
    iptables -C OUTPUT -m mark --mark 32768/32768 -j ACCEPT 2>/dev/null || iptables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
}

firewall_start_v6() {
    if [ $IPV6 -eq 0 ]; then
        return 0
    fi
    ip6tables -t mangle -N B4 >/dev/null 2>&1
    ip6tables -t mangle -F B4 >/dev/null 2>&1
    ip6tables -t mangle -A B4 -m connmark --mark 32768/32768 -j RETURN
    ip6tables -t mangle -A B4 -p udp --dport 443 -m length --length 0:1199 -j RETURN
    ip6tables -t mangle -A B4 -p tcp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
    ip6tables -t mangle -A B4 -p udp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
    ip6tables -t mangle -A B4 -j CONNMARK --save-mark
    ip6tables -t mangle -A B4 -m mark --mark 32768/32768 -j RETURN
    ip6tables -t mangle -C PREROUTING -j B4 2>/dev/null || ip6tables -t mangle -I PREROUTING -j B4
    ip6tables -C OUTPUT -m mark --mark 32768/32768 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
}

firewall_stop_v4() {
    _iptables iptables -D B4 -t mangle -m connmark --mark 32768/32768 -j RETURN
    _iptables iptables -D B4 -t mangle -p udp --dport 443 -m length --length 0:1199 -j RETURN
    _iptables iptables -D B4 -t mangle -p tcp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables iptables -D B4 -t mangle -p udp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables iptables -D B4 -t mangle -j CONNMARK --save-mark
    _iptables iptables -D B4 -t mangle -m mark --mark 32768/32768 -j RETURN
    iptables -t mangle -C PREROUTING -j B4 2>/dev/null && iptables -t mangle -D PREROUTING -j B4
    _iptables iptables -D OUTPUT -m mark --mark 32768/32768 -j ACCEPT
    iptables -t mangle -F B4 >/dev/null 2>&1
    iptables -t mangle -X B4 >/dev/null 2>&1
}

firewall_stop_v6() {
    if [ $IPV6 -eq 0 ]; then
        return 0
    fi
    _iptables ip6tables -D B4 -t mangle -m connmark --mark 32768/32768 -j RETURN
    _iptables ip6tables -D B4 -t mangle -p udp --dport 443 -m length --length 0:1199 -j RETURN
    _iptables ip6tables -D B4 -t mangle -p tcp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables ip6tables -D B4 -t mangle -p udp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
    _iptables ip6tables -D B4 -t mangle -j CONNMARK --save-mark
    _iptables ip6tables -D B4 -t mangle -m mark --mark 32768/32768 -j RETURN
    ip6tables -t mangle -C PREROUTING -j B4 2>/dev/null && ip6tables -t mangle -D PREROUTING -j B4
    _iptables ip6tables -D OUTPUT -m mark --mark 32768/32768 -j ACCEPT
    ip6tables -t mangle -F B4 >/dev/null 2>&1
    ip6tables -t mangle -X B4 >/dev/null 2>&1
}

_iptables() {
    ARG="$@"
    CMD=$1
    ACTION=$2
    shift
    shift
    RULE="$@"
    $CMD -C $RULE 2>/dev/null
    exists=$((!$?))
    if [ "$ACTION" = "-A" -o "$ACTION" = "-I" ]; then
        [ $exists -eq 0 ] && $ARG || true
    else
        [ $exists -ne 0 ] && $ARG || true
    fi
}

system_config() {
    sysctl -w net.netfilter.nf_conntrack_checksum=0 >/dev/null 2>&1
    sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1
}

case "$1" in
install) install ;;
start) start ;;
stop) stop ;;
restart) restart ;;
firewall_start)
    firewall_start_v4
    firewall_start_v6
    ;;
firewall_stop)
    firewall_stop_v4
    firewall_stop_v6
    ;;
*)
    echo "Usage: $0 {start|stop}"
    exit 1
    ;;
esac
