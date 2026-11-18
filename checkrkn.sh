#!/bin/bash
set -u

NAME=checkrkn
DIR=/etc/$NAME
BIN=/usr/local/sbin/$NAME
TABLE=$NAME
[ -f "$DIR/config" ] && . "$DIR/config"
LIST_KIND="${CHECKRKN_LIST:-full}"
[ "$LIST_KIND" = "safe" ] && LIST_FILE=blocklist-safe.txt || LIST_FILE=blocklist.txt
LIST_URL="${CHECKRKN_URL:-https://raw.githubusercontent.com/Risaro/checkrkn/main/lists/$LIST_FILE}"
SELF_URL="${CHECKRKN_SELF:-https://raw.githubusercontent.com/Risaro/checkrkn/main/checkrkn.sh}"
MIN_ENTRIES=1000
MAX_ENTRIES=300000
MIN_PREFIX4=12
MIN_PREFIX6=24
AUTOBAN="${CHECKRKN_AUTOBAN:-1}"
BAN_TIME="${CHECKRKN_BAN_TIME:-24h}"
SCAN_PORTS="${CHECKRKN_SCAN_PORTS:-4}"
HONEYPOT="${CHECKRKN_HONEYPOT:-1}"
HONEY_PORTS="${CHECKRKN_HONEY_PORTS:-21,23,135,139,445,1433,1521,2323,2375,3306,3389,5432,5555,5900,6379,7547,8291,9200,11211,27017,37777}"
HONEY_KEEP="${CHECKRKN_HONEY_KEEP:-7d}"

G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'
log()  { echo "$(date '+%F %T') $*"; }
ok()   { echo -e "${G}$*${N}"; }
warn() { echo -e "${Y}$*${N}"; }
err()  { echo -e "${R}$*${N}"; }

need_root() { [ "$(id -u)" -eq 0 ] || { err "Запустите от root."; exit 1; }; }

apt_install() {
    DEBIAN_FRONTEND=noninteractive apt-get -qq update >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$@" >/dev/null 2>&1
}

ensure_deps() {
    local miss=()
    command -v nft >/dev/null || miss+=(nftables)
    command -v curl >/dev/null || miss+=(curl)
    command -v python3 >/dev/null || miss+=(python3)
    [ ${#miss[@]} -gt 0 ] && apt_install "${miss[@]}"
    command -v nft >/dev/null || { err "nft недоступен, установка прервана."; exit 1; }
}

normalize() {
    awk -v m4="$MIN_PREFIX4" -v m6="$MIN_PREFIX6" -v o4="$2" -v o6="$3" '
    {
        sub(/#.*/, ""); gsub(/[ \t\r]/, "")
        if ($0 == "") next
        s = $0; p = ""
        i = index(s, "/")
        if (i) { p = substr(s, i + 1); s = substr(s, 1, i - 1); if (p !~ /^[0-9]+$/) next }
        if (s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
            n = split(s, a, "."); for (k = 1; k <= n; k++) if (a[k] + 0 > 255) next
            if (p == "") p = 32
            if (p + 0 < m4 || p + 0 > 32) next
            print s "/" p > o4
        } else if (s ~ /^[0-9a-fA-F:]+$/ && s ~ /:.*:/) {
            if (p == "") p = 128
            if (p + 0 < m6 || p + 0 > 128) next
            print s "/" p > o6
        }
    }' "$1"
}

overlap_check() {
    python3 - "$1" "$2" <<'PY'
import ipaddress, sys
block = [ipaddress.ip_network(l.strip(), strict=False) for l in open(sys.argv[1]) if l.strip()]
allow = [ipaddress.ip_network(l.strip(), strict=False) for l in open(sys.argv[2]) if l.strip()]
bad = [f"{b} пересекается с {a}" for b in block for a in allow if b.version == a.version and b.overlaps(a)]
print("\n".join(bad[:20]))
sys.exit(1 if bad else 0)
PY
}

render() {
    local b4="$1" b6="$2" a4="$3" a6="$4" out="$5"
    {
        echo "table inet $TABLE {}"
        echo "delete table inet $TABLE"
        echo "table inet $TABLE {"
        echo "  set allow4 { type ipv4_addr; flags interval; auto-merge; }"
        echo "  set allow6 { type ipv6_addr; flags interval; auto-merge; }"
        echo "  set block4 { type ipv4_addr; flags interval; auto-merge; }"
        echo "  set block6 { type ipv6_addr; flags interval; auto-merge; }"
        echo "  set autoban4 { type ipv4_addr; flags dynamic,timeout; timeout $BAN_TIME; size 262144; }"
        echo "  set autoban6 { type ipv6_addr; flags dynamic,timeout; timeout $BAN_TIME; size 262144; }"
        echo "  set seen4 { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 2m; size 524288; }"
        echo "  set seen6 { type ipv6_addr . inet_service; flags dynamic,timeout; timeout 2m; size 524288; }"
        echo "  set rate4 { type ipv4_addr; flags dynamic,timeout; timeout 2m; size 262144; }"
        echo "  set rate6 { type ipv6_addr; flags dynamic,timeout; timeout 2m; size 262144; }"
        echo "  set openports { type inet_service; flags interval; auto-merge; }"
        echo "  set honeyports { type inet_service; flags interval; auto-merge; }"
        echo "  set honey4 { type ipv4_addr; flags dynamic,timeout; timeout $HONEY_KEEP; size 262144; }"
        echo "  set honey6 { type ipv6_addr; flags dynamic,timeout; timeout $HONEY_KEEP; size 262144; }"
        echo "  counter honeypot {}"
        echo "  counter dropped4 {}"
        echo "  counter dropped6 {}"
        echo "  counter autobanned {}"
        echo "  counter autoban_drops {}"
        echo "  chain pre {"
        echo "    type filter hook prerouting priority raw - 10; policy accept;"
        echo "    ip saddr @allow4 accept"
        echo "    ip6 saddr @allow6 accept"
        echo "    ip saddr @autoban4 tcp flags & (fin | syn | rst | ack) == syn counter name autoban_drops drop"
        echo "    ip6 saddr @autoban6 tcp flags & (fin | syn | rst | ack) == syn counter name autoban_drops drop"
        echo "    ip saddr @block4 tcp flags & (fin | syn | rst | ack) == syn counter name dropped4 drop"
        echo "    ip6 saddr @block6 tcp flags & (fin | syn | rst | ack) == syn counter name dropped6 drop"
        if [ "$HONEYPOT" = "1" ] && [ "$6" -gt 0 ]; then
            echo "    tcp flags & (fin | syn | rst | ack) == syn fib daddr type local tcp dport @honeyports tcp dport != @openports add @honey4 { ip saddr } add @autoban4 { ip saddr } counter name honeypot drop"
            echo "    tcp flags & (fin | syn | rst | ack) == syn fib daddr type local tcp dport @honeyports tcp dport != @openports add @honey6 { ip6 saddr } add @autoban6 { ip6 saddr } counter name honeypot drop"
        fi
        if [ "$AUTOBAN" = "1" ] && [ "$6" -gt 0 ]; then
            echo "    tcp flags & (fin | syn | rst | ack) == syn fib daddr type local tcp dport != @openports ip saddr . tcp dport != @seen4 add @seen4 { ip saddr . tcp dport } add @rate4 { ip saddr limit rate over $SCAN_PORTS/minute burst $SCAN_PORTS packets } add @autoban4 { ip saddr } counter name autobanned drop"
            echo "    tcp flags & (fin | syn | rst | ack) == syn fib daddr type local tcp dport != @openports ip6 saddr . tcp dport != @seen6 add @seen6 { ip6 saddr . tcp dport } add @rate6 { ip6 saddr limit rate over $SCAN_PORTS/minute burst $SCAN_PORTS packets } add @autoban6 { ip6 saddr } counter name autobanned drop"
        fi
        echo "  }"
        for hook in input forward; do
            echo "  chain $hook {"
            echo "    type filter hook $hook priority filter - 20; policy accept;"
            echo "    ip saddr @allow4 accept"
            echo "    ip6 saddr @allow6 accept"
            echo "    meta l4proto != tcp ip saddr @autoban4 ct state new counter name autoban_drops drop"
            echo "    meta l4proto != tcp ip6 saddr @autoban6 ct state new counter name autoban_drops drop"
            echo "    meta l4proto != tcp ip saddr @block4 ct state new counter name dropped4 drop"
            echo "    meta l4proto != tcp ip6 saddr @block6 ct state new counter name dropped6 drop"
            echo "  }"
        done
        echo "}"
        [ -s "$7" ] && echo "add element inet $TABLE openports { $(paste -sd, "$7") }"
        [ -s "$8" ] && echo "add element inet $TABLE autoban4 { $(paste -sd, "$8") }"
        [ -s "$9" ] && echo "add element inet $TABLE autoban6 { $(paste -sd, "$9") }"
        [ -n "$HONEY_PORTS" ] && echo "add element inet $TABLE honeyports { $HONEY_PORTS }"
        [ -s "${10}" ] && echo "add element inet $TABLE honey4 { $(paste -sd, "${10}") }"
        [ -s "${11}" ] && echo "add element inet $TABLE honey6 { $(paste -sd, "${11}") }"
        for pair in "allow4:$a4" "allow6:$a6" "block4:$b4" "block6:$b6"; do
            local set="${pair%%:*}" file="${pair#*:}"
            [ -s "$file" ] || continue
            split -l 2000 "$file" "$file.chunk."
            for c in "$file".chunk.*; do
                echo "add element inet $TABLE $set { $(paste -sd, "$c") }"
            done
            rm -f "$file".chunk.*
        done
    } > "$out"
}

apply_in() {
    local src="$1" tmp="$2" n4 n6 ov
    normalize "$src" "$tmp/b4" "$tmp/b6"; : >> "$tmp/b4"; : >> "$tmp/b6"
    if [ -s "$DIR/allow.txt" ]; then normalize "$DIR/allow.txt" "$tmp/a4" "$tmp/a6"; fi
    : >> "$tmp/a4"; : >> "$tmp/a6"
    n4=$(wc -l < "$tmp/b4"); n6=$(wc -l < "$tmp/b6")
    if [ $((n4 + n6)) -lt "$MIN_ENTRIES" ] || [ $((n4 + n6)) -gt "$MAX_ENTRIES" ]; then
        log "[ERROR] размер списка v4=$n4 v6=$n6 вне $MIN_ENTRIES..$MAX_ENTRIES, не применён"; return 1
    fi
    cat "$tmp/b4" "$tmp/b6" > "$tmp/all"; cat "$tmp/a4" "$tmp/a6" > "$tmp/allow"
    if ! ov=$(overlap_check "$tmp/all" "$tmp/allow"); then
        log "[ERROR] список задевает адреса из $DIR/allow.txt, не применён:"; echo "$ov"; return 1
    fi
    open_ports > "$tmp/ports"
    keep_bans autoban4 > "$tmp/ban4"; keep_bans autoban6 > "$tmp/ban6"
    keep_bans honey4 > "$tmp/hon4"; keep_bans honey6 > "$tmp/hon6"
    render "$tmp/b4" "$tmp/b6" "$tmp/a4" "$tmp/a6" "$tmp/rules.nft" "$(wc -l < "$tmp/ports")" "$tmp/ports" "$tmp/ban4" "$tmp/ban6" "$tmp/hon4" "$tmp/hon6"
    nft -c -f "$tmp/rules.nft" || { log "[ERROR] проверка nft не прошла, не применён"; return 1; }
    nft -f "$tmp/rules.nft" || { log "[ERROR] не удалось применить правила"; return 1; }
    log "[OK] применено: v4=$n4 v6=$n6"
}

open_ports() {
    {
        ss -Hltn 2>/dev/null | awk '{print $4}' | sed 's/.*://'
        iptables -t nat -S 2>/dev/null | grep -o -- '--dport [0-9:]*' | awk '{print $2}' | tr ':' '-'
        [ -s "$DIR/ports.txt" ] && grep -oE '^[0-9]+(-[0-9]+)?' "$DIR/ports.txt"
    } | grep -E '^[0-9]+(-[0-9]+)?$' | sort -u
}

keep_bans() {
    nft -j list set inet "$TABLE" "$1" 2>/dev/null | python3 -c '
import json, sys
for x in json.load(sys.stdin)["nftables"]:
    for e in x.get("set", {}).get("elem", []) or []:
        v = e["elem"]["val"] if isinstance(e, dict) and "elem" in e else e
        if isinstance(v, str):
            print(v)' 2>/dev/null
}

cmd_ports() {
    nft list table inet "$TABLE" >/dev/null 2>&1 || return 0
    local p; p=$(open_ports | paste -sd,)
    [ -n "$p" ] || return 0
    printf 'flush set inet %s openports\nadd element inet %s openports { %s }\n' "$TABLE" "$TABLE" "$p" | nft -f -
}

apply_from() {
    local tmp rc
    tmp=$(mktemp -d)
    apply_in "$1" "$tmp"; rc=$?
    rm -rf "$tmp"
    return $rc
}

cmd_update() {
    local tmp; tmp=$(mktemp)
    if curl -fsSL --max-time 30 "$LIST_URL" -o "$tmp" && [ -s "$tmp" ]; then
        if apply_from "$tmp"; then cp "$tmp" "$DIR/list.txt"; rm -f "$tmp"; return 0; fi
        log "[WARN] новый список отклонён, оставляю последний рабочий"
    else
        log "[WARN] список не скачался, оставляю последний рабочий"
    fi
    rm -f "$tmp"
    [ -s "$DIR/list.txt" ] && apply_from "$DIR/list.txt"
}

cmd_boot() {
    if [ -s "$DIR/list.txt" ]; then apply_from "$DIR/list.txt"; else cmd_update; fi
}

set_size() {
    nft -j list set inet "$TABLE" "$1" 2>/dev/null | python3 -c 'import json,sys;d=json.load(sys.stdin)["nftables"];print(sum(len(x["set"].get("elem",[])) for x in d if "set" in x))' 2>/dev/null
}

cmd_status() {
    if ! nft list table inet "$TABLE" >/dev/null 2>&1; then warn "Не активен."; return 1; fi
    echo "Блок IPv4: $(set_size block4) диапазонов, IPv6: $(set_size block6)"
    echo "Белый список IPv4: $(set_size allow4), IPv6: $(set_size allow6)"
    echo "Автобан сейчас: IPv4 $(set_size autoban4), IPv6 $(set_size autoban6)"
    echo "Попались в ловушку за $HONEY_KEEP: IPv4 $(set_size honey4), IPv6 $(set_size honey6)"
    echo "Открытые порты: $(nft list set inet "$TABLE" openports 2>/dev/null | tr -d '\n\t' | grep -o 'elements = {[^}]*' | sed 's/elements = { //' | cut -c1-150)"
    nft list counters table inet "$TABLE" 2>/dev/null | awk '/counter/{n=$2} /packets/{print "Отброшено " n ": " $2 " пакетов, " $4 " байт"}'
    [ -s "$DIR/list.txt" ] && echo "Последний рабочий список: $(stat -c %y "$DIR/list.txt" | cut -d. -f1)"
    systemctl list-timers "$NAME-update.timer" --no-pager 2>/dev/null | sed -n 2p
}

install_self() {
    if [ -f "$0" ] && [ "$(readlink -f "$0")" != "$BIN" ] && head -1 "$0" 2>/dev/null | grep -q '^#!/bin/bash'; then
        install -m 755 "$0" "$BIN"
    elif [ "$(readlink -f "$0" 2>/dev/null)" != "$BIN" ]; then
        curl -fsSL --max-time 30 "$SELF_URL" -o "$BIN.new" && bash -n "$BIN.new" && install -m 755 "$BIN.new" "$BIN"
        rm -f "$BIN.new"
    fi
    [ -x "$BIN" ] || { err "Не удалось установить $BIN"; exit 1; }
}

cmd_install() {
    need_root; ensure_deps
    mkdir -p "$DIR"; [ -f "$DIR/allow.txt" ] || : > "$DIR/allow.txt"
    install_self
    {
        echo "CHECKRKN_LIST=\"$LIST_KIND\""
        echo "CHECKRKN_AUTOBAN=\"$AUTOBAN\""
        echo "CHECKRKN_BAN_TIME=\"$BAN_TIME\""
        echo "CHECKRKN_SCAN_PORTS=\"$SCAN_PORTS\""
        echo "CHECKRKN_HONEYPOT=\"$HONEYPOT\""
        echo "CHECKRKN_HONEY_PORTS=\"$HONEY_PORTS\""
        [ -n "${CHECKRKN_URL:-}" ] && echo "CHECKRKN_URL=\"$CHECKRKN_URL\""
    } > "$DIR/config"
    cat > /etc/systemd/system/$NAME.service <<EOF
[Unit]
Description=$NAME blocklist
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN boot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/$NAME-update.service <<EOF
[Unit]
Description=$NAME list update

[Service]
Type=oneshot
ExecStart=$BIN update
EOF
    cat > /etc/systemd/system/$NAME-ports.service <<UNIT
[Unit]
Description=$NAME refresh open ports

[Service]
Type=oneshot
ExecStart=$BIN ports
UNIT
    cat > /etc/systemd/system/$NAME-ports.timer <<UNIT
[Unit]
Description=$NAME refresh open ports every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
UNIT
    cat > /etc/systemd/system/$NAME-update.timer <<EOF
[Unit]
Description=$NAME list update every 6h

[Timer]
OnCalendar=*-*-* 00/6:30:00
RandomizedDelaySec=45m
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable -q "$NAME.service" "$NAME-update.timer" "$NAME-ports.timer"
    systemctl start "$NAME-update.timer" "$NAME-ports.timer"
    if cmd_update; then ok "$NAME установлен."; cmd_status; else err "Список не применён, смотрите сообщения выше."; exit 1; fi
}

cmd_uninstall() {
    need_root
    systemctl disable --now -q "$NAME.service" "$NAME-update.timer" "$NAME-ports.timer" 2>/dev/null
    rm -f /etc/systemd/system/$NAME.service /etc/systemd/system/$NAME-update.service /etc/systemd/system/$NAME-update.timer /etc/systemd/system/$NAME-ports.service /etc/systemd/system/$NAME-ports.timer "$BIN"
    systemctl daemon-reload
    nft delete table inet "$TABLE" 2>/dev/null
    ok "$NAME удалён (настройки в $DIR сохранены)."
}

case "${1:-install}" in
    install)   cmd_install ;;
    update)    need_root; mkdir -p "$DIR"; cmd_update ;;
    boot)      need_root; mkdir -p "$DIR"; cmd_boot ;;
    status)    cmd_status ;;
    ports)     need_root; cmd_ports ;;
    trapped)   keep_bans honey4; keep_bans honey6 ;;
    unban)     need_root; nft delete element inet "$TABLE" autoban4 "{ ${2:?ip} }" 2>/dev/null || nft delete element inet "$TABLE" autoban6 "{ ${2:?ip} }" ;;
    uninstall) cmd_uninstall ;;
    *) echo "Использование: $NAME [install|update|status|ports|trapped|unban IP|uninstall]"; exit 1 ;;
esac
