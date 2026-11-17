#!/bin/bash
set -u

NAME=checkrkn
DIR=/etc/$NAME
BIN=/usr/local/sbin/$NAME
TABLE=$NAME
LIST_URL="${CHECKRKN_URL:-https://gist.githubusercontent.com/Risaro/99e65e4285454bc07a746f5b54e4160f/raw/blacklist.txt}"
SELF_URL="${CHECKRKN_SELF:-https://raw.githubusercontent.com/Risaro/checkrkn/main/checkrkn.sh}"
MIN_ENTRIES=100
MAX_ENTRIES=50000
MIN_PREFIX4=16
MIN_PREFIX6=32

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
        echo "  counter dropped4 {}"
        echo "  counter dropped6 {}"
        echo "  chain pre {"
        echo "    type filter hook prerouting priority raw - 10; policy accept;"
        echo "    ip saddr @allow4 accept"
        echo "    ip6 saddr @allow6 accept"
        echo "    ip saddr @block4 counter name dropped4 drop"
        echo "    ip6 saddr @block6 counter name dropped6 drop"
        echo "  }"
        echo "}"
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
    render "$tmp/b4" "$tmp/b6" "$tmp/a4" "$tmp/a6" "$tmp/rules.nft"
    nft -c -f "$tmp/rules.nft" || { log "[ERROR] проверка nft не прошла, не применён"; return 1; }
    nft -f "$tmp/rules.nft" || { log "[ERROR] не удалось применить правила"; return 1; }
    log "[OK] применено: v4=$n4 v6=$n6"
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
    cat > /etc/systemd/system/$NAME-update.timer <<EOF
[Unit]
Description=$NAME daily update

[Timer]
OnCalendar=*-*-* 03:20:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable -q "$NAME.service" "$NAME-update.timer"
    systemctl start "$NAME-update.timer"
    if cmd_update; then ok "$NAME установлен."; cmd_status; else err "Список не применён, смотрите сообщения выше."; exit 1; fi
}

cmd_uninstall() {
    need_root
    systemctl disable --now -q "$NAME.service" "$NAME-update.timer" 2>/dev/null
    rm -f /etc/systemd/system/$NAME.service /etc/systemd/system/$NAME-update.service /etc/systemd/system/$NAME-update.timer "$BIN"
    systemctl daemon-reload
    nft delete table inet "$TABLE" 2>/dev/null
    ok "$NAME удалён (настройки в $DIR сохранены)."
}

case "${1:-install}" in
    install)   cmd_install ;;
    update)    need_root; mkdir -p "$DIR"; cmd_update ;;
    boot)      need_root; mkdir -p "$DIR"; cmd_boot ;;
    status)    cmd_status ;;
    uninstall) cmd_uninstall ;;
    *) echo "Использование: $NAME [install|update|status|uninstall]"; exit 1 ;;
esac
