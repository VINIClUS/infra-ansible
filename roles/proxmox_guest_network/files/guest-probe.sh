#!/bin/sh
# Guest-side network probe, run as: pct exec <vmid> -- sh -s -- <args> < guest-probe.sh
# Args: cidr gateway mtu nameserver|- mac dns-name https-url [systemd-unit...]
# Prints one key=yes|no line per check and a final result=ok|fail. It never
# prints addresses, so the output can be logged as-is.
set -u
cidr=$1 gw=$2 mtu=$3 ns=$4 mac=$5 dns_name=$6 url=$7
shift 7
failed=0

check() {
	name=$1
	shift
	if "$@" >/dev/null 2>&1; then
		echo "$name=yes"
	else
		echo "$name=no"
		failed=1
	fi
}

v4=$(ip -4 -o addr show dev eth0 2>/dev/null | awk '{print $4}')
count=$(printf '%s\n' "$v4" | grep -c .)
echo "ipv4_count=$count"
[ "$count" -eq 1 ] || failed=1
check ipv4_expected sh -c 'printf "%s\n" "$1" | grep -qxF "$2"' _ "$v4" "$cidr"
check no_global_ipv6 sh -c '! ip -6 -o addr show scope global | grep -q .'
check mtu_expected sh -c '[ "$(cat /sys/class/net/eth0/mtu)" = "$1" ]' _ "$mtu"
check mac_unchanged sh -c '[ "$(cat /sys/class/net/eth0/address)" = "$1" ]' _ "$mac"
check default_route sh -c 'ip -4 route show default | awk -v gw="$1" '\''$1 == "default" && $2 == "via" && $3 == gw && $4 == "dev" && $5 == "eth0" { found = 1 } END { exit !found }'\''' _ "$gw"
check gateway_ping ping -c 2 -W 2 "$gw"
check full_size_frame ping -c 1 -W 2 -M do -s $((mtu - 28)) "$gw"
if [ "$ns" != "-" ]; then
	check resolver_expected sh -c 'awk '\''$1 == "nameserver" { print $2; exit }'\'' /etc/resolv.conf | grep -qxF "$1"' _ "$ns"
fi
check dns_lookup getent hosts "$dns_name"
if command -v curl >/dev/null 2>&1; then
	check https_reachable curl -fsS -o /dev/null --max-time 15 "$url"
else
	check https_reachable wget -q -O /dev/null -T 15 "$url"
fi
for unit in "$@"; do
	check "unit_active[$unit]" systemctl is-active --quiet "$unit"
done

if [ "$failed" -eq 0 ]; then echo result=ok; else echo result=fail; fi
