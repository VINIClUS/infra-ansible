#!/bin/sh
# Verifies a hot-plugged secondary NIC from inside the guest, run as:
#   pct exec <vmid> -- sh -s -- <iface> <cidr> <mtu> <probe> < guest-nic-probe.sh
# Prints one yes/no line per check and result=ok|fail, never an address.
iface=$1
cidr=$2
mtu=$3
probe=$4
fail=0
check() {
	if [ "$2" = yes ]; then echo "$1=yes"; else echo "$1=no"; fail=1; fi
}
present=no
[ -e "/sys/class/net/$iface" ] && present=yes
check iface_present "$present"

v4=$(ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}')
count=$(printf '%s\n' "$v4" | grep -c .)
r=no; [ "$count" = 1 ] && r=yes
check ipv4_count_one "$r"
r=no; [ "$v4" = "$cidr" ] && r=yes
check ipv4_expected "$r"

r=no; [ "$present" = yes ] && [ "$(cat "/sys/class/net/$iface/mtu")" = "$mtu" ] && r=yes
check mtu_expected "$r"

defaults=$(ip -4 route show default | grep -c .)
r=no; [ "$defaults" = 1 ] && r=yes
check one_default_route "$r"
r=no; ip -4 route show default | grep -q " dev $iface\( \|$\)" || r=yes
check default_route_elsewhere "$r"

r=no
ping -c 2 -W 1 -M do -s $((mtu - 28)) -I "$iface" "$probe" >/dev/null 2>&1 && r=yes
check full_size_frame "$r"

if [ "$fail" = 0 ]; then echo result=ok; else echo result=fail; fi
