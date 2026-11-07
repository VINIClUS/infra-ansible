#!/bin/sh
# Read-only per-node SDN check, streamed over stdin (sh -s -- ...).
# Usage: <pre|post> <node-address> <vxlan-port> [<vnet>:<tag>:<mtu> ...]
# Prints key=value facts and one PROBLEM line per failure; exit 1 on problems.
mode=$1
addr=$2
port=$3
shift 3
fail=0
problem() {
	echo "PROBLEM $*"
	fail=1
}

grep -qxF 'source /etc/network/interfaces.d/*' /etc/network/interfaces ||
	problem "/etc/network/interfaces does not source /etc/network/interfaces.d/*"
[ -e /etc/network/interfaces.new ] && problem "pending /etc/network/interfaces.new"
ifquery --check -a >/dev/null 2>&1 || problem "ifquery --check -a reports drift"
ip -4 -o addr show | grep -q " inet $addr/" || problem "node address $addr is missing"
echo "default_route=$(ip -4 route show default | head -n 1 | tr -s ' ')"
pve-firewall status 2>/dev/null | grep -q 'enabled/running' ||
	problem "host firewall is not enabled/running (VXLAN guard inactive)"
iptables -S PVEFW-HOST-IN 2>/dev/null |
	grep -qE -- "--match-set [^ ]+ src -m udp --dport $port -j RETURN" ||
	problem "PVEFW-HOST-IN has no IPset-restricted UDP $port rule"

if [ "$mode" = post ]; then
	for spec in "$@"; do
		vnet=${spec%%:*}
		rest=${spec#*:}
		tag=${rest%%:*}
		mtu=${rest#*:}
		grep -qx "auto $vnet" /etc/network/interfaces.d/sdn 2>/dev/null ||
			problem "$vnet is missing from /etc/network/interfaces.d/sdn"
		bridge=$(ip -d link show "$vnet" 2>/dev/null) || {
			problem "bridge $vnet is absent"
			continue
		}
		echo "$bridge" | grep -q " mtu $mtu " || problem "bridge $vnet mtu is not $mtu"
		vx=$(ip -d link show "vxlan_$vnet" 2>/dev/null) || {
			problem "vxlan_$vnet is absent"
			continue
		}
		echo "$vx" | grep -q "vxlan id $tag " || problem "vxlan_$vnet id is not $tag"
		echo "$vx" | grep -q "dstport $port " || problem "vxlan_$vnet dstport is not $port"
		echo "$vx" | grep -q " mtu $mtu " || problem "vxlan_$vnet mtu is not $mtu"
		echo "vnet=$vnet tag=$tag mtu=$mtu"
	done
fi
echo "problems=$fail"
exit $fail
