#!/bin/sh
# Keeps the guest eth0 MTU in step with its PVE net0, run as:
#   pct exec <vmid> -- sh -s -- pre|post <mtu> < guest-mtu.sh
# PVE sets mtu= only on the host side of the veth and never writes it into
# /etc/network/interfaces, and ifupdown2 resets an eth0 without "mtu" to 1500
# on every boot. PVE keeps extra attributes of the eth0 stanza when it rewrites
# the file at start (static stanzas only; a dhcp stanza is written bare), so:
#   pre  - before the stop: put "mtu <mtu>" in the eth0 inet stanza, whatever
#          its method, so the first boot with the new net0 already uses it;
#   post - after the start: keep "mtu <mtu>" only in a static stanza and set
#          the live eth0 MTU if it still differs.
# Prints file=changed / live=changed for what it touched.
set -eu
mode=$1
mtu=$2
f=${NETISO_INTERFACES_FILE:-/etc/network/interfaces}
case "$mode" in pre | post) ;; *) echo "usage: pre|post <mtu>" >&2; exit 2 ;; esac
case "$mtu" in '' | *[!0-9]*) echo "bad mtu" >&2; exit 2 ;; esac

# A stanza is right when it carries exactly one "mtu <mtu>" (pre, or post on a
# static stanza) or none (post on dhcp/manual); only a wrong one is rewritten,
# so the attribute order PVE writes on every start does not count as drift.
state=$(awk -v mtu="$mtu" -v mode="$mode" '
	/^[ \t]*iface[ \t]+eth0[ \t]+inet[ \t]/ { in_eth0 = 1; want = (mode == "pre" || ($4 != "dhcp" && $4 != "manual")); seen = 1; next }
	/^[ \t]*$/ || /^[ \t]*(iface|auto|allow-|mapping|source)/ { in_eth0 = 0 }
	in_eth0 && $1 == "mtu" { total++; if ($2 == mtu) good++ }
	END { if (!seen) print "absent"; else if ((want && total == 1 && good == 1) || (!want && total == 0)) print "ok"; else print "fix" }
' "$f")
if [ "$state" = absent ]; then
	echo "no eth0 inet stanza in $f" >&2
	exit 3
fi
if [ "$state" = fix ]; then
	awk -v mtu="$mtu" -v mode="$mode" '
		/^[ \t]*iface[ \t]+eth0[ \t]+inet[ \t]/ {
			print
			if (mode == "pre" || ($4 != "dhcp" && $4 != "manual")) print "\tmtu " mtu
			in_eth0 = 1
			next
		}
		/^[ \t]*$/ || /^[ \t]*(iface|auto|allow-|mapping|source)/ { in_eth0 = 0 }
		in_eth0 && $1 == "mtu" { next }
		{ print }
	' "$f" > "$f.netiso"
	# cat keeps the inode, owner and mode of the guest file.
	cat "$f.netiso" > "$f"
	echo file=changed
fi
rm -f "$f.netiso"

if [ "$mode" = post ] && [ -e /sys/class/net/eth0 ] && [ "$(cat /sys/class/net/eth0/mtu)" != "$mtu" ]; then
	ip link set dev eth0 mtu "$mtu"
	echo live=changed
fi
