#!/bin/sh
# Keeps a guest interface MTU in step with its PVE netX, run as:
#   pct exec <vmid> -- sh -s -- pre|post <mtu> [<iface>] < guest-mtu.sh
# <iface> defaults to eth0 (net0).
# PVE sets mtu= only on the host side of the veth and never writes it into
# /etc/network/interfaces, and ifupdown2 resets an interface without "mtu" to
# 1500 on every boot. PVE keeps extra attributes of the stanza when it rewrites
# the file at start (static stanzas only; a dhcp stanza is written bare), so:
#   pre  - before the stop: put "mtu <mtu>" in the inet stanza, whatever its
#          method, so the first boot with the new netX already uses it;
#   post - after the start (or a hot-plug): keep "mtu <mtu>" only in a static
#          stanza and set the live MTU if it still differs.
# Prints file=changed / live=changed for what it touched.
set -eu
mode=$1
mtu=$2
iface=${3:-eth0}
f=${NETISO_INTERFACES_FILE:-/etc/network/interfaces}
# Overridable so tests never touch the real links of the machine running them.
net=${NETISO_SYS_CLASS_NET:-/sys/class/net}
case "$mode" in pre | post) ;; *) echo "usage: pre|post <mtu> [<iface>]" >&2; exit 2 ;; esac
case "$mtu" in '' | *[!0-9]*) echo "bad mtu" >&2; exit 2 ;; esac
case "$iface" in eth[0-9] | eth[1-9][0-9]) ;; *) echo "bad iface" >&2; exit 2 ;; esac

# A stanza is right when it carries exactly one "mtu <mtu>" (pre, or post on a
# static stanza) or none (post on dhcp/manual); only a wrong one is rewritten,
# so the attribute order PVE writes on every start does not count as drift.
state=$(awk -v mtu="$mtu" -v mode="$mode" -v iface="$iface" '
	$1 == "iface" && $2 == iface && $3 == "inet" { in_if = 1; want = (mode == "pre" || ($4 != "dhcp" && $4 != "manual")); seen = 1; next }
	/^[ \t]*$/ || /^[ \t]*(iface|auto|allow-|mapping|source)/ { in_if = 0 }
	in_if && $1 == "mtu" { total++; if ($2 == mtu) good++ }
	END { if (!seen) print "absent"; else if ((want && total == 1 && good == 1) || (!want && total == 0)) print "ok"; else print "fix" }
' "$f")
if [ "$state" = absent ]; then
	echo "no $iface inet stanza in $f" >&2
	exit 3
fi
if [ "$state" = fix ]; then
	awk -v mtu="$mtu" -v mode="$mode" -v iface="$iface" '
		$1 == "iface" && $2 == iface && $3 == "inet" {
			print
			if (mode == "pre" || ($4 != "dhcp" && $4 != "manual")) print "\tmtu " mtu
			in_if = 1
			next
		}
		/^[ \t]*$/ || /^[ \t]*(iface|auto|allow-|mapping|source)/ { in_if = 0 }
		in_if && $1 == "mtu" { next }
		{ print }
	' "$f" > "$f.netiso"
	# cat keeps the inode, owner and mode of the guest file.
	cat "$f.netiso" > "$f"
	echo file=changed
fi
rm -f "$f.netiso"

if [ "$mode" = post ] && [ -e "$net/$iface" ] && [ "$(cat "$net/$iface/mtu")" != "$mtu" ]; then
	ip link set dev "$iface" mtu "$mtu"
	echo live=changed
fi
