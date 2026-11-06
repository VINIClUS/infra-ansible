#!/bin/sh
# Drops a removed NIC's stanza from the guest network file, run as:
#   pct exec <vmid> -- sh -s -- <iface> < guest-nic-forget.sh
# PVE hot-removes the interface but leaves its "auto"/"iface" lines behind,
# and ifupdown2 would then try to bring up a missing interface on every boot.
# Prints file=changed when it rewrote the file.
set -eu
iface=$1
f=${NETISO_INTERFACES_FILE:-/etc/network/interfaces}
case "$iface" in eth[1-9] | eth[1-9][0-9]) ;; *) echo "bad iface" >&2; exit 2 ;; esac
awk -v i="$iface" '
	$1 == "auto" && NF == 2 && $2 == i { next }
	$1 == "allow-hotplug" && NF == 2 && $2 == i { next }
	$1 == "iface" && $2 == i { skip = 1; next }
	skip && (/^[ \t]*$/ || $1 ~ /^(iface|auto|allow-|mapping|source)/) { skip = 0 }
	skip { next }
	{ print }
' "$f" > "$f.netiso"
if cmp -s "$f" "$f.netiso"; then
	rm -f "$f.netiso"
	exit 0
fi
# cat keeps the inode, owner and mode of the guest file.
cat "$f.netiso" > "$f"
rm -f "$f.netiso"
echo file=changed
