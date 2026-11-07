# Synthetic legacy PVE readback

`pve-runtime.json` contains complete IPv4/IPv6 filter tables with declarations
for every jump/goto target, standard PVE Drop/DropBroadcast/reject helper bodies,
synthetic other-host policy, a project probe and synthetic SHA1/base64 signature
comments. Helper semantics follow the public `proxmox/pve-firewall` source used
by S1; multicast constants are protocol constants, not private topology.

No production table, chain identity, address, MAC, set member or signature was
copied from a private capture. Named ipset definitions accompany the filter
rules, and the links are fictional. The fixture is evidence for parser/path
unit tests; it does not represent a running probe or production readiness.

Round 2 also parses complete real, already-loaded baseline tables kept only in
an ignored private artifact. That baseline does not contain the fictional
probe, so it must never be reported as project runtime-ready.

`check_loadable.py` always opens a fresh unprivileged user/network namespace and
validates both entire tables with `iptables-restore --test`. A worker receiving
the original namespace FD refuses to write there. The two empty synthetic ipsets
are created only inside that namespace using Linux's installed netfilter UAPI;
no ipset executable, dependency installation, build or host ruleset load is used.
Membership and project readiness are separate unit checks, not claimed by this
loadability test. Positive parsing of real, complete already-loaded tables is
recorded only in the ignored private round-2 evidence.
