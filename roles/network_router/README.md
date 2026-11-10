# network_router

Configures the zone router guest for the private VNets: IPv4 forwarding, an
nftables zone policy with NAT, and dnsmasq (DNS and optional DHCP) for the VNets
only. The role is disabled by default and needs an exact `--limit` and
`--tags network_router`.

- IPv6 is disabled on every interface first (sysctl), and when netplan
  manages the guest a `90-network-router.yaml` override sets
  `accept-ra: false` and `link-local: []` on the uplink and every zone
  interface, so networkd never turns IPv6 back on when a link is reconfigured.
  The role asserts the uplink has no global IPv6 address (the LAN router hands
  out public SLAAC addresses). The input chain also drops all new IPv6.
- Each zone interface must already carry the declared gateway address and the
  VNet MTU (`network_router_mtu`).
- Policy (`templates/nftables.conf.j2`, `table inet filter` plus `table ip
  nat`): input and forward default drop; established/related accepted; TCP MSS
  of both SYNs lowered to `network_router_mtu - 40` (every forwarded flow has
  one end in a VNet, and a guest's Docker bridge still announces 1460); zones with `full_access` reach
  everything; the trusted LAN (`network_router_lan_cidr`) may open connections
  into the VNets; zones with `internet` reach only non-RFC1918 destinations
  through the uplink; `network_router_forward_rules` adds explicit allowances.
  Private sources are masqueraded on the uplink except towards
  `network_router_pve_nodes`, which carry a static route back so their host
  firewall sees the real source.
- DNS (53) and DHCP (67) are accepted only on zone interfaces and dropped on
  the uplink. dnsmasq is installed with service starts blocked
  (`policy-rc.d`), then configured with `bind-interfaces`, one `interface=` per
  zone, `except-interface=lo` and `no-dhcp-interface=<uplink>`; the role asserts
  nothing answers DNS on the uplink or a wildcard address. DHCP ranges announce
  the router, DNS and the VNet MTU (option 26).
- Every ruleset is validated with `nft --check`. A verified complete preimage
  is published atomically before arming `network-router-deadman`; a staging
  failure stops outside the apply/rescue block. Applying and restoring also
  use same-directory temporary files, file/directory fsync and atomic replace,
  preserving ownership and mode. A fresh SSH connection must succeed. Finalizing
  stops only the timer, waits boundedly for any queued/running recovery without
  killing it, and fails the attempt if recovery ran. Only then are the final
  persistent hash and loaded semantic ruleset checked; table/DNS checks follow.

```bash
ansible-playbook -i <private-inventory> playbooks/network-router.yml \
  --limit <exact-router-host> --tags network_router
```

A `--check` run on a fresh guest validates the contract, interfaces, sysctl,
netplan override and the rendered ruleset, then stops validating at the
package-dependent steps (nftables service, dnsmasq configuration and
services), which only run for real.

## Recovery boundaries

The root-owned helper `/usr/local/sbin/network-router-recovery.py` is mode 0600
and is invoked with `/usr/bin/python3`. Its CLI accepts only fixed `nft` or
`netplan` operations, never caller-supplied paths or native commands. Its private
operation state and locks live in `/run/network-router-recovery` (0700), with
files 0600. The existing nft `.prev` keeps the current file's ownership/mode;
the candidate must be 0600. An incomplete or recovered attempt is not silently
rearmed. Inspect/classify it and obtain fresh network/service readbacks before
an operator prepares another attempt. Reboot invalidates the transient state;
these timers are not reboot-persistent recovery guarantees.

The role's timer protects nft only. For a separately reviewed netplan change,
an operator may stage the same reviewed helper before the role, then invoke
`netplan arm <actual-before-sha256> <reviewed-desired-sha256>`. This fixed-path
operation snapshots only `/etc/netplan/90-network-router.yaml` into
`/run/network-router-recovery/netplan.before` and arms the separate 15 minute
`samba-ad-router-policy-netplan-deadman` pair. It does not install a new overlay.
The `netplan finalize` operation rejects a triggered recovery and verifies the
final overlay hash; the operator must then verify fresh actual links/routes,
wait-online requirements and services. `netplan recover` first waits for any
running restoration, then repeats atomic restore/generate/reload if necessary.
It refuses foreign overlay bytes, while accepting either complete before or
desired image so a failed native generate/reload is safely retryable. Never
classify a stopped timer alone as completed recovery or reapply an expired
attempt to hide failure. Use the independently verified recovery channel when
SSH is unavailable, and leave an in-progress restoration uninterrupted.

## Changing the uplink address

`proxmox_router_vm` is create-only, so an uplink re-IP is manual and must not
collide with the old address holder:

1. `qm set <vmid> --net0 <same net0>,link_down=1` (take the uplink off the LAN).
2. `qm set <vmid> --ipconfig0 ip=<new>/24,gw=<gateway>` and
   `qm cloudinit update <vmid>`.
3. `qm reboot <vmid>` (an HA-managed VM is restarted by HA), then remove
   `link_down` while watching the tap for the old address.
4. Update the inventory, re-pin the host key (cloud-init regenerates it when
   the instance changes) and re-run `network_router` and the node routes.


## Restricted identity zone

A zone may opt into `restricted: true`. Its forward chain runs before existing
LAN, operations `full_access` and Internet allowances; only explicit
`network_router_forward_rules` with exact IPv4 source/destination and TCP/UDP
ports pass. All other forwarded traffic with that zone is dropped. Existing
zones keep their current policy. Restricted zones cannot enable `full_access`,
`internet`, `ssh_to_router` or DHCP, and dnsmasq does not bind their interfaces.
Return traffic is established/related. This routes policy only: same-L2 traffic
requires the dedicated guest firewall with default IN/OUT DROP and anti-spoofing.
Samba S1 adds the QEMU NIC with `samba_ad_router_nic` before this role runs.

As regras da cadeia restrita emitem match e verdict na mesma instrução nft.
Fluxos dessa zona não são emitidos novamente no loop genérico de forward; o
render não cria um ACCEPT incondicional por quebra de linha. A política legada
fora da zona restrita permanece no seu caminho existente. A prova S1 também
verifica o AST carregado contra a matriz e os jumps, além do fingerprint aprovado.

## Exact DNS host records

`network_router_dns_host_records` defaults to `[]`, preserving the existing
dnsmasq output. Each entry must contain only `name` (a lowercase FQDN with
labels of at most 63 characters and at most 253 characters overall) and
`address` (one canonical dotted-decimal IPv4 address, with octets 0–255).
The role validates the list and every record before changing network files.
It emits `host-record=name,address`, so only that exact name is answered;
subdomains retain their normal forwarding behavior. For example:

```yaml
network_router_dns_host_records:
  - name: app.example.internal
    address: 192.0.2.139
```
