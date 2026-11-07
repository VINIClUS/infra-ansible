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
- Every ruleset is validated with `nft --check`, then loaded under a dead-man
  timer (`network-router-deadman`) that restores the previous ruleset unless a
  fresh SSH connection from the controller succeeds.

```bash
ansible-playbook -i <private-inventory> playbooks/network-router.yml \
  --limit <exact-router-host> --tags network_router
```

A `--check` run on a fresh guest validates the contract, interfaces, sysctl,
netplan override and the rendered ruleset, then stops validating at the
package-dependent steps (nftables service, dnsmasq configuration and
services), which only run for real.

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

