"""Dedicated Samba substrate lifecycle. JSON stdin; no secrets or automatic deployment.

Runs on the source PVE node. All cluster operations use pvesh's local proxy.
A partial resource is deliberately left stopped for explicit, digest-bound recovery.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

GIB = 1024 ** 3

# Use the installed authoritative parser, which can retain errors and skip a rule.
PVE_VALIDATE_FW = r"""
use strict; use warnings;
local $SIG{__WARN__} = sub { die "firewall parser warning\n"; };
my $cluster = PVE::Firewall::load_clusterfw_conf();
my $conf = PVE::Firewall::load_vmfw_conf($cluster, $ARGV[0], $ARGV[1]);
my $rules = $conf->{rules};
die "rule count mismatch\n" unless scalar(@$rules) == $ARGV[2];
for my $r (@$rules) { die "invalid firewall rule\n" if $r->{errors}; }
"""


def require(ok, field):
    if not ok:
        raise ValueError("S1 precondition failed: " + field)


def digest(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[a-f0-9]{40}", value))


def spec_hash(r):
    return hashlib.sha256(json.dumps({k: r[k] for k in ["owner", "scope", "resource", "template", "firewall"]},
                                   sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def marker(r):
    return "samba-ad:s1:" + r["scope"] + ":" + spec_hash(r)


def validate(r):
    require(set(r) == {"schema", "enabled", "apply", "action", "owner", "scope", "compatibility", "boot",
                       "resource", "template", "expected_digest", "firewall"}, "request fields")
    require(type(r["schema"]) is int and r["schema"] == 1 and r["owner"] == "samba-ad", "schema/owner")
    require(r["enabled"] is True and type(r["apply"]) is bool and type(r["boot"]) is bool, "activation")
    require(r["scope"] in ["lab", "production"] and r["action"] in ["present", "start", "absent"], "scope/action")
    require(r["action"] != "start" or r["boot"], "explicit start boot flag")
    c, t = r["resource"], r["template"]
    require(set(c) == {"vmid", "node", "kind", "name", "address", "gateway", "bridge", "mac", "storage",
                       "cores", "memory_mib", "disk_gib", "mtu"}, "resource fields")
    require(set(t) == {"node", "vmid", "digest", "disk", "storage"}, "template fields")
    for value in [c["vmid"], t["vmid"]]:
        require(type(value) is int and 100 <= value <= 999999999, "VMID")
    require(c["vmid"] != t["vmid"] and c["kind"] in ["lxc", "qemu"], "type/identity")
    for value in [c["node"], t["node"], c["storage"], t["storage"]]:
        require(isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}", value), "placement")
    require(digest(t["digest"]) and (r["expected_digest"] is None or digest(r["expected_digest"])), "digests")
    require(isinstance(c["name"], str) and len(c["name"]) <= 253 and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in c["name"].split(".")), "DNS name")
    require(re.fullmatch(r"[a-z][a-z0-9]{1,7}", c["bridge"]), "bridge")
    require(re.fullmatch(r"02(?::[0-9A-F]{2}){5}", c["mac"]), "local unicast MAC")
    address = ipaddress.IPv4Interface(c["address"])
    gw = ipaddress.IPv4Address(c["gateway"])
    require(address.network.prefixlen >= 24 and gw in address.network
            and address.ip not in [gw, address.network.network_address, address.network.broadcast_address]
            and gw not in [address.network.network_address, address.network.broadcast_address], "static network")
    for field, low, high in [("cores", 1, 16), ("memory_mib", 1024, 65536), ("disk_gib", 16, 1024), ("mtu", 1280, 1450)]:
        require(type(c[field]) is int and low <= c[field] <= high, field)
    require(t["disk"] == ("rootfs" if c["kind"] == "lxc" else "scsi0"), "root disk")
    if r["scope"] == "lab":
        require(c["name"].endswith(".lab.ad.test") and r["compatibility"] is None, "disposable lab identity")
    else:
        # Only a new S2-reviewed revision may implement production acceptance. No boolean bypass.
        require(False, "production lifecycle awaits S2 reviewed compatibility integration")
    require(r["scope"] == "lab" or r["action"] != "absent", "cleanup only lab")
    f = r["firewall"]
    require(set(f) == {"admin_sources", "flows"} and f["admin_sources"] and f["flows"], "firewall")
    for peer in f["admin_sources"]:
        require(ipaddress.IPv4Network(peer).prefixlen == 32, "exact admin source")
    for flow in f["flows"]:
        require(set(flow) == {"direction", "peer", "proto", "port"}, "firewall flow fields")
        require(flow["direction"] in ["IN", "OUT"] and flow["proto"] in ["tcp", "udp"], "firewall flow")
        require(ipaddress.IPv4Network(flow["peer"]).prefixlen == 32, "exact peer")
        require(isinstance(flow["port"], str) and re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", flow["port"]), "port")
        ports = [int(x) for x in flow["port"].split("-")]
        require(1 <= min(ports) <= max(ports) <= 65535 and ports == sorted(ports), "port bounds")


def firewall_text(r):
    c = r["resource"]
    lines = ["# " + marker(r), "[OPTIONS]", "enable: 1", "policy_in: DROP", "policy_out: DROP",
             "ipfilter: 1", "macfilter: 1", "dhcp: 0", "ndp: 0", "radv: 0", "log_level_in: nolog", "log_level_out: nolog", "", "[IPSET ipfilter-net0]",
             str(ipaddress.IPv4Interface(c["address"]).ip), "", "[RULES]"]
    for flow in r["firewall"]["flows"]:
        peer = "-source" if flow["direction"] == "IN" else "-dest"
        lines.append(f'{flow["direction"]} ACCEPT {peer} {flow["peer"]} -p {flow["proto"]} -dport {flow["port"].replace("-", ":")}')
    lines += ["IN DROP", "OUT DROP"]
    return "\n".join(lines) + "\n"


def size_gib(config, disk):
    match = re.search(r"(?:^|,)size=([0-9]+)([GM])(?:,|$)", config.get(disk, ""))
    require(match is not None, "root disk size")
    return int(match[1]) / (1024 if match[2] == "M" else 1)


def desired_config(r, isolated=False):
    c = r["resource"]
    common = {"cores": c["cores"], "memory": c["memory_mib"], "onboot": 0, "description": marker(r), "tags": "samba-ad;s1;lab"}
    link = "1" if isolated else "0"
    if c["kind"] == "lxc":
        return dict(common, hostname=c["name"], swap=0,
                    net0=f'name=eth0,bridge={c["bridge"]},hwaddr={c["mac"]},ip={c["address"]},gw={c["gateway"]},mtu={c["mtu"]},firewall=1,type=veth,link_down={link}')
    return dict(common, sockets=1, balloon=0, name=c["name"], ipconfig0=f'ip={c["address"]},gw={c["gateway"]}',
                net0=f'virtio={c["mac"]},bridge={c["bridge"]},firewall=1,mtu={c["mtu"]},link_down={link}')


def pairs(value):
    return dict(x.split("=", 1) for x in value.split(",") if "=" in x)


def safe_devices(config, disk):
    for key, value in config.items():
        require(not (re.fullmatch(r"(?:hostpci|usb|unused|efidisk|tpmstate|dev|virtiofs|parallel)[0-9]+", key)
                     or key.startswith("lxc.") or re.fullmatch(r"mp[0-9]+", key)
                     or key in ["hookscript", "cicustom", "args"]), "unmanaged devices/hooks")
        if re.fullmatch(r"serial[0-9]+", key):
            require(value == "socket", "host serial device")
        if re.fullmatch(r"(?:scsi|sata|virtio|ide)[0-9]+", key) and key != disk:
            require(key == "ide2" and "cloudinit" in value and "media=cdrom" in value, "additional disk")


def verify_config(r, config, configured=True, isolated=False):
    c = r["resource"]
    require(config.get("description") == marker(r) and config.get("template", 0) == 0, "ownership")
    require(config.get("hostname" if c["kind"] == "lxc" else "name") == c["name"], "guest identity")
    require(not config.get("lock"), "guest lock")
    if configured:
        for k, value in desired_config(r, isolated=isolated).items():
            got = config.get(k)
            if k in ["cores", "memory", "onboot", "swap", "sockets", "balloon"]:
                require(str(got if got is not None else 0) == str(value), "configured sizing")
            elif k == "tags":
                require(set((got or "").split(";")) == set(value.split(";")), "project tags")
            else:
                require(pairs(got or "") == pairs(value) if k in ["net0", "ipconfig0"] else got == value,
                        "configured identity")
        require(size_gib(config, r["template"]["disk"]) == c["disk_gib"], "disk size")
        require(config[r["template"]["disk"]].startswith(c["storage"] + ":"), "disk placement")
        if c["kind"] == "lxc":
            require(config.get("unprivileged") == 1 and not config.get("features"), "LXC isolation")
    safe_devices(config, r["template"]["disk"])
    require(not any(re.fullmatch(r"net[1-9][0-9]*", k) for k in config), "additional NIC")


def capacity(api, r, guests, booting=False):
    c, t = r["resource"], r["template"]
    for node in ({c["node"]} if booting else {c["node"], t["node"]}):
        memory = api.get(f"/nodes/{node}/status")["memory"]
        allocations = [g for g in guests if g.get("node") == node and g.get("type") in ["qemu", "lxc"] and not g.get("template")
                       and (not booting or g.get("vmid") != c["vmid"])]
        require(all(type(g.get("maxmem")) is int for g in allocations), "capacity reservations known")
        free = min(memory["total"] - memory["used"], memory["total"] - sum(g["maxmem"] for g in allocations))
        require(free - c["memory_mib"] * 1024**2 >= 2 * GIB, "2 GiB host reserve")
    if booting:
        return
    for node, storage in {(t["node"], t["storage"]), (c["node"], c["storage"])}:
        status = api.get(f"/nodes/{node}/storage/{storage}/status")
        require(status.get("active") == 1 and status.get("enabled") == 1
                and status.get("avail", 0) >= c["disk_gib"] * GIB + 2 * GIB, "storage capacity")


def check_collisions(r, api, guests):
    c = r["resource"]
    for g in guests:
        if g.get("type") not in ["lxc", "qemu"]:
            continue
        if g.get("vmid") == c["vmid"]:
            continue
        for current in [1, 0]:
            config = api.get(f'/nodes/{g["node"]}/{g["type"]}/{g["vmid"]}/config', current=current)
            require(c["name"] not in [config.get("name"), config.get("hostname")], "name collision")
            for key, value in config.items():
                if re.fullmatch(r"(?:net|ipconfig)[0-9]+", key):
                    require(c["mac"].lower() not in str(value).lower(), "MAC collision")
                    require(not re.search(r"(?:^|,)ip=" + re.escape(str(ipaddress.IPv4Interface(c["address"]).ip))
                                          + r"(?:/|,|$)", str(value)), "IP collision")


def pending_empty(api, path):
    require(not any("pending" in x or x.get("delete") for x in api.get(path + "/pending")), "pending changes")


def reconcile(r, api, check=False):
    validate(r)
    c, t = r["resource"], r["template"]
    check = check or not r["apply"]
    cluster = api.get("/cluster/status")
    require(any(x.get("type") == "cluster" and x.get("quorate") == 1 for x in cluster), "quorum")
    nodes = {x["name"] for x in cluster if x.get("type") == "node" and x.get("online") == 1}
    require({c["node"], t["node"]} <= nodes and not any(x.get("type") == "node" and x.get("online") != 1
                                                                     for x in cluster), "online nodes")
    guests = api.get("/cluster/resources")
    live = [g for g in guests if g.get("vmid") == c["vmid"]]
    require(len(live) <= 1, "unique cluster VMID")
    path = f'/nodes/{c["node"]}/{c["kind"]}/{c["vmid"]}'
    if live:
        allowed_nodes = {c["node"], t["node"]} if r["action"] == "absent" else {c["node"]}
        require(live[0].get("node") in allowed_nodes and live[0].get("type") == c["kind"], "placement/type")
        if r["action"] == "absent":
            path = f'/nodes/{live[0]["node"]}/{c["kind"]}/{c["vmid"]}'
        cfg = api.get(path + "/config", current=1)
        require(digest(r["expected_digest"]) and cfg.get("digest") == r["expected_digest"], "guest digest")
        verify_config(r, cfg, configured=r["action"] != "absent", isolated=not r["boot"] or r["action"] == "start")
        require(not any("pending" in x or x.get("delete") for x in api.get(path + "/pending")), "pending changes")
        power = api.get(path + "/status/current")["status"]
        if r["action"] == "absent":
            require(power == "stopped", "recovery requires stopped lab; never stop a guest implicitly")
            if not check:
                api.mutate("delete", path)
            return {"changed": True, "state": "absent"}
        require(api.firewall(c["node"], c["kind"], c["vmid"], firewall_text(r), False), "firewall drift")
        if r["action"] == "start":
            require(power == "stopped", "explicit start requires stopped guest")
            if not check:
                boot_disconnected(r, api, path, cfg)
            return {"changed": True, "state": "planned_start" if check else "started"}
        require(power == ("running" if r["boot"] else "stopped"), "power state; no implicit restart")
        require(not r["boot"] or api.enforce(r), "runtime firewall")
        return {"changed": False, "state": "verified", "digest": cfg["digest"]}
    if r["action"] == "absent":
        return {"changed": False, "state": "absent"}
    require(r["action"] != "start", "cannot start absent guest")
    require(r["expected_digest"] is None, "new guest absence")
    require(c["node"] != t["node"] or c["storage"] == t["storage"], "local clone storage")
    check_collisions(r, api, guests)
    capacity(api, r, guests)
    require(api.get("/cluster/firewall/options").get("enable") == 1, "cluster firewall enabled")
    require(api.get(f'/nodes/{c["node"]}/firewall/options').get("enable", 1) == 1, "node firewall enabled")
    template_path = f'/nodes/{t["node"]}/{c["kind"]}/{t["vmid"]}'
    source = api.get(template_path + "/config", current=1)
    require(source.get("template") == 1 and source.get("digest") == t["digest"] and not source.get("lock")
            and not source.get("onboot"), "template digest/identity")
    safe_devices(source, t["disk"])
    require(not any(re.fullmatch(r"net[1-9][0-9]*", k) for k in source), "template additional NIC")
    require(source.get("ostype") == "debian" if c["kind"] == "lxc" else source.get("ostype") in ["l26"], "Debian template")
    if c["kind"] == "lxc":
        require(source.get("unprivileged") == 1, "unprivileged template")
    require(source.get(t["disk"], "").startswith(t["storage"] + ":")
            and size_gib(source, t["disk"]) <= c["disk_gib"], "local disk/no shrink")
    if check:
        return {"changed": True, "state": "planned"}
    api.assert_firewall_absent(r)
    api.probe_address(r)
    # Recheck the template immediately before clone; clone API has no digest parameter.
    require(api.get(template_path + "/config", current=1).get("digest") == t["digest"], "template changed")
    api.mutate("create", template_path + "/clone", newid=c["vmid"], full=1, storage=t["storage"],
               description=marker(r), **{("hostname" if c["kind"] == "lxc" else "name"): c["name"]})
    source_path = f'/nodes/{t["node"]}/{c["kind"]}/{c["vmid"]}'
    clone = api.get(source_path + "/config", current=1)
    verify_config(r, clone, configured=False)
    require(api.get(source_path + "/status/current")["status"] == "stopped", "clone stopped")
    params = desired_config(r, isolated=True)
    if c["kind"] == "lxc" and clone.get("features"):
        params["delete"] = "features"
    api.mutate("set", source_path + "/config", digest=clone["digest"], **params)
    clone = api.get(source_path + "/config", current=1)
    if size_gib(clone, t["disk"]) < c["disk_gib"]:
        api.mutate("set", source_path + "/resize", disk=t["disk"], size=str(c["disk_gib"]) + "G", digest=clone["digest"])
    if t["node"] != c["node"]:
        require(api.get(source_path + "/status/current")["status"] == "stopped", "offline migration")
        api.mutate("create", source_path + "/migrate", target=c["node"], online=0,
                   **({"target-storage": c["storage"]} if c["kind"] == "lxc" else {"targetstorage": c["storage"], "with-local-disks": 1}))
    cfg = api.get(path + "/config", current=1)
    verify_config(r, cfg, isolated=True)
    require(api.get(path + "/status/current")["status"] == "stopped", "destination stopped")
    require(api.firewall(c["node"], c["kind"], c["vmid"], firewall_text(r), True), "firewall readback")
    if r["boot"]:
        boot_disconnected(r, api, path, cfg)
    return {"changed": True, "state": "created", "digest": api.get(path + "/config", current=1)["digest"]}


def boot_disconnected(r, api, path, cfg):
    guests = api.get("/cluster/resources")
    check_collisions(r, api, guests)
    api.probe_address(r)
    capacity(api, r, guests, booting=True)
    require(api.get(path + "/config", current=1)["digest"] == cfg["digest"], "preboot digest")
    api.mutate("create", path + "/status/start")
    require(api.get(path + "/status/current")["status"] == "running", "boot readback")
    require(api.enforce(r), "runtime firewall; guest left disconnected")
    before_link = api.get(path + "/config", current=1)
    verify_config(r, before_link, isolated=True)
    check_collisions(r, api, api.get("/cluster/resources"))
    api.probe_address(r)
    pending_empty(api, path)
    api.mutate("set", path + "/config", digest=before_link["digest"], net0=desired_config(r)["net0"])
    pending_empty(api, path)
    verify_config(r, api.get(path + "/config", current=1))
    require(api.link_ready(r, connected=True), "effective host NIC link")


PVE_READ_RUNTIME = r"""
import json, subprocess, sys
from pathlib import Path
def read(argv):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=20).stdout
print(json.dumps({"status":read(["pve-firewall","status"]),
 "ipv4":read(["iptables-save","-t","filter"]), "ipv6":read(["ip6tables-save","-t","filter"]),
 "ipsets":read(["ipset","save"]), "links":json.loads(read(["ip","-j","-d","link","show"])),
 "bridge_filter":{"ipv4":int(Path("/proc/sys/net/bridge/bridge-nf-call-iptables").read_text()),
                  "ipv6":int(Path("/proc/sys/net/bridge/bridge-nf-call-ip6tables").read_text())},
 "firewall":Path("/etc/pve/firewall/"+str(int(sys.argv[1]))+".fw").read_text()}))
"""


def ipt_rule(body):
    """Canonical AND clauses, preserving negation and jump/goto semantics."""
    tokens = shlex.split(body)
    if len(tokens) == 4 and tokens[:3] == ["-m", "comment", "--comment"] and re.fullmatch(r"PVESIG:(?:[A-Za-z0-9+/]{27}|[a-fA-F0-9]{40})", tokens[3]):
        return None  # Pure non-terminating signature, never ignore a rule with a target.
    aliases = {"--jump": "-j", "--goto": "-g", "--match": "-m", "--protocol": "-p", "--source": "-s", "--destination": "-d", "--set-mark": "--set-xmark"}
    widths = {"--physdev-is-bridged": 0, "--match-set": 2, "--tcp-flags": 2}
    singles = {"-j", "-g", "-m", "-p", "-s", "-d", "-i", "-o", "--physdev-in", "--physdev-out", "--ctstate", "--mac-source", "--set-xmark", "--dport", "--sport", "--dports", "--sports", "--icmp-type", "--icmpv6-type", "--mark", "--src-type", "--dst-type", "--limit", "--limit-burst", "--nflog-prefix", "--nflog-group", "--nflog-range", "--nflog-threshold", "--reject-with"}
    clauses = []; i = 0
    while i < len(tokens):
        negate = tokens[i] == "!"
        if negate: i += 1
        key = aliases.get(tokens[i], tokens[i]); i += 1
        require(key in singles or key in widths, "unsupported runtime clause")
        width = widths.get(key, 1); values = tokens[i:i + width]; i += width
        require(len(values) == width, "truncated runtime clause")
        if key == "-p": values[0] = {"6": "tcp", "17": "udp", "58": "ipv6-icmp", "icmpv6": "ipv6-icmp"}.get(values[0], values[0])
        if key in ["-s", "-d"]: values[0] = str(ipaddress.ip_network(values[0], strict=False))
        if key == "--mac-source": values[0] = values[0].lower()
        if key == "--ctstate": values[0] = ",".join(sorted(values[0].split(",")))
        if key == "--icmpv6-type": values[0] = {"router-advertisement": "134"}.get(values[0], values[0])
        if key == "--set-xmark":
            mark, _, mask = values[0].partition("/")
            values[0] = hex(int(mark, 0)) + "/" + hex(int(mask, 0) if mask else 0xffffffff)
        if key == "-m" and values[0] in ["tcp", "udp"] and "-p" in tokens and tokens[tokens.index("-p") + 1] in [values[0], {"tcp": "6", "udp": "17"}[values[0]]]:
            require(not negate, "negated protocol module")
            continue
        clauses.append(tuple((["!" + key] if negate else [key]) + values))
    require(sum(item[0] in ["-j", "-g"] for item in clauses) == 1, "missing/duplicate runtime target")
    return tuple(sorted(clauses))


def saved_filter(text):
    require(text.count("*filter\n") == 1 and text.count("COMMIT") == 1, "filter family")
    chains = {}; policies = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or line in ["*filter", "COMMIT"]: continue
        if line.startswith(":"):
            name, policy, counters = line[1:].split()
            require(name not in chains, "duplicate chain")
            chains[name] = []; policies[name] = policy
        else:
            require(line.startswith("-A "), "unknown save command")
            _, chain, body = line.split(" ", 2)
            require(chain in chains, "undeclared chain")
            rule = ipt_rule(body)
            if rule is not None: chains[chain].append(rule)
    # A real save cannot reference an undeclared user chain. Reject incomplete
    # evidence too, including references after a terminal rule.
    builtin = {"ACCEPT", "DROP", "REJECT", "RETURN", "MARK", "CONNMARK", "NFLOG", "LOG", "NFQUEUE"}
    for rules in chains.values():
        for rule in rules:
            transfer, target = transfer_of(rule)
            require(target in chains or (transfer == "-j" and target in builtin), "undeclared runtime target")
    return chains, policies


def transfer_of(rule):
    return next(((item[0], item[1]) for item in rule if item[0] in ["-j", "-g"]), (None, None))


def deny_helper(chains, name, seen=None):
    seen = set() if seen is None else seen
    if name not in chains or name in seen: return False
    for rule in chains[name]:
        transfer, target = transfer_of(rule)
        if target in ["DROP", "REJECT", "RETURN", "NFLOG", "LOG"]: continue
        if not deny_helper(chains, target, seen | {name}): return False
    return True


def bridge_bindings(chains, direction, iface, vmid):
    parent = "PVEFW-FWBR-" + direction
    require(parent in chains, "FWBR parent")
    expected = ipt_rule(f'-m physdev --physdev-is-bridged --physdev-{"out" if direction == "IN" else "in"} {iface} -j {iface}-{direction}')
    require(chains[parent].count(expected) == 1, "exact own FWBR binding")
    for rule in chains[parent]:
        if rule == expected: continue
        # Exact other-VM interface bindings cannot match this guest's device.
        physical = next((item[1] for item in rule if item[0] == "--physdev-" + ("out" if direction == "IN" else "in")), None)
        match = re.fullmatch(r"(?:tap|veth)([0-9]+)i[0-9]+", physical or "")
        if match and int(match[1]) != vmid:
            foreign = ipt_rule(f'-m physdev --physdev-is-bridged --physdev-{"out" if direction == "IN" else "in"} {physical} -j {physical}-{direction}')
            if rule == foreign: continue
        transfer, target = transfer_of(rule)
        # A jump returns here; a goto may return to PVEFW-FORWARD and skip the
        # binding. No parent goto is accepted without a total-termination proof.
        require(transfer == "-j", "goto can escape the FWBR binding")
        require(target not in ["ACCEPT", "RETURN", "MARK", "CONNMARK"] and deny_helper(chains, target), "broader FWBR path")


def exact_ipsets(r, text):
    c = r["resource"]; base = f'PVEFW-{c["vmid"]}-ipfilter-net0-v'
    sets = {}; members = {}
    for line in text.splitlines():
        fields = shlex.split(line)
        if not fields or len(fields) < 2 or fields[1] not in [base + "4", base + "6"]: continue
        name = fields[1]
        if fields[0] == "create":
            require(name not in sets and fields[2] == "hash:net" and "family" in fields, "ipset type")
            sets[name] = fields[fields.index("family") + 1]; members[name] = set()
        elif fields[0] == "add":
            require(name in members and len(fields) in [3, 4] and (len(fields) == 3 or fields[3] == "nomatch"), "ipset member flags")
            entry = (str(ipaddress.ip_network(fields[2], strict=False)), len(fields) == 4)
            require(entry not in members[name], "duplicate ipset member"); members[name].add(entry)
        else: require(False, "unexpected ipset operation")
    require(sets == {base + "4": "inet", base + "6": "inet6"}, "ipset families")
    mac = bytearray.fromhex(c["mac"].replace(":", "")); mac[0] ^= 2
    eui = bytes(mac[:3]) + bytes.fromhex("fffe") + bytes(mac[3:])
    linklocal = ipaddress.IPv6Address(int(ipaddress.IPv6Address("fe80::")) | int.from_bytes(eui, "big"))
    require(members[base + "4"] == {(str(ipaddress.ip_network(str(ipaddress.IPv4Interface(c["address"]).ip) + "/32")), False)}
            and members[base + "6"] == {(str(linklocal) + "/128", False), ("fe80::/10", True)}, "broader/stale ipset membership")


def runtime_firewall_ready(r, saved):
    """Prove the supported legacy PVE path and exact project policy; unknown fails closed."""
    try:
        require(isinstance(saved, dict) and saved["status"].strip() == "Status: enabled/running", "firewall service")
        c = r["resource"]; vmid = c["vmid"]
        iface = ("veth" if c["kind"] == "lxc" else "tap") + str(vmid) + "i0"
        exact_ipsets(r, saved["ipsets"])
        require(saved["bridge_filter"] == {"ipv4": 1, "ipv6": 1}, "bridge netfilter hooks")
        links = {link["ifname"]: link for link in saved["links"]}
        bridge, left, right = f"fwbr{vmid}i0", f"fwln{vmid}i0", f"fwpr{vmid}p0"
        require(links[iface].get("master") == bridge and links[left].get("master") == bridge
                and links[right].get("master") == c["bridge"]
                and links[left].get("link_index") == links[right]["ifindex"]
                and links[right].get("link_index") == links[left]["ifindex"]
                and links[bridge]["linkinfo"]["info_kind"] == "bridge"
                and links[c["bridge"]]["linkinfo"]["info_kind"] == "bridge", "same-L2 bridge path")
        for version in [4, 6]:
            chains, policies = saved_filter(saved[f"ipv{version}"])
            require(chains.get("FORWARD") == [ipt_rule("-j PVEFW-FORWARD")], "reachable first FORWARD hook")
            forward = ["-m conntrack --ctstate INVALID -j DROP", "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                       "-m physdev --physdev-is-bridged --physdev-in fwln+ -j PVEFW-FWBR-IN",
                       "-m physdev --physdev-is-bridged --physdev-out fwln+ -j PVEFW-FWBR-OUT"]
            require(chains.get("PVEFW-FORWARD") == [ipt_rule(x) for x in forward], "broader PVE forward path")
            require(chains.get("PVEFW-SET-ACCEPT-MARK") == [ipt_rule("-j MARK --set-mark 0x80000000/0x80000000")], "accept-mark helper")
            for direction in ["IN", "OUT"]:
                bridge_bindings(chains, direction, iface, vmid)
                bodies = [f"-j CONNMARK --set-mark {vmid}"]
                if direction == "OUT":
                    bodies.append(f'-m mac ! --mac-source {c["mac"]} -j DROP')
                    if version == 6: bodies.append("-p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP")
                    bodies += [f'-m set ! --match-set PVEFW-{vmid}-ipfilter-net0-v{version} src -j DROP',
                               "-j MARK --set-mark 0x0/0x80000000"]
                if version == 4:
                    for flow in r["firewall"]["flows"]:
                        if flow["direction"] != direction: continue
                        peer = "-s" if direction == "IN" else "-d"
                        action = "-j ACCEPT" if direction == "IN" else "-g PVEFW-SET-ACCEPT-MARK"
                        bodies.append(f'{peer} {flow["peer"]} -p {flow["proto"]} --dport {flow["port"].replace("-", ":")} {action}')
                # Explicit final rules block before PVE's implicit ICMP policy helper.
                bodies += ["-j DROP", "-j PVEFW-Drop", "-j DROP"]
                require(chains.get(iface + "-" + direction) == [ipt_rule(x) for x in bodies], "stale/broader project policy")
        return True
    except (ValueError, KeyError, TypeError, IndexError):
        return False


class Pvesh:
    def run(self, argv):
        result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=180)
        if result.returncode or (argv[:2] == ["pve-firewall", "compile"] and result.stderr.strip()):
            raise RuntimeError("PVE command failed; output suppressed; resource may require recovery")
        return result.stdout

    def get(self, path, **params):
        argv = ["pvesh", "get", path, "--output-format", "json"]
        for key, value in params.items():
            argv += ["--" + key, str(value)]
        return json.loads(self.run(argv))

    def mutate(self, method, path, **params):
        argv = ["pvesh", method, path, "--output-format", "json"]
        for k, v in params.items():
            argv += ["--" + k, str(v)]
        raw = self.run(argv).strip()
        result = json.loads(raw) if raw else None
        if isinstance(result, str) and result.startswith("UPID:"):
            task_node = result.split(":")[1]
            for _ in range(900):
                status = self.get(f"/nodes/{task_node}/tasks/{result}/status")
                if status["status"] == "stopped":
                    require(status.get("exitstatus") == "OK", "PVE task failed; explicit recovery required")
                    return
                time.sleep(2)
            raise RuntimeError("PVE task timeout; do not retry until live task readback")

    def enforce(self, r):
        for _ in range(15):
            rules = json.loads(self.node_run(r, "python3 -c " + shlex.quote(PVE_READ_RUNTIME) + " " + str(r["resource"]["vmid"])))
            if rules.get("firewall") == firewall_text(r) and runtime_firewall_ready(r, rules):
                return True
            time.sleep(2)
        return False

    def node_run(self, r, remote_command):
        c = r["resource"]
        nodes = self.get("/cluster/status")
        peers = [n for n in nodes if n.get("type") == "node" and n.get("name") == c["node"]]
        require(len(peers) == 1, "firewall node identity")
        address = str(ipaddress.IPv4Address(peers[0]["ip"]))
        command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
                   "-o", "HostKeyAlias=" + c["node"], "-o", "UserKnownHostsFile=/etc/pve/nodes/" + c["node"]
                   + "/ssh_known_hosts", "root@" + address, remote_command]
        return self.run(command)


    def link_ready(self, r, connected):
        c = r["resource"]
        name = ("veth" if c["kind"] == "lxc" else "tap") + str(c["vmid"]) + "i0"
        links = json.loads(self.node_run(r, "ip -j link show"))
        matches = [link for link in links if link.get("ifname") == name]
        return (len(matches) == 1 and (not connected or
                {"UP", "LOWER_UP"} <= set(matches[0].get("flags", []))))

    def assert_firewall_absent(self, r):
        require(not Path(f"/etc/pve/firewall/{r['resource']['vmid']}.fw").exists(), "orphan firewall policy")

    def probe_address(self, r):
        c = r["resource"]
        self.run(["arping", "-D", "-I", c["bridge"], "-c", "3", "-w", "5", str(ipaddress.IPv4Interface(c["address"]).ip)])

    def firewall(self, node, kind, vmid, text, apply):
        path = Path(f"/etc/pve/firewall/{vmid}.fw")
        if apply:
            # Never overwrite a preexisting guest policy, even for a newly cloned VMID.
            require(not path.exists(), "preexisting firewall policy")
            with path.open("x") as f:
                f.write(text)
            self.run(["perl", "-MPVE::Firewall", "-e", PVE_VALIDATE_FW,
                      "ct" if kind == "lxc" else "vm", str(vmid), str(len([line for line in text.split("[RULES]\n")[1].splitlines() if line]))])
            self.run(["pve-firewall", "compile"])
            self.run(["pve-firewall", "status"])
        return path.exists() and path.read_text() == text


def main():
    try:
        r = json.load(sys.stdin)
        print(json.dumps(reconcile(r, Pvesh(), check="--check" in sys.argv)))
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, subprocess.SubprocessError):
        print("S1 failed (values suppressed); inspect exact owned resource/task before recovery", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
