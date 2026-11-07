"""Simulated PVE lifecycle: no SSH, real API, disks or dependencies."""
import copy
import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]

def module():
    path = ROOT / "tools/samba_ad/guest.py"
    assert path.exists(), "dedicated lifecycle is missing"
    spec = importlib.util.spec_from_file_location("samba_guest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def request():
    return {"schema": 1, "enabled": True, "apply": True, "action": "present", "owner": "samba-ad",
            "scope": "lab", "compatibility": None, "boot": True,
            "resource": {"vmid": 800080, "node": "node-b", "kind": "lxc", "name": "probe.lab.ad.test",
                         "address": "198.51.100.80/25", "gateway": "198.51.100.1", "bridge": "vnidtest",
                         "mac": "02:00:5E:70:00:80", "storage": "local-lvm", "cores": 2,
                         "memory_mib": 4096, "disk_gib": 64, "mtu": 1450},
            "template": {"node": "node-a", "vmid": 7900, "digest": "a" * 40,
                         "disk": "rootfs", "storage": "local-lvm"},
            "expected_digest": None,
            "firewall": {"admin_sources": ["192.0.2.25/32"], "flows": [
                {"direction": "IN", "peer": "192.0.2.25/32", "proto": "tcp", "port": "22"},
                {"direction": "OUT", "peer": "192.0.2.123/32", "proto": "udp", "port": "123"}]}}


class Fake:
    def __init__(self):
        self.calls = []
        self.guests = {}
        self.template = {"template": 1, "digest": "a" * 40, "hostname": "tpl-debian", "unprivileged": 1,
                         "rootfs": "local-lvm:base-7900-disk-0,size=32G", "net0": "name=eth0,bridge=vnold,ip=dhcp",
                         "features": "nesting=1", "ostype": "debian"}
        self.available = 16 * 1024**3
        self.fail = None
        self.kind = "lxc"
        self.enforcement_ok = True
        self.fw = {}

    def get(self, path):
        self.calls.append(("get", path, {}))
        if path == "/cluster/status":
            return [{"type": "cluster", "quorate": 1}, *[{"type": "node", "name": n, "online": 1}
                    for n in ["node-a", "node-b"]]]
        if path == "/cluster/resources":
            return [{"type": self.kind, "vmid": i, "node": c["node"], "status": c.get("status", "stopped")}
                    for i, c in self.guests.items()]
        if path.endswith("/7900/config"):
            return copy.deepcopy(self.template)
        if path.endswith("/status") and "/storage/" in path:
            return {"active": 1, "enabled": 1, "avail": 500 * 1024**3}
        if path.endswith("/status") and "/tasks/" not in path:
            return {"memory": {"total": 32 * 1024**3, "used": 32 * 1024**3 - self.available}}
        if path.endswith("/firewall/options"):
            return {"enable": 1}
        if path.endswith("/pending"):
            return []
        if path.endswith("/status/current"):
            return {"status": self.guests[int(path.split("/")[4])].get("status", "stopped")}
        if path.endswith("/config"):
            return copy.deepcopy(self.guests[int(path.split("/")[4])])
        raise AssertionError(path)

    def mutate(self, method, path, **params):
        self.calls.append((method, path, params))
        if self.fail and path.endswith(self.fail):
            raise RuntimeError("simulated partial failure")
        if path.endswith("/clone"):
            self.guests[params["newid"]] = dict(self.template, node="node-a", template=0,
                description=params["description"], digest="b" * 40,
                **{k: params[k] for k in ["hostname", "name"] if k in params})
        elif path.endswith("/config"):
            self.guests[int(path.split("/")[4])].update({k: v for k, v in params.items() if k not in ["delete", "digest"]})
            for key in params.get("delete", "").split(","):
                self.guests[int(path.split("/")[4])].pop(key, None)
        elif path.endswith("/resize"):
            c = self.guests[int(path.split("/")[4])]
            c[params["disk"]] = "local-lvm:vm-800080-disk-0,size=" + params["size"]
        elif path.endswith("/migrate"):
            self.guests[int(path.split("/")[4])]["node"] = params["target"]
        elif path.endswith("/status/start"):
            self.guests[int(path.split("/")[4])]["status"] = "running"
        elif method == "delete":
            del self.guests[int(path.split("/")[4])]

    def enforce(self, r):
        self.calls.append(("enforce", "runtime", {}))
        return self.enforcement_ok

    def firewall(self, node, kind, vmid, text, apply):
        self.calls.append(("firewall", str(vmid), {}))
        if apply:
            self.fw[vmid] = text
        return self.fw.get(vmid) == text


def test_full_clone_is_stopped_configured_migrated_and_filtered_before_first_boot():
    m = module(); api = Fake()
    result = m.reconcile(request(), api)
    calls = [(method, path) for method, path, _ in api.calls]
    assert result["changed"]
    clone = next(p for method, p, a in api.calls if p.endswith("/clone"))
    assert ("create", clone) in calls
    params = next(a for _, p, a in api.calls if p == clone)
    assert params["full"] == 1 and "target" not in params
    migration = next(i for i, (_, p, _) in enumerate(api.calls) if p.endswith("/migrate"))
    boot = next(i for i, (_, p, _) in enumerate(api.calls) if p.endswith("/status/start"))
    assert migration < boot
    assert api.calls[migration][2]["online"] == 0
    assert any(method == "firewall" for method, _, _ in api.calls[:boot])
    c = api.guests[800080]
    assert c["node"] == "node-b" and "nesting" not in c.get("features", "")
    assert "ip=198.51.100.80/25" in c["net0"] and "firewall=1" in c["net0"]
    assert "unconfined" not in str(c) and c["unprivileged"] == 1
    assert "nesting=1" == api.template["features"]


@pytest.mark.parametrize("change", ["digest", "capacity", "collision", "unsafe_template", "extra_nic"])
def test_preconditions_fail_without_any_mutation(change):
    m = module(); api = Fake(); r = request()
    if change == "digest": api.template["digest"] = "c" * 40
    if change == "capacity": api.available = 6 * 1024**3 - 1
    if change == "collision": api.guests[800080] = {"node": "node-b", "hostname": "foreign", "digest": "d" * 40}
    if change == "unsafe_template": api.template["unprivileged"] = 0
    if change == "extra_nic": api.template["net1"] = "bridge=vnforeign"
    with pytest.raises(ValueError): m.reconcile(r, api)
    assert all(method == "get" for method, _, _ in api.calls)


def test_check_mode_only_reads():
    m = module(); api = Fake()
    assert m.reconcile(request(), api, check=True)["changed"]
    assert all(method == "get" for method, _, _ in api.calls)


def test_partial_migration_failure_is_stopped_and_requires_explicit_recovery():
    m = module(); api = Fake(); api.fail = "/migrate"
    with pytest.raises(RuntimeError): m.reconcile(request(), api)
    assert api.guests[800080]["node"] == "node-a"
    assert not any(p.endswith("/status/start") for _, p, _ in api.calls)
    api.fail = None; api.calls.clear()
    with pytest.raises(ValueError): m.reconcile(request(), api)
    assert all(method == "get" for method, _, _ in api.calls)


def test_reexecution_requires_digest_and_verifies_without_reconfiguring():
    m = module(); api = Fake(); r = request(); m.reconcile(r, api)
    r["expected_digest"] = "b" * 40; api.calls.clear()
    assert not m.reconcile(r, api)["changed"]
    assert all(method in ["get", "firewall", "enforce"] for method, _, _ in api.calls)
    r["expected_digest"] = "f" * 40
    with pytest.raises(ValueError): m.reconcile(r, api)


def test_final_resources_require_matching_s2_evidence_and_lab_cannot_impersonate_final():
    m = module(); api = Fake(); r = request(); r["scope"] = "production"
    with pytest.raises(ValueError): m.reconcile(r, api)
    r = request(); r["resource"]["name"] = "dc01.ad.example.invalid"
    with pytest.raises(ValueError): m.reconcile(r, api)
    assert not api.guests


def test_recovery_only_destroys_exact_stopped_owned_lab_and_digest():
    m = module(); api = Fake(); r = request(); r["boot"] = False; m.reconcile(r, api)
    r["action"] = "absent"; r["expected_digest"] = "b" * 40
    assert m.reconcile(r, api)["changed"] and not api.guests
    api.guests[800080] = {"node": "node-b", "hostname": "foreign", "digest": "b" * 40}
    with pytest.raises(ValueError): m.reconcile(r, api)


def test_guest_firewall_restricts_both_directions_and_same_l2():
    m = module(); text = m.firewall_text(request())
    assert "policy_in: DROP" in text and "policy_out: DROP" in text
    assert "ipfilter: 1" in text and "macfilter: 1" in text and "dhcp: 0" in text
    assert "[IPSET ipfilter-net0]" in text and "198.51.100.80" in text
    assert "IN ACCEPT -source 192.0.2.25/32 -p tcp -dport 22" in text
    assert "OUT ACCEPT -dest 192.0.2.123/32 -p udp -dport 123" in text
    assert "0.0.0.0/0" not in text


def test_qemu_fallback_uses_offline_local_disks_and_numeric_api_strings():
    m = module(); api = Fake(); api.kind = "qemu"; r = request()
    r["resource"]["kind"] = "qemu"; r["template"]["disk"] = "scsi0"
    api.template = {"template": 1, "digest": "a" * 40, "name": "tpl-debian", "ostype": "l26",
                    "scsi0": "local-lvm:base-7900-disk-0,size=16G", "memory": "2048", "sockets": 2, "balloon": 1024,
                    "net0": "virtio=02:00:5E:00:00:01,bridge=vnold", "ide2": "local-lvm:vm-7900-cloudinit,media=cdrom"}
    original = api.mutate
    def strings(method, path, **params):
        original(method, path, **params)
        if path.endswith("/config") and 800080 in api.guests:
            api.guests[800080]["memory"] = str(api.guests[800080]["memory"])
    api.mutate = strings
    assert m.reconcile(r, api)["changed"]
    migration = next(a for _, p, a in api.calls if p.endswith("/migrate"))
    assert migration["online"] == 0 and migration["with-local-disks"] == 1
    assert migration["targetstorage"] == "local-lvm"
    assert api.guests[800080]["sockets"] == 1 and api.guests[800080]["balloon"] == 0


@pytest.mark.parametrize("device", ["scsi1", "hostpci2", "usb3", "unused0", "efidisk0", "dev0", "virtiofs0", "parallel0", "serial0"])
def test_templates_with_extra_disks_or_passthrough_are_not_cloned(device):
    m = module(); api = Fake(); api.template[device] = "foreign:volume"
    with pytest.raises(ValueError): m.reconcile(request(), api)
    assert all(method == "get" for method, _, _ in api.calls)


def test_partial_source_clone_can_be_recovered_without_changing_identity():
    m = module(); api = Fake(); r = request(); api.fail = "/migrate"
    with pytest.raises(RuntimeError): m.reconcile(r, api)
    api.fail = None; r["action"] = "absent"; r["expected_digest"] = "b" * 40
    assert m.reconcile(r, api)["changed"] and not api.guests


def test_link_stays_disconnected_when_runtime_firewall_cannot_be_verified():
    m = module(); api = Fake(); api.enforcement_ok = False
    with pytest.raises(ValueError): m.reconcile(request(), api)
    assert "link_down=1" in api.guests[800080]["net0"]
    assert not any("link_down=0" in a.get("net0", "") for _, _, a in api.calls)


def test_first_boot_is_disconnected_until_effective_firewall_readback():
    m = module(); api = Fake(); m.reconcile(request(), api)
    boot = next(i for i, (_, p, _) in enumerate(api.calls) if p.endswith("/status/start"))
    enforce = next(i for i, (method, _, _) in enumerate(api.calls) if method == "enforce")
    linkup = next(i for i, (_, _, a) in enumerate(api.calls) if "link_down=0" in a.get("net0", ""))
    assert boot < enforce < linkup
    assert "link_down=1" in next(a["net0"] for _, _, a in api.calls[:boot] if "net0" in a)


def test_runtime_firewall_requires_unconditional_drop_and_bindings_in_both_families():
    m = module(); r = request(); iface = "veth800080i0"
    def family():
        return "\n".join(["*filter", f":{iface}-IN - [0:0]", f":{iface}-OUT - [0:0]",
            f"-A PVEFW-FWBR-IN -m physdev --physdev-out {iface} -j {iface}-IN",
            f"-A PVEFW-FWBR-OUT -m physdev --physdev-in {iface} -j {iface}-OUT",
            f"-A {iface}-OUT -m mac ! --mac-source 02:00:5e:70:00:80 -j DROP",
            f"-A {iface}-OUT -m set ! --match-set PVEFW-800080-ipfilter-net0-v4 src -j DROP",
            f"-A {iface}-IN -j DROP", f"-A {iface}-OUT -j DROP", "COMMIT"])
    valid = "Status: enabled/running\n" + family() + "\n" + family()
    assert hasattr(m, "runtime_firewall_ready"), "runtime policy verification missing"
    assert m.runtime_firewall_ready(r, valid)
    assert not m.runtime_firewall_ready(r, "Status: enabled/running\n" + family())
    assert not m.runtime_firewall_ready(r, valid.replace(f"-A {iface}-IN -j DROP", f"-A {iface}-IN -m conntrack --ctstate INVALID -j DROP"))
    assert not m.runtime_firewall_ready(r, valid.replace("--physdev-out " + iface, "--physdev-out foreign"))


def test_explicit_start_requires_stopped_owned_digest_and_effective_firewall():
    m = module(); api = Fake(); r = request(); r["boot"] = False; m.reconcile(r, api)
    r.update(action="start", boot=True, expected_digest="b" * 40)
    assert m.reconcile(r, api)["state"] == "started"
    assert api.guests[800080]["status"] == "running" and "link_down=0" in api.guests[800080]["net0"]
    with pytest.raises(ValueError): m.reconcile(r, api)


def test_start_of_absent_guest_never_clones():
    m = module(); api = Fake(); r = request(); r["action"] = "start"
    with pytest.raises(ValueError): m.reconcile(r, api)
    assert not api.guests


def test_api_normalization_of_tag_order_does_not_look_like_identity_drift():
    m = module(); api = Fake(); original = api.mutate
    def normalize(method, path, **params):
        original(method, path, **params)
        if path.endswith("/config") and 800080 in api.guests:
            api.guests[800080]["tags"] = ";".join(sorted(api.guests[800080]["tags"].split(";")))
    api.mutate = normalize
    assert m.reconcile(request(), api)["state"] == "created"


def test_explicit_start_rechecks_host_reserve_after_offline_preparation():
    m = module(); api = Fake(); r = request(); r["boot"] = False; m.reconcile(r, api)
    api.available = 6 * 1024**3 - 1; api.calls.clear()
    r.update(action="start", boot=True, expected_digest="b" * 40)
    with pytest.raises(ValueError): m.reconcile(r, api)
    assert all(method in ["get", "firewall"] for method, _, _ in api.calls)
    assert api.guests[800080].get("status", "stopped") == "stopped"


def test_start_does_not_count_own_ram_reservation_twice_or_change_foreign_guests():
    m = module(); api = Fake(); original_get = api.get
    api.guests[800081] = {"node": "node-b", "hostname": "foreign", "memory": 23 * 1024,
                         "digest": "f" * 40}
    foreign = api.guests[800081].copy()
    def reserved(path):
        result = original_get(path)
        if path == "/cluster/resources":
            for guest in result:
                guest["maxmem"] = int(api.guests[guest["vmid"]].get("memory", 0)) * 1024**2
        return result
    api.get = reserved
    r = request(); r["boot"] = False; m.reconcile(r, api)
    r.update(action="start", boot=True, expected_digest="b" * 40)
    assert m.reconcile(r, api)["state"] == "started"
    assert api.guests[800081] == foreign
