"""S2 lifecycle guards; all PVE effects use the existing simulated cluster."""
import pytest

from test_samba_ad_guest import Fake, module, request


class LabFake(Fake):
    def __init__(self):
        super().__init__()
        self.shutdown_stuck = False
        self.residue = False

    def assert_lab_firewall(self, r):
        content = self.fw.get(r["resource"]["vmid"])
        if content is not None and content != module().firewall_text(r):
            raise ValueError("foreign firewall")

    def cleanup_readback(self, r, volumes):
        if self.residue or r["resource"]["vmid"] in self.guests:
            raise ValueError("cleanup incomplete")

    def mutate(self, method, path, **params):
        if path.endswith("/status/shutdown"):
            self.calls.append((method, path, params))
            assert params == {"timeout": 60, "forceStop": 0}
            if not self.shutdown_stuck:
                self.guests[int(path.split("/")[4])]["status"] = "stopped"
        else:
            super().mutate(method, path, **params)


def owned():
    m = module(); api = LabFake(); r = request()
    m.reconcile(r, api)
    r["expected_digest"] = "b" * 40
    api.calls.clear()
    return m, api, r


def test_explicit_lab_stop_and_absent_never_force_shutdown():
    m, api, r = owned(); r["action"] = "stop"
    assert m.reconcile(r, api)["state"] == "stopped"
    assert api.guests[800080]["status"] == "stopped"
    api.calls.clear()
    assert m.reconcile(r, api)["changed"] is False
    assert not any(p.endswith("/status/shutdown") for _, p, _ in api.calls)
    r["action"] = "absent"
    assert m.reconcile(r, api)["state"] == "absent"
    assert not api.guests


@pytest.mark.parametrize("change", ["owner", "digest", "production", "firewall", "policy"])
def test_stop_absent_refuse_foreign_or_stale(change):
    m, api, r = owned(); r["action"] = "stop"
    if change == "owner": api.guests[800080]["description"] = "foreign"
    if change == "digest": r["expected_digest"] = "c" * 40
    if change == "production": r["scope"] = "production"
    if change == "firewall": api.fw[800080] = "foreign"
    if change == "policy": r["firewall"]["flows"][0]["port"] = "443"
    with pytest.raises(ValueError): m.reconcile(r, api)
    assert not any(method in ["create", "set", "delete"] for method, _, _ in api.calls)
    assert api.guests[800080]["status"] == "running"


def test_shutdown_timeout_does_not_delete_or_retry():
    m, api, r = owned(); r["action"] = "stop"; api.shutdown_stuck = True
    with pytest.raises(ValueError): m.reconcile(r, api)
    assert api.guests[800080]["status"] == "running"
    assert sum(p.endswith("/status/shutdown") for _, p, _ in api.calls) == 1
    r["action"] = "absent"
    with pytest.raises(ValueError): m.reconcile(r, api)


def test_stop_check_mode_does_not_mutate_and_cleanup_residue_is_failure():
    m, api, r = owned(); r["action"] = "stop"
    assert m.reconcile(r, api, check=True)["state"] == "planned_stop"
    assert api.guests[800080]["status"] == "running"
    assert not any(method == "create" for method, _, _ in api.calls)
    m.reconcile(r, api); r["action"] = "absent"; api.residue = True
    with pytest.raises(ValueError): m.reconcile(r, api)


def test_cleanup_rejects_foreign_firewall_before_delete():
    m, api, r = owned(); api.guests[800080]["status"] = "stopped"
    r["action"] = "absent"; api.fw[800080] = "unowned"
    with pytest.raises(ValueError): m.reconcile(r, api)
    assert 800080 in api.guests


def test_owned_zfs_subvolume_and_foreign_disk_are_distinguished():
    m = module(); r = request()
    r["resource"]["storage"] = r["template"]["storage"] = "local-zfs"
    assert m.owned_volumes(r, {"rootfs": "local-zfs:subvol-800080-disk-0,size=64G"}) == [
        "local-zfs:subvol-800080-disk-0"]
    with pytest.raises(ValueError):
        m.owned_volumes(r, {"rootfs": "local-zfs:subvol-800081-disk-0,size=64G"})


def test_real_cleanup_adapter_refuses_owned_volume_without_vmid_metadata(monkeypatch):
    m = module(); api = m.Pvesh(); r = request(); reads = []
    monkeypatch.setattr(api, "assert_firewall_absent", lambda r: None)

    def get(path, **params):
        reads.append(path)
        return [] if path == "/cluster/resources" else [{"volid": "local-lvm:vm-800080-disk-0"}]
    monkeypatch.setattr(api, "get", get)
    with pytest.raises(ValueError): api.cleanup_readback(r, [])
    assert reads[0] == "/cluster/resources"
