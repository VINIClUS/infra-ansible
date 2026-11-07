"""No native probe, file creation, xattr, fork or ACL runs on the test host."""
import copy
import errno
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def module():
    path = Path(__file__).resolve().parents[1] / "tools/samba_ad/guest_probe.py"
    assert path.is_file(), "guest-only protected probe missing"
    spec = importlib.util.spec_from_file_location("guest_probe", path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def expected():
    return {"run_id": "a" * 32, "host_namespaces": {n: n + ":[1]" for n in ["user", "mnt", "pid"]},
            "guest": {"hostname": "probe.lab.ad.test", "euid": 0,
                      "namespaces": {n: n + ":[2]" for n in ["user", "mnt", "pid"]},
                      "uid_map": "0 100000 65536", "apparmor": "lxc-test (enforce)",
                      "filesystem": "ext4", "parent_dev": 10, "parent_ino": 20,
                      "boot_id": "b" * 32, "cgroup": "0::/init.scope"}}


class Ops:
    def __init__(self):
        self.current = copy.deepcopy(expected()["guest"])
        self.created = False; self.cleaned = False; self.replaced = False
        self.errors = []; self.acl_error = None; self.ntacl_calls = 0

    def identity(self): return self.current

    def create(self, run_id, parent):
        self.created = True
        return "owned-fd"

    def ntacl(self, handle):
        assert handle == "owned-fd"; self.ntacl_calls += 1
        if self.errors:
            code = self.errors.pop(0)
            if code: raise OSError(code, "sensitive error must not escape")

    def acl(self, handle):
        if self.acl_error: raise OSError(self.acl_error, "sensitive error")

    def cleanup(self, handle):
        assert handle == "owned-fd"
        if self.replaced: raise ValueError("entry replaced")
        self.cleaned = True


@pytest.mark.parametrize("change", ["host_ns", "uid_map", "hostname", "tmpfs", "apparmor", "device"])
def test_probe_rejects_host_identity_before_open(change):
    m = module(); ops = Ops()
    if change == "host_ns": ops.current["namespaces"]["mnt"] = "mnt:[1]"
    if change == "uid_map": ops.current["uid_map"] = "0 0 4294967295"
    if change == "hostname": ops.current["hostname"] = "host"
    if change == "tmpfs": ops.current["filesystem"] = "tmpfs"
    if change == "apparmor": ops.current["apparmor"] = "unconfined"
    if change == "device": ops.current["parent_dev"] = 11
    result = m.run_probe(expected(), ops)
    assert result["status"] == "operational_error"
    assert not ops.created


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES, errno.EOPNOTSUPP])
def test_reproduced_protected_failure_is_conclusive_and_cleans_own_file(code):
    m = module(); ops = Ops(); ops.errors = [code, code]
    result = m.run_probe(expected(), ops)
    assert result["status"] == "incompatible"
    assert result["checks"][0]["attempts"] == [errno.errorcode[code]] * 2
    assert ops.ntacl_calls == 2 and ops.cleaned


@pytest.mark.parametrize("errors", [[errno.ENOSPC], [errno.EINVAL], [errno.EPERM, None]])
def test_operational_or_nonreproduced_error_never_becomes_incompatibility(errors):
    m = module(); ops = Ops(); ops.errors = errors
    result = m.run_probe(expected(), ops)
    assert result["status"] == "operational_error"
    assert ops.cleaned
    assert "sensitive" not in str(result)


def test_positive_probe_is_only_two_checks_and_always_cleans():
    m = module(); ops = Ops()
    result = m.run_probe(expected(), ops)
    assert result["status"] == "passed"
    assert [c["name"] for c in result["checks"]] == ["security_ntacl", "posix_acl"]
    assert result["cleanup"] == "complete" and ops.cleaned
    assert "selection" not in result


def test_probe_cleanup_refuses_replaced_entry():
    m = module(); ops = Ops(); ops.replaced = True
    result = m.run_probe(expected(), ops)
    assert result["status"] == "operational_error"
    assert result["cleanup"] == "incomplete" and not ops.cleaned


def test_native_cleanup_checks_inode_and_closes_fds_without_unlinking_substitute(monkeypatch):
    m = module(); effects = []
    original = SimpleNamespace(st_dev=10, st_ino=20)
    monkeypatch.setattr(m.os, "stat", lambda *a, **kw: SimpleNamespace(st_dev=10, st_ino=21, st_mode=0o100600))
    monkeypatch.setattr(m.os, "unlink", lambda *a, **kw: effects.append("unlink"))
    monkeypatch.setattr(m.os, "close", lambda fd: effects.append(fd))
    with pytest.raises(ValueError):
        m.NativeOps().cleanup({"fd": 90, "dir": 91, "name": "exclusive", "inode": original})
    assert effects == [90, 91]
