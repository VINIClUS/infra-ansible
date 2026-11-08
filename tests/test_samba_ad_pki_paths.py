"""Readonly guards must refuse foreign paths before role file/user mutations."""
from types import SimpleNamespace

import pytest


def test_future_directory_rejects_redirected_or_writable_ancestors(tmp_path):
    from tools.samba_ad import pki_files
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        pki_files.future_directory(alias / "child")
    target.chmod(0o777)
    with pytest.raises(ValueError):
        pki_files.future_directory(target / "child")
    target.chmod(0o700)
    assert pki_files.future_directory(target / "new" / "nested") == target / "new" / "nested"


@pytest.mark.parametrize("case", ["dedicated", "uid0", "shared_home", "login_shell", "shared_group", "shared_uid", "shared_primary_group"])
def test_ca_account_guard_refuses_existing_foreign_accounts(monkeypatch, case):
    import pwd
    import grp
    from tools.samba_ad import pki_ca
    from test_samba_ad_pki_ca_config import request
    r = request()
    account = SimpleNamespace(pw_uid=987, pw_gid=987, pw_dir=r["paths"]["ca_state"],
                              pw_shell="/usr/sbin/nologin")
    group = SimpleNamespace(gr_gid=987, gr_mem=[])
    if case == "uid0": account.pw_uid = 0
    if case == "shared_home": account.pw_dir = "/home/shared"
    if case == "login_shell": account.pw_shell = "/bin/sh"
    if case == "shared_group": group.gr_mem = ["other"]
    accounts = [SimpleNamespace(pw_name=r["service_user"], pw_uid=987, pw_gid=987)]
    if case == "shared_uid": accounts.append(SimpleNamespace(pw_name="other", pw_uid=987, pw_gid=988))
    if case == "shared_primary_group": accounts.append(SimpleNamespace(pw_name="other", pw_uid=988, pw_gid=987))
    monkeypatch.setattr(pwd, "getpwnam", lambda _: account)
    monkeypatch.setattr(grp, "getgrnam", lambda _: group)
    monkeypatch.setattr(pwd, "getpwall", lambda: accounts)
    if case == "dedicated":
        assert pki_ca.service_account(r) is account
    else:
        with pytest.raises(ValueError):
            pki_ca.service_account(r)


def test_ca_inspector_requires_a_verified_public_chain(tmp_path, monkeypatch):
    from tools.samba_ad import pki_ca
    from test_samba_ad_pki_ca_config import request
    r = request()
    binary = tmp_path / "binary"
    binary.write_bytes(b"test-only"); binary.chmod(0o700)
    import hashlib
    for artifact in r["tools"].values():
        artifact["sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    password = tmp_path / "password"; password.write_bytes(b"test-only"); password.chmod(0o600)
    key = tmp_path / "key"; key.write_bytes(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nTEST ONLY"); key.chmod(0o600)
    bad_cert = tmp_path / "cert"; bad_cert.write_bytes(b"not a certificate")
    def file(filename, **kwargs):
        if filename == r["paths"]["issuer_key"]: return key
        if filename == r["paths"]["issuer_password_ref"]: return password
        if filename in [r["paths"]["root_cert"], r["paths"]["issuer_cert"]]: return bad_cert
        return binary
    monkeypatch.setattr(pki_ca, "secure_file", file)
    class Host:
        def inspect(self, target):
            return target | {"uid": 0, "virtualization": "kvm", "addresses": [target["address"]]}
    with pytest.raises(ValueError):
        pki_ca.inspect(r, Host())
