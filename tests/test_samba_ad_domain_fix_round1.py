"""F1-F5 source regressions. No host install, services, secrets or native Samba."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import types
import pytest
from tools.samba_ad import domain, domain_source as source

FIXTURE = Path(__file__).parent / "fixtures/samba_ad_vendor_runtime.json"

def metadata(): return json.loads(FIXTURE.read_text())
def pins(): return {r["Package"]: r["Version"] for r in metadata()}

def test_f1_five_packages_do_not_cover_runtime():
    incomplete = {n: v for n, v in pins().items() if n in ["samba", "samba-ad-dc", "python3-samba", "libldb2", "python3-ldb"]}
    with pytest.raises(ValueError): source.validate_pins(incomplete)


def test_f1_authenticated_edges_and_base_constraints_are_distinct():
    plan = source.dependency_plan(metadata(), pins())
    assert set(plan["vendor"]) == set(pins())
    assert "libngtcp2-16" in plan["vendor"]
    assert not any(term[0] in ["libndr6", "libsmbldap2"] for group in plan["base"] for term in group)
    assert any(term[0] == "python3" and term[1:] == ("<<", "3.14") for group in plan["base"] for term in group)
    changed = pins(); changed["samba-libs"] = "2:4.25.1+dfsg-99"
    with pytest.raises(ValueError): source.dependency_plan(metadata(), changed)
    for missing in ["samba-dsdb-modules", "libtalloc2", "python3-tdb"]:
        changed = pins(); changed.pop(missing)
        with pytest.raises(ValueError): source.dependency_plan(metadata(), changed)


def test_f2_modified_provision_ldif_refused_before_any_write(monkeypatch, tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tar:
        entry = tarfile.TarInfo("./usr/share/samba/setup/provision_users.ldif")
        payload = b"signed provisioning input"; entry.size = len(payload)
        tar.addfile(entry, io.BytesIO(payload))
    monkeypatch.setattr(source, "verified_archives", lambda _: [("samba-ad-provision", "4.25.1", tmp_path / "test.deb")])
    monkeypatch.setattr(source, "verify_base_dependencies", lambda _: None, raising=False)
    def command(argv):
        if argv[0] == "dpkg-query": return b"installed 4.25.1"
        assert argv[:2] == ["dpkg-deb", "--fsys-tarfile"]
        return data.getvalue()
    monkeypatch.setattr(source, "command", command)
    class Changed:
        def read_bytes(self): return b"modified schema/LDIF"
    monkeypatch.setattr(source, "secure_file", lambda *a, **kw: Changed())
    with pytest.raises(ValueError): source.verify_installed({})


def test_f4_selective_rc_policy_is_not_a_no_start_policy(monkeypatch, tmp_path):
    policy = tmp_path / "policy-rc.d"
    policy.write_text('#!/bin/sh\n[ "$1 $2" = "samba-ad-dc start" ] && exit 101\nexit 0\n'); policy.chmod(0o700)
    monkeypatch.setattr(source, "secure_file", lambda *a, **kw: policy)
    monkeypatch.setattr(source, "verified_archives", lambda _: [])
    monkeypatch.setattr(source, "verify_base_dependencies", lambda _: None, raising=False)
    monkeypatch.setattr(source, "verify_installed", lambda _: None)
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a[0], 101, b"", b""))
    writes=[]; monkeypatch.setattr(source, "command", lambda argv: writes.append(argv))
    with pytest.raises(ValueError): source.install({"fingerprint": domain.CANDIDATE_PRIMARY, "key_sha256": domain.CANDIDATE_KEY_SHA256})
    assert writes == []
    assert "exit 0" in policy.read_text()


@pytest.mark.parametrize("quality_error", [False, True])
def test_f5_native_quality_failure_precedes_config_and_database(monkeypatch, capsys, quality_error):
    samba = types.ModuleType("samba"); samba.version = "4.25.1"
    def quality(password):
        if quality_error:
            print(password); print(password, file=sys.stderr)
            raise RuntimeError("native failure: " + password)
        return False
    samba.check_password_quality = quality
    auth = types.ModuleType("samba.auth"); auth.system_session = lambda: object()
    dsdb = types.ModuleType("samba.dsdb"); dsdb.DS_DOMAIN_FUNCTION_2016 = 7
    provision = types.ModuleType("samba.provision"); mutations=[]
    provision.provision = lambda *args, **kwargs: mutations.append("database")
    for m in [samba, auth, dsdb, provision]: monkeypatch.setitem(sys.modules, m.__name__, m)
    class Weak:
        def read_text(self): return "abcdefghijklmn\n"
    monkeypatch.setattr(domain, "secure_file", lambda *a, **kw: Weak())
    class Native(domain.Native):
        def inspect(self, request): return "provision"
        def prepare_config(self, request): mutations.append("config")
        def database(self): return object()
    r={"target":{"realm":"AD.EXAMPLE.INVALID","netbios":"EXAMPLE"},"substrate":{"resource":{"address":"198.51.100.10/25"}}}
    with pytest.raises(ValueError) as error: Native({}).provision(r)
    assert mutations == []
    assert "abcdefghijklmn" not in str(error.value)
    output=capsys.readouterr(); assert "abcdefghijklmn" not in output.out+output.err


@pytest.mark.parametrize("mask_scope", ["etc", "run"])
def test_f3_masks_member_units_and_unmasks_dc_before_database(tmp_path, mask_scope):
    from tools.samba_ad.domain_services import ServiceOps, MEMBERS, DC
    units = tmp_path / "usr/lib/systemd/system"; units.mkdir(parents=True)
    for name in [*MEMBERS, DC]:
        (units / name).write_text("[Service]\nExecStart=/usr/sbin/samba\n"); (units/name).chmod(0o644)
    masks=tmp_path / "etc/systemd/system"; masks.mkdir(parents=True)
    runtime=tmp_path / "run/systemd/system"; runtime.mkdir(parents=True)
    ((masks if mask_scope=="etc" else runtime)/DC).symlink_to("/dev/null")
    states = {name: {"LoadState":"loaded", "UnitFileState":"enabled", "ActiveState":"inactive", "SubState":"dead", "FragmentPath":"/usr/lib/systemd/system/"+name, "DropInPaths":""} for name in [*MEMBERS, DC]}
    states[DC].update(LoadState="masked",UnitFileState="masked" if mask_scope=="etc" else "masked-runtime",FragmentPath="/dev/null")
    for item in tmp_path.rglob("*"):
        if item.is_dir(): item.chmod(0o755)
    calls=[]
    def run(argv, **kwargs):
        if argv[1] == "daemon-reload": calls.append(argv); return b""
        unit=argv[-1]
        if argv[1] == "show": return "".join(f"{k}={v}\n" for k,v in states[unit].items()).encode()
        calls.append(argv)
        action=argv[2] if argv[1]=="--runtime" else argv[1]
        if action=="disable": states[unit]["UnitFileState"]="disabled"
        elif action=="mask":
            (masks/unit).symlink_to("/dev/null"); states[unit].update(LoadState="masked",UnitFileState="masked",FragmentPath="/dev/null")
        elif action=="unmask":
            ((runtime if "--runtime" in argv else masks)/unit).unlink(); states[unit].update(LoadState="loaded",UnitFileState="disabled",FragmentPath="/usr/lib/systemd/system/"+unit)
        elif action=="enable": states[unit]["UnitFileState"]="enabled"
        else: pytest.fail("unexpected service mutation")
        return b""
    ops=ServiceOps(root=tmp_path, run=run)
    before=ops.inspect(initial=True)
    ops.converge_initial(before)
    assert states[DC]["UnitFileState"]=="enabled" and states[DC]["ActiveState"]=="inactive"
    assert all(states[n]["UnitFileState"]=="masked" for n in MEMBERS)
    assert not any(any(v in ["start","stop","restart"] for v in c) for c in calls)
    states[DC].update(ActiveState="active",SubState="running")
    count=len(calls); ops.inspect(initial=False); assert len(calls)==count
    states["winbind.service"]["UnitFileState"]="enabled"
    with pytest.raises(ValueError): ops.inspect(initial=False)
    assert len(calls)==count
    states["winbind.service"]["UnitFileState"]="masked"
    (masks/DC).symlink_to("/dev/null")
    states[DC].update(LoadState="masked",UnitFileState="masked",FragmentPath="/dev/null",ActiveState="inactive")
    with pytest.raises(ValueError): ops.inspect(initial=False)
    assert len(calls)==count
    (masks/DC).unlink(); states[DC].update(LoadState="loaded",UnitFileState="enabled",ActiveState="active",FragmentPath="/usr/lib/systemd/system/"+DC)
    states[DC]["FragmentPath"]="/etc/systemd/system/foreign.service"
    with pytest.raises(ValueError): ops.inspect(initial=False)


def test_f1_base_python_bounds_and_libc_are_checked_separately(monkeypatch,tmp_path):
    payload="\n\n".join("\n".join(f"{k}: {v}" for k,v in row.items()) for row in metadata()).encode()
    path=tmp_path/"Packages"; path.write_bytes(payload);path.chmod(0o600)
    spec={"directory":str(tmp_path),"packages":pins(),"packages_sha256":source.hashlib.sha256(payload).hexdigest()}
    versions={"python3":"3.13.5"}; real_run=source.subprocess.run
    def run(argv,**kwargs):
        if argv[0]=="dpkg-query": return subprocess.CompletedProcess(argv,0,("installed "+versions.get(argv[-1],"999:999")).encode(),b"")
        assert argv[:2]==["dpkg","--compare-versions"]
        return real_run(argv,**kwargs)
    monkeypatch.setattr(source.subprocess,"run",run)
    source.verify_base_dependencies(spec)
    versions["python3"]="3.14.0"
    with pytest.raises(ValueError): source.verify_base_dependencies(spec)
    versions["python3"]="3.13.5";versions["libc6"]="2.37"
    with pytest.raises(ValueError): source.verify_base_dependencies(spec)


def test_f3_failed_initial_transition_cannot_replace_config_or_enter_provision(monkeypatch):
    from tools.samba_ad import pki_files
    samba = types.ModuleType("samba"); samba.version="4.25.1"; samba.check_password_quality=lambda _: True
    auth=types.ModuleType("samba.auth");auth.system_session=lambda:object()
    dsdb=types.ModuleType("samba.dsdb");dsdb.DS_DOMAIN_FUNCTION_2016=7
    provision=types.ModuleType("samba.provision");writes=[]
    provision.provision=lambda *a,**kw:writes.append("database")
    for m in [samba,auth,dsdb,provision]: monkeypatch.setitem(sys.modules,m.__name__,m)
    baseline=b"reviewed baseline"
    class Protected:
        def read_text(self): return "Strong_SYNTHETIC_123!"
        def read_bytes(self): return baseline
    monkeypatch.setattr(domain,"secure_file",lambda *a,**kw:Protected())
    monkeypatch.setattr(pki_files,"atomic_file",lambda *a,**kw:writes.append("config"))
    class Fail:
        def converge_initial(self, expected): raise ValueError("unit transition failed")
    class Native(domain.Native):
        def inspect(self, request): self.services=Fail();self.service_snapshot={};return "provision"
        def database(self): return object()
    r={"identity":{"config_sha256":domain.hashlib.sha256(baseline).hexdigest()},
       "target":{"realm":"AD.EXAMPLE.INVALID","netbios":"EXAMPLE"},
       "substrate":{"resource":{"address":"198.51.100.10/25"}}}
    with pytest.raises(ValueError): Native({}).provision(r)
    assert writes==[]


def test_f4_canonical_deny_all_preserved_and_all_service_actions_denied(monkeypatch,tmp_path):
    policy=tmp_path/"policy-rc.d";policy.write_bytes(source.DENY_ALL_POLICY);policy.chmod(0o700)
    monkeypatch.setattr(source,"secure_file",lambda *a,**kw:policy)
    monkeypatch.setattr(source,"verified_archives",lambda _:[])
    monkeypatch.setattr(source,"verify_base_dependencies",lambda _:None)
    monkeypatch.setattr(source,"verify_installed",lambda _:None)
    probes=[]
    def run(argv,**kwargs): probes.append(argv[1:]);return subprocess.CompletedProcess(argv,101,b"",b"")
    monkeypatch.setattr(source.subprocess,"run",run)
    installs=[];monkeypatch.setattr(source,"command",lambda argv:installs.append(argv))
    source.install({"fingerprint":domain.CANDIDATE_PRIMARY,"key_sha256":domain.CANDIDATE_KEY_SHA256})
    assert {tuple(v) for v in probes}=={(s,a) for s in ["samba","samba-ad-dc","smbd","nmbd","winbind"] for a in ["start","stop","restart","reload","force-reload","try-restart","reload-or-restart","try-reload-or-restart"]}
    assert installs==[["dpkg","--install"]]
    assert policy.read_bytes()==source.DENY_ALL_POLICY


def test_f2_signed_hardlinked_provision_data_are_verified(monkeypatch,tmp_path):
    data=io.BytesIO();payload=b"immutable shared schema"
    with tarfile.open(fileobj=data,mode="w") as tar:
        original=tarfile.TarInfo("./usr/share/samba/setup/schema.ldif");original.size=len(payload)
        tar.addfile(original,io.BytesIO(payload))
        alias=tarfile.TarInfo("./usr/share/samba/setup/schema-alias.ldif");alias.type=tarfile.LNKTYPE;alias.linkname=original.name
        tar.addfile(alias)
    monkeypatch.setattr(source,"verified_archives",lambda _:[("samba-ad-provision","4.25.1",tmp_path/"test.deb")])
    monkeypatch.setattr(source,"verify_base_dependencies",lambda _:None)
    monkeypatch.setattr(source,"command",lambda argv:b"installed 4.25.1" if argv[0]=="dpkg-query" else data.getvalue())
    reads=[]
    class Signed:
        def read_bytes(self):return payload
    def read(path,**kwargs):reads.append(str(path));return Signed()
    monkeypatch.setattr(source,"secure_file",read)
    source.verify_installed({})
    assert set(reads)=={"/usr/share/samba/setup/schema.ldif","/usr/share/samba/setup/schema-alias.ldif"}


def test_f3_missing_legacy_alias_is_maskable_without_inventing_a_vendor_unit(monkeypatch,tmp_path):
    from tools.samba_ad.domain_services import ServiceOps,MEMBERS,DC
    directory=tmp_path/"usr/lib/systemd/system";directory.mkdir(parents=True)
    for unit in [*MEMBERS[1:],DC]:
        path=directory/unit;path.write_text("[Service]\nExecStart=/usr/sbin/samba\n");path.chmod(0o644)
    for path in tmp_path.rglob("*"):
        if path.is_dir():path.chmod(0o755)
    def run(argv,**kwargs):
        unit=argv[-1];missing=unit=="samba.service"
        values={"LoadState":"not-found" if missing else "loaded","UnitFileState":"" if missing else "disabled","ActiveState":"inactive","SubState":"dead","FragmentPath":"" if missing else "/usr/lib/systemd/system/"+unit,"DropInPaths":""}
        return subprocess.CompletedProcess(argv,1 if missing else 0,"".join(f"{k}={v}\n" for k,v in values.items()).encode(),b"")
    monkeypatch.setattr(domain.subprocess,"run",run)
    observed=ServiceOps(root=tmp_path).inspect(initial=True)
    assert observed["samba.service"]["LoadState"]=="not-found"
    assert observed["smbd.service"]["LoadState"]=="loaded"
