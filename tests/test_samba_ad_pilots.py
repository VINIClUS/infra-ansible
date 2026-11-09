"""Synthetic failure cases; these are never infrastructure acceptance evidence."""
import copy
import importlib
import json
from pathlib import Path
import subprocess

import pytest


def mod():
    return importlib.import_module("tools.samba_ad.pilots")


def test_membership_never_adopts_or_rejoins_an_unowned_account():
    m = mod()
    assert m.membership_action(False, None, "owned", "S-1-5-21-1-2-3", None) == "join"
    assert m.membership_action(True, "owned", "owned", "S-1-5-21-1-2-3", "S-1-5-21-1-2-3") == "verify"
    for member, owner, sid in [(False, "foreign", None), (True, "foreign", "S-1-5-21-1-2-3"),
                                (True, "owned", "S-1-5-21-4-5-6"), (False, "owned", None)]:
        with pytest.raises(ValueError):
            m.membership_action(member, owner, "owned", "S-1-5-21-1-2-3", sid)


def test_secret_qga_transport_never_uses_argv_or_encoded_command(monkeypatch):
    m = mod(); calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, json.dumps({"exited": 1, "exitcode": 0,
            "out-data": '{"state":"checked"}'}), "")
    monkeypatch.setattr(m.subprocess, "run", run)
    result = m.qga(12345, ["powershell.exe", "-NoProfile", "-Command", "PUBLIC_SCRIPT"],
                   {"password": "SENTINEL-NOT-ARGV"})
    assert result == {"state": "checked"}
    argv, kwargs = calls[0]
    assert argv[:7] == ["qm", "guest", "exec", "12345", "--pass-stdin", "1", "--synchronous"]
    assert "SENTINEL" not in repr(argv)
    assert "SENTINEL-NOT-ARGV" in kwargs["input"]
    assert kwargs["timeout"] <= 600


@pytest.mark.parametrize("result", [
    {"exited": 0, "pid": 22}, {"exited": 1, "exitcode": 1, "err-data": "SECRET"},
    {"exited": 1, "exitcode": 0, "out-truncated": True, "out-data": "{}"},
])
def test_qga_partial_failure_is_generic_and_never_retries(monkeypatch, result):
    m = mod(); calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, json.dumps(result), "SECRET")
    monkeypatch.setattr(m.subprocess, "run", run)
    with pytest.raises(ValueError, match="values suppressed") as exc:
        m.qga(12345, ["public"], {"password": "SECRET"})
    assert "SECRET" not in str(exc.value) and len(calls) == 1


def test_stale_or_disagreeing_dc_evidence_cannot_unlock_join():
    m = mod(); now = 2000
    r = {"sid": "S-1-5-21-1-2-3", "dcs": {k: {"fqdn": k + ".ad.test", "machine_id": k}
         for k in ["dc01", "dc02"]}}
    records = [{"schema": "samba-ad-pilot-dc/v1", "role": k, "fqdn": v["fqdn"],
                "machine_id": v["machine_id"], "sid": r["sid"], "observed": now,
                "sysvol_sha256": "a" * 64, "request_sha256": m.sha(r)} for k, v in r["dcs"].items()]
    m.dc_evidence(r, records, now)
    for field, value in [("observed", now-301), ("sid", "S-1-5-21-3-2-1"),
                          ("sysvol_sha256", "b"*64), ("request_sha256", "f"*64)]:
        broken = copy.deepcopy(records); broken[1][field] = value
        with pytest.raises(ValueError): m.dc_evidence(r, broken, now)
    with pytest.raises(ValueError): m.dc_evidence(r, records[:1], now)


def test_no_new_pilot_flow_in_automatic_main():
    root = Path(__file__).resolve().parents[1]
    for p in (root / ".github/workflows").glob("*"):
        assert "samba-ad-pilots.yml" not in p.read_text()


def pilot_request(windows=False):
    from test_samba_ad_domain import request as domain_request
    from test_samba_ad_guest import request as guest_request
    m = mod(); domain, manifest = domain_request()
    role = "windows_pilot" if windows else "linux_pilot"
    declared = manifest["resources"][role]
    s = guest_request()
    s.update(scope="production", apply=False, expected_digest="f"*40)
    s["resource"] = {k: declared[k] for k in ["vmid", "node", "kind", "mac", "bridge", "storage", "cores", "memory_mib", "disk_gib"]}
    s["resource"].update(name=declared["fqdn"], address=declared["address"] + "/25",
                         gateway=manifest["network"]["gateway"], mtu=manifest["network"]["mtu"])
    s["template"] = {k: declared["template"][k] for k in ["node", "vmid", "storage"]} | {"disk": "scsi0", "digest": "a"*40}
    template = {k: s["template"][k] for k in ["node", "vmid", "digest"]} | {"kind": "qemu"}
    review = "git:" + "a"*40 + ":reviews/pilot.json"
    data = {"schema": "samba-ad-pilot-substrate/v1", "purpose": role, "manifest": manifest,
            "target_sha256": m.sha({k:s[k] for k in ["owner", "scope", "resource", "template", "firewall"]}),
            "clone_uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "provenance": {"reviewed_config_revision": "a"*40, "review_ref": review,
                "path": "inventories/prod/contracts/samba-ad-" + role.replace("_", "-") + ".yml"},
            "report": {"schema": "samba-ad-pilot-template-observation/v1", "artifact_sha256": "b"*64,
                "review_ref": review, "platform_fingerprint": {
                    "nodes": {n: {"kernel":"test-kernel", "pve":"test-pve"} for n in {declared["node"], template["node"]}},
                    "templates": [template], "isolation":"qemu-no-passthrough", "policy_sha256":m.sha(s["firewall"])},
                "subject": {"node":declared["node"], "template":template,"config_digest":"a"*40,
                    "boot_id":"a"*32,"uuid":"bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", "mac":"02:00:5E:00:AA:01"},
                "template_observation": {"family":"windows" if windows else "debian", "edition":"ServerStandard" if windows else "13",
                    "build":"26100" if windows else "13", "architecture":"x86_64", "machine_id":"b"*32,
                    "local_sid":"S-1-5-21-4-5-6" if windows else None,
                    "image_state":"IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE" if windows else "machine-id-empty", "domain":None}}}
    s["compatibility"] = {"sha256":m.sha(data), "data":data}
    r = {"schema":"samba-ad-pilot/v1", "enabled":True,"apply":False,"action":"prepare","pilot":role,
         "substrate":s,"identity":{"uuid":data["clone_uuid"],"machine_id":"c"*32,
             "boot_id":"aaaaaaaa-aaaa-bbbb-cccc-dddddddddddd","interface":"Ethernet" if windows else "eth0",
             "local_sid":"S-1-5-21-7-8-9" if windows else None},
         "sid":"S-1-5-21-1-2-3","dcs":{k:{"fqdn":v["fqdn"],"address":v["address"],
              "machine_id":("d" if k=="dc01" else "e")*32,"boot_id":"aaaaaaaa-aaaa-bbbb-cccc-dddddddddddd",
              "source":copy.deepcopy(domain["source"]),"certificate_sha256":"a"*64}
              for k,v in manifest["resources"].items() if k in ["dc01","dc02"]},
         "trust":{},"ou":"OU=Samba-Pilot-aaaaaaaaaaaaaaaa,DC=ad,DC=example,DC=invalid",
         "provenance":{"private_revision":"b"*40,"review_ref":review},"linux":None,"windows":None,
         "credential_ref":"/run/samba-ad-pilot-credentials/"+role+"/join.json"}
    import hashlib
    for name in ["root","issuer"]:
        pem="-----BEGIN CERTIFICATE-----\nTEST-ONLY\n-----END CERTIFICATE-----\n"
        r["trust"][name+"_pem"]=pem; r["trust"][name+"_sha256"]=hashlib.sha256(pem.encode()).hexdigest()
    if windows:
        from tools.samba_ad.pilot_baseline import URL, SHA256
        from tools.samba_ad.pilot_baseline_catalog import CATALOG
        r["windows"]={"edition":"ServerStandard","build":"26100","support_until":"2034-11-14",
            "support_ref":"https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025",
            "rsat_source":"C:\\SambaADAssets\\FoD","rsat_files":{"fixture.cab":"a"*64},
            "rsop":{"profile":"server2025-gpmc-rsop-v1","template_artifact_sha256":"b"*64,
                    "samples":{"Computer":"c"*64,"User":"d"*64},"review_ref":review},
            "baseline":{"title":"Windows Server 2025 Security Baseline v2602","publisher":"Microsoft Corporation",
                "url":URL,"sha256":SHA256,"catalog_sha256":m.sha(CATALOG),
                "archive":"C:\\SambaADAssets\\baseline.zip",
                "gpo_name":"Samba-Pilot-aaaaaaaaaaaaaaaa",
                "review_ref":review}}
    else:
        r["linux"]={"packages":{n:"1.0" for n in ["adcli","sssd-ad","sssd-tools","libnss-sss","libpam-sss",
            "krb5-user","smbclient","ldap-utils","chrony","ca-certificates","python3-ldap","libpam-modules"]},
            "files":{p:None for p in ["/etc/sssd/sssd.conf","/etc/krb5.conf","/etc/nsswitch.conf",
                     "/etc/pam.d/common-session","/etc/chrony/chrony.conf","/etc/resolv.conf"]},
            "assets":{"fixture.deb":"a"*64}}
    return r, manifest


@pytest.mark.parametrize("windows", [False, True])
def test_typed_pilot_contract_accepts_only_its_own_manifest_and_os(windows):
    r, manifest = pilot_request(windows)
    assert mod().validate(r, manifest)["state"] == "validated"
    from tools.samba_ad.compatibility import validate_bundle
    with pytest.raises(ValueError): validate_bundle(r["substrate"]["compatibility"], r["substrate"])


@pytest.mark.parametrize("case", ["role", "template", "uuid", "machine_id", "domain", "os", "review", "pki", "unknown", "secret"])
def test_pilot_semantic_drift_fails_even_with_resealed_hash(case):
    r, manifest = pilot_request(True); m=mod(); d=r["substrate"]["compatibility"]["data"]
    if case == "role": d["purpose"]="linux_pilot"
    if case == "template": r["substrate"]["template"]["digest"]="d"*40
    if case == "uuid": r["identity"]["uuid"]=d["report"]["subject"]["uuid"]
    if case == "machine_id": r["identity"]["machine_id"]=d["report"]["template_observation"]["machine_id"]
    if case == "domain": d["report"]["template_observation"]["domain"]="foreign.test"
    if case == "os": d["report"]["template_observation"]["edition"]="Home"
    if case == "review": d["report"]["review_ref"]="pending"
    if case == "pki": r["trust"]["root_pem"]+="PRIVATE KEY"
    if case == "unknown": r["passed"]=True
    if case == "secret": r["credential_ref"]="/tmp/secret.json"
    d["target_sha256"]=m.sha({k:r["substrate"][k] for k in ["owner","scope","resource","template","firewall"]})
    r["substrate"]["compatibility"]["sha256"]=m.sha(d)
    with pytest.raises(ValueError): m.validate(r, manifest)


@pytest.mark.parametrize("setting", [
    {"key":r"HKLM\Software\Policies\Microsoft Services\AdmPwd","name":"AdmPwdEnabled","value":1},
    {"key":r"HKLM\System\CurrentControlSet\Control\Lsa","name":"LmCompatibilityLevel","value":6},
    {"key":r"HKLM\Software\Policies\Microsoft\PassportForWork","name":"Enabled","value":1},
    {"key":r"HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation","name":"RequireSecuritySignature","value":0},
])
def test_baseline_cannot_smuggle_deferred_or_weakened_controls(setting):
    r, manifest=pilot_request(True)
    r["windows"]["baseline"]["settings"]=[setting | {"baseline_file":"test/Registry.pol"}]
    with pytest.raises(ValueError): mod().validate(r, manifest)


def test_public_bootstrap_loads_actual_dependencies_and_stays_below_exec_limit():
    import base64
    import zlib
    import jinja2
    root=Path(__file__).resolve().parents[1]
    template=root/"roles/samba_ad_pilots/templates/bootstrap.py.j2"
    env=jinja2.Environment(); env.filters["to_json"]=json.dumps
    env.filters["samba_ad_pilot_pack_sources"]=lambda v:base64.b64encode(zlib.compress(json.dumps(v).encode(),9)).decode()
    code=env.from_string(template.read_text()).render(role_path=str(template.parent.parent),
        lookup=lambda _,p:Path(p).read_text())
    assert len(code.encode()) < 120000
    r, manifest=pilot_request()
    wire={"schema":"samba-ad-pilot-wire/v1","request":r,"manifest":manifest,"credentials":None,
          "dc_records":[],"directory":None,"probe":None}
    result=subprocess.run(["python3","-B","-c",code,"--validate"],input=json.dumps(wire),
        capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state"] == "validated"


@pytest.mark.parametrize("case", ["disabled","missing_limit","broad_limit","extra_tag","root"])
def test_manual_role_guards_precede_transport(tmp_path,case):
    import os
    root=Path(__file__).resolve().parents[1]
    inv=tmp_path/"inventory.json"
    inv.write_text(json.dumps({"samba_ad_hosts":{"hosts":{"test-node":{"ansible_connection":"local",
        "ansible_user":"root" if case=="root" else "ansible"}}}}))
    argv=["ansible-playbook","-i",str(inv),"playbooks/samba-ad-pilots.yml","--check","--tags","samba_ad_pilots"]
    if case in ["disabled","extra_tag","root"]: argv += ["--limit","test-node"]
    if case=="broad_limit": argv += ["--limit","all"]
    if case=="extra_tag": argv += ["--tags","samba_ad_pilots,all"]
    if case!="disabled": argv += ["-e",'{"samba_ad_pilots_enabled":true}']
    result=subprocess.run(argv,cwd=root,capture_output=True,text=True,timeout=30,
        env=os.environ|{"ANSIBLE_LOCAL_TEMP":str(tmp_path/"ansible"),"ANSIBLE_NOCOLOR":"1"})
    assert (result.returncode==0)==(case=="disabled"),result.stdout+result.stderr
    assert "changed=0" in result.stdout and "Probe only the owned" not in result.stdout


def test_foreign_qga_identity_never_opens_credential_reference(monkeypatch):
    m=mod(); r, manifest=pilot_request(); r["action"]="join"
    monkeypatch.setattr(m,"pve_guard",lambda _:None)
    monkeypatch.setattr(m,"qga",lambda *a:{"nonce":a[2]["nonce"],"identity":{},"member":False})
    monkeypatch.setattr(m.os,"open",lambda *a:pytest.fail("credential reference opened before guest identity"))
    with pytest.raises(ValueError): m.run_guest(r,manifest,{"linux":"PUBLIC","windows":"PUBLIC"},"execute")


def test_live_s1_rejects_duplicate_pilot_uuid_before_clone():
    from tools.samba_ad import guest
    from test_samba_ad_guest import Fake
    r,_=pilot_request(True); s=r["substrate"]; api=Fake()
    api.guests[800099]={"name":"foreign","node":"node-a", "smbios1":"uuid="+r["identity"]["uuid"]}
    with pytest.raises(ValueError,match="UUID collision"):
        guest.check_collisions(s,api,[{"vmid":800099,"node":"node-a","type":"qemu"}])
    assert all(method=="get" for method,_,_ in api.calls)


def test_verified_guest_reads_protected_secret_only_after_second_live_guard(monkeypatch,tmp_path):
    import os
    import types
    m=mod(); r,manifest=pilot_request(); r["action"]="join"
    parent=tmp_path/"credentials"; parent.mkdir(mode=0o700)
    folder=parent/"linux_pilot"; folder.mkdir(mode=0o700)
    path=folder/"join.json"; path.write_text('{"username":"pilot-user","password":"SENTINEL-PRIVATE-PASSWORD"}')
    path.chmod(0o600); r["credential_ref"]=str(path)
    real_lstat=Path.lstat; real_fstat=os.fstat
    def root_stat(info):
        return types.SimpleNamespace(st_uid=0,st_mode=info.st_mode,st_nlink=info.st_nlink,st_size=info.st_size)
    monkeypatch.setattr(Path,"lstat",lambda p:root_stat(real_lstat(p)))
    monkeypatch.setattr(m.os,"fstat",lambda fd:root_stat(real_fstat(fd)))
    events=[]
    monkeypatch.setattr(m,"pve_guard",lambda _:events.append("guard"))
    def qga(vmid,command,payload):
        events.append(payload["mode"])
        if payload["mode"]=="probe":
            assert payload["credentials"] is None
            return {"nonce":payload["nonce"],"identity":r["identity"],"member":False}
        assert events==["guard","probe","guard","execute"]
        assert payload["credentials"]["password"]=="SENTINEL-PRIVATE-PASSWORD"
        assert "SENTINEL" not in repr(command)
        return {"nonce":payload["nonce"],"state":"checked"}
    monkeypatch.setattr(m,"qga",qga)
    assert m.run_guest(r,manifest,{"linux":"PUBLIC","windows":"PUBLIC"},"execute")["state"]=="checked"


@pytest.mark.parametrize("wrong_pin", [False,True])
def test_linux_ldap_pins_same_tls_connection_before_password(monkeypatch,wrong_pin):
    import hashlib
    import struct
    import sys
    import types
    from tools.samba_ad import pilot_linux
    r, manifest=pilot_request(); dc=r["dcs"]["dc01"]
    dc["certificate_sha256"]=hashlib.sha256(b"certificate").hexdigest() if not wrong_pin else "a"*64
    calls=[]
    class Connection:
        def set_option(self,*a): pass
        def simple_bind_s(self,user,password): calls.append((user,password))
        def get_option(self,*a): return b"certificate"
        def search_s(self,*a): return [("dn",{"objectSid":[bytes([1,4])+bytes([0,0,0,0,0,5])+struct.pack("<IIII",21,1,2,3)]})]
    ldap=types.SimpleNamespace(initialize=lambda _:Connection(),OPT_NETWORK_TIMEOUT=1,OPT_REFERRALS=2,
        OPT_X_TLS_CACERTFILE=3,OPT_X_TLS_REQUIRE_CERT=4,OPT_X_TLS_DEMAND=5,OPT_X_TLS_NEWCTX=6,
        OPT_X_TLS_PEERCERT=7,SCOPE_BASE=0)
    monkeypatch.setitem(sys.modules,"ldap",ldap)
    if wrong_pin:
        with pytest.raises(ValueError): pilot_linux.ldap_connection(r,manifest,{"username":"pilot-user","password":"SENTINEL"},dc)
        assert calls == [("","")]
    else:
        pilot_linux.ldap_connection(r,manifest,{"username":"pilot-user","password":"SENTINEL"},dc)
        assert calls == [("",""),("pilot-user@AD.EXAMPLE.INVALID","SENTINEL")]


def test_join_probe_fails_tls_before_it_can_return_identity_for_secret_release(monkeypatch):
    from tools.samba_ad import pilot_linux
    r,manifest=pilot_request(); r["action"]="join"
    monkeypatch.setattr(pilot_linux,"inspect",lambda _: (False,{"files":{}}))
    def reject(_): raise ValueError("public TLS pin failed")
    monkeypatch.setattr(pilot_linux,"tls",reject)
    with pytest.raises(ValueError,match="public TLS pin failed"):
        pilot_linux.execute({"request":r,"manifest":manifest,"mode":"probe","nonce":"test","credentials":None})


@pytest.mark.parametrize('configured', ['AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 'invalid-uuid'])
def test_uuid_guard_rejects_equivalent_uppercase_and_invalid_identity(configured):
    from tools.samba_ad import guest
    from test_samba_ad_guest import Fake
    r,_=pilot_request(True); api=Fake()
    api.guests[800099]={'name':'foreign','node':'node-a','smbios1':'uuid='+configured}
    with pytest.raises(ValueError):
        guest.check_collisions(r['substrate'],api,[{'vmid':800099,'node':'node-a','type':'qemu'}])


@pytest.mark.parametrize('configured,accepted', [
    ('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE',False),('invalid-uuid',False),(None,False),
    ('bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee',True)])
def test_template_uuid_is_canonical_and_valid_before_clone(configured,accepted):
    from tools.samba_ad import guest
    from test_samba_ad_guest import Fake
    r,_=pilot_request(True);s=r['substrate'];s['expected_digest']=None
    api=Fake();original=api.get
    target=f"/nodes/{s['template']['node']}/qemu/{s['template']['vmid']}/config"
    def get(path,**kwargs):
        if path=='/cluster/status':
            return [{'type':'cluster','quorate':1}, *[{'type':'node','name':n,'online':1}
                    for n in {s['template']['node'],s['resource']['node']}]]
        if path==target:
            result={'template':1,'digest':s['template']['digest'],'name':'source-template','ostype':'win11',
                    'onboot':0,'scsi0':s['template']['storage']+':base-disk-0,size=16G'}
            if configured is not None:result['smbios1']='uuid='+configured
            return result
        result=original(path,**kwargs)
        if path.startswith('/nodes/') and path.endswith('/status') and '/storage/' not in path:
            result.update(kversion='test-kernel',pveversion='test-pve')
        return result
    api.get=get
    if accepted:assert guest.reconcile(s,api,check=True)['state']=='planned'
    else:
        with pytest.raises(ValueError,match='UUID'):guest.reconcile(s,api,check=True)
    assert not api.guests


def test_only_linux_prepare_can_bypass_two_dc_gate():
    m=mod()
    for pilot in ['linux_pilot','windows_pilot']:
        for action in ['prepare','join','verify','policy']:
            assert m.needs_dc_gate({'pilot':pilot,'action':action}) == (pilot!='linux_pilot' or action!='prepare')


@pytest.mark.parametrize('action',['prepare','join','verify','policy'])
def test_rsop_qualification_is_mandatory_for_policy_without_creating_join_cycle(action):
    r,m=pilot_request(True);r['action']=action;r['windows']['rsop']=None
    if action=='policy':
        with pytest.raises(ValueError):mod().validate(r,m)
    else:assert mod().validate(r,m)['state']=='validated'


def test_windows_prepare_without_two_dc_records_stops_before_guest_or_directory(monkeypatch,capsys):
    import io
    import sys
    m=mod();r,manifest=pilot_request(True);r['apply']=True
    wire={'schema':'samba-ad-pilot-wire/v1','request':r,'manifest':manifest,'credentials':None,
          'dc_records':[],'directory':None,'probe':None}
    monkeypatch.setattr(m.resource,'setrlimit',lambda *a:None)
    monkeypatch.setattr(sys,'stdin',io.StringIO(json.dumps(wire)))
    monkeypatch.setattr(sys,'argv',['pilot','--execute'])
    monkeypatch.setattr(m,'run_guest',lambda *a:pytest.fail('Windows prepare escaped two-DC gate'))
    assert m.main({})==2
    assert 'values suppressed' in capsys.readouterr().err


def test_role_dc_gate_matches_linux_only_exception_and_prepare_never_creates_directory():
    import yaml
    import jinja2
    root=Path(__file__).resolve().parents[1]
    tasks=yaml.safe_load((root/'roles/samba_ad_pilots/tasks/main.yml').read_text())
    collect=next(t for t in tasks if t['name'].startswith('Collect fresh'))
    directory=next(t for t in tasks if t['name'].startswith('Create or inspect'))
    env=jinja2.Environment()
    for pilot in ['linux_pilot','windows_pilot']:
        for action in ['prepare','join','verify','policy']:
            r={'pilot':pilot,'action':action}
            render=lambda expression:env.from_string('{% if '+expression+' %}yes{% else %}no{% endif %}').render(samba_ad_pilots_request=r)=='yes'
            assert render(collect['when'])==mod().needs_dc_gate(r)
            assert render(directory['when'])==(action!='prepare')


@pytest.mark.parametrize('account_code', [0,6,7,12])
def test_pam_account_preserves_actual_denial_code(account_code):
    import ctypes
    from tools.samba_ad import pilot_linux
    class Function:
        def __init__(self,fn): self.fn=fn
        def __call__(self,*args): return self.fn(*args)
    class PAM:
        def __init__(self):
            self.ended=[]
            self.pam_start=Function(lambda service,user,conv,handle:0)
            self.pam_acct_mgmt=Function(lambda handle,flags:account_code)
            self.pam_end=Function(lambda handle,code:self.ended.append(code) or 0)
    lib=PAM(); result=pilot_linux.pam_account('fixture@ad.example.invalid',lib)
    assert result['account']==account_code and lib.ended==[account_code]
    if account_code:
        with pytest.raises(ValueError): pilot_linux.require_pam(result)
    else: pilot_linux.require_pam(result)


def test_drs_health_rejects_missing_naming_context_errors_wrong_partner_and_stale_success():
    import datetime
    from tools.samba_ad.pilots_dc import check_replication
    base="DC=ad,DC=example,DC=invalid"; now=1794139200
    contexts=[base,"CN=Configuration,"+base,"CN=Schema,CN=Configuration,"+base,
              "DC=DomainDnsZones,"+base,"DC=ForestDnsZones,"+base]
    rows=[{"NC dn":dn,"is deleted":False,"consecutive failures":0,"last attempt message":"was successful",
           "NTDS DN":"CN=NTDS Settings,CN=DC02,CN=Servers,CN=site,CN=Sites,CN=Configuration,"+base,
           "last success":datetime.datetime.fromtimestamp(now,datetime.timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC")}
          for dn in contexts]
    check_replication({"repsFrom":rows},base,"dc02",now)
    with pytest.raises(ValueError): check_replication({"repsFrom":rows[:-1]},base,"dc02",now)
    with pytest.raises(ValueError): check_replication({"repsFrom":rows},base,"dc01",now)
    with pytest.raises(ValueError): check_replication({"repsFrom":rows},base,"dc02",now+901)
    rows[0]["consecutive failures"]=1
    with pytest.raises(ValueError): check_replication({"repsFrom":rows},base,"dc02",now)


def test_check_mode_directory_preserves_measured_guid_and_never_mutates(monkeypatch):
    import sys
    import types
    from tools.samba_ad import pilots_dc
    r,manifest=pilot_request(); r["action"]="verify"
    owner="samba-ad:s6:"+r["substrate"]["compatibility"]["data"]["target_sha256"]
    dn="CN=LINUX-PILOT,"+r["ou"]
    class Entry(dict): pass
    computer=Entry(description=[owner.encode()],objectSid=[b"sid"],objectGUID=[b"g"*16]); computer.dn=dn
    class DB:
        def domain_dn(self): return "DC=ad,DC=example,DC=invalid"
        def search(self,**kw):
            return [computer] if kw["expression"].startswith("(sAMAccountName=") else [Entry(description=[owner.encode()])]
        def add(self,*a): pytest.fail("check mode mutated AD")
    monkeypatch.setattr(pilots_dc,"inspect",lambda *a:None)
    monkeypatch.setattr(pilots_dc,"database",lambda:DB())
    monkeypatch.setitem(sys.modules,"ldb",types.SimpleNamespace(SCOPE_SUBTREE=2,binary_encode=lambda x:x))
    monkeypatch.setitem(sys.modules,"samba.ndr",types.SimpleNamespace(ndr_unpack=lambda *a:r["sid"]+"-1001"))
    monkeypatch.setitem(sys.modules,"samba.dcerpc",types.SimpleNamespace(security=types.SimpleNamespace(dom_sid=object)))
    result=pilots_dc.directory(r,manifest,{"request_sha256":mod().sha(r),"identity":r["identity"],"member":True})
    assert result["computer_guid"]==(b"g"*16).hex() and result["changed"] is False


def test_windows_script_parses_without_running_or_modifying_host():
    import shutil
    if not shutil.which("pwsh"): pytest.skip("PowerShell AST parser is unavailable on this test host")
    root=Path(__file__).resolve().parents[1]
    result=subprocess.run(["pwsh","-NoLogo","-NoProfile","-NonInteractive","-Command",
        "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("+
        "'"+str(root/"tools/samba_ad/pilot_windows.ps1")+"',[ref]$t,[ref]$e);"+
        "$e | ForEach-Object {$_.Message};if($e.Count){exit 1}"],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stdout+result.stderr
