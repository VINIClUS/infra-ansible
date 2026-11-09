"""S5 fail-closed orchestration. Fixtures never assert native runtime acceptance."""
import importlib.util
from pathlib import Path
import pytest


def api():
    assert importlib.util.find_spec('tools.samba_ad.replica'), 'S5 backend missing'
    from tools.samba_ad import replica
    return replica


def test_existing_forest_required_and_partial_join_is_never_retried():
    m = api()
    expected = dict(realm='AD.EXAMPLE.INVALID', netbios='EXAMPLE', fqdn='dc02.ad.example.invalid', sid='S-1-5-21-1-2-3')
    peer = dict(expected, fqdn='dc01.ad.example.invalid', domain_level=7, forest_level=7, schema_version=88)
    assert m.join_action(expected, peer, None, False, False) == 'join'
    local = dict(peer, fqdn=expected['fqdn'])
    assert m.join_action(expected, peer, local, True, False) == 'current'
    for occupied, attempted in [(True, False), (False, True), (True, True)]:
        with pytest.raises(ValueError): m.join_action(expected, peer, None, occupied, attempted)
    for key, value in [('sid', 'S-1-5-21-9-9-9'), ('schema_version', 89), ('domain_level', 6)]:
        with pytest.raises(ValueError): m.join_action(expected, dict(peer, **{key:value}), None, False, False)
    with pytest.raises(ValueError): m.join_action(dict(expected, sid=None), peer, None, False, False)


def test_join_check_and_reexecution_never_join_again():
    m = api()
    class Backend:
        def __init__(self, action): self.action, self.calls = action, []
        def inspect(self, r): self.calls.append('inspect'); return self.action
        def join(self, r): self.calls.append('join')
        def harden(self, r): self.calls.append('harden')
        def verify(self, r): self.calls.append('verify'); return {'state':'current','changed':False}
    for action, apply, calls in [('join',False,['inspect']),('current',True,['inspect','verify']),('join',True,['inspect','join','harden','verify'])]:
        b = Backend(action); m.execute({'apply':apply}, b); assert b.calls == calls


def test_dc01_guard_remains_exact():
    api()
    from tools.samba_ad.domain import smb_conf
    with pytest.raises(ValueError): smb_conf('AD.EXAMPLE.INVALID','EXAMPLE','dc02',['192.0.2.53'])


def test_safe_native_join_disables_remote_cleanup_and_partial_reuse():
    m = api()
    class Context:
        def cleanup_old_join(self): pytest.fail('upstream deletion invoked')
        def build_nc_lists(self): self.calls.append('build')
        def join_add_objects(self): self.calls.append('objects')
        def join_provision(self): self.calls.append('local')
        def join_replicate(self): self.calls.append('replicate'); raise RuntimeError('sensitive')
        def join_add_dns_records(self): self.calls.append('dns')
        def join_replicate_new_dns_records(self): self.calls.append('dns_replicate')
        def join_finalise(self): self.calls.append('finalise')
    c=Context();c.calls=[]
    with pytest.raises(ValueError) as error: m.run_join_context(c, lambda:None)
    assert c.calls == ['build','objects','local','replicate']
    assert 'sensitive' not in str(error.value)


def request():
    import copy
    from test_samba_ad_domain import request as dc01_request
    from test_samba_ad_compatibility import reseal, sha
    peer,manifest=dc01_request();peer['target']['sid']='S-1-5-21-1-2-3'
    local=copy.deepcopy(peer);declared=manifest['resources']['dc02']
    local['target']['fqdn']=declared['fqdn']
    substrate=local['substrate']
    for key in ['node','vmid','mac']:substrate['resource'][key]=declared[key]
    substrate['resource']['name']=declared['fqdn'];substrate['resource']['address']=declared['address']+'/25'
    data=substrate['compatibility']['data'];data['choice']['target_role']='dc02'
    data['choice']['target_sha256']=sha({k:substrate[k] for k in ['owner','scope','resource','template','firewall']})
    reseal(substrate)
    pki=local['pki'];pki['profile']='dc02';pki['target']['role']='dc02';pki['target']['fqdn']=declared['fqdn']
    pki['target']['spec_sha256']=data['choice']['target_sha256']
    pki['target']['address']=declared['address'];pki['target']['mac']=declared['mac']
    for key in ['auth_key_ref','password_ref']:pki['credential'][key]=pki['credential'][key].replace('/dc01/','/dc02/')
    for profile,other,direction in [(peer,local,'IN'),(local,peer,'OUT')]:
        profile['substrate']['firewall']['flows'].append({'direction':direction,'peer':other['substrate']['resource']['address'].split('/')[0]+'/32','proto':'tcp','port':'22'})
        profile['substrate']['compatibility']['data']['choice']['target_sha256']=sha({k:profile['substrate'][k] for k in ['owner','scope','resource','template','firewall']})
        profile['pki']['target']['spec_sha256']=profile['substrate']['compatibility']['data']['choice']['target_sha256']
        reseal(profile['substrate'])
    return {'schema':'samba-ad-replica/v1','enabled':True,'apply':False,'local':local,'peer':peer,
            'join_user':'ReplicaJoin','site':'Default-First-Site-Name','peer_leaf_sha256':'a'*64},manifest


def test_dc02_contract_binds_substrate_pki_peer_and_nonempty_sid():
    import copy
    m=api();r,manifest=request()
    assert m.validate_request(r,manifest)=={'state':'validated'}
    for mutate in [lambda x:x['local']['target'].update(sid=None),
                   lambda x:x['local']['pki'].update(profile='dc01'),
                   lambda x:x['peer']['target'].update(sid='S-1-5-21-9-9-9'),
                   lambda x:x.update(password='SENTINEL'),
                   lambda x:x['local']['substrate']['compatibility']['data']['report'].update(qualification='pending')]:
        bad=copy.deepcopy(r);mutate(bad)
        with pytest.raises(ValueError):m.validate_request(bad,manifest)


def test_replica_transport_requires_exact_bidirectional_ssh_flow():
    import copy
    m=api();r,manifest=request()
    # A valid domain contract alone does not authorize a new SYSVOL SSH path.
    r['peer']['substrate']['firewall']['flows'].pop()
    r['local']['substrate']['firewall']['flows'].pop()
    with pytest.raises(ValueError):m.sysvol_network(r)
    source=r['peer']['substrate']['resource']['address'].split('/')[0]+'/32'
    receiver=r['local']['substrate']['resource']['address'].split('/')[0]+'/32'
    r['peer']['substrate']['firewall']['flows'].append({'direction':'IN','peer':receiver,'proto':'tcp','port':'22'})
    r['local']['substrate']['firewall']['flows'].append({'direction':'OUT','peer':source,'proto':'tcp','port':'22'})
    m.sysvol_network(r)


def test_failure_after_join_quarantines_owned_dc_before_returning():
    m=api()
    class Backend:
        def inspect(self,r):return 'join'
        def join(self,r):self.joined=True
        def harden(self,r):raise ValueError('failed acceptance')
        def quarantine(self,r):self.blocked=True
    backend=Backend();backend.joined=False;backend.blocked=False
    with pytest.raises(ValueError):m.execute({'apply':True},backend)
    assert backend.joined and backend.blocked


def test_missing_sysvol_transport_refuses_before_native_join_or_attempt(monkeypatch):
    from tools.samba_ad import sysvol
    m=api();native=m.Native({})
    monkeypatch.setattr(native,'inspect',lambda r:'join')
    def refuse(expected):raise ValueError('transport unavailable')
    monkeypatch.setattr(sysvol,'prejoin',refuse,raising=False)
    with pytest.raises(ValueError,match='transport unavailable'):
        native.join({'local':{'target':{'sid':'S-1-5-21-1-2-3'}}})


def test_native_api_boundary_persists_attempt_before_remote_mutation(tmp_path,monkeypatch):
    import contextlib
    import json
    import sys
    from types import ModuleType,SimpleNamespace
    from tools.samba_ad import sysvol
    m=api();native=m.Native({});root=tmp_path/'owned';root.mkdir(mode=0o700)
    monkeypatch.setattr(m,'ROOT',root);monkeypatch.setattr(m,'quiet_native',contextlib.nullcontext)
    monkeypatch.setattr(native,'inspect',lambda r:'join')
    monkeypatch.setattr(sysvol,'prejoin',lambda r:None)
    creds=object();lp=SimpleNamespace(set=lambda k,v:None)
    monkeypatch.setattr(native,'credentials',lambda r,machine:(lp,creds))
    monkeypatch.setattr(native,'prepare_config',lambda r:None)
    monkeypatch.setattr(native,'remote_absent',lambda db,r:None)
    monkeypatch.setattr(native,'dns_absent',lambda db,r:None)
    calls=[]
    class Context:
        def __init__(self,**kw):
            assert kw['creds'] is creds and kw['netbios_name']=='DC02'
            assert kw['promote_existing'] is False and kw['plaintext_secrets'] is False
            assert json.loads((root/'attempt.json').read_text())=={'sid':'S-1-5-21-1-2-3'}
            self.domsid='S-1-5-21-1-2-3';self.behavior_version=7
            self.domain_name='EXAMPLE';self.realm='AD.EXAMPLE.INVALID';self.dnsdomain='ad.example.invalid'
            self.SPNs=[];self.replica_flags=0;self.samdb=object()
        def build_nc_lists(self):calls.append('build')
        def join_add_objects(self):calls.append('objects')
        def join_provision(self):calls.append('local')
        def join_replicate(self):raise RuntimeError('SECRET_SENTINEL')
        def cleanup_old_join(self):pytest.fail('destructive upstream cleanup')
    samba=ModuleType('samba');samba.__path__=[];samba.dsdb=SimpleNamespace(UF_SERVER_TRUST_ACCOUNT=1,UF_TRUSTED_FOR_DELEGATION=2)
    join=ModuleType('samba.join');join.DCJoinContext=Context
    dcerpc=ModuleType('samba.dcerpc');dcerpc.misc=SimpleNamespace(SEC_CHAN_BDC=1);dcerpc.drsuapi=SimpleNamespace(DRSUAPI_DRS_WRIT_REP=1,DRSUAPI_DRS_FULL_SYNC_IN_PROGRESS=2)
    for name,module in [('samba',samba),('samba.join',join),('samba.dcerpc',dcerpc)]:monkeypatch.setitem(sys.modules,name,module)
    r={'local':{'target':{'sid':'S-1-5-21-1-2-3','realm':'AD.EXAMPLE.INVALID'}},'peer':{'target':{'fqdn':'dc01.ad.example.invalid'}},'site':'Site'}
    with pytest.raises(ValueError) as error:native.join(r)
    assert 'SECRET_SENTINEL' not in str(error.value)
    assert calls==['build','objects','local'] and (root/'attempt.json').exists()
    with pytest.raises(FileExistsError):native.join(r)
    assert calls==['build','objects','local']


def test_native_diagnostics_do_not_escape_file_descriptors(capfd):
    import os
    with api().quiet_native():
        print('SECRET_SENTINEL')
        os.write(1,b'NATIVE_SECRET\n');os.write(2,b'NATIVE_SECRET\n')
    out=capfd.readouterr()
    assert 'SECRET' not in out.out+out.err
