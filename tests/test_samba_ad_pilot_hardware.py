"""Synthetic Windows hardware qualification; never an operational receipt."""
import copy
import pytest
from test_samba_ad_pilots import pilot_request
from tools.samba_ad import guest, pilot_substrate
from tools.samba_ad.compatibility import sha


def qualified():
    r, _ = pilot_request(True)
    s = r["substrate"]; t = s["template"]; c = s["resource"]
    h = s["compatibility"]["data"]["report"]["hardware"]
    s["compatibility"]["data"]["report"]["hardware"] = h
    seal(s)
    return s,h


def seal(s):
    s["compatibility"]["sha256"]=sha(s["compatibility"]["data"])


def config(s,h,template=False,storage=None):
    c=s["resource"];t=s["template"];storage=storage or c["storage"]
    vols=h["template_volumes"] if template else {k:storage+":vm-"+str(c["vmid"])+"-disk-"+str(i) for i,k in enumerate(["efidisk0","scsi0"])}
    return guest.desired_config(s) | {"template":int(template),"digest":"f"*40,"bios":"ovmf","machine":h["machine"],"cpu":"host",
            "scsi0":vols["scsi0"]+",size="+str(c["disk_gib"])+"G",
            "efidisk0":vols["efidisk0"]+",efitype=4m,pre-enrolled-keys=1,size=4M"}


def test_qualified_server_efi_can_pass_substrate_and_owned_guest_guards():
    s,h=qualified()
    pilot_substrate.validate_pilot_bundle(s["compatibility"],s)
    guest.verify_config(s,config(s,h))
    assert guest.owned_volumes(s,config(s,h)) == [config(s,h)["scsi0"].split(",")[0],config(s,h)["efidisk0"].split(",")[0]]


@pytest.mark.parametrize("case",["no_hardware","nested","slat","secure_boot","efi_hash","linux"])
def test_hardware_qualification_fails_closed_even_when_resealed(case):
    s,h=qualified();d=s["compatibility"]["data"]
    if case=="no_hardware":del d["report"]["hardware"]
    if case=="nested":next(iter(h["nodes"].values()))["nested"]=False
    if case=="slat":next(iter(h["nodes"].values()))["slat"]="none"
    if case=="secure_boot":h["native"]["secure_boot"]=False
    if case=="efi_hash":h["efi_sha256"]="unknown"
    if case=="linux":d["purpose"]="linux_pilot"
    seal(s)
    with pytest.raises(ValueError):pilot_substrate.validate_pilot_bundle(s["compatibility"],s)


@pytest.mark.parametrize("device,value",[("efidisk0","foreign:vm-1-disk-1,efitype=4m,pre-enrolled-keys=1"),
    ("efidisk0","{storage}:vm-{vmid}-disk-0,efitype=2m,pre-enrolled-keys=1"),
    ("efidisk0","{storage}:vm-{vmid}-disk-0,efitype=4m,pre-enrolled-keys=0"),
    ("efidisk0","{storage}:vm-{vmid}-disk-2,efitype=4m,pre-enrolled-keys=1"),
    ("bios","seabios"),("cpu","kvm64"),("machine","pc-i440fx-9.2"),("tpmstate0","foreign:vm-1-disk-3"),
    ("hostpci0","0000:00:01.0"),("efidisk1","foreign:vm-1-disk-2"),("scsi0","foreign:vm-1-disk-0,size=64G")])
def test_managed_windows_rejects_drift_or_unowned_devices(device,value):
    s,h=qualified();cfg=config(s,h);cfg[device]=value.format(storage=s["resource"]["storage"],vmid=s["resource"]["vmid"])
    with pytest.raises(ValueError):guest.verify_config(s,cfg)


@pytest.mark.parametrize("case",["valid","secure_boot","hypervisor","nx"])
def test_native_hardware_gate_runs_before_any_policy_mutation(case):
    from test_samba_ad_pilot_policy import powershell,ROOT
    body=". '"+str(ROOT/'tools/samba_ad/pilot_baseline_windows.ps1')+"';"+r'''
$script:case='CASE';$script:reached=$false
function Confirm-SecureBootUEFI {return $script:case -ne 'secure_boot'}
function Get-CimInstance {
 $properties=@(1,2,5)
 if($script:case -eq 'hypervisor'){$properties=@(2,5)}
 if($script:case -eq 'nx'){$properties=@(1,2)}
 return @{AvailableSecurityProperties=$properties}
}
function Check-Assets {$script:reached=$true;throw 'stop after hardware gate'}
try{Apply-Policy $null $null $null}catch{}
Assert-S6 ($script:reached -eq ($script:case -eq 'valid'))
'''.replace('CASE',case)
    result=powershell(body)
    assert result.returncode==0,result.stdout+result.stderr


class WindowsFake:
    def __init__(self,s,h):
        from test_samba_ad_guest import Fake
        self.inner=Fake();self.inner.kind="qemu";self.s=s;self.h=h
        self.inner.template=config(s,h,template=True) | {"ostype":"win11","smbios1":"uuid=bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee","onboot":0,"digest":s["template"]["digest"]}
        self.calls=self.inner.calls;self.guests=self.inner.guests;self.host_bad=False;self.efi_bad=False;self.migration_bad=False;self.clone_bad=False
    def __getattr__(self,key):return getattr(self.inner,key)
    def windows_host(self,r,node):
        result={k:v for k,v in self.h["nodes"][node].items() if k!="artifact_sha256"}
        if self.host_bad:result["nested"]=False
        return result
    def efi_hash(self,r):return "0"*64 if self.efi_bad else self.h["efi_sha256"]
    def get(self,path,**params):
        if path=="/cluster/status":return [{"type":"cluster","quorate":1}]+[{"type":"node","name":n,"online":1} for n in self.h["nodes"]]
        if path.endswith(f'/{self.s["template"]["vmid"]}/config'):return copy.deepcopy(self.inner.template)
        result=self.inner.get(path,**params)
        if path.endswith('/status') and '/storage/' not in path:
            result.update(kversion='test-kernel',pveversion='test-pve')
        return result
    def mutate(self,method,path,**params):
        self.inner.mutate(method,path,**params)
        c=self.s["resource"];t=self.s["template"]
        if path.endswith('/clone'):
            cfg=self.guests[c['vmid']];cfg['node']=t['node']
            for key,volume in {'scsi0':f"{t['storage']}:vm-{c['vmid']}-disk-1",'efidisk0':f"{t['storage']}:vm-{c['vmid']}-disk-0"}.items():
                cfg[key]=volume+','+cfg[key].split(',',1)[1]
            if self.clone_bad:cfg['efidisk0']=cfg['efidisk0'].replace('-disk-0','-disk-8')
        if path.endswith('/migrate'):
            for key,volume in {'scsi0':f"{c['storage']}:vm-{c['vmid']}-disk-1",'efidisk0':f"{c['storage']}:vm-{c['vmid']}-disk-0"}.items():
                cfg=self.guests[c['vmid']];cfg[key]=volume+','+cfg[key].split(',',1)[1]
            if self.migration_bad:cfg['efidisk0']=cfg['efidisk0'].replace('-disk-0','-disk-8')


def test_qualified_windows_clone_migrates_exact_owned_efi_and_can_start():
    s,h=qualified();s.update(apply=True,expected_digest=None,boot=False);api=WindowsFake(s,h)
    assert guest.reconcile(s,api)['state']=='created'
    assert api.guests[s['resource']['vmid']]['efidisk0'].startswith(guest.windows_volumes(s)['efidisk0']+',')
    s.update(action='start',boot=True,expected_digest='b'*40)
    assert guest.reconcile(s,api)['state']=='started'
    s['action']='present'
    assert guest.reconcile(s,api)['state']=='verified'


@pytest.mark.parametrize('drift',['host','efi','clone','migration'])
def test_hardware_drift_stops_before_boot_and_before_clone_for_source_drift(drift):
    s,h=qualified();s.update(apply=True,expected_digest=None);api=WindowsFake(s,h)
    setattr(api,drift+'_bad',True)
    with pytest.raises(ValueError):guest.reconcile(s,api)
    assert not any(p.endswith('/status/start') for _,p,_ in api.calls)
    if drift in ['host','efi']:assert not any(p.endswith('/clone') for _,p,_ in api.calls)


@pytest.mark.parametrize('action',['stop','absent'])
def test_windows_production_destructive_actions_remain_refused(action):
    s,h=qualified();s['action']=action;api=WindowsFake(s,h)
    with pytest.raises(ValueError):guest.reconcile(s,api)
    assert not api.calls


@pytest.mark.parametrize('drift',[None,'second_cpu','nested'])
def test_live_host_probe_reads_all_cpus_and_nested_without_mutation(monkeypatch,drift):
    import shlex,subprocess,json
    s,h=qualified();api=guest.Pvesh()
    cpu='vendor_id : GenuineIntel\nmodel name : fixture-only\nflags : vmx ept nx\n'
    files={'/proc/cpuinfo':cpu+'\n'+cpu.replace('fixture-only','different' if drift=='second_cpu' else 'fixture-only'),
           '/sys/module/kvm_intel/parameters/nested':'N' if drift=='nested' else 'Y',
           '/proc/sys/kernel/random/boot_id':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'}
    def node_run(target,command):
        args=shlex.split(command)
        assert args[:2]==['python3','-c']
        patch='from pathlib import Path\nfiles='+repr(files)+'\nPath.read_text=lambda p:files[str(p)]\n'
        result=subprocess.run(['python3','-c',patch+args[2]],capture_output=True,text=True)
        if result.returncode:raise ValueError('probe rejected')
        return result.stdout
    monkeypatch.setattr(api,'node_run',node_run)
    if drift=='second_cpu':
        with pytest.raises(ValueError):api.windows_host(s,s['resource']['node'])
    else:
        result=api.windows_host(s,s['resource']['node'])
        assert result['nested'] is (drift!='nested')
        assert result['model']=='fixture-only'


@pytest.mark.parametrize('case',['foreign_clone','shared_volume','wrong_destination','wrong_template','shared_root'])
def test_volume_qualification_does_not_adopt_or_share_storage(case):
    s,h=qualified()
    if case=='foreign_clone':h['clone_volumes']['efidisk0']='local-lvm:vm-999-disk-0'
    if case=='shared_volume':h['clone_volumes']['efidisk0']=h['clone_volumes']['scsi0']
    if case=='wrong_destination':h['destination_volumes']['efidisk0']='foreign:vm-999-disk-0'
    if case=='wrong_template':h['template_volumes']['efidisk0']='local-lvm:base-999-disk-0'
    if case=='shared_root':
        cfg=config(s,h);cfg['scsi0']+=',shared=1'
        with pytest.raises(ValueError):guest.verify_config(s,cfg)
        return
    seal(s)
    with pytest.raises(ValueError):pilot_substrate.validate_pilot_bundle(s['compatibility'],s)
