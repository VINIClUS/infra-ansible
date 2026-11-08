"""Real authenticated vendor units; systemctl uses only disposable --root trees."""
import json
from pathlib import Path
import subprocess
import pytest
from tools.samba_ad import domain
from tools.samba_ad.domain_services import ServiceOps

DC="samba-ad-dc.service"
ALIAS="samba.service"
MEMBERS=("smbd.service","nmbd.service","winbind.service")
FIXTURE=Path(__file__).parent/"fixtures/samba_ad_systemd_units.json"

class Offline:
    def __init__(self,root):
        self.root=root;self.running=False;self.mutations=[]
        units=root/"usr/lib/systemd/system";units.mkdir(parents=True)
        for name,item in json.loads(FIXTURE.read_text()).items():
            (units/name).write_text(item["text"]);(units/name).chmod(0o644)
        for prefix in ["etc/systemd/system","run/systemd/system"]:(root/prefix).mkdir(parents=True)
        for path in root.rglob("*"):
            if path.is_dir():path.chmod(0o755)
    def native(self,*args):
        result=subprocess.run(["systemctl","--root="+str(self.root),"--no-reload",*args],capture_output=True)
        return result
    def state(self,unit):
        result=self.native("is-enabled",unit)
        return result.stdout.decode().strip()
    def local(self,unit):
        return [self.root/p/unit for p in ["etc/systemd/system","run/systemd/system"]]
    def run(self,argv,**kwargs):
        if argv[1]=="show":
            unit=argv[-1];paths=self.local(unit);found=next((p for p in paths if p.is_symlink()),None)
            masked=found is not None and str(found.readlink())=="/dev/null"
            missing=unit==ALIAS and found is None
            active=self.running and unit in [DC,ALIAS] and not masked and not missing
            dropin=self.root/"etc/systemd/system/samba-ad-dc.service.d/60-samba-ad-firewall.conf"
            values={"LoadState":"masked" if masked else "not-found" if missing else "loaded","UnitFileState":self.state(unit),"ActiveState":"active" if active else "inactive","SubState":"running" if active else "dead","FragmentPath":"/dev/null" if masked else "" if missing else "/usr/lib/systemd/system/"+(DC if unit==ALIAS else unit),"DropInPaths":"/etc/systemd/system/samba-ad-dc.service.d/60-samba-ad-firewall.conf" if dropin.exists() and unit in [DC,ALIAS] else ""}
            return "".join(f"{k}={v}\n" for k,v in values.items()).encode()
        self.mutations.append(argv)
        if argv[1]=="daemon-reload":return b""
        args=argv[1:];result=self.native(*args)
        assert result.returncode==0,result.stderr.decode()
        return result.stdout
    def ops(self):return ServiceOps(root=self.root,run=self.run)

def mask_members(driver):
    for member in MEMBERS:assert driver.native("mask",member).returncode==0


def test_r1a_real_vendor_alias_is_accepted_on_readonly_reexecution(tmp_path):
    driver=Offline(tmp_path);mask_members(driver)
    result=driver.native("enable",DC)
    assert result.returncode==0,result.stderr.decode()
    alias=tmp_path/"etc/systemd/system"/ALIAS
    assert str(alias.readlink())=="/usr/lib/systemd/system/"+DC
    assert not (tmp_path/"usr/lib/systemd/system"/ALIAS).exists()
    driver.running=True
    before=list(driver.mutations);driver.ops().inspect(initial=False)
    assert driver.mutations==before


@pytest.mark.parametrize("initial",["absent","persistent_mask","runtime_mask","enabled","enabled_then_masked","enabled_members","enabled_members_then_masked"])
def test_r1b_initial_preparation_stays_boot_blocked_after_database_and_failure(tmp_path,initial):
    driver=Offline(tmp_path)
    if initial in ["enabled","enabled_then_masked"]:assert driver.native("enable",DC).returncode==0
    if initial=="enabled_then_masked":assert driver.native("mask",DC).returncode==0
    if initial in ["enabled_members","enabled_members_then_masked"]:
        for unit in MEMBERS:
            assert driver.native("enable",unit).returncode==0
            if initial=="enabled_members_then_masked":assert driver.native("mask",unit).returncode==0
    if initial in ["persistent_mask","runtime_mask"]:
        args=["--runtime"] if initial=="runtime_mask" else []
        for unit in [DC,ALIAS]:assert driver.native(*args,"mask",unit).returncode==0
    ops=driver.ops();before=ops.inspect(initial=True)
    ops.converge_initial(before)
    assert driver.state(DC)=="masked"
    assert driver.state(ALIAS)=="masked"
    assert not (tmp_path/"etc/systemd/system/multi-user.target.wants"/DC).exists()
    assert not any((tmp_path/"etc/systemd/system"/alias).is_symlink() for alias in ["smb.service","nmb.service"])
    database=tmp_path/"var/lib/samba/private/sam.ldb";database.parent.mkdir(parents=True);database.write_text("synthetic partial DB marker")
    mutations=list(driver.mutations)
    with pytest.raises(ValueError):driver.ops().inspect(initial=False)
    assert driver.mutations==mutations
    assert driver.state(DC)=="masked" and driver.state(ALIAS)=="masked"


def test_r1a_rejects_alias_to_member_without_replacing_it(tmp_path):
    driver=Offline(tmp_path);alias=tmp_path/"etc/systemd/system"/ALIAS
    alias.symlink_to("/usr/lib/systemd/system/smbd.service")
    with pytest.raises(ValueError):driver.ops().inspect(initial=True)
    assert str(alias.readlink())=="/usr/lib/systemd/system/smbd.service"
    assert not driver.mutations


def test_final_activation_uses_actual_vendor_alias_and_boot_links(tmp_path):
    driver=Offline(tmp_path);ops=driver.ops();blocked=ops.converge_initial(ops.inspect(initial=True))
    ops.activate(blocked)
    assert driver.state(DC)=="enabled"
    assert str((tmp_path/"etc/systemd/system"/ALIAS).readlink())=="/usr/lib/systemd/system/"+DC
    assert all(driver.state(member)=="masked" for member in MEMBERS)
    driver.running=True;before=list(driver.mutations);ops.inspect(initial=False);assert driver.mutations==before


def test_pre_activation_failure_cannot_unmask_or_enable(tmp_path):
    driver=Offline(tmp_path);ops=driver.ops();blocked=ops.converge_initial(ops.inspect(initial=True))
    class Refuse(domain.Native):
        def pre_activation(self,request):raise ValueError("configuration/policy/TLS/firewall not ready")
    native=Refuse({});native.services=ops;native.blocked_services=blocked
    before=list(driver.mutations)
    with pytest.raises(ValueError):native.activate({})
    assert driver.mutations==before
    assert driver.state(DC)=="masked" and driver.state(ALIAS)=="masked"


def test_execute_interruption_after_database_keeps_persistent_block_and_reexec_readonly(tmp_path):
    driver=Offline(tmp_path);ops=driver.ops()
    class FailAfterDatabase:
        def inspect(self,request):return "provision"
        def provision(self,request):
            self.blocked=ops.converge_initial(ops.inspect(initial=True))
            path=tmp_path/"var/lib/samba/private/sam.ldb";path.parent.mkdir(parents=True);path.write_text("synthetic partial DB marker")
        def harden(self,request):raise RuntimeError("interrupted before policy/TLS/firewall completion")
        def verify(self,request):pytest.fail("must not verify failed hardening")
    with pytest.raises(RuntimeError):domain.execute({"apply":True},FailAfterDatabase())
    before=list(driver.mutations)
    with pytest.raises(ValueError):driver.ops().inspect(initial=False)
    assert driver.mutations==before
    assert driver.state(DC)=="masked" and driver.state(ALIAS)=="masked"
    assert not (tmp_path/"etc/systemd/system/multi-user.target.wants"/DC).exists()
