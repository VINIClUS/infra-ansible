"""Independent local watcher, abrupt SIGKILL and controlled fake DC process."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import pytest


@pytest.mark.parametrize('mode',['kill','expire','complete'])
def test_external_watcher_stops_fake_dc_after_manual_sigkill(tmp_path,mode):
    # All processes are local controlled sleepers. No manager, services or SSH.
    owner=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    dc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    env=dict(os.environ,S5_TEST_ROOT=str(tmp_path),S5_TEST_OWNER=str(owner.pid),S5_TEST_DC=str(dc.pid),S5_TEST_MODE=mode)
    code=r'''
import contextlib,importlib.util,json,os,signal,sys,time
from pathlib import Path
from tools.samba_ad import replica
root=Path(os.environ['S5_TEST_ROOT']);owner=int(os.environ['S5_TEST_OWNER']);dc=int(os.environ['S5_TEST_DC'])
if importlib.util.find_spec('tools.samba_ad.replica_watch') is None:
 (root/'ready').touch();time.sleep(.5);sys.exit(0)
from tools.samba_ad import replica_watch
start,_=replica.process_identity(owner)
mode=os.environ['S5_TEST_MODE'];boot='test-boot'
token={'pid':owner,'starttime':start,'boot_id':boot,'deadline':time.time()+(.3 if mode=='expire' else 5)}
class Local:
 def lock(self):return contextlib.nullcontext()
 def committed(self):return (root/'committed').exists()
 def revoked(self):return (root/'revoked').exists()
 def lease_valid(self):
  try:
   current,state=replica.process_identity(owner)
   return replica.activation_matches(token,owner,current,state,boot,time.time())
  except (FileNotFoundError,ProcessLookupError):return False
 def revoke(self):(root/'revoked').write_text('durable revocation')
 def block(self):
  os.kill(dc,signal.SIGKILL)
  (root/'masked').write_text('only owned fake DC blocked')
 def disarm(self):(root/'disarmed').touch()
(root/'ready').touch()
while replica_watch.supervise(Local()) not in ['blocked','committed']:time.sleep(.02)
'''
    monitor=subprocess.Popen([sys.executable,'-c',code],env=env,cwd=Path(__file__).resolve().parents[1])
    try:
        deadline=time.monotonic()+5
        while not (tmp_path/'ready').exists() and time.monotonic()<deadline:time.sleep(.01)
        assert (tmp_path/'ready').exists()
        assert dc.poll() is None
        if mode=='kill':owner.kill();owner.wait(timeout=5)
        if mode=='complete':(tmp_path/'committed').write_text('validated receipt fixture')
        assert monitor.wait(timeout=5)==0
        if mode=='complete':
            assert dc.poll() is None and (tmp_path/'disarmed').exists()
            assert not (tmp_path/'revoked').exists()
            return
        try:dc.wait(timeout=1)
        except subprocess.TimeoutExpired:pytest.fail('manual SIGKILL left the partial fake DC active')
        assert dc.returncode==-signal.SIGKILL
        assert (tmp_path/'revoked').exists() and (tmp_path/'masked').exists()
    finally:
        for process in [owner,dc,monitor]:
            if process.poll() is None:process.kill()
            process.wait(timeout=5)


def test_expiry_during_commit_validation_cannot_publish_joined_receipt(tmp_path,monkeypatch):
    import contextlib
    from tools.samba_ad import replica,replica_watch
    expired=False
    class Fake:
        expected={'sid':'S-1-5-21-1-2-3','spec_sha256':'a'*64}
        def lock(self):return contextlib.nullcontext()
        def revoked(self):return False
        def owned(self):
            nonlocal expired
            expired=True
    monkeypatch.setattr(replica_watch,'NativeWatch',Fake)
    monkeypatch.setattr(replica_watch,'command',lambda *a,**kw:b'')
    monkeypatch.setattr(replica,'ROOT',tmp_path)
    def lease():
        if expired:raise ValueError('deadline elapsed during unit validation')
    monkeypatch.setattr(replica,'activation_lease',lease)
    with pytest.raises(ValueError):replica_watch.commit(Fake.expected)
    assert not (tmp_path/'joined.json').exists()


def test_native_activation_requires_external_watcher_before_unmask_and_start(tmp_path,monkeypatch):
    from tools.samba_ad import replica,replica_watch
    calls=[]
    native=replica.Native({});native.service_snapshot={};native.blocked_services={}
    monkeypatch.setattr(replica,'ACTIVATION',tmp_path/'activation.json')
    monkeypatch.setattr(native,'pre_activation',lambda r:calls.append('pre_activation'))
    monkeypatch.setattr(replica_watch,'arm',lambda r,s:calls.append('arm'))
    monkeypatch.setattr(replica,'activation_lease',lambda:calls.append('lease'))
    monkeypatch.setattr(replica,'command',lambda argv:calls.append(tuple(argv)) or b'')
    class Services:
        def activate(self,snapshot):
            assert ('systemctl','start',replica_watch.SERVICE) in calls
            assert ('systemctl','is-active','--quiet',replica_watch.TIMER) in calls
            assert ('systemctl','is-enabled','--quiet',replica_watch.TIMER) in calls
            calls.append('release_masks')
        def inspect(self,initial):assert initial is False
    native.services=Services();native.activate({})
    assert calls.index('arm')<calls.index(('systemctl','start',replica_watch.SERVICE))<calls.index('release_masks')
    assert calls.index('release_masks')<calls.index(('systemctl','start','samba-ad-dc.service'))


def test_revocation_stops_only_exact_owned_units_and_restores_service_masks(tmp_path,monkeypatch):
    from tools.samba_ad import replica,replica_watch
    calls=[];watch=replica_watch.NativeWatch.__new__(replica_watch.NativeWatch)
    class Services:
        def inspect(self,initial):
            assert initial and calls[-1]==['systemctl','stop','samba-ad-dc.service'];return {'owned':'stopped'}
        def converge_initial(self,observed):assert observed=={'owned':'stopped'};calls.append('masked')
    monkeypatch.setattr(replica,'ROOT',tmp_path)
    monkeypatch.setattr(watch,'owned',lambda:Services())
    monkeypatch.setattr(replica_watch,'command',lambda argv:calls.append(argv) or b'')
    watch.block()
    assert calls==[['systemctl','disable','--now','samba-ad-sysvol.timer'],
                   ['systemctl','stop','samba-ad-sysvol.service'],
                   ['systemctl','stop','samba-ad-dc.service'],'masked']
    assert json.loads((tmp_path/'watch-status.json').read_text())['state']=='blocked'


def test_revocation_wins_over_late_completion():
    import contextlib
    from tools.samba_ad.replica_watch import supervise
    calls=[]
    class State:
        def lock(self):return contextlib.nullcontext()
        def revoked(self):return True
        def committed(self):pytest.fail('revoked activation cannot be adopted')
        def lease_valid(self):pytest.fail('revoked activation cannot become live')
        def revoke(self):calls.append('revoke')
        def block(self):calls.append('block')
        def disarm(self):pytest.fail('must keep watching partial DC')
    assert supervise(State())=='blocked' and calls==['revoke','block']
