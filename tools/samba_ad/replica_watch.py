"""Systemd-owned partial-DC watchdog, independent of the manual join process."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from tools.samba_ad import replica
from tools.samba_ad.domain import fields, hex_value, require
from tools.samba_ad.domain_services import ServiceOps, MEMBERS, DC, ALIAS, DROPIN
from tools.samba_ad.pki_files import atomic_file, secure_directory, secure_file

TIMER='samba-ad-replica-watch.timer'
SERVICE='samba-ad-replica-watch.service'
OWNED_FILES=(DROPIN,'/etc/systemd/system/'+TIMER,'/etc/systemd/system/'+SERVICE,
             '/etc/systemd/system/samba-ad-sysvol.timer','/etc/systemd/system/samba-ad-sysvol.service')


def command(argv,data=None,allowed=(0,)):
    result=subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False)
    require(result.returncode in allowed)
    return result.stdout


@contextlib.contextmanager
def lock():
    secure_directory(replica.ROOT,exact=True)
    fd=os.open(replica.ROOT/'supervision.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as file:
        fcntl.flock(file,fcntl.LOCK_EX)
        yield


def arm(request,snapshot):
    require(not (replica.ROOT/'watch.json').exists() and not (replica.ROOT/'revoked.json').exists())
    record={'schema':'samba-ad-replica-watch/v1',
            'identity':{'sid':request['target']['sid'],'spec_sha256':request['pki']['target']['spec_sha256'],
                        'machine_id':request['identity']['machine_id']},
            'vendor':{unit:snapshot[unit]['vendor_sha256'] for unit in [*MEMBERS,DC,ALIAS]},
            'files':{path:hashlib.sha256(secure_file(path).read_bytes()).hexdigest() for path in OWNED_FILES}}
    atomic_file(replica.ROOT/'watch.json',json.dumps(record,sort_keys=True).encode())


def supervise(io):
    """Commit and revocation share a lock: a late parent cannot undo expiry."""
    with io.lock():
        if not io.revoked() and io.committed():
            io.disarm()
            return 'committed'
        if not io.revoked() and io.lease_valid():return 'watching'
        io.revoke()  # Durable before stopping; boot and commit refuse it.
        io.block()
        return 'blocked'


class NativeWatch:
    def __init__(self):
        require(os.geteuid()==0)
        self.record=json.loads(secure_file(replica.ROOT/'watch.json',secret=True).read_bytes())
        fields(self.record,'schema identity vendor files')
        require(self.record['schema']=='samba-ad-replica-watch/v1')
        fields(self.record['identity'],'sid spec_sha256 machine_id')
        require(self.record['identity']['machine_id']==Path('/etc/machine-id').read_text().strip())
        require(set(self.record['vendor'])=={*MEMBERS,DC,ALIAS} and set(self.record['files'])==set(OWNED_FILES))
        for value in [*self.record['vendor'].values(),*self.record['files'].values()]:hex_value(value)
        self.expected={key:self.record['identity'][key] for key in ['sid','spec_sha256']}

    def lock(self):return lock()

    def revoked(self):return (replica.ROOT/'revoked.json').exists() or (replica.ROOT/'revoked.json').is_symlink()

    def committed(self):
        path=replica.ROOT/'joined.json'
        if not path.exists():return False
        return json.loads(secure_file(path,secret=True).read_bytes())==self.expected

    def lease_valid(self):
        try:
            replica.activation_lease()
            return True
        except Exception:return False

    def owned(self):
        for path,digest in self.record['files'].items():
            require(hashlib.sha256(secure_file(path).read_bytes()).hexdigest()==digest)
        services=ServiceOps(run=command)
        for unit,digest in self.record['vendor'].items():
            require(services.snapshot(unit)['vendor_sha256']==digest)
        return services

    def revoke(self):
        if not self.revoked():
            atomic_file(replica.ROOT/'revoked.json',json.dumps({'state':'revoked','at':int(time.time()),
                        'reason':'manual_process_lost_or_expired'}).encode())

    def block(self):
        services=self.owned()  # Never stop a substituted unit or unrelated guest.
        command(['systemctl','disable','--now','samba-ad-sysvol.timer'])
        command(['systemctl','stop','samba-ad-sysvol.service'])
        command(['systemctl','stop',DC])
        services.converge_initial(services.inspect(initial=True))
        atomic_file(replica.ROOT/'watch-status.json',json.dumps({'state':'blocked','last_check':int(time.time())}).encode())

    def disarm(self):
        self.owned()
        command(['systemctl','disable','--now',TIMER])


def commit(data):
    io=NativeWatch()
    with io.lock():
        require(not io.revoked() and data==io.expected)
        replica.activation_lease()
        io.owned()
        for action in ['is-active','is-enabled']:command(['systemctl',action,'--quiet',TIMER])
        replica.activation_lease()  # Recheck deadline after potentially slow readbacks.
        atomic_file(replica.ROOT/'joined.json',json.dumps(data).encode())
        if replica.ACTIVATION.exists():secure_file(replica.ACTIVATION,secret=True).unlink()


def main():
    result=supervise(NativeWatch())
    print(json.dumps({'state':result}))
