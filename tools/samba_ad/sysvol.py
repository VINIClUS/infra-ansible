"""DC01-authoritative SYSVOL pull. No DFS-R; no automatic conflict resolution."""
from __future__ import annotations
import configparser
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
import time
from tools.samba_ad.domain import require, sha
from tools.samba_ad.pki_files import atomic_file, secure_directory, secure_file, sync_dir

ROOT=Path('/var/lib/samba-ad-sysvol')
TREE=Path('/var/lib/samba/sysvol')
CONFIG=Path('/etc/samba-ad-sysvol.json')
HELPER='/usr/local/libexec/samba-ad-s5'
ERROR='S5 SYSVOL refused; inspect local status (values suppressed)'


def run(argv, timeout=300):
    result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    require(result.returncode==0)
    return result.stdout


def stable_stat(value):
    return tuple(getattr(value,key) for key in ['st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_nlink','st_mtime_ns','st_ctime_ns'])


def snapshot(root, require_ntacl=True):
    """Hash content, numeric owners, POSIX ACL and security.NTACL without following links.

    The optional ACL check permits generic filesystem diagnostics; runtime always
    uses the strict default. It is not exposed on the command line or request.
    """
    root=Path(root); root_stat=root.lstat()
    require(stat.S_ISDIR(root_stat.st_mode))
    rows={};total=0
    for path in [root,*sorted(root.rglob('*'))]:
        st=path.lstat()
        require(st.st_dev==root_stat.st_dev and (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)))
        require(not stat.S_ISREG(st.st_mode) or st.st_nlink==1)
        require(not st.st_mode & (stat.S_ISUID|stat.S_ISGID))
        name=str(path.relative_to(root))
        require('\n' not in name and '\x00' not in name and len(name)<2048)
        attrs={key:hashlib.sha256(os.getxattr(path,key,follow_symlinks=False)).hexdigest() for key in sorted(os.listxattr(path,follow_symlinks=False))}
        if require_ntacl: require('security.NTACL' in attrs)
        acl_ids=[]
        for key in ['system.posix_acl_access','system.posix_acl_default']:
            if key not in attrs:continue
            acl=os.getxattr(path,key,follow_symlinks=False)
            require(len(acl)>=4 and struct.unpack('<I',acl[:4])[0]==2 and (len(acl)-4)%8==0)
            for tag,_,identity in struct.iter_unpack('<HHI',acl[4:]):
                if tag in [2,8]:acl_ids.append(['uid' if tag==2 else 'gid',identity])
        row={'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'xattrs':attrs,'acl_ids':acl_ids,'kind':'directory'}
        if stat.S_ISREG(st.st_mode):
            total+=st.st_size;require(st.st_size<=64*1024*1024 and total<=1024*1024*1024)
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as file:
                require(stable_stat(os.fstat(file.fileno()))==stable_stat(st))
                data=file.read();require(stable_stat(os.fstat(file.fileno()))==stable_stat(st))
            row.update(kind='file',sha256=hashlib.sha256(data).hexdigest())
            if path.name.upper()=='GPT.INI':
                encoding='utf-16' if data.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'
                parser=configparser.ConfigParser();parser.read_string(data.decode(encoding))
                version=parser.getint('General','Version');require(0<=version<=0xffffffff)
                row['gpt_version']=version
        require(stable_stat(path.lstat())==stable_stat(st))
        rows[name]=row;require(len(rows)<=100000)
    return {'digest':sha(rows),'entries':rows}


def idmap(tree):
    ids=set()
    for row in tree['entries'].values():
        ids.update([('uid',row['uid']),('gid',row['gid'])])
        ids.update(tuple(v) for v in row['acl_ids'])
    result={}
    for kind,identity in sorted(ids):
        sid=run(['wbinfo','--'+kind+'-to-sid',str(identity)],timeout=15).decode().strip()
        require(re.fullmatch(r'S-1-(?:[0-9]+-)+[0-9]+',sid))
        result[kind+':'+str(identity)]=sid
    return result


def validate_tree(tree, config):
    require(set(p.name for p in tree.iterdir())=={config['realm'].lower()})
    result=snapshot(tree)
    policies=tree/config['realm'].lower()/'Policies'
    require(policies.is_dir())
    for path in policies.iterdir():
        require(path.is_dir() and re.fullmatch(r'\{[A-Fa-f0-9-]{36}\}',path.name))
        require((path/'GPT.INI').is_file())
    # The security.NTACL value is preserved byte-for-byte. Native sysvolcheck
    # resolves descriptors against this SAME domain SID before and after copy.
    return result


def synchronize(io, baseline):
    require(io.current()==baseline)
    before=io.remote()
    transferred=io.transfer()
    require(before==transferred and io.remote()==before)
    require(io.current()==baseline)
    io.publish()
    io.verify()
    return before


def export_command(original):
    require(original in ['manifest','rsync --server --daemon .'])
    return 'manifest' if original=='manifest' else 'rsync'


def local_domain(config):
    from tools.samba_ad import domain
    native=domain.Native({});native.db=native.database();observed=native.observed()
    require(observed['sid']==config['sid'] and observed['realm']==config['realm'])
    require(observed['fqdn']==config['fqdn'])
    require((observed['domain_level'],observed['forest_level'],observed['schema_version'])==(7,7,88))
    return native


def runtime_config():
    config=json.loads(secure_file(CONFIG,secret=True).read_bytes())
    require(config['schema']=='samba-ad-sysvol-runtime/v1' and config['role'] in ['source','consumer'])
    require(os.geteuid()==0)
    require(Path('/etc/machine-id').read_text().strip()==config['machine_id'])
    local_domain(config)
    import samba
    require(samba.version=='4.25.1')
    require(run(['samba','--version']).decode().strip()=='Version 4.25.1')
    from tools.samba_ad.domain_source import validate_pins
    validate_pins(config['packages'])
    for name,version in config['packages'].items():
        require(run(['dpkg-query','--show','--showformat=${db:Status-Status} ${Version}',name]).decode()=='installed '+version)
    return config


def export(mode):
    config=runtime_config();require(config['role']=='source')
    secure_directory(ROOT,exact=True)
    fd=os.open(ROOT/'export.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        run(['samba-tool','ntacl','sysvolcheck'])
        data=validate_tree(TREE,config)
        if mode=='manifest':
            print(json.dumps({'sid':config['sid'],'packages':config['packages'],'idmap':idmap(data),**data},sort_keys=True));return
        # Fixed daemon-over-SSH read-only module. Never accepts a caller path,
        # server option, module or sudo argument. No TCP rsync daemon is started.
        run_args=['/usr/bin/rsync','--server','--daemon','--config=/etc/samba-ad-sysvol-rsync.conf','.']
        result=subprocess.run(run_args,timeout=240,check=False)
        require(result.returncode==0)


class Pull:
    def __init__(self,config,initial_baseline=None):
        self.config=config
        self.initial_baseline=initial_baseline
        self.last_local=None
        self.stage=None
        self.ssh=['/usr/bin/ssh','-F','/dev/null','-T','-i',str(ROOT/'pull_ed25519'),
                  '-oBatchMode=yes','-oIdentitiesOnly=yes','-oStrictHostKeyChecking=yes',
                  '-oUserKnownHostsFile='+str(ROOT/'known_hosts'),'-oGlobalKnownHostsFile=/dev/null',
                  '-oConnectTimeout=10','-oConnectionAttempts=1','-oServerAliveInterval=15','-oServerAliveCountMax=2']
        secure_file(ROOT/'pull_ed25519',secret=True);secure_file(ROOT/'known_hosts',secret=True)

    def current(self):
        self.last_local = snapshot(TREE,require_ntacl=False) if self.initial_baseline is not None else validate_tree(TREE,self.config)
        return self.last_local

    def remote(self,resolve_ids=True):
        data=json.loads(run(self.ssh+['samba-sysvol@'+self.config['peer_fqdn'],'manifest'],timeout=60))
        require(data.pop('sid')==self.config['sid'])
        require(data.pop('packages')==self.config['packages'])
        mappings=data.pop('idmap')
        if resolve_ids:require(mappings==idmap(data))
        require(set(data)=={'digest','entries'} and sha(data['entries'])==data['digest'])
        return data

    def transfer(self):
        self.stage=Path(tempfile.mkdtemp(prefix='.samba-ad-sysvol-',dir=TREE.parent))
        # Never dereference symlinks or materialize devices/special files. The
        # manifest rejects these even if rsync would silently skip them.
        run(['/usr/bin/rsync','--fsync','-aAX','--numeric-ids','--delete-delay','--no-links','--no-devices','--no-specials',
             '--timeout=120','-e',shlex.join(self.ssh),
             'samba-sysvol@'+self.config['peer_fqdn']+'::sysvol/',str(self.stage)+'/'])
        return validate_tree(self.stage,self.config)

    def publish(self):
        require(self.stage is not None and self.stage.parent==TREE.parent)
        require(TREE.stat().st_dev==self.stage.stat().st_dev)
        for path in sorted(self.stage.rglob('*')):
            if path.is_dir():sync_dir(path)
        sync_dir(self.stage)
        # A durable partial marker means ANY interruption is inspect-only next
        # time. Exchange publishes a complete tree in one Linux rename syscall.
        marker={'stage':str(self.stage),'started':int(time.time())}
        atomic_file(ROOT/'partial.json',json.dumps(marker).encode())
        libc=ctypes.CDLL(None,use_errno=True)
        result=libc.renameat2(-100,os.fsencode(self.stage),-100,os.fsencode(TREE),2)
        require(result==0)
        sync_dir(TREE.parent)
        # Detect a local write racing the final pre-exchange snapshot, restore
        # the complete previous tree atomically and retain both for inspection.
        previous=snapshot(self.stage,require_ntacl=self.initial_baseline is None)
        if previous != self.last_local:
            require(libc.renameat2(-100,os.fsencode(self.stage),-100,os.fsencode(TREE),2)==0)
            sync_dir(TREE.parent)
            require(False)
        self.initial_baseline=None

    def verify(self):
        run(['samba-tool','ntacl','sysvolcheck'])
        require(self.current()==self.remote())
        # Preserve the former owned tree for explicit inspection, not recursive
        # deletion. A subsequent sync refuses until that path is reviewed.


def prejoin(expected):
    config=json.loads(secure_file(CONFIG,secret=True).read_bytes())
    require(config['schema']=='samba-ad-sysvol-runtime/v1' and config['role']=='consumer')
    require(all(config[key]==expected[key] for key in ['sid','realm','fqdn']))
    require(Path('/etc/machine-id').read_text().strip()==config['machine_id'])
    receipt=json.loads(secure_file(ROOT/'consumer-ready.json',secret=True).read_bytes())
    require(receipt['sid']==expected['sid'])
    require(not (ROOT/'status.json').exists() and not (ROOT/'partial.json').exists())
    # Authentication/host key/export/SID/content are proven before remote join
    # mutations. Numeric ID -> SID equality requires the joined local database
    # and is therefore checked again during the first actual transfer.
    data=Pull(config).remote(resolve_ids=False)
    require(expected['realm'].lower() in data['entries'])


def sync(initial_baseline=None):
    config=runtime_config();require(config['role']=='consumer')
    secure_directory(ROOT,exact=True)
    fd=os.open(ROOT/'sync.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        old={}
        backend=None
        status=ROOT/'status.json'
        if status.exists():old=json.loads(secure_file(status,secret=True).read_bytes())
        try:
            require(not (ROOT/'partial.json').exists())
            backend=Pull(config,initial_baseline)
            baseline=old.get('baseline')
            if baseline is None:
                require(initial_baseline is not None and not old)
                # The only adoption point: join's fresh local SYSVOL, before it
                # is writable to clients. Never invoked by timer or CLI retry.
                baseline=initial_baseline
            result=synchronize(backend,baseline)
            record={'state':'ok','last_success':int(time.time()),'last_attempt':int(time.time()),'failures':0,
                    'baseline':result,'sid':config['sid']}
            atomic_file(status,json.dumps(record,sort_keys=True).encode())
            # The exchanged old tree contains only previously owned SYSVOL.
            # Remove through fd-safe shutil after lstat/manifest validation.
            import shutil
            require(backend.stage is not None and backend.stage.parent==TREE.parent)
            snapshot(backend.stage,require_ntacl=initial_baseline is None)
            require(shutil.rmtree.avoids_symlink_attacks)
            shutil.rmtree(backend.stage)
            (ROOT/'partial.json').unlink();sync_dir(ROOT)
            return {'state':'synced','changed':True,'last_success':record['last_success']}
        except Exception:
            # An unpublished temporary tree has no recovery value. Delete only
            # this process's exact staging path with Python's fd-safe walker.
            if backend is not None and backend.stage is not None and not (ROOT/'partial.json').exists():
                import shutil
                require(backend.stage.parent==TREE.parent and shutil.rmtree.avoids_symlink_attacks)
                shutil.rmtree(backend.stage)
            atomic_file(status,json.dumps({**old,'state':'failed_or_conflict','last_attempt':int(time.time()),
                                          'failures':old.get('failures',0)+1},sort_keys=True).encode())
            raise ValueError(ERROR) from None


def inspect():
    config=runtime_config();require(config['role']=='consumer')
    status=json.loads(secure_file(ROOT/'status.json',secret=True).read_bytes())
    require(status['state']=='ok' and status['sid']==config['sid'])
    require(0<=time.time()-status['last_success']<=600)
    require(not (ROOT/'partial.json').exists())
    require(validate_tree(TREE,config)==status['baseline'])
    run(['samba-tool','ntacl','sysvolcheck'])
    for action in ['is-active','is-enabled']:run(['systemctl',action,'--quiet','samba-ad-sysvol.timer'])
    return {'state':'current','changed':False,'age_seconds':int(time.time()-status['last_success'])}


def main():
    try:
        args=sys.argv[1:]
        if args==['--sysvol-export-manifest']:export('manifest');return 0
        if args==['--sysvol-export-rsync']:export('rsync');return 0
        if args==['--sysvol-gate']:
            mode=export_command(os.environ.get('SSH_ORIGINAL_COMMAND',''))
            os.execv('/usr/bin/sudo',['sudo','-n',HELPER,'--sysvol-export-'+mode])
        require(args in [['--sysvol-sync'],['--sysvol-inspect']])
        print(json.dumps(sync() if args==['--sysvol-sync'] else inspect()));return 0
    except Exception:
        print(ERROR,file=sys.stderr);return 1
