"""Manual SYSVOL transport preparation; only public key crosses hosts."""
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import sys
from tools.samba_ad import domain, replica, sysvol
from tools.samba_ad.domain import require, fields
from tools.samba_ad.pki_files import atomic_file, future_directory, secure_file, secure_directory


def public_key(value):
    require(isinstance(value,str) and re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}=?',value))
    return value


def authorized_key(address,key):
    require(str(ipaddress.IPv4Address(address))==address)
    return 'restrict,from="'+address+'",command="'+sysvol.HELPER+' --sysvol-gate" '+public_key(key)+'\n'


def rsync_config():
    return ('[sysvol]\npath = /var/lib/samba/sysvol\nuse chroot = yes\nread only = yes\nlist = no\n'
            'uid = 0\ngid = 0\nmax connections = 1\ntimeout = 120\n'
            'lock file = /run/samba-ad-sysvol-rsync.lock\n'
            'refuse options = links copy-links copy-dirlinks keep-dirlinks devices specials copy-devices write-devices inplace append append-verify remove-source-files\n')


def owned_write(path,content,mode=0o600):
    path=Path(path);future_directory(path.parent)
    if not path.parent.exists():path.parent.mkdir(mode=0o755)
    if path.exists() or path.is_symlink():
        require(secure_file(path).read_bytes()==content)
        require(path.stat().st_mode & 0o777==mode)
    else:
        atomic_file(path,content);path.chmod(mode)


def validate(payload):
    fields(payload,'schema request manifest role public_key host_key helper')
    require(payload['schema']=='samba-ad-sysvol-setup/v1')
    replica.validate_request(payload['request'],payload['manifest'])
    require(payload['request']['enabled'])
    require(payload['role'] in ['source','consumer'])
    public_key(payload['host_key'])
    if payload['role']=='source':public_key(payload['public_key'])
    else:require(payload['public_key'] is None)
    require(isinstance(payload['helper'],str) and payload['helper'].startswith('#!/usr/bin/python3\n'))


def prepare(payload,apply):
    validate(payload)
    r=payload['request'];source=payload['role']=='source'
    local=r['peer'] if source else r['local']
    native=domain.Native(payload['manifest']) if source else replica.Native(payload['manifest'])
    action=native.inspect(local if source else r)
    if source:
        require(action=='current');native.verify(local)
    if not apply:return {'state':'checked','changed':False}
    config={'schema':'samba-ad-sysvol-runtime/v1','role':payload['role'],
            'sid':local['target']['sid'],'realm':local['target']['realm'],'fqdn':local['target']['fqdn'],
            'machine_id':local['identity']['machine_id'],'packages':local['source']['packages'],'peer_fqdn':r['peer']['target']['fqdn']}
    directory=future_directory(sysvol.ROOT)
    exists=directory.exists()
    if not exists:directory.mkdir(mode=0o700)
    secure_directory(directory,exact=True)
    owned_write(sysvol.HELPER,payload['helper'].encode(),0o755)
    owned_write(sysvol.CONFIG,json.dumps(config,sort_keys=True).encode())
    if source:
        # Refuse adoption of an unrelated login. Existing service account is
        # accepted only with our exact installed transport receipt.
        receipt=directory/'transport.json'
        try:account=pwd.getpwnam('samba-sysvol')
        except KeyError:account=None
        if account is not None:require(receipt.exists())
        if account is None:
            sysvol.run(['useradd','--system','--home-dir','/nonexistent','--no-create-home','--shell','/bin/sh','--password','*','samba-sysvol'])
            account=pwd.getpwnam('samba-sysvol')
        require(0<account.pw_uid<1000 and account.pw_dir=='/nonexistent' and account.pw_shell=='/bin/sh')
        addr=r['local']['substrate']['resource']['address'].split('/')[0]
        owned_write('/etc/ssh/samba-ad-sysvol.keys',authorized_key(addr,payload['public_key']).encode(),0o644)
        owned_write('/etc/ssh/sshd_config.d/70-samba-ad-sysvol.conf',
                    b'Match User samba-sysvol\n    AuthorizedKeysFile /etc/ssh/samba-ad-sysvol.keys\n    DisableForwarding yes\n    PermitTTY no\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    AuthenticationMethods publickey\nMatch all\n',0o644)
        owned_write('/etc/sudoers.d/samba-ad-sysvol',('samba-sysvol ALL=(root) NOPASSWD: '+sysvol.HELPER+' --sysvol-export-manifest, '+sysvol.HELPER+' --sysvol-export-rsync\n').encode(),0o440)
        owned_write('/etc/samba-ad-sysvol-rsync.conf',rsync_config().encode())
        sysvol.run(['visudo','-cf','/etc/sudoers.d/samba-ad-sysvol'])
        sysvol.run(['sshd','-t'])
        effective=dict(line.split(' ',1) for line in sysvol.run(['sshd','-T','-C','user=samba-sysvol,host='+r['local']['target']['fqdn']+',addr='+addr]).decode().splitlines())
        require(all(effective.get(k)==v for k,v in {'permitrootlogin':'no','passwordauthentication':'no',
                'kbdinteractiveauthentication':'no','authenticationmethods':'publickey','disableforwarding':'yes',
                'permittty':'no','authorizedkeysfile':'/etc/ssh/samba-ad-sysvol.keys'}.items()))
        # Base non-root key-only policy and existing administrator settings are
        # left intact. The added Match applies solely to the dedicated account.
        if receipt.exists():
            require(json.loads(secure_file(receipt,secret=True).read_bytes())=={'uid':account.pw_uid,'public_key':payload['public_key']})
            return {'state':'source_ready','changed':False}
        sysvol.run(['systemctl','reload','ssh.service'])
        owned_write(receipt,json.dumps({'uid':account.pw_uid,'public_key':payload['public_key']},sort_keys=True).encode())
        # Existing S4 AIDE was verified clean above. Include precisely this
        # reviewed SSH addition in its own baseline before the S4 re-readback.
        sysvol.run(['aide','--config=/etc/samba-ad-integrity.conf','--init'])
        secure_file('/var/lib/samba-ad-integrity/aide.db.new',secret=True).replace('/var/lib/samba-ad-integrity/aide.db')
        native.verify(local)
        return {'state':'source_ready','changed':True}
    key=directory/'pull_ed25519'
    if key.exists():
        secure_file(key,secret=True)
        require((directory/'consumer-ready.json').exists())
    else:
        require(not key.is_symlink() and not key.with_suffix('.pub').exists())
        # Generated in place on DC02. Neither private bytes nor a private hash
        # is returned, copied, slurped or placed in Ansible facts.
        sysvol.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','samba-ad-sysvol-pull','-f',str(key)])
    pub=secure_file(str(key)+'.pub').read_text().split()
    key_public=public_key(' '.join(pub[:2]))
    known=r['peer']['target']['fqdn']+' '+payload['host_key']+'\n'
    owned_write(directory/'known_hosts',known.encode())
    owned_write('/etc/systemd/system/samba-ad-sysvol.service',
                ('[Unit]\nDescription=DC01 to DC02 SYSVOL pull\nAfter=samba-ad-dc.service network-online.target\nRequires=samba-ad-dc.service\n'
                 '[Service]\nType=oneshot\nExecStart='+sysvol.HELPER+' --sysvol-sync\nTimeoutStartSec=300\nUMask=0077\nPrivateTmp=yes\n').encode(),0o644)
    owned_write('/etc/systemd/system/samba-ad-sysvol.timer',b'[Unit]\nDescription=Pull authoritative SYSVOL every two minutes\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=2min\nPersistent=true\n[Install]\nWantedBy=timers.target\n',0o644)
    if (directory/'consumer-ready.json').exists():
        require(json.loads(secure_file(directory/'consumer-ready.json',secret=True).read_bytes())=={'sid':config['sid'],'public_key':key_public})
        return {'state':'consumer_ready','changed':False,'public_key':key_public}
    sysvol.run(['systemctl','daemon-reload'])
    # Timer is enabled only after first successful native join + sync.
    owned_write(directory/'consumer-ready.json',json.dumps({'sid':config['sid'],'public_key':key_public},sort_keys=True).encode())
    return {'state':'consumer_ready','changed':True,'public_key':key_public}


def main():
    try:
        payload=domain.loads(sys.stdin.read())
        result=prepare(payload,'--execute' in sys.argv)
        print(json.dumps(result,sort_keys=True));return 0
    except Exception:
        print(sysvol.ERROR,file=sys.stderr);return 1
