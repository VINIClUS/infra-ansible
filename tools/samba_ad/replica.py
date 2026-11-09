"""Manual, inert S5: native Samba 4.25.1 join into an existing forest only."""
from __future__ import annotations
import contextlib
import fcntl
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
from tools.samba_ad import domain
from tools.samba_ad.domain import command, fields, require, forest_action
from tools.samba_ad.pki_files import atomic_file, secure_directory, secure_file, sync_dir

ERROR = 'S5 precondition failed (values suppressed)'
ROOT = Path('/var/lib/samba-ad-replica')


def validate_request(r, manifest):
    require(r['schema'] == 'samba-ad-replica/v1')
    require(type(r['enabled']) is bool and type(r['apply']) is bool)
    if not r['enabled']:
        fields(r, 'schema enabled apply'); require(not r['apply'])
        return {'state': 'disabled'}
    fields(r, 'schema enabled apply local peer join_user site peer_leaf_sha256')
    domain.hex_value(r['peer_leaf_sha256'])
    domain.validate_host_request(r['local'], manifest, 'dc02')
    domain.validate_request(r['peer'], manifest)
    for profile in ['local', 'peer']:
        require(r[profile]['enabled'] and not r[profile]['apply'])
        require(r[profile]['target']['sid'] is not None)
    require(all(r['local']['target'][k] == r['peer']['target'][k] for k in ['realm','netbios','sid']))
    require(r['local']['source']['packages']==r['peer']['source']['packages'])
    require(r['local']['target']['fqdn'].split('.')[0] == 'dc02')
    require(r['peer']['target']['fqdn'].split('.')[0] == 'dc01')
    require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', r['join_user']))
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,63}', r['site']))
    sysvol_network(r)
    return {'state': 'validated'}


def sysvol_network(request):
    for profile,other,direction in [('peer','local','IN'),('local','peer','OUT')]:
        peer=request[other]['substrate']['resource']['address'].split('/')[0]+'/32'
        require({'direction':direction,'peer':peer,'proto':'tcp','port':'22'} in request[profile]['substrate']['firewall']['flows'])


def join_action(expected, peer, local, occupied, attempted):
    require(expected['sid'] is not None)
    peer_expected = dict(expected, fqdn=peer['fqdn'])
    require(peer['fqdn'] != expected['fqdn'])
    forest_action(peer_expected, peer, True)
    if local is not None:
        require(not attempted)
        return forest_action(expected, local, occupied)
    require(not occupied and not attempted)
    return 'join'


def execute(request, adapter):
    action = adapter.inspect(request)
    if not request['apply']: return {'state':'checked', 'changed':False}
    if action == 'current': return adapter.verify(request)
    try:
        adapter.join(request)
        adapter.harden(request)
        result = adapter.verify(request)
    except Exception:
        try: adapter.quarantine(request)
        except Exception: raise ValueError('S5 failed; quarantine unverified (values suppressed)') from None
        raise ValueError(ERROR) from None
    result['changed'] = True
    return result


def run_join_context(ctx, absence, dns_absence=lambda: None):
    """Pinned upstream do_join sequence, deliberately omitting destructive cleanup.

    join_provision fills local DRS databases with the EXISTING SID; it does not
    create a forest. No join_provision_own_domain, schema upgrade or retry path.
    """
    try:
        absence()
        ctx.build_nc_lists()
        ctx.join_add_objects()
        ctx.join_provision()
        ctx.join_replicate()
        dns_absence()
        ctx.join_add_dns_records()
        ctx.join_replicate_new_dns_records()
        ctx.join_finalise()
    except Exception:
        raise ValueError(ERROR) from None


@contextlib.contextmanager
def quiet_native():
    # Native Samba can print passwords in exception diagnostics. Suppress both
    # Python streams and underlying C writes to fd1/fd2, restoring on failure.
    saved = [os.dup(1), os.dup(2)]
    try:
        with open(os.devnull, 'w') as sink:
            os.dup2(sink.fileno(), 1); os.dup2(sink.fileno(), 2)
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink): yield
    finally:
        for fd, old in zip([1,2], saved): os.dup2(old, fd); os.close(old)


class Native(domain.Native):
    profile = 'dc02'

    def configuration(self, r):
        # Preserve the exact S4 protocol floor without widening its DC01 API.
        conf = domain.smb_conf(r['target']['realm'], r['target']['netbios'], 'dc01', self.manifest['network']['dns_forwarders'])
        return conf.replace('netbios name = DC01', 'netbios name = DC02').replace('/dc01/active.conf','/dc02/active.conf').replace('read only = no','read only = yes')

    def credentials(self, r, machine):
        from samba.credentials import Credentials, MUST_USE_KERBEROS
        from samba.param import LoadParm
        from samba import gensec
        lp = LoadParm(); lp.load('/etc/samba/smb.conf')
        lp.set('realm', r['local']['target']['realm']); lp.set('workgroup', r['local']['target']['netbios'])
        lp.set('tls cafile', r['peer']['pki']['trust']['root_file'])
        lp.set('tls verify peer', 'ca_and_name')
        creds = Credentials(); creds.guess(lp)
        creds.set_kerberos_state(MUST_USE_KERBEROS)
        creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)
        if machine: creds.set_machine_account(lp)
        else:
            password = secure_file('/run/samba-ad-domain-credentials/dc02/join', secret=True).read_text().rstrip('\n')
            require(len(password) >= 14 and '\x00' not in password)
            creds.set_username(r['join_user']); creds.set_password(password)
            del password
        return lp, creds

    def remote(self, r, profile, machine):
        from samba.samdb import SamDB
        from samba.auth import system_session
        target = r[profile]
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        root=x509.load_pem_x509_certificate(secure_file(target['pki']['trust']['root_file']).read_bytes())
        require(root.fingerprint(hashes.SHA256()).hex()==target['pki']['trust']['root_sha256'])
        context = ssl.create_default_context(cafile=target['pki']['trust']['root_file'])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((target['target']['fqdn'],636),timeout=10) as sock:
            with context.wrap_socket(sock,server_hostname=target['target']['fqdn']) as tls:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                # Public leaf pin, stored in the reviewed S3 trust/provenance via
                # local generation for DC02; peer PKI is authenticated by CA/SAN.
                require(tls.version() in ['TLSv1.2','TLSv1.3'])
                if profile=='peer': require(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()==r['peer_leaf_sha256'])
        lp, creds = self.credentials(r, machine)
        db = SamDB(url='ldaps://' + target['target']['fqdn'], credentials=creds, session_info=system_session(), lp=lp)
        saved = getattr(self,'db',None); self.db = db
        observed = self.observed(); self.db = saved
        forest_action(target['target'], observed, True)
        return db, observed, lp, creds

    def remote_absent(self, db, r):
        import ldb
        # Check all naming contexts, not only the expected OU/site. Never
        # remove stale accounts, DNS identities or a server in another site.
        name = 'DC02'; fqdn = r['local']['target']['fqdn']
        expression = '(|(sAMAccountName=DC02$)(sAMAccountName=dns-DC02)(dNSHostName=' + ldb.binary_encode(fqdn) + ')(cn=' + name + '))'
        for base in [db.domain_dn(), db.get_config_basedn()]:
            require(not db.search(base=base, scope=ldb.SCOPE_SUBTREE, expression=expression, attrs=['dn']))
        self.dns_absent(db,r)

    def dns_absent(self,db,r):
        import ldb
        for base in ['DC=DomainDnsZones,'+str(db.domain_dn()),'DC=ForestDnsZones,'+str(db.get_root_basedn())]:
            require(not db.search(base=base,scope=ldb.SCOPE_SUBTREE,expression='(&(objectClass=dnsNode)(name=dc02))',attrs=['dn']))
        fqdn=r['local']['target']['fqdn']
        for server in [r['peer']['substrate']['resource']['address'].split('/')[0]]:
            result = command(['dig','+time=3','+tries=1','+noall','+comments','+answer','@'+server,fqdn,'A']).decode()
            require('status: NOERROR' in result or 'status: NXDOMAIN' in result)
            require(not any(line and not line.startswith(';') for line in result.splitlines()))

    def inspect(self, request):
        from tools.samba_ad import domain_network
        from tools.samba_ad.domain_services import ServiceOps
        r = request['local']
        require(os.geteuid() == 0)
        require(Path('/etc/machine-id').read_text().strip() == r['identity']['machine_id'])
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == r['identity']['boot_id'])
        require(socket.getfqdn() == r['target']['fqdn'])
        interface = r['pki']['target']['interface']
        require(Path('/sys/class/net',interface,'address').read_text().strip().upper() == r['substrate']['resource']['mac'].upper())
        addresses=json.loads(command(['ip','-j','-4','addr','show','dev',interface]))
        require(any(a['local']==r['substrate']['resource']['address'].split('/')[0] for dev in addresses for a in dev['addr_info']))
        require(hashlib.sha256(secure_file('/etc/samba/smb.conf').read_bytes()).hexdigest() == r['identity']['config_sha256'])
        self.host_guard(r); self.verify_packages(r); self.generation(r); domain_network.inspect(r)
        self.db = self.database() if Path('/var/lib/samba/private/sam.ldb').exists() else None
        attempted = (ROOT/'attempt.json').exists() or (ROOT/'attempt.json').is_symlink()
        receipt = ROOT/'joined.json'
        completed = receipt.exists()
        if completed:
            require(json.loads(secure_file(receipt,secret=True).read_bytes()) == {'sid':r['target']['sid'],'spec_sha256':r['pki']['target']['spec_sha256']})
        require(not attempted or completed)
        self.services = ServiceOps(); self.service_snapshot = self.services.inspect(initial=self.db is None)
        occupied = self.db is not None
        if self.db is None:
            require(not completed and not Path('/etc/krb5.keytab').exists())
            for path in ['/var/lib/samba/private','/var/lib/samba/sysvol','/var/lib/samba-ad-integrity']:
                p=Path(path); require(not p.is_symlink() and (not p.exists() or p.is_dir() and not any(p.iterdir())))
            active=Path('/var/lib/samba-ad-pki/dc02/active.conf'); require(not active.exists() and not active.is_symlink())
        with quiet_native():
            peer, observed, _, _ = self.remote(request,'peer',machine=completed)
            action = join_action(r['target'],observed,self.observed() if self.db else None,occupied,attempted and not completed)
            if action == 'join': self.remote_absent(peer,request)
        return action

    def join(self, request):
        require(self.inspect(request) == 'join')
        r=request['local']
        from tools.samba_ad import sysvol
        sysvol.prejoin(r['target'])
        from samba.join import DCJoinContext
        from samba import dsdb
        from samba.dcerpc import misc, drsuapi
        from tools.samba_ad.pki_files import future_directory
        directory=future_directory(ROOT)
        if not directory.exists(): directory.mkdir(mode=0o700)
        # O_EXCL + fsync before ANY remote mutation; an interrupted join cannot
        # be resumed even if upstream left no local database.
        fd=os.open(ROOT/'attempt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as file:
            json.dump({'sid':r['target']['sid']},file);file.flush();os.fsync(file.fileno())
        sync_dir(ROOT)
        self.prepare_config(r)
        logger=logging.getLogger('samba-ad-replica-null');logger.handlers=[logging.NullHandler()];logger.propagate=False
        with quiet_native():
            lp,creds=self.credentials(request,False)
            ctx=DCJoinContext(logger=logger,server=request['peer']['target']['fqdn'],creds=creds,lp=lp,
                              site=request['site'],netbios_name='DC02',domain=r['target']['realm'],
                              dns_backend='SAMBA_INTERNAL',promote_existing=False,plaintext_secrets=False)
            require(str(ctx.domsid)==r['target']['sid'] and ctx.behavior_version==7)
            lp.set('workgroup',ctx.domain_name);lp.set('realm',ctx.realm)
            ctx.userAccountControl=dsdb.UF_SERVER_TRUST_ACCOUNT|dsdb.UF_TRUSTED_FOR_DELEGATION
            ctx.SPNs.append('E3514235-4B06-11D1-AB04-00C04FC2DCD2/$NTDSGUID/%s' % ctx.dnsdomain)
            ctx.secure_channel_type=misc.SEC_CHAN_BDC
            ctx.replica_flags|=drsuapi.DRSUAPI_DRS_WRIT_REP|drsuapi.DRSUAPI_DRS_FULL_SYNC_IN_PROGRESS
            ctx.domain_replica_flags=ctx.replica_flags
            run_join_context(ctx,lambda:self.remote_absent(ctx.samdb,request),lambda:self.dns_absent(ctx.samdb,request))
        self.db=self.database()
        from tools.samba_ad import sysvol
        self.initial_sysvol=sysvol.snapshot(sysvol.TREE,require_ntacl=False)

    def activate(self,r):
        self.pre_activation(r)
        self.activation_started=True
        self.services.activate(self.blocked_services)
        command(['systemctl','start','samba-ad-dc.service'])
        self.services.inspect(initial=False)

    def quarantine(self,request):
        if not getattr(self,'activation_started',False):return
        from tools.samba_ad.domain_services import MEMBERS,DC,ALIAS
        require(json.loads(secure_file(ROOT/'attempt.json',secret=True).read_bytes())=={'sid':request['local']['target']['sid']})
        # Revalidate canonical fragments/aliases before stopping ONLY our DC.
        for unit in [*MEMBERS,DC,ALIAS]:
            current=self.services.snapshot(unit)
            require(current['vendor_sha256']==self.service_snapshot[unit]['vendor_sha256'])
        if getattr(self,'timer_started',False):command(['systemctl','disable','--now','samba-ad-sysvol.timer'])
        command(['systemctl','stop',DC])
        self.services.converge_initial(self.services.inspect(initial=True))

    def configure_policy(self, r):
        # A replica never writes forest policy. Verify the replicated S4 policy.
        import ldb
        row=self.db.search(base=self.db.domain_dn(),scope=ldb.SCOPE_BASE,attrs=list(domain.PASSWORD_POLICY))[0]
        require(all(int(row[k][0])==v for k,v in domain.PASSWORD_POLICY.items()))

    def harden(self, request):
        super().harden(request['local'])
        command(['samba_dnsupdate','--use-nsupdate','--fail-immediately'])
        for profile in ['peer','local']:
            command(['samba-tool','drs','kcc',request[profile]['target']['fqdn'],'--machine-pass','--use-kerberos=required'])
        from tools.samba_ad.replica_health import wait_for_health
        with quiet_native(): wait_for_health(self,request)
        from tools.samba_ad import sysvol
        sysvol.sync(initial_baseline=self.initial_sysvol)
        self.timer_started=True
        command(['systemctl','enable','--now','samba-ad-sysvol.timer'])

    def initial_receipt(self, r):
        return (ROOT/'attempt.json').exists() and not (ROOT/'joined.json').exists()

    def verify(self, request):
        r=request['local']
        result=super().verify(r)
        from tools.samba_ad.replica_health import verify
        with quiet_native(): verify(self,request)
        from tools.samba_ad import sysvol
        sysvol.inspect()
        data={'sid':r['target']['sid'],'spec_sha256':r['pki']['target']['spec_sha256']}
        receipt=ROOT/'joined.json'
        if receipt.exists(): require(json.loads(secure_file(receipt,secret=True).read_bytes())==data)
        else: atomic_file(receipt,json.dumps(data).encode())
        result.update(replication='verified',dns_gc_kerberos='verified',sysvol='verified')
        return result


def main():
    try:
        payload=domain.loads(sys.stdin.read());fields(payload,'schema request manifest')
        require(payload['schema']=='samba-ad-replica-wire/v1')
        r=payload['request']; state=validate_request(r,payload['manifest'])
        if state['state']=='disabled': result={'state':'disabled','changed':False}
        else:
            if '--execute' not in sys.argv:r['apply']=False
            # flock serializes the complete check/join/hardening sequence.
            secure_directory('/run',exact=False)
            fd=os.open('/run/samba-ad-replica.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                result=execute(r,Native(payload['manifest']))
        print(json.dumps(result,sort_keys=True));return 0
    except Exception:
        print(ERROR,file=sys.stderr);return 1

if __name__=='__main__': raise SystemExit(main())
