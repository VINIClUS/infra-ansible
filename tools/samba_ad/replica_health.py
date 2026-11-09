"""Native authenticated readbacks; no request-supplied health verdicts."""
import time
from tools.samba_ad.domain import command, require


def healthy_neighbours(rows, expected_nc, peer_dn, now):
    seen=set()
    for row in rows:
        if str(row.source_dsa_obj_dn).lower() != peer_dn.lower(): continue
        require(row.result_last_attempt[0] == 0 and row.consecutive_sync_failures == 0)
        success=row.last_success/10000000-11644473600
        require(-5 <= now-success <= 900)
        seen.add(str(row.naming_context_dn).lower())
    require(seen == {str(n).lower() for n in expected_nc})


def verify(native, request):
    import ldb
    from samba import drs_utils
    from samba.dcerpc import drsuapi
    databases={}
    for profile in ['peer','local']:
        db,_,lp,creds=native.remote(request,profile,True)
        root=db.search(base='',scope=ldb.SCOPE_BASE,attrs=['isSynchronized','isGlobalCatalogReady','dnsHostName'])[0]
        require(str(root['isSynchronized'][0])=='TRUE' and str(root['isGlobalCatalogReady'][0])=='TRUE')
        require(str(root['dnsHostName'][0]).lower()==request[profile]['target']['fqdn'])
        # Kerberos is REQUIRED in native.remote credentials. An LDAPS SASL
        # connection and this GC bind cannot silently fall back to NTLM.
        from samba.samdb import SamDB
        gc=SamDB(url='ldaps://'+request[profile]['target']['fqdn']+':3269',credentials=creds,lp=lp)
        require(gc.search(base=db.domain_dn(),scope=ldb.SCOPE_BASE,attrs=['objectGUID']))
        databases[profile]=(db,lp,creds)
    for profile,other in [('peer','local'),('local','peer')]:
        db,lp,creds=databases[profile]
        peer=databases[other][0]
        nc=[db.domain_dn(),db.get_config_basedn(),db.get_schema_basedn(),
            'DC=DomainDnsZones,'+str(db.domain_dn()),'DC=ForestDnsZones,'+str(db.get_root_basedn())]
        connection,handle,_=drs_utils.drsuapi_connect(request[profile]['target']['fqdn'],lp,creds)
        req=drsuapi.DsReplicaGetInfoRequest1();req.info_type=drsuapi.DRSUAPI_DS_REPLICA_INFO_NEIGHBORS
        _,info=connection.DsReplicaGetInfo(handle,1,req)
        healthy_neighbours(info.array,nc,str(peer.get_dsServiceName()),time.time())
        address=request[profile]['substrate']['resource']['address'].split('/')[0]
        realm=request[profile]['target']['realm'].lower()
        for service,port in [('_ldap._tcp.dc._msdcs.',389),('_kerberos._tcp.',88),('_gc._tcp.',3268)]:
            raw=command(['dig','+time=3','+tries=1','+short','@'+address,service+realm,'SRV']).decode()
            found={(int(v[2]),v[3].rstrip('.').lower()) for line in raw.splitlines() if len(v:=line.split())==4}
            require(all((port,request[p]['target']['fqdn']) in found for p in ['peer','local']))


def wait_for_health(native,request):
    deadline=time.monotonic()+180
    while True:
        try:
            verify(native,request);return
        except Exception:
            if time.monotonic()>=deadline:raise ValueError('S5 native replication health pending (values suppressed)') from None
            time.sleep(5)
