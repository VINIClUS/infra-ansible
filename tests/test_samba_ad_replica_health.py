import time
from types import SimpleNamespace
import pytest
from tools.samba_ad.replica_health import healthy_neighbours


def test_missing_stale_foreign_or_failed_partition_is_rejected():
    now=time.time();peer='CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=example,DC=invalid'
    ncs=['DC=example,DC=invalid','CN=Configuration,DC=example,DC=invalid']
    def row(nc):return SimpleNamespace(source_dsa_obj_dn=peer,naming_context_dn=nc,result_last_attempt=(0,'ok'),consecutive_sync_failures=0,last_success=int((now+11644473600)*10000000))
    rows=[row(nc) for nc in ncs]
    healthy_neighbours(rows,ncs,peer,now)
    with pytest.raises(ValueError):healthy_neighbours(rows[:1],ncs,peer,now)
    for field,value in [('last_success',0),('result_last_attempt',(5,'refused')),('consecutive_sync_failures',1),('source_dsa_obj_dn','foreign')]:
        bad=row(ncs[0]);setattr(bad,field,value)
        with pytest.raises(ValueError):healthy_neighbours([bad,rows[1]],ncs,peer,now)
