"""Actual rename exchange and old directory descriptors; no Samba or transport."""
import json
import os
from pathlib import Path
import pytest
from tools.samba_ad import sysvol


def fixture(tmp_path,monkeypatch,late=False):
    state=tmp_path/'state';state.mkdir(mode=0o700)
    tree=tmp_path/'sysvol';tree.mkdir(mode=0o700);(tree/'policy').write_text('old')
    baseline=sysvol.snapshot(tree,require_ntacl=False)
    fd=os.open(tree,os.O_RDONLY|os.O_DIRECTORY)
    expected=tmp_path/'expected';expected.mkdir(mode=0o700);(expected/'policy').write_text('new')
    expected_snapshot=sysvol.snapshot(expected,require_ntacl=False)
    original_snapshot=sysvol.snapshot
    class LocalPull(sysvol.Pull):
        expected=expected_snapshot
        def __init__(self,config,initial_baseline=None):
            self.config=config;self.initial_baseline=initial_baseline;self.last_local=None;self.stage=None
        def current(self):
            self.last_local=original_snapshot(tree,require_ntacl=False);return self.last_local
        def remote(self):return self.expected
        def transfer(self):
            if hasattr(self,'allocate_stage'):self.allocate_stage()
            else:self.stage=tmp_path/'stage';self.stage.mkdir(mode=0o700)
            (self.stage/'policy').write_text('new')
            return original_snapshot(self.stage,require_ntacl=False)
        def verify(self):
            if late:
                handle=os.open('late-policy',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=fd)
                with os.fdopen(handle,'w') as stream:stream.write('authorship through old fd')
            assert self.current()==self.remote()
    monkeypatch.setattr(sysvol,'ROOT',state);monkeypatch.setattr(sysvol,'TREE',tree)
    monkeypatch.setattr(sysvol,'RETIRED',tmp_path/'retired',raising=False)
    monkeypatch.setattr(sysvol,'runtime_config',lambda:{'role':'consumer','sid':'S-1-5-21-1-2-3'})
    monkeypatch.setattr(sysvol,'Pull',LocalPull)
    monkeypatch.setattr(sysvol,'snapshot',lambda path,**kw:original_snapshot(path,require_ntacl=False))
    return state,tree,baseline,fd,LocalPull


def test_late_writer_with_pre_exchange_directory_fd_is_never_deleted(tmp_path,monkeypatch):
    state,tree,baseline,fd,_=fixture(tmp_path,monkeypatch,late=True)
    try:
        try:sysvol.sync(initial_baseline=baseline)
        except ValueError:pass
        preserved=list(tmp_path.rglob('late-policy'))
        assert len(preserved)==1, 'concurrent authorship was deleted'
        assert preserved[0].read_text()=='authorship through old fd'
        assert json.loads((state/'status.json').read_text())['state']=='failed_or_conflict'
    finally:os.close(fd)


def test_write_after_success_is_preserved_and_detected_next_sync(tmp_path,monkeypatch):
    state,tree,baseline,fd,_=fixture(tmp_path,monkeypatch)
    try:
        assert sysvol.sync(initial_baseline=baseline)['state']=='synced'
        handle=os.open('late-policy',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=fd)
        with os.fdopen(handle,'w') as stream:stream.write('even later authorship')
        with pytest.raises(ValueError):sysvol.sync()
        assert len(list(tmp_path.rglob('late-policy')))==1
        assert json.loads((state/'status.json').read_text())['state']=='failed_or_conflict'
    finally:os.close(fd)


def test_retention_capacity_does_not_block_unchanged_syncs(tmp_path,monkeypatch):
    state,tree,baseline,fd,pull=fixture(tmp_path,monkeypatch)
    monkeypatch.setattr(sysvol,'RETENTION_LIMIT',1)
    try:
        first=sysvol.sync(initial_baseline=baseline)
        assert first['retention']=={'count':1,'limit':1,'saturated':True}
        retained=list(sysvol.RETIRED.iterdir())
        for _ in range(3):
            result=sysvol.sync()
            assert result['changed'] is False and result['retention']==first['retention']
            assert list(sysvol.RETIRED.iterdir())==retained
        # A new source revision cannot silently evict the old fd-reachable tree.
        (tmp_path/'expected'/'policy').write_text('newer')
        pull.expected=sysvol.snapshot(tmp_path/'expected',require_ntacl=False)
        with pytest.raises(ValueError):sysvol.sync()
        assert list(sysvol.RETIRED.iterdir())==retained
        assert (tree/'policy').read_text()=='new'
        assert (retained[0]/'tree'/'policy').read_text()=='old'
    finally:os.close(fd)
