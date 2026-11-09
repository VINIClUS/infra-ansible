"""Real temporary trees exercise conflict/failure logic; no runtime acceptance."""
import importlib.util
import os
from pathlib import Path
import pytest


def api():
    assert importlib.util.find_spec('tools.samba_ad.sysvol'), 'S5 SYSVOL implementation missing'
    from tools.samba_ad import sysvol
    return sysvol


def test_tree_rejects_links_devices_escape_and_changed_gpt(tmp_path):
    m=api(); root=tmp_path/'tree';root.mkdir();(root/'GPT.INI').write_text('[General]\nVersion=1\n')
    first=m.snapshot(root, require_ntacl=False)
    (root/'GPT.INI').write_text('[General]\nVersion=2\n')
    assert m.snapshot(root, require_ntacl=False) != first
    (root/'escape').symlink_to('/etc')
    with pytest.raises(ValueError):m.snapshot(root,require_ntacl=False)
    (root/'escape').unlink();os.link(root/'GPT.INI',root/'hardlink')
    with pytest.raises(ValueError):m.snapshot(root,require_ntacl=False)


def test_conflict_or_changed_source_never_replaces_live_tree(tmp_path):
    m=api()
    class IO:
        def __init__(self):self.calls=[];self.remote_calls=0;self.local='baseline'
        def current(self):return self.local
        def remote(self):self.remote_calls+=1;return 'source' if self.remote_calls==1 else 'raced'
        def transfer(self):self.calls.append('transfer');return 'source'
        def publish(self):self.calls.append('publish')
        def verify(self):self.calls.append('verify')
    backend=IO()
    with pytest.raises(ValueError):m.synchronize(backend,'baseline')
    assert backend.calls==['transfer']
    backend=IO();backend.local='unauthorized DC02 edit'
    with pytest.raises(ValueError):m.synchronize(backend,'baseline')
    assert backend.calls==[]


def test_receiver_is_rechecked_after_transfer():
    m=api()
    class IO:
        def current(self):self.n+=1;return 'baseline' if self.n==1 else 'raced'
        def remote(self):return 'source'
        def transfer(self):return 'source'
        def publish(self):pytest.fail('overwrote concurrent authorship')
    io=IO();io.n=0
    with pytest.raises(ValueError):m.synchronize(io,'baseline')


def test_exporter_rejects_arbitrary_remote_command():
    m=api()
    assert m.export_command('rsync --server --daemon .') == 'rsync'
    assert m.export_command('manifest') == 'manifest'
    for value in ['rsync --server --sender . /etc', 'manifest; id', '', 'sudo sh', 'rsync --server --daemon .\n']:
        with pytest.raises(ValueError):m.export_command(value)


def test_success_requires_post_copy_verification():
    m=api()
    class IO:
        def current(self):return 'baseline'
        def remote(self):return 'source'
        def transfer(self):return 'source'
        def publish(self):self.published=True
        def verify(self):raise ValueError('ACL mismatch')
    io=IO();io.published=False
    with pytest.raises(ValueError):m.synchronize(io,'baseline')
    assert io.published


def test_snapshot_ignores_read_atime_but_detects_acl_metadata(tmp_path):
    m=api();root=tmp_path/'tree';root.mkdir();file=root/'data';file.write_bytes(b'policy')
    os.utime(file,(1,2))
    first=m.snapshot(root,require_ntacl=False)
    assert m.snapshot(root,require_ntacl=False)==first
    os.setxattr(file,'user.fixture-acl',b'changed')
    assert m.snapshot(root,require_ntacl=False)!=first


def test_gpt_ini_accepts_windows_unicode_bom_without_changing_bytes(tmp_path):
    m=api();root=tmp_path/'tree';root.mkdir();file=root/'GPT.INI'
    data='[General]\r\nVersion=65537\r\n'.encode('utf-16');file.write_bytes(data)
    tree=m.snapshot(root,require_ntacl=False)
    assert tree['entries']['GPT.INI']['gpt_version']==65537
    assert file.read_bytes()==data
