"""Publication error boundaries with real exchange and pre-exchange writer fds."""
import errno
import json
import os
import re
from pathlib import Path

import pytest

from tools.samba_ad import sysvol
from test_samba_ad_sysvol_fix_round1 import fixture


def write_late(fd):
    handle = os.open('late-policy', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
    with os.fdopen(handle, 'w') as stream:
        stream.write('authorship through pre-exchange fd')


def fail():
    raise OSError(errno.EIO, 'injected publication persistence failure')


@pytest.mark.parametrize('boundary', [
    'receipt_before', 'receipt_after', 'marker_before', 'marker_after',
    'exchange_before', 'exchange_after', 'live_parent_fsync', 'retired_parent_fsync',
    'previous_snapshot', 'rollback_before', 'rollback_after', 'rollback_parent_fsync',
    'verify', 'status_before', 'status_after', 'unlink_before', 'unlink_after', 'final_fsync',
])
def test_publication_errors_preserve_generation_and_old_fd_writer(tmp_path, monkeypatch, boundary):
    state, tree, baseline, fd, pull = fixture(tmp_path, monkeypatch)
    original_atomic = sysvol.atomic_file
    original_sync = sysvol.sync_dir
    original_snapshot = sysvol.snapshot
    original_unlink = Path.unlink
    original_verify = pull.verify
    library = sysvol.ctypes.CDLL(None, use_errno=True)
    original_exchange = library.renameat2
    exchanges = 0
    injected = False

    def inject():
        nonlocal injected
        assert not injected
        injected = True
        if not boundary.startswith('rollback'):
            write_late(fd)
        fail()

    def atomic(path, data):
        prefix = {'receipt.json': 'receipt', 'partial.json': 'marker', 'status.json': 'status'}.get(path.name)
        # Fail only the successful status write; allow the handler's failed status.
        target = path.name != 'status.json' or json.loads(data)['state'] == 'ok'
        if target and boundary == prefix + '_before':
            inject()
        original_atomic(path, data)
        if target and boundary == prefix + '_after':
            inject()

    def exchange(*args):
        nonlocal exchanges
        exchanges += 1
        prefix = 'exchange' if exchanges == 1 else 'rollback'
        if boundary == prefix + '_before':
            inject()
        result = original_exchange(*args)
        assert result == 0
        if exchanges == 1 and boundary.startswith('rollback'):
            write_late(fd)
        if boundary == prefix + '_after':
            inject()
        return result

    def sync_dir(path):
        if exchanges == 1 and boundary == 'live_parent_fsync' and path == tree.parent:
            inject()
        if exchanges == 1 and boundary == 'retired_parent_fsync' and path.parent == sysvol.RETIRED:
            inject()
        if exchanges == 2 and boundary == 'rollback_parent_fsync' and path == tree.parent:
            inject()
        if boundary == 'final_fsync' and path == state and not (state / 'partial.json').exists():
            inject()
        return original_sync(path)

    def snapshot(path, **kwargs):
        if exchanges == 1 and boundary == 'previous_snapshot' and path.name == 'tree':
            inject()
        return original_snapshot(path, **kwargs)

    def verify(self):
        if boundary == 'verify':
            inject()
        original_verify(self)

    def unlink(path, *args, **kwargs):
        if path == state / 'partial.json' and boundary == 'unlink_before':
            inject()
        result = original_unlink(path, *args, **kwargs)
        if path == state / 'partial.json' and boundary == 'unlink_after':
            inject()
        return result

    library.renameat2 = exchange
    monkeypatch.setattr(sysvol.ctypes, 'CDLL', lambda *a, **kw: library)
    monkeypatch.setattr(sysvol, 'atomic_file', atomic)
    monkeypatch.setattr(sysvol, 'sync_dir', sync_dir)
    monkeypatch.setattr(sysvol, 'snapshot', snapshot)
    monkeypatch.setattr(pull, 'verify', verify)
    monkeypatch.setattr(Path, 'unlink', unlink)
    try:
        with pytest.raises(ValueError, match=re.escape(sysvol.ERROR)):
            sysvol.sync(initial_baseline=baseline)
        assert injected, 'requested boundary was not reached'
        slots = list(sysvol.RETIRED.iterdir())
        assert len(slots) == 1, 'publication generation was deleted'
        assert (slots[0] / 'tree').is_dir()
        preserved = list(tmp_path.rglob('late-policy'))
        assert len(preserved) == 1, 'concurrent authorship was deleted'
        assert preserved[0].read_text() == 'authorship through pre-exchange fd'
        assert json.loads((state / 'status.json').read_text())['state'] == 'failed_or_conflict'
        assert sorted([(tree / 'policy').read_text(), (slots[0] / 'tree' / 'policy').read_text()]) == ['new', 'old']
        if boundary == 'final_fsync':
            assert (tree / 'policy').read_text() == 'new'
            assert not (state / 'partial.json').exists()
            assert preserved[0] == slots[0] / 'tree' / 'late-policy'
    finally:
        os.close(fd)


@pytest.mark.parametrize('boundary', ['transfer', 'stage_fsync'])
def test_proven_unpublished_staging_is_cleaned(tmp_path, monkeypatch, boundary):
    state, tree, baseline, fd, pull = fixture(tmp_path, monkeypatch)
    original_transfer = pull.transfer
    original_sync = sysvol.sync_dir

    def transfer(self):
        result = original_transfer(self)
        if boundary == 'transfer':
            fail()
        return result

    def sync_dir(path):
        if boundary == 'stage_fsync' and path.name == 'tree':
            fail()
        return original_sync(path)

    monkeypatch.setattr(pull, 'transfer', transfer)
    monkeypatch.setattr(sysvol, 'sync_dir', sync_dir)
    try:
        with pytest.raises(ValueError, match=re.escape(sysvol.ERROR)):
            sysvol.sync(initial_baseline=baseline)
        assert list(sysvol.RETIRED.iterdir()) == []
        assert sysvol.snapshot(tree, require_ntacl=False) == baseline
        assert not (state / 'partial.json').exists()
        assert json.loads((state / 'status.json').read_text())['state'] == 'failed_or_conflict'
    finally:
        os.close(fd)
