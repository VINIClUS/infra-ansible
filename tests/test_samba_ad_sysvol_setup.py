import importlib.util
import pytest


def api():
    assert importlib.util.find_spec('tools.samba_ad.sysvol_setup'), 'SYSVOL setup missing'
    from tools.samba_ad import sysvol_setup
    return sysvol_setup


def test_source_key_is_nonroot_exact_ip_and_forced_readonly_commands():
    m=api();key='ssh-ed25519 '+ 'A'*68
    line=m.authorized_key('192.0.2.22',key)
    assert 'from="192.0.2.22"' in line and 'restrict,' in line
    assert 'command="/usr/local/libexec/samba-ad-s5 --sysvol-gate"' in line
    for bad in ['0.0.0.0/0','192.0.2.22/32','192.0.2.22,192.0.2.23']:
        with pytest.raises(ValueError):m.authorized_key(bad,key)
    with pytest.raises(ValueError):m.authorized_key('192.0.2.22',key+'\nssh-rsa BAD')


def test_export_config_refuses_write_and_paths_and_special_files():
    config=api().rsync_config()
    for item in ['read only = yes','use chroot = yes','path = /var/lib/samba/sysvol','max connections = 1','uid = 0','gid = 0']:
        assert item in config
    assert 'refuse options =' in config
