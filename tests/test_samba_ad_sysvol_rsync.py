"""Native rsync stdio transport against temporary unprivileged directories.

No SSH connection, daemon listener, security.NTACL or real Samba is exercised.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import pytest
from tools.samba_ad.sysvol_setup import rsync_config


def test_native_rsync_archive_acl_xattr_module_and_forced_command_shape(tmp_path):
    if not shutil.which('rsync'):pytest.skip('rsync unavailable')
    source=tmp_path/'source';source.mkdir();destination=tmp_path/'destination';destination.mkdir()
    file=source/'GPT.INI';file.write_text('[General]\nVersion=42\n');file.chmod(0o640)
    os.setxattr(file,'user.s5-fixture',b'ACL transport fixture')
    # Production module config, adapted ONLY for the non-root temporary test.
    config=rsync_config().replace('/var/lib/samba/sysvol',str(source)).replace('use chroot = yes','use chroot = no').replace('uid = 0\n','').replace('gid = 0\n','').replace('/run/samba-ad-sysvol-rsync.lock',str(tmp_path/'rsync.lock'))
    module=tmp_path/'rsync.conf';module.write_text(config)
    args=tmp_path/'args';transport=tmp_path/'stdio-transport'
    transport.write_text('#!/usr/bin/python3\nimport os,sys,json\nopen('+repr(str(args))+',"w").write(json.dumps(sys.argv[1:]))\nos.execv("/usr/bin/rsync",["rsync","--server","--daemon","--config='+str(module)+'","."])\n')
    transport.chmod(0o700)
    result=subprocess.run(['rsync','-aAX','--numeric-ids','--delete-delay','--no-links','--no-devices','--no-specials','--timeout=10','-e',str(transport),'samba-sysvol@fixture::sysvol/',str(destination)+'/'],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
    assert (destination/'GPT.INI').read_bytes()==file.read_bytes()
    assert (destination/'GPT.INI').stat().st_mode & 0o777==0o640
    assert os.getxattr(destination/'GPT.INI','user.s5-fixture')==b'ACL transport fixture'
    import json
    argv=json.loads(args.read_text());assert argv[-4:]==['rsync','--server','--daemon','.']
    # The same authenticated export endpoint cannot write back into DC01.
    bad=subprocess.run(['rsync','-a','-e',str(transport),str(file),'samba-sysvol@fixture::sysvol/'],capture_output=True,text=True,timeout=20)
    assert bad.returncode!=0
