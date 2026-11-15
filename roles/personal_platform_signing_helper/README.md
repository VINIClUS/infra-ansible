# Roles Anywhere signing helper

Disabled by default. When `personal_platform_signing_helper_enabled` is true,
this role installs the AWS Roles Anywhere credential helper at the fixed path
`/usr/local/bin/aws_signing_helper` (root 0755) that `host_gate.py` calls for the
`credential_process` renewal. Contract: infra-ansible#30 (G4).

- Pin: version `1.8.5`, sha256
  `beec9ed1c492d93db809890f16713e3556353294b823c2184ad4e891f1b2b54d`, from the
  official release URL
  `https://rolesanywhere.amazonaws.com/releases/1.8.5/X86_64/Linux/Amzn2023/aws_signing_helper`.
  These are the same values as CnesData `apps/central_api/Dockerfile`. The role
  refuses any other URL shape; changing the pin is a reviewed change of the
  version and the digest together.
- It reads the host architecture first and refuses anything but `x86_64`.
- `get_url` verifies the checksum before the file is moved into place; an
  existing file with another digest is replaced, a matching one is left alone.
- Readback: `stat` sha256, regular file, not a symlink, owner root:root, mode
  0755, and `aws_signing_helper version` equal to the pinned version.
- `--check` runs the gates (host, URL shape and the real `uname -m`) and reports
  whether `get_url` would change the file; it skips only the post-install
  version and readback assert, because nothing was downloaded.
- It requires one exact host (`--limit` equal to the host and a single play
  host) and `personal_platform_delivery_enabled`. It never starts a service,
  requests a session or reads a certificate.

Isolated run, before or after the rest of the delivery playbook (the
checkpoint/smoke assert of the playbook is tagged `always`, so it still runs):

```bash
ansible-playbook -i <personal inventory> playbooks/personal-platform-delivery.yml \
  --limit <host> --tags personal_platform_signing_helper \
  -e personal_platform_delivery_enabled=true \
  -e personal_platform_signing_helper_enabled=true \
  -e personal_platform_delivery_checkpoint_sha256=<64 hex> \
  -e personal_platform_limnopulse_smoke_evidence_sha256=<64 hex>
```

Rollback: remove `/usr/local/bin/aws_signing_helper`. Nothing else is touched.
