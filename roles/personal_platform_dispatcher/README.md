# Dispatcher pessoal

Disabled by default. Enable personal_platform_dispatcher_enabled only in private
inventory and run personal-platform-delivery.yml with the exact host limit and
personal_platform_delivery tag. Installation does not deploy an application or
reload SSH. The owner must separately approve activation after full sshd readback.

The root-owned standard-library closure (host_gate.py plus the hash-checked
integrated EXT1 contract.py cost validator) accepts only validate, deploy and
rollback-previous via SSH_ORIGINAL_COMMAND. Sudo grants only that exact interpreter,
file and fixed argument, with no Docker group, arbitrary command or forwarding.
The private governance document and runtime checksum are mandatory owner inputs.
No credential values or real inventory belong in this repository.

The forced-command account accepts exactly one key:
personal_platform_dispatcher_authorized_key, an ed25519 public key from private
inventory, installed with exclusive authorized_keys. A missing or placeholder key
refuses the installation.

Per run, `--tags personal_platform_private_handoffs` installs only the private
handoffs named in personal_platform_dispatcher_handoffs (host-gate,
original-platform, original-baseline), each as {src, sha256}. The bytes are copied
from the controller file unchanged to their fixed root 0600 paths and read back by
sha256; host-gate also requires the installed runtime to match its runtime_sha256.
Builders and the preflight readback live in tools/personal_platform/.
