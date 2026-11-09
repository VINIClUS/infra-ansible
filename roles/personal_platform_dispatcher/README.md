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
