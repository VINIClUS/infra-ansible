# Credenciais pessoais

Disabled by default. This role creates private /run directories only. It does not
issue certificates, create keys, request sessions, import credentials or enable
a renewal service. It installs the fixed root-only oneshot unit without starting
or enabling it. Original RA identity/profile/anchor and the three operational
unit/recovery/API probe sessions belong to their existing owners.

The runtime accepts temporary sessions only, writes credentials atomically with
mode 0400 and removes ephemeral directories on every exit. Credential replacement
must use the same host-wide lease, respect the current 156-second margin, replace
the client and prove healthy readback before the previous session expires.
No fourth runtime identity, static fallback or cross-application mount is allowed.
