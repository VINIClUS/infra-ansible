# Semaphore controller role

Installs the pinned native amd64 Semaphore release by extracting its verified
official package into an immutable version directory. PostgreSQL data,
Semaphore state, and protected configuration remain outside that release.
The active release is selected with an atomic symlink replacement.

The role is disabled by default. An enabled run fails closed unless it targets
one Debian 13 amd64 systemd host through an exact `--limit` and only the
`semaphore_controller` tag.

## Required controller environment

- `SEMAPHORE_DB_PASSWORD`
- `SEMAPHORE_ACCESS_KEY_ENCRYPTION` (base64-encoded 16, 24, or 32-byte key)
- `SEMAPHORE_ADMIN_PASSWORD` (first setup only)

The first setup runs through protected standard input with Ansible logging
disabled. Secrets are not command arguments. The generated cookie secrets are
retained while the final configuration is rendered as root-owned mode `0640`.
The administrator password is not stored in the configuration and should be
rotated after first login.

The role installs and starts `semaphore.service`, binds Semaphore to loopback
port 3000, and succeeds only after `GET /api/ping` returns HTTP 200 with the
exact body `pong`, without trimming or whitespace normalization.
