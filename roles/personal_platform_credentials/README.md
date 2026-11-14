# Credenciais pessoais

Disabled by default. This role creates the private /run directories (root 0700)
and the shared `current/` directory (root:10001 0710) only. It does not
issue certificates, create keys, request sessions, import credentials or enable
a renewal service. It installs the fixed root-only oneshot unit
`personal-platform-credential-reload.service` and the timer
`personal-platform-credential-reload.timer` (`OnBootSec=30s`,
`OnUnitActiveSec=300s`) without starting them. The timer is not enabled by
default; enabling it is an operational step on the host. Original RA
identity/profile/anchor and the three operational unit/recovery/API probe
sessions belong to their existing owners.

## cnesdata: credential_process JSON

Contract: CnesData#473 amendment-5 and infra-ansible#55 slice 2A.

- The renewer obtains a 3600-second Roles Anywhere session and publishes
  `/run/personal-platform/credentials/cnesdata/current/aws-credentials.json`
  (credential_process v1 with `Version` and `Expiration`) by atomic replacement
  in the same directory: file root:10001 0440, directory `current/`
  root:10001 0710, parents root 0700. Owner and mode are final before the
  rename, and the bytes, owner, mode and link count are read back.
- It publishes when 1800 seconds or less remain, or when the file is missing,
  unreadable or not the recorded generation. It refuses a generation with less
  than 3300 seconds of life and never removes the current one.
- It never restarts or recreates the API container: botocore refreshes the
  credentials in the same process. The container binds `current/` read-only at
  `/run/credentials`; the compose may not set any `AWS_*` environment.
- Adoption is proven one cycle behind from the container's JSON stdout event
  `aws_credentials_refreshed key_fp=<sha256[:12]> previous_fp=… pid=…`, in the
  same container (`Id`, `StartedAt`, `RestartCount`). A new container counts only
  when the accepted deploy checkpoint names its Id and it logged its boot line
  (`previous_fp=none`). Failures print `credential_adoption=missing`,
  `credential_adoption=container_replaced` or
  `credential_adoption=container_restarted` and fail the unit (exit 2) after the
  lease is released; publication of the next generation continues.
- The governance fixes `duration_seconds = 3600` and carries the CRL
  `trust_deadline`; seven days before it the unit fails with
  `credential_trust=expiring`.
- Generation records and state stay 0600 under
  `/run/personal-platform/credentials/cnesdata`, outside the mount, with no copy
  of the secret.
- `tmpfiles.d` (`/etc/tmpfiles.d/personal-platform-credentials.conf`) recreates
  the tmpfs directories on boot, so the bind source exists before the first
  publication.

## LimnoPulse

LimnoPulse keeps the unchanged legacy path: temporary INI files with mode 0400,
the same host-wide lease, the 156-second margin, a client restart and a healthy
readback before the previous session expires. It has no consumer today.

No fourth runtime identity, static fallback or cross-application mount is allowed.
