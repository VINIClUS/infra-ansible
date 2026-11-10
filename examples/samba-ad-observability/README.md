# Dedicated AD observability source

These fictitious examples are disabled and contain no usable assets or credentials.
This source adds an independent Alloy 1.18.1 instance per owned AD host, an
authenticated loopback SQLite queue, a fixed-route mTLS ingress on collector TCP
443, and dedicated Prometheus 3.8.0/Loki 3.6.0 backends. Existing shared services,
configuration and retention are not imported or modified. Alerts are evaluated
locally; no Alertmanager, email or other external notification is configured.

Linux preparation uses `playbooks/samba-ad-observability.yml`, one exact inventory
host limit and the `samba_ad_observability` tag. The explicit enabled/apply/activate
switches separate validation, preparation and activation. Assets are qualified
local files with exact digests; no package installer or download runs on targets.
Private deployment supplies machine identity, SAN allowlist, expected node/source
matrix, concrete DRS neighbours and SID, and PKI references. Never commit real
configuration, logs, certificates, tokens or private keys.

Prepare dedicated services before S3 activates their certificates. Linux S3
requests use adapter `telemetry` (client) or `observability_gateway` (server), port
443. The optional manifest profiles `telemetry_linux_pilot`,
`telemetry_windows_pilot` and `observability_gateway` retain host-specific SANs,
168-hour lifetime, separate JWK credentials and no renewal/rekey grants. The
gateway requires the optional `telemetry_collector` identity with scope
`samba-ad-observability-only`. The six original profiles and default manifests
remain valid. Copy no leaf private key between hosts.

For Windows Server 2025 build 26100 (Standard/Datacenter, including qualified
evaluation editions), stage the official qualified Alloy, Python 3.13, PowerShell
7.4+ and step 0.31.0 assets under administrator/SYSTEM control. Render
`agent.alloy.j2` with platform `windows`, the fixed Windows token/canary paths and
an empty log_files mapping. Supply protected staged configuration paths outside
the final installation directory. Run `telemetry_windows_pki.ps1` with
`-Enabled -Apply -Action AuthPrepare -Limit <COMPUTERNAME> -Tag samba_ad_observability`;
register only its public JWK in the host-bound CA profile and matching local PKI
configuration. Then run `telemetry_windows.ps1` with `-Enabled -Apply -Action
Install` and the same limit/tag, adding `-Activate` only for the reviewed issuance
window. This installs four dedicated SYSTEM tasks, including the actual local
certificate producer. Initial issuance enables them after publishing a validated
leaf; rotation generates a fresh RSA3072 key, validates chain/SAN/EKU/TTL/SPKI,
and requires the gateway to observe that leaf on both write routes. Failed
publication rolls back or blocks transport if rollback cannot be demonstrated.
Stale transition/blocked markers require directed local recovery; they are never
silently cleared. Evaluation OS acceptance is not a licence receipt.

The queue acknowledges only after SQLite FULL-synchronous commit and removes a
batch only after upstream acknowledgement. Delivery is at-least-once: duplicates
are possible if a remote ACK is lost. Its 512 MiB payload cap rejects new batches
with retryable 503 and exposes rejection/backlog/heartbeat metrics. Preserve
source logs/bookmarks and reconcile sequence receipts when capacity or pipeline
drop alerts fire. Durability covers batches accepted by the queue, not arbitrary
events lost before Alloy forwards them. Loki rejects samples older than 48 hours;
prolonged outages or a permanently rejected oldest batch require directed replay
and reconciliation rather than automatic discard. Canary logs also need an
explicit runtime disk-capacity/rotation policy; no shared logrotate policy is
changed by this source.

The source-only tests use synthetic certificates/events and loopback services.
Set `S7_ALLOY`, `S7_PROMTOOL` and `S7_LOKI` to verified official binary paths to
enable native queue kill/recovery and rule evaluation tests. PowerShell-native
certificate verification runs when `pwsh` is available. None proves Windows
ScheduledTasks, real Event Log bookmarks, real Samba JSON fields, DC replication,
certificate rotation under the deployed service sandbox, or production outage
recovery; those require the separately authorized target acceptance window.
