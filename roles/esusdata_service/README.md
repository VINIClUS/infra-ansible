# esusdata_service

Deploys one published esusdata (Observatorio APS) release onto the dedicated
`esusdata-lxc` container. Disabled by default; the enabled role requires an
exact `X.Y.Z` version, the exact `--limit` host, and only the
`esusdata_service` tag, so it runs solely through
`playbooks/esusdata-service.yml`, normally invoked by the root-owned
`esusdata-deploy` boundary (`tools/deploy/esusdata_deploy.py`).

Before anything is installed, the role downloads `SHA256SUMS` and
`SHA256SUMS.sig` from the GitHub release, verifies the signature with
`ssh-keygen -Y verify` against the release signer pinned in this role
(esusdata ADR 0021; the trust store is never fetched next to the artifacts),
selects the `.deb` checksum from the verified manifest, and downloads the
package pinned to that checksum.

It then installs the package, renders `/etc/observatorio-aps/application.yml`
(the package never overwrites it), installs the PEC TLS root certificate that
`observatorio.source.tls-root-cert` points to (esusdata ADR 0022: every
session to the PEC is TLS verified against it), writes `pec.env` from the
private inventory vault as `observatorio:observatorio 0600`, loads an nftables rule
that admits the service port only from loopback and the edge proxy, restarts
the unit, and waits for `GET /api/v1/ready`. Any failure restores the
preceding configuration, reinstalls the preceding cached package, waits for it
to become ready, and fails the run. Only the current and rollback packages stay
cached under `/var/cache/esusdata-deploy`.
