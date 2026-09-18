# cnesdata_deployer

Installs the root-owned boundary used by an unprivileged CnesData deploy
runner (`github-runner`, labels `deploy-dev`/`deploy-prod`). The runner can
pass one candidate image tag to
`/usr/local/sbin/cnesdata-deploy-{dev,prod}`; it cannot choose a host, user,
script, or SSH key. The command-scoped sudo policy forbids caller environment
preservation and sets a fixed secure path. The tag regex in the sudoers file
is defense-in-depth, not the validation boundary — the shell script
independently re-checks the tag with a real Bash regex before it is ever
placed on the SSH command line.

Set `cnesdata_deployer_environment` to `dev` or `prod` per host; it fixes the
script path, sudoers path, and accepted tag pattern
(`^develop-[0-9a-f]{7,40}$` for dev, `^main-[0-9a-f]{7,40}$` for prod).
Bootstrap requires `CNESDATA_DEPLOY_VPS_SSH_PRIVATE_KEY` and
`CNESDATA_DEPLOY_VPS_KNOWN_HOSTS` (the pinned VPS host key, one line as
produced by `ssh-keyscan`) in the Ansible controller environment. Both are
installed only in mode-0600 root files under `/etc/cnesdata-deploy/`, and all
secret-bearing tasks use `no_log`.

The GitHub Actions job invokes `sudo cnesdata-deploy-<env> <tag>` — it never
holds the VPS SSH key. The script validates the tag, then SSHes to the VPS
with `StrictHostKeyChecking=yes` against the pinned known_hosts file and
passes the tag as the command, which the VPS's existing forced-command
(`deploy/dev/deploy.sh` / `deploy/prod/deploy.sh` in `CnesData`) executes.
