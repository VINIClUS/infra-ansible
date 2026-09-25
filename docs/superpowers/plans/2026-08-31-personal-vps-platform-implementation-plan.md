# Personal VPS Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add disabled-by-default, reusable Ansible automation for a hardened personal VPS, a globally serialized deployment boundary, Cloudflare Tunnel/Nginx ingress, temporary AWS credentials, bounded observability, and InfluxDB backup without changing the municipal deployment path.

**Architecture:** Keep public, reusable roles and validation in infra-ansible while all real hosts, identities and secrets remain in the private personal-infra-live repository. Host mutations use a root-owned global lease and fixed dispatchers. SSH closure is a two-apply transaction, application releases are immutable digest-bound archives, and every dangerous transition has a tested restore path.

**Tech Stack:** Ansible Core, Debian systemd, nftables, OpenSSH, Docker Engine and Compose, Python 3.12 standard library, Cloudflare Tunnel, Nginx, IAM Roles Anywhere aws_signing_helper, Grafana Alloy, InfluxDB 2 CLI, pytest, ansible-lint, yamllint.

**Spec:** docs/superpowers/specs/2026-08-29-personal-vps-platform-and-cd-design.md

## Global Constraints

- Start from green main@cb6bff041a10159d3e6518cccb22c4198e2de47c, the merged design PR head. Re-read the head before each task branch.
- Existing municipal roles, the ansible-prod runner, Infisical paths and .github/workflows/pipeline.yml behavior remain byte-for-byte compatible unless a focused regression test proves an additive validation-only change is required.
- Every new role defaults to disabled or observe-only. The public example inventory contains aliases and fake keys only.
- The real VPS hostname, IP, host key, Cloudflare account/zone IDs, certificates, tokens and SSM values never enter this repository, tests, CI logs or artifacts.
- Stage A and Stage B are separate playbooks and separate operator invocations. Stage B consumes the exact Stage A evidence digest.
- Hostinger provider-firewall mutation is outside this repository. The role verifies supplied read-only evidence and fails closed when it is absent, stale or ambiguous.
- No human or deployment user joins the docker group. Root-owned fixed helpers are the only Docker mutation path.
- All host-changing workflows, timers, deployers and runbooks acquire the same root-owned lease. Expiration alone never permits takeover.
- Release input is exactly three length-prefixed frames: evidence envelope, bounded archive and ephemeral repository-scoped GITHUB_TOKEN.
- Archive extraction rejects absolute paths, traversal, links, devices, duplicates, undeclared files and decompression beyond per-file or aggregate limits before writing each byte.
- Temporary GitHub tokens, registry configuration, AWS credentials and rendered secrets live only below /run and are removed on every terminal path.
- Containers use immutable image digests, non-root IDs, read-only roots, explicit limits, loopback ports and isolated product networks.
- Nginx trusts CF-Connecting-IP only from an exact declared cloudflared peer. No broad RFC1918 range is trusted.
- Tests run without production credentials or network mutation.
- Commit format is type(scope): description. Never commit directly to main.

## File Map

| Path | Responsibility |
|---|---|
| roles/personal_vps_preflight/** | Read-only host and provider-evidence gate |
| roles/personal_vps_accounts/** | Human/deployment accounts and forced keys |
| roles/personal_vps_ssh_stage_a/** | Alternate access establishment |
| roles/personal_vps_ssh_stage_b/** | Legacy SSH/firewall closure |
| roles/personal_platform_runtime/** | Root-owned directories and Docker mode |
| roles/personal_platform_dispatcher/** | Lease, archive validation, deploy/rollback helpers |
| roles/personal_platform_edge/** | cloudflared and loopback Nginx |
| roles/personal_platform_credentials/** | Roles Anywhere renewal and reload hooks |
| roles/personal_platform_observability/** | Alloy and journald bounds |
| roles/influxdb_s3_backup/** | Consistent backup/upload/retention client boundary |
| playbooks/personal-vps-*.yml | Explicit phase entrypoints |
| tools/personal_platform/** | Pure Python validators and fixed command helpers |
| tests/test_personal_*.py | Unit, static and transaction contracts |
| inventories/example/hosts.yml | Disabled public example only |

---

### Task 1: Freeze the Municipal Compatibility Boundary

**Branch:** feat/personal-vps-001-compatibility-gate

**Files:**
- Create: tests/test_personal_platform_compatibility.py
- Modify: inventories/example/hosts.yml
- Modify: README

**Interfaces:**
- Consumes the current pipeline, existing playbooks and roles.
- Produces one disabled example group named personal_vps_example.
- Proves no existing playbook includes a personal role and no personal playbook targets an existing municipal group.

- [ ] **Step 1: Write the failing boundary test**

    def test_personal_profile_is_disabled_and_separate() -> None:
        inventory = load_yaml("inventories/example/hosts.yml")
        host = inventory["personal_vps_example"]["hosts"]["personal-vps-example"]
        assert host["personal_vps_enabled"] is False
        assert host["ansible_host"] == "192.0.2.10"

    def test_existing_pipeline_contract_is_unchanged() -> None:
        workflow = load_yaml(".github/workflows/pipeline.yml")
        assert workflow["jobs"]["deploy"]["runs-on"] == [
            "self-hosted", "linux", "x64", "ansible-prod"
        ]
        assert "personal" not in workflow["jobs"]["deploy"]

- [ ] **Step 2: Run python -m pytest -q tests/test_personal_platform_compatibility.py**

Expected: FAIL because the example group does not exist.

- [ ] **Step 3: Add only the disabled documentation/example contract**

Use TEST-NET-1 address 192.0.2.10, fake Ed25519 public keys and personal_vps_enabled: false. Document that personal-infra-live owns real composition.

- [ ] **Step 4: Run the focused test and the existing workflow tests**

    python -m pytest -q tests/test_personal_platform_compatibility.py tests/test_github_workflow.py
    ansible-inventory -i inventories/example/hosts.yml --list
    git diff --check

- [ ] **Step 5: Commit**

    git add README inventories/example/hosts.yml tests/test_personal_platform_compatibility.py
    git commit -m "test(personal-vps): freeze municipal compatibility boundary"

### Task 2: Implement the Read-Only VPS Preflight

**Branch:** feat/personal-vps-002-preflight

**Files:**
- Create: roles/personal_vps_preflight/defaults/main.yml
- Create: roles/personal_vps_preflight/tasks/main.yml
- Create: roles/personal_vps_preflight/templates/report.json.j2
- Create: roles/personal_vps_preflight/README.md
- Create: playbooks/personal-vps-preflight.yml
- Create: tests/test_personal_vps_preflight.py

**Interfaces:**
- Produces personal_vps_preflight_report and its SHA-256 digest.
- Requires expected SSH fingerprint, minimum resources, declared listeners and current Hostinger backup/firewall evidence.
- check_mode is mandatory and changed count is zero.

- [ ] **Step 1: Write failing static and fixture tests**

    def test_preflight_is_read_only_and_fail_closed() -> None:
        tasks = read("roles/personal_vps_preflight/tasks/main.yml")
        assert "ansible.builtin.assert" in tasks
        assert "hostinger_backup_evidence" in tasks
        assert "hostinger_firewall_evidence" in tasks
        assert "copy:" not in tasks
        assert "package:" not in tasks

    def test_report_omits_real_host_and_secret_values() -> None:
        report = render_fixture("personal_vps_preflight")
        assert set(report) >= {"schema_version", "host_key_fingerprint", "checks"}
        assert report["host_alias"] == "personal-vps-example"
        assert "ansible_host" not in report

- [ ] **Step 2: Verify RED**

    python -m pytest -q tests/test_personal_vps_preflight.py

- [ ] **Step 3: Add defaults and assertions**

Default enabled=false. Validate Debian release, CPU/RAM/disk minimums, package-manager locks, failed units, filesystem state, port ownership, Docker data root, conflicting users/files and undeclared public listeners. Require provider evidence with captured_at, subject and status fields.

- [ ] **Step 4: Render a deterministic redacted report**

The report contains booleans and hashes, never addresses, usernames beyond declared aliases, public-key bodies, tokens or process command lines. Write it only to the controller artifact directory delegated to localhost.

- [ ] **Step 5: Run check mode and syntax gates**

    ansible-playbook -i inventories/example/hosts.yml playbooks/personal-vps-preflight.yml --syntax-check
    ansible-playbook -i inventories/example/hosts.yml playbooks/personal-vps-preflight.yml --check
    python -m pytest -q tests/test_personal_vps_preflight.py

- [ ] **Step 6: Commit**

    git add roles/personal_vps_preflight playbooks/personal-vps-preflight.yml tests/test_personal_vps_preflight.py
    git commit -m "feat(personal-vps): add fail-closed host preflight"

### Task 3: Create Accounts and Stage A Alternate Access

**Branch:** feat/personal-vps-003-ssh-stage-a

**Files:**
- Create: roles/personal_vps_accounts/**
- Create: roles/personal_vps_ssh_stage_a/**
- Create: templates under both roles for authorized_keys and sudoers
- Create: playbooks/personal-vps-ssh-stage-a.yml
- Create: tests/test_personal_vps_ssh_stage_a.py

**Interfaces:**
- Creates one named human administrator and exactly cnesdata-deploy, limnopulse-deploy and platform-deploy.
- Automation authorized_keys use command="/usr/local/sbin/personal-platform-dispatch <project>",restrict.
- Produces a signed/redacted Stage A evidence document but does not change root login or firewall.

- [ ] **Step 1: Write tests that reject broad privilege**

    def test_deploy_users_have_forced_commands_and_no_docker_group() -> None:
        text = read("roles/personal_vps_accounts/templates/authorized_keys.j2")
        assert 'command="/usr/local/sbin/personal-platform-dispatch' in text
        assert "restrict" in text
        assert "docker" not in read("roles/personal_vps_accounts/tasks/main.yml")

    def test_stage_a_does_not_close_legacy_access() -> None:
        all_text = role_text("personal_vps_ssh_stage_a")
        assert "PermitRootLogin no" not in all_text
        assert "PasswordAuthentication no" not in all_text

- [ ] **Step 2: Run focused tests and observe missing-role failures**

- [ ] **Step 3: Implement account validation before mutation**

Require non-empty Ed25519 key lists, distinct UIDs, /usr/sbin/nologin for automation users, no password hashes, validated visudo fragments and exact helper commands.

- [ ] **Step 4: Install cloudflared SSH ingress as a prerequisite hook**

The role consumes a rendered root-owned tunnel config path but does not fetch a token or manage DNS. Validate cloudflared tunnel ingress validate before restart.

- [ ] **Step 5: Add explicit human and automation probe hooks**

Both probes are delegated to the controller and their successful transcripts are reduced to timestamps, target aliases and fingerprints. The original root session remains an operator runbook requirement.

- [ ] **Step 6: Verify and commit**

    python -m pytest -q tests/test_personal_vps_ssh_stage_a.py
    ansible-playbook -i inventories/example/hosts.yml playbooks/personal-vps-ssh-stage-a.yml --syntax-check
    ansible-lint roles/personal_vps_accounts roles/personal_vps_ssh_stage_a
    git add roles/personal_vps_accounts roles/personal_vps_ssh_stage_a playbooks/personal-vps-ssh-stage-a.yml tests/test_personal_vps_ssh_stage_a.py
    git commit -m "feat(personal-vps): establish stage-a alternate access"

### Task 4: Implement Stage B SSH and nftables Closure

**Branch:** feat/personal-vps-004-ssh-stage-b

**Files:**
- Create: roles/personal_vps_ssh_stage_b/**
- Create: roles/personal_vps_ssh_stage_b/templates/99-personal-hardening.conf.j2
- Create: roles/personal_vps_ssh_stage_b/templates/personal-platform.nft.j2
- Create: playbooks/personal-vps-ssh-stage-b.yml
- Create: playbooks/personal-vps-ssh-recover.yml
- Create: tests/test_personal_vps_ssh_stage_b.py

**Interfaces:**
- Consumes exact Stage A evidence digest and provider-firewall readback.
- Produces a transaction directory with prior SSH/nftables bytes and checksums.
- Never edits provider firewall.

- [ ] **Step 1: Write tests for the two-apply and rollback invariants**

    def test_stage_b_requires_stage_a_digest() -> None:
        defaults = load_yaml("roles/personal_vps_ssh_stage_b/defaults/main.yml")
        assert defaults["personal_vps_stage_a_evidence_sha256"] == ""

    def test_sshd_template_closes_legacy_access() -> None:
        text = read("roles/personal_vps_ssh_stage_b/templates/99-personal-hardening.conf.j2")
        for line in (
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "AuthenticationMethods publickey",
        ):
            assert line in text

- [ ] **Step 2: Confirm RED**

- [ ] **Step 3: Implement backup, validate, install, reload**

Write candidates into the transaction directory, run sshd -t -f and nft -c -f, atomically install, then reload rather than restart SSH. Default nftables ingress is loopback plus established only; outbound is declared DNS, NTP, HTTPS and tunnel traffic.

- [ ] **Step 4: Add post-apply access probes and automatic local-file restore**

On a failed probe, restore exact prior bytes from the same transaction and reload. Do not invoke Hostinger recovery mode or snapshot restore.

- [ ] **Step 5: Verify provider evidence**

Require explicit evidence that public TCP 22, 80 and 443 are not allowed before the phase is accepted.

- [ ] **Step 6: Run tests, syntax, lint and commit**

    python -m pytest -q tests/test_personal_vps_ssh_stage_b.py
    ansible-playbook -i inventories/example/hosts.yml playbooks/personal-vps-ssh-stage-b.yml --syntax-check
    ansible-playbook -i inventories/example/hosts.yml playbooks/personal-vps-ssh-recover.yml --syntax-check
    git commit -am "feat(personal-vps): close legacy ssh and ingress safely"

### Task 5: Add the Root-Owned Runtime Boundary

**Branch:** feat/personal-vps-005-runtime-boundary

**Files:**
- Modify: roles/container_runtime/defaults/main.yml
- Modify: roles/container_runtime/tasks/main.yml
- Create: roles/personal_platform_runtime/**
- Create: playbooks/personal-vps-runtime.yml
- Create: tests/test_personal_platform_runtime.py

**Interfaces:**
- Adds container_runtime_access_mode with existing lab default unchanged and personal-root-only as an opt-in.
- Creates the approved /etc, /opt, /srv, /var/lib, /var/log and /run directory tree.
- Produces no application Compose content.

- [ ] **Step 1: Add failing compatibility tests**

Assert the existing enabled lab path still appends its technical user to docker, while personal-root-only rejects any docker group membership and creates no user.

- [ ] **Step 2: Run existing container role tests plus the new test**

- [ ] **Step 3: Implement the additive mode**

Keep all existing defaults. In personal-root-only mode install Docker/Compose, enable Docker, remove declared deployment users from docker, and validate the socket owner/mode.

- [ ] **Step 4: Create root-owned application directory skeletons**

Validate app IDs against cnesdata|limnopulse only. Directories must have fixed owners/modes and no symlink components.

- [ ] **Step 5: Verify idempotence and commit**

    python -m pytest -q tests/test_personal_platform_runtime.py
    python -m pytest -q tests/test_lab_container_host_role.py
    ansible-lint roles/container_runtime roles/personal_platform_runtime
    git add roles/container_runtime roles/personal_platform_runtime playbooks/personal-vps-runtime.yml tests/test_personal_platform_runtime.py
    git commit -m "feat(personal-vps): add root-only container runtime mode"

### Task 6: Implement the Global Coordination Lease

**Branch:** feat/personal-vps-006-global-lease

**Files:**
- Create: tools/personal_platform/lease.py
- Create: tools/personal_platform/process_identity.py
- Create: tests/test_personal_platform_lease.py
- Create: roles/personal_platform_dispatcher/templates/personal-platform-lease-recover.j2

**Interfaces:**
- acquire(owner_class, operation, github_run, pid_identity) returns an unpredictable owner token.
- renew(token), release(token) and recover_stale(expected_record, proof, approver) use file locking and compare-before-replace semantics.
- Lease records contain no credential or command input.

- [ ] **Step 1: Write race and stale-owner tests**

    def test_expiration_does_not_allow_takeover(tmp_path) -> None:
        lease = LeaseStore(tmp_path)
        first = lease.acquire(owner("workflow", expires_in=-1))
        with pytest.raises(LeaseBusy):
            lease.acquire(owner("systemd"))
        assert lease.read().token_hash == sha256(first.token)

    def test_recovery_fails_if_record_changes_during_proof(tmp_path) -> None:
        lease = mutating_store(tmp_path)
        with pytest.raises(LeaseChanged):
            lease.recover_stale(expected=lease.read(), proof=terminal_proof(), approver="operator")

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement atomic create/renew/release**

Use os.open with O_CREAT|O_EXCL, fcntl.flock, fsync, atomic rename, monotonic watchdog scheduling and constant-time token-hash comparison. Persist only token hash.

- [ ] **Step 4: Implement reviewed recovery proof adapters**

Workflow proof requires terminal GitHub run; systemd proof requires inactive invocation; human proof requires operator-confirmed ended session; every path also proves local PID identity absent.

- [ ] **Step 5: Run concurrency tests repeatedly**

    python -m pytest -q tests/test_personal_platform_lease.py
    for run in 1 2 3 4 5; do python -m pytest -q tests/test_personal_platform_lease.py; done

- [ ] **Step 6: Commit**

    git add tools/personal_platform/lease.py tools/personal_platform/process_identity.py tests/test_personal_platform_lease.py roles/personal_platform_dispatcher
    git commit -m "feat(dispatcher): serialize all host mutations"

### Task 7: Validate the Three-Frame Release Protocol

**Branch:** feat/personal-vps-007-release-protocol

**Files:**
- Create: tools/personal_platform/protocol.py
- Create: tools/personal_platform/archive.py
- Create: tools/personal_platform/github_evidence.py
- Create: tests/test_personal_platform_protocol.py
- Create: tests/test_personal_platform_archive.py
- Create: tests/test_personal_platform_github_evidence.py

**Interfaces:**
- read_frame(stream, maximum_bytes) reads a fixed-width unsigned length and exactly that payload.
- validate_envelope returns a typed immutable DeploymentEnvelope.
- extract_archive streams only declared regular files into a new staging directory.
- verify_github_evidence compares live workflow/run/artifact metadata and archive digest.

- [ ] **Step 1: Write malformed frame tests**

Cover short prefixes, zero/oversized lengths, short payloads, fourth-frame bytes, malformed UTF-8/JSON, oversized token and token newline rejection.

- [ ] **Step 2: Write hostile archive tests**

Cover ../, absolute paths, Windows drive paths, symlink/hardlink, FIFO/device, duplicate normalized names, undeclared files, wrong size/checksum and compressed bombs crossing the aggregate ceiling.

- [ ] **Step 3: Run tests and confirm modules are absent**

- [ ] **Step 4: Implement frame/envelope parsing**

Allow only schema_version=1, project/repository/workflow allowlists, 40-lower-hex source SHA, sha256 digests, RFC3339 future expiry, digest image references, approved requested actions and the complete platform-plan evidence tuple.

- [ ] **Step 5: Implement streaming extraction**

Open each destination with O_NOFOLLOW|O_CREAT|O_EXCL, count before every write, fsync files/directory and compare the embedded canonical manifest byte-for-byte after canonical JSON encoding.

- [ ] **Step 6: Implement live GitHub verification behind an HTTP protocol**

Mock the boundary in tests. Require successful exact workflow, SHA/ref, artifact ID, non-expiration and GitHub digest. Never format token into URL, command, environment or exception.

- [ ] **Step 7: Verify and commit**

    python -m pytest -q tests/test_personal_platform_protocol.py tests/test_personal_platform_archive.py tests/test_personal_platform_github_evidence.py
    git add tools/personal_platform tests/test_personal_platform_protocol.py tests/test_personal_platform_archive.py tests/test_personal_platform_github_evidence.py
    git commit -m "feat(dispatcher): validate bounded release evidence"

### Task 8: Implement Candidate Deploy, Switch and Rollback

**Branch:** feat/personal-vps-008-deploy-transaction

**Files:**
- Create: tools/personal_platform/dispatcher.py
- Create: tools/personal_platform/compose_policy.py
- Create: tools/personal_platform/deployment_ledger.py
- Create: roles/personal_platform_dispatcher/templates/personal-platform-dispatch.j2
- Create: roles/personal_platform_dispatcher/templates/personal-platform-sudoers.j2
- Create: tests/test_personal_platform_dispatcher.py

**Interfaces:**
- Fixed actions are validate, deploy and rollback-previous only.
- Dispatcher consumes the protocol, owns the global lease, renders secrets after validation, starts a candidate on an alternate loopback port, switches a named Nginx upstream and records a redacted ledger.
- Rollback selects only the immediately previous accepted manifest.

- [ ] **Step 1: Write command and Compose policy tests**

Reject arbitrary argv, shell metacharacters, mutable tags, build, privileged, host network, docker.sock, cross-product mounts/networks, public ports, unbounded logs/resources and missing healthchecks.

- [ ] **Step 2: Write failure-injection transaction tests**

Cover pull failure, candidate timeout, local smoke failure, Nginx validation failure, switch failure, post-switch failure and ledger fsync failure. Each case preserves or restores the prior accepted release and releases the lease.

- [ ] **Step 3: Implement a small state machine**

States: RECEIVED, VERIFIED, STAGED, CANDIDATE_HEALTHY, SWITCHED, ACCEPTED, ROLLED_BACK, FAILED. Every transition is append-only and redacted.

- [ ] **Step 4: Implement ephemeral registry authentication**

Feed the third-frame token to docker login through stdin using a mode-0700 DOCKER_CONFIG under /run. Remove it in finally. Public GHCR still uses the token for evidence verification, without packages permission.

- [ ] **Step 5: Add fixed sudoers and forced-command templates**

Validate with visudo -cf. Deployment users may invoke only their exact dispatcher project; platform-deploy may invoke platform operations but no shell.

- [ ] **Step 6: Verify and commit**

    python -m pytest -q tests/test_personal_platform_dispatcher.py
    python -m pytest -q tests/test_personal_platform_lease.py tests/test_personal_platform_archive.py
    git add tools/personal_platform roles/personal_platform_dispatcher tests/test_personal_platform_dispatcher.py
    git commit -m "feat(dispatcher): add health-guarded release transaction"

### Task 9: Add Cloudflare Tunnel and Nginx Rate-Limit Roles

**Branch:** feat/personal-vps-009-edge

**Files:**
- Create: roles/personal_platform_edge/**
- Create: roles/personal_platform_edge/templates/cloudflared.yml.j2
- Create: roles/personal_platform_edge/templates/nginx.conf.j2
- Create: roles/personal_platform_edge/templates/app.conf.j2
- Create: playbooks/personal-vps-edge.yml
- Create: tests/test_personal_platform_edge.py

**Interfaces:**
- Ingress order is SSH, CnesData API, LimnoPulse API, explicit 404.
- Nginx listens on loopback only.
- Rate zones default to 10 r/s burst 20, 5 r/m burst 5 and 2 r/m burst 2.

- [ ] **Step 1: Write template tests for ingress order, exact trusted peer and limits**

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement configuration rendering**

Require exact tunnel UUID, local targets, hostnames and exact cloudflared peer address. Discard forwarding headers from all other peers. Add body/header/connection/upstream bounds and request IDs.

- [ ] **Step 4: Validate before reload**

Run cloudflared tunnel ingress validate and nginx -t against candidates. Reload only after both pass.

- [ ] **Step 5: Add spoofing and 429 fixture tests**

Two validated CF client IPs create distinct keys; an untrusted peer supplying CF-Connecting-IP remains keyed by the peer.

- [ ] **Step 6: Verify and commit**

    python -m pytest -q tests/test_personal_platform_edge.py
    ansible-playbook -i inventories/example/hosts.yml playbooks/personal-vps-edge.yml --syntax-check
    git add roles/personal_platform_edge playbooks/personal-vps-edge.yml tests/test_personal_platform_edge.py
    git commit -m "feat(edge): add tunnel and loopback nginx contracts"

### Task 10: Add Roles Anywhere Credential Renewal

**Branch:** feat/personal-vps-010-credentials

**Files:**
- Create: roles/personal_platform_credentials/**
- Create: roles/personal_platform_credentials/templates/credential-renewer.service.j2
- Create: roles/personal_platform_credentials/templates/credential-renewer.timer.j2
- Create: tools/personal_platform/credential_renewer.py
- Create: tests/test_personal_platform_credentials.py

**Interfaces:**
- One app-specific config/certificate/key/profile/role tuple.
- Atomic shared-credentials and expiration files below /run/personal-platform/<app>/aws.
- A fixed reload hook must prove the new identity before traffic switch or worker continuation.

- [ ] **Step 1: Write tests for isolation and expiry behavior**

Reject cross-app paths, world/group-readable keys, session duration other than 3600, refresh beyond half-life, silent use past advisory window and any static AWS key variable.

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement helper invocation and atomic files**

Invoke aws_signing_helper without shell, parse expiration, write by descriptor with 0400 app UID, fsync and rename the directory-visible file.

- [ ] **Step 4: Integrate the global lease and reload hook**

If another operation owns the lease near the safety margin, signal it to renew or abort. Otherwise acquire, renew, start the candidate/replacement, perform a read-only AWS identity/health probe and switch only on success.

- [ ] **Step 5: Add a long-lived client fixture**

Hold a fake SDK client across file replacement and prove either explicit provider reconstruction or candidate replacement. Failure stops the app before credential expiry.

- [ ] **Step 6: Verify and commit**

    python -m pytest -q tests/test_personal_platform_credentials.py tests/test_personal_platform_lease.py
    git add roles/personal_platform_credentials tools/personal_platform/credential_renewer.py tests/test_personal_platform_credentials.py
    git commit -m "feat(credentials): renew roles-anywhere sessions safely"

### Task 11: Add Alloy, Journald and InfluxDB Backup

**Branch:** feat/personal-vps-011-observability-backup

**Files:**
- Create: roles/personal_platform_observability/**
- Create: roles/influxdb_s3_backup/**
- Create: playbooks/personal-vps-observability.yml
- Create: playbooks/personal-vps-backup.yml
- Create: tests/test_personal_platform_observability.py
- Create: tests/test_influxdb_s3_backup.py

**Interfaces:**
- Native unprivileged Alloy, no Docker socket.
- journald bounds are seven days and 512 MiB.
- Backup is consistent, checksum-verified and uploaded write-only to the declared S3 prefix.

- [ ] **Step 1: Write tests for forbidden labels, privileges and delete actions**

- [ ] **Step 2: Implement Alloy and journald templates**

Allow only bounded host/unit/app labels; reject tenant, user, email, token, object key and request ID labels.

- [ ] **Step 3: Implement backup staging and verification**

Acquire the global lease, run influx backup into a new root-only directory, verify manifest/checksum, upload with checksum metadata, read back size/checksum, then remove staging. No DeleteObject or retention bypass.

- [ ] **Step 4: Add systemd units and failure metrics**

Daily timer with randomized delay and no overlap. Retention remains an S3 lifecycle responsibility.

- [ ] **Step 5: Verify and commit**

    python -m pytest -q tests/test_personal_platform_observability.py tests/test_influxdb_s3_backup.py
    ansible-lint roles/personal_platform_observability roles/influxdb_s3_backup
    git add roles/personal_platform_observability roles/influxdb_s3_backup playbooks/personal-vps-observability.yml playbooks/personal-vps-backup.yml tests
    git commit -m "feat(personal-vps): add bounded telemetry and backup"

### Task 12: Build the Platform Acceptance and Recovery Gate

**Branch:** test/personal-vps-012-acceptance

**Files:**
- Create: tests/test_personal_platform_acceptance.py
- Create: docs/runbooks/personal-vps-stage-a.md
- Create: docs/runbooks/personal-vps-stage-b.md
- Create: docs/runbooks/personal-vps-lease-recovery.md
- Create: docs/runbooks/personal-vps-disaster-recovery.md
- Create: playbooks/personal-vps-acceptance.yml

**Interfaces:**
- Produces no runtime capability.
- Acceptance proves preflight, Stage A/B separation, lease contention, protocol rejection, candidate rollback, renewed credentials, edge isolation, backup and recovery.

- [ ] **Step 1: Write the acceptance contract**

The test enumerates every new role/playbook, proves defaults are disabled, scans for real domains/IPs/secrets/private keys, and verifies all mutation paths import the same lease client.

- [ ] **Step 2: Write executable runbooks**

Include exact evidence required, go/no-go checkpoints and rollback commands. Stage B requires a fresh Hostinger snapshot no older than 24 hours and an open Stage A session.

- [ ] **Step 3: Run the complete repository gate**

    python -m pytest -q
    pwsh -NoProfile -File tests/Validate-InfraAnsibleScaffold.ps1
    pwsh -NoProfile -File tests/Validate-AnsibleContainer.ps1
    ansible-inventory -i inventories/example/hosts.yml --list
    for playbook in playbooks/*.yml; do ansible-playbook -i inventories/example/hosts.yml "$playbook" --syntax-check; done
    yamllint .
    ansible-lint .
    git diff --check

- [ ] **Step 4: Run containerized validation exactly as CI does**

    docker build --tag infra-ansible-tools:personal-vps --file tools/ansible/Dockerfile .
    docker run --rm infra-ansible-tools:personal-vps --version

- [ ] **Step 5: Commit**

    git add tests/test_personal_platform_acceptance.py docs/runbooks playbooks/personal-vps-acceptance.yml
    git commit -m "test(personal-vps): add platform acceptance gate"

## Execution Order

Tasks 1-2 are serial foundations. Tasks 3 and 5 may start after Task 2. Task 4 waits for Task 3. Task 6 is the serial mutation primitive. Tasks 7, 9 and 11 may start after Task 6; Task 8 waits for Task 7; Task 10 waits for Tasks 6 and 8. Task 12 waits for all prior tasks.

## Plan Self-Review Record

- Spec coverage: all reusable capabilities in Sections 3-15 map to Tasks 2-12.
- Safety: provider-firewall writes, Hostinger recovery actions, real inventory and production secrets remain out of this public repository.
- Compatibility: Task 1 and the full final gate preserve the municipal pipeline and all existing role defaults.
- Type consistency: project IDs, user names, directory roots, lease ownership and three-frame protocol names are identical across producers and consumers.
- Cost: this repository provisions no AWS resource and cannot enable a paid service.
- Completeness scan: implementation tasks contain no unresolved marker, generic test instruction or undefined interface.

## Execution Handoff

Implement with isolated worktrees and reviewed PRs. Do not run any playbook against the real VPS until Tasks 1-12 are merged, the private live composition plan is complete, and the operator separately approves Stage A with current Hostinger evidence.
