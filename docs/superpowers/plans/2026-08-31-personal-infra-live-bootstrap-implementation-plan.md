# Personal Infrastructure Live Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the private personal-infra-live repository and compose the personal AWS, Cloudflare and Hostinger VPS environment with remote state, strict GitHub OIDC gates, SSM/KMS secrets, IAM Roles Anywhere, cost containment and reviewed product delivery.

**Architecture:** A private live repository pins an immutable infra-ansible revision and owns shared, edge and live-inventory composition while each product state owns only its application resources. OpenTofu plans and applies are manually joined by exact expiring artifacts, protected by native S3 locking plus a separate conditional coordination lease. GitHub-hosted runners use customized-sub OIDC; the VPS uses per-application Roles Anywhere identities.

**Tech Stack:** Private GitHub repository on GitHub Free, GitHub Actions hosted runners, OpenTofu 1.8+, AWS us-east-2, ACM/WAF/Pricing Plan Manager us-east-1, S3 native locking, KMS, SSM Standard, IAM/OIDC, IAM Roles Anywhere and CRL, AWS Budgets, Cloudflare provider/API, Ansible pinned by commit, pytest, OPA/Conftest, shellcheck.

**Spec:** docs/superpowers/specs/2026-08-29-personal-infra-live-composition-design.md and docs/superpowers/specs/2026-08-29-personal-vps-platform-and-cd-design.md

## Global Constraints

- This plan is temporarily stored in infra-ansible. Task 1 creates private VINIClUS/personal-infra-live and copies this plan plus the composition Spec into it before any credential or real inventory is added.
- The repository must be private before the first real identifier is committed. GitHub Actions paid spending remains USD 0.
- Never copy municipal infra-ansible-inventory, Infisical configuration, controller credentials, runners or environment files.
- Primary region is us-east-2. Only ACM CloudFront certificates, CLOUDFRONT-scope WAF and Pricing Plan Manager endpoint use us-east-1.
- OpenTofu state is private, versioned, KMS-encrypted and uses use_lockfile=true. Workflows never use -lock=false.
- The separate coordination lease is retained across preflight-to-apply credential handoff; native .tflock remains owned only by each OpenTofu process.
- GitHub OIDC customized subject includes repo, context and job_workflow_ref. Every AWS role requires its exact immutable reusable workflow path/ref.
- GitHub Free private repositories do not provide required environment approvals; evidence validation before OIDC is the authorization gate.
- OpenTofu manages SSM names/IAM only. Secret values enter through a separately authorized PutParameter bootstrap/rotation and never appear in config, plan or state.
- The offline root CA private key never enters AWS, GitHub, the VPS repository or OpenTofu state. No AWS Private CA is created.
- CloudFront Free eligibility and two available slots are required before product DNS. Failure has no pay-as-you-go or paid-tier fallback.
- Operational envelope is USD 4 shared, USD 3 LimnoPulse and USD 8 CnesData. Automation freezes at USD 15; USD 5 remains unallocated reserve to the USD 20 governance maximum.
- LimnoPulse rollout completes before CnesData starts.
- No workflow has a destroy action. Destructive restore, force-unlock and provider-firewall edits are human-reviewed runbooks.

## Target Repository Layout

    .github/workflows/
      validate.yml
      bootstrap-oidc.yml
      plan-shared.yml
      apply-shared.yml
      plan-edge.yml
      apply-edge.yml
      host-deploy-cnesdata.yml
      host-deploy-limnopulse.yml
      reusable-plan-gate.yml
      reusable-apply-gate.yml
      reusable-host-deploy-cnesdata.yml
      reusable-host-deploy-limnopulse.yml
    bootstrap/
      state/
      github-oidc/
    stacks/
      shared/
      edge/
    live/prod/
      inventory/
      group_vars/
      application-contracts/
      requirements.yml
    policies/
    schemas/
    scripts/
    tests/
    docs/runbooks/
    opentofu.lock.hcl

---

### Task 1: Create and Seal the Private Repository

**Branch:** bootstrap/repository

**Files:**
- Create: README.md
- Create: SECURITY.md
- Create: .gitignore
- Create: .gitattributes
- Create: .github/CODEOWNERS
- Create: docs/superpowers/specs/2026-08-29-personal-infra-live-composition-design.md
- Create: docs/superpowers/plans/2026-08-31-personal-infra-live-bootstrap-implementation-plan.md
- Create: tests/test_repository_boundary.py

**Interfaces:**
- Produces a private repository whose default branch is main.
- Produces no cloud or host resource.

- [ ] **Step 1: Verify the intended owner and repository do not conflict**

    gh repo view VINIClUS/personal-infra-live --json nameWithOwner,visibility,defaultBranchRef

Expected: not found. If it exists, stop and review its visibility/content; never overwrite it.

- [ ] **Step 2: Create the repository privately without local secrets**

    gh repo create VINIClUS/personal-infra-live --private --disable-wiki --disable-issues

- [ ] **Step 3: Write the failing repository-boundary test**

    def test_forbidden_municipal_and_secret_paths_are_absent() -> None:
        names = all_repository_paths()
        assert not any("infisical" in name.lower() for name in names)
        assert not any("infra-ansible-inventory" in name for name in names)
        assert not any(name.endswith((".pem", ".key", ".p12", ".tfstate")) for name in names)

- [ ] **Step 4: Add minimal docs, ignores and copied governing documents**

Ignore .terraform, *.tfstate*, *.tfplan, plan artifacts, inventory host_vars secrets, PEM/key/P12, rendered .env and local evidence.

- [ ] **Step 5: Run the test and scan history**

    python -m pytest -q tests/test_repository_boundary.py
    git grep -nEi '(BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16})' -- . ':!docs/superpowers/specs/*'
    git diff --check

- [ ] **Step 6: Commit and push**

    git add .
    git commit -m "chore(live): bootstrap private infrastructure repository"
    git push -u origin bootstrap/repository

### Task 2: Bootstrap Remote State and Native Locking

**Branch:** feat/live-001-state-bootstrap

**Files:**
- Create: bootstrap/state/main.tf
- Create: bootstrap/state/variables.tf
- Create: bootstrap/state/outputs.tf
- Create: bootstrap/state/versions.tf
- Create: bootstrap/state/README.md
- Create: stacks/shared/backend.hcl.example
- Create: stacks/edge/backend.hcl.example
- Create: tests/test_state_bootstrap.py

**Interfaces:**
- Creates one private versioned state bucket and bootstrap KMS key using a one-time local, MFA-authenticated human session.
- Outputs names/ARNs into a redacted bootstrap receipt, not product repositories.
- Backend keys are personal/shared/prod/opentofu.tfstate, personal/edge/prod/opentofu.tfstate, cnesdata/prod/opentofu.tfstate and limnopulse/prod/opentofu.tfstate.

- [ ] **Step 1: Write tests for encryption, versioning, public blocking and native locks**

    def test_backends_use_native_locking() -> None:
        for path in backend_examples():
            text = path.read_text()
            assert "use_lockfile = true" in text
            assert "dynamodb_table" not in text
            assert "encrypt = true" in text

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement the one-time bootstrap module**

Use prevent_destroy, KMS rotation, bucket-owner-enforced ownership, TLS-only policy, public-access block and version lifecycle. Do not create an old DynamoDB lock table.

- [ ] **Step 4: Add a two-person-readable bootstrap procedure**

The procedure requires a unique bucket name, current AWS account readback, MFA session and plan review. It records resource ARNs and state lineage hashes, never credentials.

- [ ] **Step 5: Validate locally without applying**

    tofu -chdir=bootstrap/state init -backend=false -input=false
    tofu -chdir=bootstrap/state fmt -check -recursive
    tofu -chdir=bootstrap/state validate -no-color
    python -m pytest -q tests/test_state_bootstrap.py

- [ ] **Step 6: Commit**

    git add bootstrap/state stacks tests/test_state_bootstrap.py
    git commit -m "feat(state): define encrypted native-lock backend"

### Task 3: Bootstrap Customized GitHub OIDC Subjects

**Branch:** feat/live-002-github-oidc-bootstrap

**Files:**
- Create: bootstrap/github-oidc/main.tf
- Create: bootstrap/github-oidc/subject_templates.json
- Create: scripts/verify_oidc_subject.py
- Create: .github/workflows/bootstrap-oidc.yml
- Create: tests/test_oidc_subject_contract.py
- Create: docs/runbooks/github-oidc-bootstrap.md

**Interfaces:**
- Configures include_claim_keys exactly repo, context and job_workflow_ref for personal-infra-live, CnesData and limnopulse.
- Bootstrap is one-time, human-dispatched and idempotently verifies readback.

- [ ] **Step 1: Write the exact-subject tests**

    EXPECTED_KEYS = ["repo", "context", "job_workflow_ref"]

    def test_subject_templates_use_exact_claim_order() -> None:
        assert load_templates()["include_claim_keys"] == EXPECTED_KEYS

    def test_no_role_trusts_only_repository_and_ref() -> None:
        for policy in trust_policies():
            assert "job_workflow_ref" in json.dumps(policy)

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement provider/template bootstrap**

Use the existing GitHub OIDC provider if its issuer/thumbprint/audience are exact; otherwise fail for human reconciliation. Apply repository subject customizations through the supported GitHub API and read them back.

- [ ] **Step 4: Pin every workflow action by full SHA**

Workflow permissions are contents:read and id-token:write only for the final bootstrap job. No pull_request trigger.

- [ ] **Step 5: Run tests and offline workflow validation**

    python -m pytest -q tests/test_oidc_subject_contract.py
    python scripts/verify_oidc_subject.py --fixtures tests/fixtures/oidc
    actionlint .github/workflows/bootstrap-oidc.yml

- [ ] **Step 6: Commit**

    git add bootstrap/github-oidc scripts/verify_oidc_subject.py .github/workflows/bootstrap-oidc.yml tests docs/runbooks/github-oidc-bootstrap.md
    git commit -m "feat(identity): bind customized github oidc subjects"

### Task 4: Build the Shared KMS, SSM and Backup Foundation

**Branch:** feat/live-003-shared-foundation

**Files:**
- Create: stacks/shared/providers.tf
- Create: stacks/shared/versions.tf
- Create: stacks/shared/variables.tf
- Create: stacks/shared/locals.tf
- Create: stacks/shared/kms.tf
- Create: stacks/shared/ssm.tf
- Create: stacks/shared/backup.tf
- Create: stacks/shared/outputs.tf
- Create: tests/test_shared_foundation.py

**Interfaces:**
- Produces one rotating customer KMS key, declared SSM names, evidence storage and Governance-locked Influx backup bucket in us-east-2.
- No aws_ssm_parameter resource or secret value exists.

- [ ] **Step 1: Write tests that reject secret values in state**

    def test_ssm_names_are_inventory_not_resources() -> None:
        text = stack_text("shared")
        assert 'resource "aws_ssm_parameter"' not in text
        assert "/personal/prod/" in text
        assert "SecureString" not in text

- [ ] **Step 2: Write backup-bucket policy tests**

Require Object Lock at creation, Governance retention, versioning, TLS, write-only uploader, no DeleteObject and lifecycle retention 7 daily/4 weekly/3 monthly.

- [ ] **Step 3: Implement shared providers and resources**

Default provider us-east-2. All supported resources use Project=shared, Environment=prod, ManagedBy=opentofu and Owner=vinisantana.

- [ ] **Step 4: Add secret-name schema**

Declare exact shared, CnesData and LimnoPulse prefixes plus the two MQTT and complete Influx paths. Disabled feature secret paths are absent.

- [ ] **Step 5: Validate and commit**

    tofu -chdir=stacks/shared init -backend=false -input=false
    tofu -chdir=stacks/shared validate -no-color
    python -m pytest -q tests/test_shared_foundation.py
    git add stacks/shared tests/test_shared_foundation.py
    git commit -m "feat(shared): add kms ssm inventory and backup storage"

### Task 5: Implement Roles Anywhere Profiles, Trust and CRL

**Branch:** feat/live-004-roles-anywhere

**Files:**
- Create: stacks/shared/roles_anywhere.tf
- Create: stacks/shared/roles_anywhere_policies.tf
- Create: schemas/x509-identities.json
- Create: scripts/verify_roles_anywhere_matrix.py
- Create: tests/test_roles_anywhere.py
- Create: docs/runbooks/offline-ca-and-crl.md
- Create: docs/runbooks/revoke-roles-anywhere-leaf.md

**Interfaces:**
- External input is only offline CA public PEM plus reviewed leaf CN/SAN metadata.
- Produces distinct platform, CnesData, LimnoPulse and backup profiles/roles.
- Trust requires exact trust-anchor SourceArn and exact x509Subject/CN plus x509SAN/URI principal tags.

- [ ] **Step 1: Write the full cross-product denial matrix**

    def test_only_matching_leaf_profile_role_tuple_is_allowed() -> None:
        for leaf, profile, role in product(all_leaves(), all_profiles(), all_roles()):
            assert evaluate(leaf, profile, role) is (
                leaf.application == profile.application == role.application
            )

- [ ] **Step 2: Add tests that prohibit AWS Private CA and private keys**

- [ ] **Step 3: Implement trust anchor, profiles, roles and enabled CRL**

Profile and role maximum session are 3600 seconds. Require sts:AssumeRole, sts:TagSession and sts:SetSourceIdentity only for rolesanywhere.amazonaws.com.

- [ ] **Step 4: Write the offline CA/CRL procedure**

Validate CA:true, keyCertSign, cRLSign and SHA-256+. Import/update signed PEM CRL with bounded nextUpdate; read back. A compromise disables profile, publishes serial, proves CreateSession denial, applies session revocation and only then rotates.

- [ ] **Step 5: Validate and commit**

    python -m pytest -q tests/test_roles_anywhere.py
    python scripts/verify_roles_anywhere_matrix.py --fixtures tests/fixtures/roles-anywhere
    tofu -chdir=stacks/shared validate -no-color
    git add stacks/shared schemas scripts tests docs/runbooks
    git commit -m "feat(identity): isolate roles-anywhere applications"

### Task 6: Add Budget, Anomaly and Cost-Freeze Controls

**Branch:** feat/live-005-cost-governance

**Files:**
- Create: stacks/shared/cost.tf
- Create: policies/cost.rego
- Create: policies/forbidden-services.rego
- Create: schemas/cost-manifest.schema.json
- Create: tests/test_cost_governance.py
- Create: tests/fixtures/plans/forbidden-*.json
- Create: docs/runbooks/cost-freeze.md

**Interfaces:**
- Alerts at actual 50/75/90/100, forecast 80/100 and anomaly USD 1.
- USD 15 action attaches only the exact freeze policy to automation roles.
- Backup writes, read/diagnostics and MFA break-glass remain possible.

- [ ] **Step 1: Write failing OPA and IAM-boundary tests**

Reject NAT, ALB, RDS/Aurora, Redshift, OpenSearch, ElastiCache, Global Tables, Marketplace, paid messaging and unapproved plans.

- [ ] **Step 2: Implement the cost manifest schema**

Fields are stack, source_sha, generated_at, currency=USD and min/base/max_monthly. Aggregate base and max calculations must include KMS post-rotation cost.

- [ ] **Step 3: Implement exact Budget action trust/policy**

Trust only budgets.amazonaws.com with exact SourceAccount and Budget SourceArn. iam:AttachRolePolicy is constrained by target role and iam:PolicyARN. No broad detach for automation.

- [ ] **Step 4: Add cost-clear and delayed-billing runbook**

Only MFA break-glass can detach after reviewed evidence. Preserve budget history.

- [ ] **Step 5: Run policy tests and commit**

    conftest test tests/fixtures/plans --policy policies
    python -m pytest -q tests/test_cost_governance.py
    git add stacks/shared/cost.tf policies schemas tests docs/runbooks/cost-freeze.md
    git commit -m "feat(cost): enforce fifteen-dollar automation freeze"

### Task 7: Create Exact GitHub OIDC Role Classes

**Branch:** feat/live-006-github-role-classes

**Files:**
- Create: stacks/shared/github_oidc.tf
- Create: schemas/oidc-role-contracts.json
- Create: tests/test_github_oidc_roles.py

**Interfaces:**
- Eight role classes: live plan/apply, CnesData host deploy, LimnoPulse host deploy, and per-product infrastructure plan/deploy.
- Plan roles are read-only except exact evidence object and backend lock operations.
- Host deploy roles read only their product SSM credential/evidence objects and cannot mutate infrastructure.

- [ ] **Step 1: Write positive and negative trust simulations**

Test exact caller repo/ref/reusable workflow path. Reject another workflow in the same repo, another product, pull request context, mutable branch pin and plan subject against deploy.

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement trust policies from the schema**

Use aud and customized sub StringEquals; do not rely on unsupported custom claims outside sub.

- [ ] **Step 4: Implement least-privilege policies**

Separate preflight and apply role permissions. Product deploy roles cannot list S3 evidence prefixes, decrypt other-product SSM, or call OpenTofu mutation APIs.

- [ ] **Step 5: Run tests and commit**

    python -m pytest -q tests/test_github_oidc_roles.py
    tofu -chdir=stacks/shared validate -no-color
    git add stacks/shared/github_oidc.tf schemas/oidc-role-contracts.json tests/test_github_oidc_roles.py
    git commit -m "feat(identity): separate github plan deploy and host roles"

### Task 8: Implement Evidence, Coordination and Reusable Workflow Gates

**Branch:** feat/live-007-workflow-gates

**Files:**
- Create: .github/workflows/reusable-plan-gate.yml
- Create: .github/workflows/reusable-apply-gate.yml
- Create: .github/workflows/reusable-host-deploy-cnesdata.yml
- Create: .github/workflows/reusable-host-deploy-limnopulse.yml
- Create: scripts/verify_github_artifact.py
- Create: scripts/coordination_lease.py
- Create: scripts/verify_plan_manifest.py
- Create: schemas/plan-manifest.schema.json
- Create: tests/test_workflow_gates.py
- Create: tests/test_coordination_lease.py

**Interfaces:**
- Caller first validates run/artifact with its ephemeral GITHUB_TOKEN.
- Reusable gate repeats validation before id-token permission is exercised.
- Apply keeps one conditional S3 coordination owner token across preflight/apply role handoff.

- [ ] **Step 1: Write workflow-order tests**

For every apply/deploy gate, assert artifact/run/SHA/ref/digest/expiry validation steps appear before the first OIDC credential step.

- [ ] **Step 2: Write lease CAS/watchdog tests**

Expiration never grants takeover. Renewal happens before half interval; a missed safety margin aborts. Recovery needs terminal GitHub run plus unchanged record.

- [ ] **Step 3: Implement exact artifact verification**

Require allowlisted workflow, successful conclusion, expected branch/SHA, artifact ownership, GitHub digest, downloaded SHA-256, internal manifest digest and expiration.

- [ ] **Step 4: Implement preflight/apply handoff**

Acquire coordination with preflight role, let the read-only tofu process own/remove its .tflock, retain coordination, discard preflight credentials, assume apply role, repeat drift and expiry checks, then apply the exact binary plan with native locking.

- [ ] **Step 5: Implement host-deploy reusable gates**

Retrieve only exact SSM-held Cloudflare/SSH input and exact versioned promotion object, connect to the forced dispatcher and stream product evidence. Do not persist a token or credential.

- [ ] **Step 6: Validate workflows and commit**

    python -m pytest -q tests/test_workflow_gates.py tests/test_coordination_lease.py
    actionlint .github/workflows
    shellcheck scripts/*.sh
    git add .github/workflows scripts schemas tests
    git commit -m "feat(delivery): gate oidc with exact expiring evidence"

### Task 9: Compose Cloudflare Edge Without Product-State Overlap

**Branch:** feat/live-008-edge-stack

**Files:**
- Create: stacks/edge/providers.tf
- Create: stacks/edge/variables.tf
- Create: stacks/edge/tunnel.tf
- Create: stacks/edge/access.tf
- Create: stacks/edge/dns.tf
- Create: stacks/edge/rate_limit.tf
- Create: stacks/edge/outputs.tf
- Create: tests/test_edge_stack.py

**Interfaces:**
- Consumes reviewed product CloudFront distribution-domain outputs and API loopback contracts.
- Owns one tunnel, SSH Access, two API DNS records, two DNS-only static CNAMEs and one narrow Free-plan rule.
- Ends tunnel ingress in explicit http_status:404.

- [ ] **Step 1: Write ownership and DNS-mode tests**

Assert static records are proxied=false; API/SSH records follow the approved tunnel mode; no product AWS resource or state data source exists.

- [ ] **Step 2: Write exact ingress-order tests**

- [ ] **Step 3: Implement tunnel, Access and DNS**

Use least-privilege Cloudflare API tokens supplied at runtime from SSM. SSH human and service-token policies are separate; APIs do not use interactive Access.

- [ ] **Step 4: Add health-gated DNS inputs**

DNS changes require a signed product target-evidence object and prior health result. Missing/unhealthy input yields no DNS mutation.

- [ ] **Step 5: Validate and commit**

    tofu -chdir=stacks/edge init -backend=false -input=false
    tofu -chdir=stacks/edge validate -no-color
    python -m pytest -q tests/test_edge_stack.py
    git add stacks/edge tests/test_edge_stack.py
    git commit -m "feat(edge): compose tunnel access and dns ownership"

### Task 10: Add Live Inventory and Product Contracts

**Branch:** feat/live-009-inventory-contracts

**Files:**
- Create: live/prod/requirements.yml
- Create: live/prod/inventory/hosts.yml
- Create: live/prod/group_vars/all.yml
- Create: live/prod/application-contracts/limnopulse.yml
- Create: live/prod/application-contracts/cnesdata.yml
- Create: schemas/application-contract.schema.json
- Create: tests/test_live_inventory.py

**Interfaces:**
- Pins infra-ansible by exact commit SHA.
- Contracts contain repo/branch/workflow, services, loopback ports, domains, registries, health paths, SSM prefix, Roles Anywhere profile ARN, CloudFront output, cost envelope, feature flags and rollback count.
- No image tag, current release or secret.

- [ ] **Step 1: Write schema tests that reject moving pins and secrets**

Reject branch/tag pins for infra-ansible, mutable images, passwords/tokens, unknown app IDs, shared loopback ports and cross-app SSM/profile references.

- [ ] **Step 2: Add encrypted/private real inventory**

Use host alias, not raw IP in application contracts. SSH fingerprint and provider evidence are workflow inputs/evidence, not plaintext inventory drift.

- [ ] **Step 3: Define exact product contracts**

LimnoPulse main precedes CnesData develop. Set us-east-2, cost 3 and 8 respectively, and static/API hostnames from the approved Specs.

- [ ] **Step 4: Validate and commit**

    ansible-galaxy collection install -r live/prod/requirements.yml
    ansible-inventory -i live/prod/inventory/hosts.yml --list
    python -m pytest -q tests/test_live_inventory.py
    git add live schemas/application-contract.schema.json tests/test_live_inventory.py
    git commit -m "feat(live): add pinned personal production composition"

### Task 11: Add Plan/Apply Entry Workflows and Secret Bootstrap

**Branch:** feat/live-010-entry-workflows

**Files:**
- Create: .github/workflows/validate.yml
- Create: .github/workflows/plan-shared.yml
- Create: .github/workflows/apply-shared.yml
- Create: .github/workflows/plan-edge.yml
- Create: .github/workflows/apply-edge.yml
- Create: scripts/put_secure_parameter.py
- Create: docs/runbooks/secret-bootstrap-and-rotation.md
- Create: tests/test_entry_workflows.py
- Create: tests/test_secure_parameter_bootstrap.py

**Interfaces:**
- Plan produces binary plan, redacted text, source/dependency/provider digests, backend/workspace, policy, cost, drift and expiration manifest.
- Apply accepts plan_run_id, artifact_id and artifact_digest only.
- Secure bootstrap uses PutParameter and verifies version/checksum without returning plaintext.

- [ ] **Step 1: Write tests for no apply-on-merge and no production PR credential**

- [ ] **Step 2: Implement validation and manual plan/apply callers**

All actions pinned by SHA. Reusable workflow pins are immutable SHA refs. Apply never replans and has no destroy input.

- [ ] **Step 3: Implement secure parameter bootstrap**

Read value only from a protected local file descriptor/stdin, never argv/env. Call PutParameter with KMS key, then compare version and a locally calculated digest through a separately authorized read path without printing value.

- [ ] **Step 4: Test wrong/expired/mixed artifacts**

Every case fails before OIDC. Add cost >15, destructive replacement and secret-in-plan fixtures.

- [ ] **Step 5: Validate and commit**

    python -m pytest -q tests/test_entry_workflows.py tests/test_secure_parameter_bootstrap.py
    actionlint .github/workflows
    git add .github/workflows scripts docs/runbooks tests
    git commit -m "feat(delivery): add manual plan apply and secret bootstrap"

### Task 12: Rehearse Stage A, Stage B and Platform Acceptance

**Branch:** ops/live-011-platform-rollout

**Files:**
- Create: docs/runbooks/platform-rollout.md
- Create: docs/runbooks/hostinger-evidence.md
- Create: docs/runbooks/state-force-unlock.md
- Create: docs/runbooks/disaster-recovery.md
- Create: tests/test_platform_rollout_contract.py

**Interfaces:**
- Produces reviewed evidence only; this task's code changes do not mutate production.
- Actual Stage A and Stage B executions remain separate manual approvals after the PR is merged.

- [ ] **Step 1: Write the rollout-order test**

Assert bootstrap state/OIDC/KMS -> shared -> edge scaffold -> preflight -> Stage A -> Stage B -> LimnoPulse -> CnesData -> drills.

- [ ] **Step 2: Document Hostinger evidence collection**

Require read-only backup age, snapshot ID/time, provider-firewall readback, host fingerprint and recovery-console availability. Unknown is blocker.

- [ ] **Step 3: Document exact Stage A checkpoint**

Keep root session open; prove human SSH through ssh.vinisantana.com and each forced automation session; record redacted digest.

- [ ] **Step 4: Document exact Stage B and rollback**

Consume Stage A digest, require snapshot under 24 hours, close OS ingress, verify provider firewall, repeat access probes and restore local transaction on failure.

- [ ] **Step 5: Run the repository acceptance gate**

    tofu fmt -check -recursive
    for stack in bootstrap/state bootstrap/github-oidc stacks/shared stacks/edge; do tofu -chdir="$stack" init -backend=false -input=false; tofu -chdir="$stack" validate -no-color; done
    python -m pytest -q
    conftest test tests/fixtures/plans --policy policies
    actionlint .github/workflows
    git diff --check

- [ ] **Step 6: Commit**

    git add docs/runbooks tests/test_platform_rollout_contract.py
    git commit -m "docs(ops): define personal platform rollout gates"

## Execution Order

Tasks 1-3 are serial bootstrap. Tasks 4, 6 and 7 start only after state/OIDC. Task 5 waits for Task 4. Task 8 waits for Tasks 6-7. Task 9 waits for Task 8. Task 10 waits for the reusable infra-ansible platform plan to merge and pins its exact SHA. Task 11 waits for Tasks 4-10. Task 12 is the final non-mutating rehearsal. Real Stage A/B execution is a later separately approved operation.

## Plan Self-Review Record

- Ownership: shared, edge, live inventory and product states do not manage the same resource.
- Identity: every OIDC and Roles Anywhere producer/consumer uses the same exact repo/ref/workflow or CN/SAN contract.
- Secrets: no OpenTofu secret resource/value; PutParameter is outside state and offline CA keys stay offline.
- Locks: native .tflock and conditional coordination lease are distinct and correctly sequenced.
- Cost: all envelopes sum to USD 15 and forbidden-service policy prevents the common fixed-cost escapes.
- GitHub Free: authorization uses immutable workflow subjects and evidence validation, not protected environments or private self-hosted runners.
- Completeness scan: no unresolved marker, automatic paid fallback or undefined production mutation remains.

## Execution Handoff

First merge Task 1 into the newly private repository. Execute Tasks 2-12 with reviewed worktree PRs. Do not perform the one-time AWS/GitHub bootstrap or real VPS rollout merely by merging these plans; each mutation is a manual run with current evidence and its own approval.
