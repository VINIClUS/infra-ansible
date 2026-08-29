# Personal Infrastructure Live Composition Design

**Date:** 2026-08-29  
**Status:** Draft for repository review; architecture approved in design discussion  
**Future repository:** private `VINIClUS/personal-infra-live`  
**Temporary publication location:** companion document in `infra-ansible`

## 1. Purpose

Define the private, environment-specific composition repository for the
personal Hostinger VPS, AWS account and Cloudflare zones used by CnesData and
LimnoPulse.

This repository is deliberately separate from `infra-ansible-inventory`. The
latter contains municipal/Proxmox topology and continues to depend on the
municipal Infisical and controller. No file, secret reference, runner,
credential, network address or state is shared between them.

The repository is created only after this document is reviewed. Once created,
this design becomes its first governing specification and the temporary copy in
`infra-ansible` is replaced by a short reference.

## 2. Ownership

`personal-infra-live` owns:

- personal VPS inventory and non-secret host metadata;
- exact `infra-ansible` revision pins;
- shared AWS bootstrap, state, KMS, budgets, OIDC and Roles Anywhere resources;
- Cloudflare Tunnel, Access policies and production DNS records;
- SSM parameter names and application trust boundaries;
- shared observability destinations and alert routing;
- platform deployment plans, evidence and runbooks.

It does not own:

- reusable Ansible roles;
- application source, Compose contracts or OCI images;
- CnesData or LimnoPulse product-specific AWS resources;
- municipal infrastructure;
- secret values, private keys, certificates or OpenTofu state in Git;
- direct data-plane mutations or destructive recovery automation.

## 3. Proposed layout

```text
.
├── .github/workflows/
│   ├── validate.yml
│   ├── plan-shared.yml
│   ├── apply-shared.yml
│   └── deploy-platform.yml
├── ansible/
│   ├── requirements.yml
│   ├── inventory/production/hosts.yml
│   ├── inventory/production/group_vars/all.yml
│   ├── inventory/production/host_vars/personal-vps.yml
│   └── playbooks/personal-vps.yml
├── opentofu/
│   ├── bootstrap/
│   ├── shared/
│   └── edge/
├── contracts/
│   ├── applications/cnesdata.yml
│   ├── applications/limnopulse.yml
│   └── cost-policy.yml
├── policies/
│   ├── forbidden-resources.rego
│   ├── required-tags.rego
│   └── retention.rego
├── runbooks/
│   ├── bootstrap.md
│   ├── ssh-lockout-recovery.md
│   ├── cost-freeze.md
│   ├── roles-anywhere-rotation.md
│   └── disaster-recovery.md
└── docs/superpowers/specs/
```

The real IP address, AWS account ID, zone IDs, tunnel ID, certificate serials
and role ARNs are treated as private operational metadata even when they are
not credentials. They belong only in this private repository or SSM.

## 4. OpenTofu state and bootstrap

### 4.1 One-time bootstrap

A local administrator uses the already configured AWS CLI with MFA-capable
credentials to create only:

- a private S3 state bucket in `us-east-2`;
- bucket versioning, public-access block and lifecycle for obsolete versions;
- the customer-managed KMS key and alias;
- the minimal GitHub OIDC provider and bootstrap plan/apply roles needed to
  transition control to CI.

Bootstrap emits redacted resource names and ARNs, never credentials. It is
re-runnable and import-aware. It has no destroy workflow.

### 4.2 Backend contract

All stacks use the S3 backend with:

- `use_lockfile = true` native S3 conditional locking;
- versioning enabled;
- SSE-KMS using the shared customer-managed key;
- separate keys for `shared`, `edge`, `cnesdata/prod` and
  `limnopulse/prod`;
- state and lock object tags;
- lifecycle limits for superseded state and lock versions;
- no local state committed or uploaded as a workflow artifact.

Force unlock is an emergency human procedure requiring the exact lock ID and
proof that no apply is running. Workflows never pass `-lock=false`.

## 5. AWS ownership and identity

### 5.1 Shared resources

The `shared` stack owns:

- one customer-managed KMS key with annual rotation;
- SSM Standard parameter hierarchy;
- AWS Budgets and Cost Anomaly Detection configuration;
- budget-action roles and cost-freeze policy;
- GitHub OIDC roles by repository and workflow;
- Roles Anywhere trust anchor, profiles and per-application roles;
- shared CloudWatch notification topic/email subscription if required;
- the private InfluxDB backup bucket;
- state and deployment-evidence storage.

The KMS key is budgeted at USD 1/month before its first rotation, USD 2/month
after the first rotation and USD 3/month after the second and later rotations.
No AWS Private CA is created.

### 5.2 GitHub OIDC roles

Separate roles exist for:

- `personal-infra-live` plan;
- `personal-infra-live` apply;
- CnesData plan/deploy;
- LimnoPulse plan/deploy.

Trust policies bind repository, branch/tag or workflow file, audience and
environment intent. The private-repository workflow cannot rely on protected
GitHub Environments, so the apply role additionally requires an exact plan
manifest and a repository/workflow claim. Plan roles are read-only apart from
writing their bounded plan evidence. Product roles cannot mutate shared,
edge or other-product resources.

### 5.3 VPS roles

Roles Anywhere profiles are distinct for:

- platform backup/secret bootstrap;
- CnesData API;
- LimnoPulse API/workers;
- InfluxDB backup uploader.

Each role has a maximum session duration and exact actions/resources. A
certificate or application compromise cannot assume another profile or read
another parameter prefix.

## 6. Secret hierarchy

SSM SecureString parameters use paths such as:

```text
/personal/prod/shared/cloudflare/access-client-id
/personal/prod/shared/cloudflare/access-client-secret
/personal/prod/shared/grafana/otlp-endpoint
/personal/prod/shared/grafana/token
/personal/prod/cnesdata/runtime/<name>
/personal/prod/limnopulse/runtime/<name>
/personal/prod/limnopulse/influx/<name>
```

Rules:

- values are encrypted with the shared KMS key;
- policies grant exact prefixes and required KMS encryption context;
- GitHub workflows retrieve only deployment-time values;
- VPS applications retrieve only their runtime prefix;
- values are masked before use and never emitted to outputs, plans or
  artifacts;
- OpenTofu creates parameter containers and policies but not secret values;
- initial values and rotations are explicit secure operations with readback by
  checksum or version, not plaintext;
- Standard parameters are used unless a measured size or policy requirement
  justifies an approved Advanced parameter.

The X.509 root CA private key is never stored in SSM. Two encrypted offline
copies are maintained in physically separate locations. VPS leaf private keys
are installed through a one-time secure bootstrap and rotated independently.

## 7. Cloudflare ownership

The `edge` stack owns:

- one production tunnel and its ingress records;
- `ssh.vinisantana.com` Access application and policies;
- API DNS records for both products;
- DNS-only CNAMEs from the two static domains to their CloudFront
  distributions;
- the narrow Cloudflare rate-limit/WAF rule available on the Free plan;
- tunnel-health notifications.

Cloudflare API tokens are least-privilege and zone/account scoped. The edge
stack consumes product distribution domain names through reviewed output
contracts; it does not read product state directly with broad permissions.

Ingress ordering is deterministic and ends in an explicit `http_status:404`
catch-all. SSH has separate human and service-token policies. API hostnames are
public through Cloudflare but do not use Access interactive authentication;
the applications use Cognito and their own authorization.

## 8. Repository and application contracts

Each application contract declares only:

- canonical repository and production branch;
- allowed workflow path;
- service IDs and loopback ports;
- API and static hostnames;
- accepted OCI registries and image names;
- required health paths;
- SSM prefix and Roles Anywhere profile ARN;
- CloudFront output name;
- cost envelope and feature flags;
- rollback retention count.

It contains no image tag or secret. A product deployment manifest supplies an
immutable digest and source SHA at promotion time.

## 9. Cost governance

The aggregate additional-services policy is:

| Envelope | Monthly operational limit |
|---|---:|
| Shared platform | USD 4 |
| CnesData | USD 8 |
| LimnoPulse | USD 3 |
| Operational ceiling | **USD 15** |
| Unallocated safety reserve | **USD 5** |
| Governance maximum | **USD 20** |

The already purchased Hostinger VPS is not counted in this additional-services
ceiling.

Controls include:

- actual-cost alerts at 50%, 75%, 90% and 100%;
- forecast alerts at 80% and 100%;
- anomaly alert at an estimated USD 1 impact;
- mandatory tags `Project`, `Environment=prod`, `ManagedBy=opentofu` and
  `Owner=vinisantana`;
- policy denial for NAT Gateway, ALB, RDS/Aurora, Redshift, OpenSearch,
  ElastiCache, Global Tables, Marketplace and unapproved paid plans;
- a USD 15 budget action that attaches a cost-freeze deny policy to automation
  roles while preserving read, diagnostics and backup writes;
- an MFA-protected human break-glass role outside automatic freeze;
- no automatic upgrade of CloudFront, Cloudflare, Grafana or GitHub plans.

The CloudFront flat-rate preflight is an explicit cost gate. It verifies that
the AWS account is eligible, including its account-level AWS Free Tier state,
that at least two of the account's maximum three Free-plan slots are available,
and that no conflicting subscription exists.
Phase 1 consumes two Free subscriptions: one per product distribution. Each
subscription binds exactly one distribution and its dedicated, non-shared AWS
WAF web ACL; Route 53 is not attached because DNS remains in Cloudflare.

As of this design date, the pinned AWS provider does not yet expose a Pricing
Plan Manager subscription resource. OpenTofu therefore creates the
distribution and WAF, then a separate manual, idempotent reconciliation step
uses the AWS Pricing Plan Manager API in `us-east-1` to create only an exact
`FREE` subscription before DNS cutover. It first lists and reads existing
subscriptions, records the returned ARN/ETag as redacted deployment evidence,
and refuses any paid tier, replacement, cancellation or ambiguous association.
This is not an OpenTofu `local-exec` provisioner. Every later plan checks for
drift, and the contract is migrated into provider state when a supported
resource becomes available.

If eligibility, quota or activation cannot be proven, the distribution remains
without production DNS and rollout stops. It never silently falls back to
pay-as-you-go or upgrades to Pro.

AWS Budgets is treated as a delayed control, not a guaranteed bank-style hard
cap. Service-level quotas and deny policies remain the primary containment.

## 10. Plan and apply protocol

### 10.1 Validation

Every change runs:

- format and validate against pinned OpenTofu/provider versions;
- provider lock checksum verification;
- Ansible lint/syntax/check-mode contracts;
- OPA/Conftest policies for forbidden resources, tags and retention;
- a custom cost manifest containing min/base/max monthly impact;
- secret and private-key scans;
- changed-stack ownership checks.

No external Infracost account or token is required.

### 10.2 Plan

The plan workflow writes an artifact containing:

- binary plan;
- human-readable redacted plan;
- source and dependency SHAs;
- backend key and workspace;
- provider lock digest;
- policy results;
- cost manifest;
- expiration time;
- aggregate SHA-256 manifest.

Plans containing secret values, destructive replacements, protected-resource
deletion or an estimated total above USD 15 fail and are not publishable.

### 10.3 Apply

A separate manual workflow receives the plan-run ID and manifest digest. It:

1. downloads the exact artifact;
2. rejects expiration or any SHA/dependency/backend drift;
3. reacquires the state lock;
4. displays the planned resource counts and cost impact;
5. applies the binary plan without replanning;
6. runs read-only health and policy checks;
7. records redacted evidence.

There is no apply-on-merge. Product deployments use independent manual
promotion workflows and cannot invoke shared OpenTofu apply implicitly.

## 11. Backup and disaster recovery

- Hostinger's included weekly backup remains the base full-host recovery path.
- A manual Hostinger snapshot is required within 24 hours before SSH/firewall,
  filesystem or major runtime changes.
- InfluxDB receives daily consistent S3 backups with 7 daily, 4 weekly and 3
  monthly retention.
- DynamoDB PITR is enabled for 35 days.
- State bucket versioning and KMS protect infrastructure recovery.
- Multi-region replication and a warm standby are out of scope for phase 1.
- The InfluxDB RPO is 24 hours; the initial RTO is best effort and measured by
  quarterly restore drills.
- Offline root CA restoration and leaf-certificate revocation/rotation are
  exercised annually.

## 12. Observability and SLO governance

Shared alert routing is email-only initially. The platform tracks:

- static availability target 99.9%;
- API availability target 99.5%;
- scheduled/queued job success target 99%;
- routine API p95 below two seconds;
- routine deploy interruption no longer than 60 seconds.

Four synthetic checks run every five minutes from two probes: two static sites
and two API health endpoints. Grafana Cloud Free receives VPS telemetry;
CloudWatch receives AWS service alarms; Cloudflare supplies tunnel alerts. No
paid paging or observability plan is enabled.

## 13. Rollout and dependency order

```text
Bootstrap state/OIDC/KMS
  -> shared budgets/SSM/Roles Anywhere
  -> edge tunnel/Access/DNS scaffold
  -> VPS Stage A and platform roles
  -> VPS Stage B closure
  -> LimnoPulse infrastructure and deployment
  -> CnesData infrastructure and deployment
  -> restore, cost-freeze and disaster-recovery drills
```

LimnoPulse is first because it validates the common VPS, Tunnel, deployment,
observability and backup paths with fewer managed processing dependencies.

## 14. Failure and recovery rules

- No workflow has an infrastructure destroy entry point.
- `prevent_destroy` or equivalent policy protects state, KMS, audit, backup and
  production data resources.
- A failed apply stops and requires a fresh plan; it never retries a partial
  plan blindly.
- A stale S3 state lock is force-unlocked only by a human following the runbook.
- Cost freeze blocks new compute/query actions but not health, readback or
  backup writes.
- DNS cutover occurs only after origin/tunnel health succeeds and has a
  documented prior-value rollback.
- Secret rotation keeps an overlap window and verifies both new and revoked
  credentials.
- Destructive recovery always requires a separately reviewed operation and
  current restore-point evidence.

## 15. Acceptance criteria

- The repository is private and contains no municipal inventory or secret.
- All reusable automation is pinned to an immutable `infra-ansible` commit.
- OpenTofu state is remote, encrypted, versioned and natively locked in S3.
- GitHub Actions uses OIDC and has paid spending fixed at USD 0.
- Plan and apply are separate, manually joined by an exact expiring manifest.
- Product and shared IAM/resource ownership cannot overlap.
- Cloudflare, AWS and VPS deployment secrets originate from SSM or
  Roles Anywhere, never Infisical.
- Cost-policy tests reject every forbidden high-cost service.
- The budget action is tested without denying backup writes or human
  break-glass access.
- No production DNS record is changed before its target passes health checks.
- Two exact CloudFront `FREE` subscriptions are `ACTIVE`, each with its own
  distribution and CloudFront-scoped WAF, before static DNS cutover.
- Restore, SSH recovery, credential rotation and cost-freeze runbooks are
  executable and contain no secret values.

## 16. References

- `infra-ansible` personal VPS platform design:
  `2026-08-29-personal-vps-platform-and-cd-design.md`
- OpenTofu S3 backend and native locking:
  <https://opentofu.org/docs/language/settings/backends/s3/>
- AWS GitHub OIDC guidance:
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html>
- AWS Systems Manager Parameter Store:
  <https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html>
- AWS Budgets actions:
  <https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-controls.html>
- CloudFront flat-rate plan quotas and eligibility:
  <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/flat-rate-pricing-plan.html>
- AWS Pricing Plan Manager API:
  <https://docs.aws.amazon.com/PricingPlanManager/latest/UserGuide/getting-started-pricingplanmanager-api.html>
- AWS provider Pricing Plan Manager support tracker:
  <https://github.com/hashicorp/terraform-provider-aws/issues/49232>
