# Continuous application lifecycle

This extension implements the shared boundaries authorized by infra-ansible#55,
comment 6755178450. It retains the original S3 CAS lease and the initial delivery
contracts. Activation is disabled by default. F2/F3 and exact historical reads
were ratified by #55 comment 6764564072. The nominal #499 v4 amendment was
ratified by #55 comment 6766483975 and CnesData#499 comment 6766483462. Product
mode providers and integrated consumer proofs remain pending; this document is not a production activation
receipt.

## Ownership and time

A single application keeper owns `Lease.acquire/checkpoint/renew/release`. It
retains owner, source, run, attempt and persisted generation through prepare,
B, host/API, static, unit, C-recovery, C-audit and terminal publication. Delegates
only read the original lease, including after legitimate renewal changes its
ETag. Expiry, changed owner, cancelled jobs or ambiguous effects do not permit
another writer to acquire.

Preparation precedes fence close and has its own fixed admission deadline.
Close fixes F once as the minimum of close+1800 and authenticated input
expiration. B consumes at most 360 seconds, API 180, static 180, unit 120,
C-recovery 240, C-audit 240 and final 60; the original 420-second recovery reserve
remains. API admission reserves the later 840 seconds. Recovery fixes
D_rec=min(F,choice_at+420), allowing 300 for convergence and120 for finalization.
A repeated stage/checkpoint does not reset admitted_at, stage deadline, F,
preparation deadline or recovery decision. Process admission reserves its full
timeout plus termination budget before spawning. SDK timeout is not permission
to continue past the original stage deadline.

The initial plan/apply guard still requires 1980 seconds. The host gate stays
pinned to `1a2a78898211317885b216c16f7a9ec585f98173`, with three frames and five
outputs. This extension adds no shared_outputs/v2 leaf.

## Plan and apply purposes

The existing eight-input/four-output infrastructure reusables also accept the
closed lifecycle purposes `application-prepare`, `phase-b`,
`phase-c-recovery`, `phase-c-audit` and `static-maintenance`. Those purposes
require the original authenticated immutable reusable and an explicit current
`application_purpose`. Promotion uses manual `promote-production.yml`; readiness
uses manual `readiness-production.yml`, both on main/production. Readiness
infra admission permits only application-prepare/mode-canary. Initial purposes
retain their initial manual callers and eight-input/four-output interface.

Plan captures real state identity and object version, generates a saved binary,
and publishes private bytes plus a sanitized public index. Deploy separately
requires the completed independent audit job, exact binary and JSON equality,
inputs/checkpoint commitments, source-bound IAM resolution and complete native
readback coverage before and after the apply. An unapproved plan is not deploy
authority. Full tracked OpenTofu source, including ASL and templates, must match
the immutable checkout and protected closure manifest; authenticating only IAM
`.tf` files is insufficient.

B initial may create the state machine and update only the corresponding API
policy. Established B only changes its definition. C initial admits the finite
mode-specific schedule/group/rules/alarms closure and its RunTask policy;
established C changes only that mode's target revision and policy. Other modes,
network, roles, counts, deadlines and task definitions remain invariants.

Convergence updates restore the original revision/policy fields. Deletion is
available only for resources absent originally and exactly proven created by
this owner. B inversion is separate from C and requires the original unit
restoration decision. Group deletion requires every ListSchedules page and
exact known membership. DELETING, pagination ambiguity, foreign schedules or
missing native readbacks retain uncertainty.

The identity policy bounds product ARNs. The existing managed session policy
preserves state restrictions. Lifecycle inline sessions explicitly deny lease
writes and all inverse deletes during advance; converge exempts only the exact
audited delete ARNs. The aggregate inline+managed ARN 2048-character bound is
checked, with no wildcard fallback. Evidence writes remain confined to the
current step. KMS permissions do not grant S3 writes into another step.

## Protected application role

`application_promotion` is null by default. Enabled configuration creates one
shared role using the existing GitHub provider, exact reusable SHA and production
subject, an expiration, exact lease/evidence/KMS scopes and deterministic
product-role delegation. It has no state read/write, static bucket, CloudFront
or tenant capability. IAM grants and the sensitive private fragment are
rendered and evaluated natively. Product owns observer/normal/recovery static
roles and their policies; the shared role never receives those policies.

The only current private application fragment is version 4. It contains
account/region, application identity, immutable producer/closure, the exact
`caller_by_purpose` map, provider, lease/evidence, ten deterministic delegation
ARNs, trust/policy commitments and expiration. Versions 1/2/3 and singular
`caller` are rejected; historical evidence retains its own original bytes and
protocol. This fragment remains separate from shared_outputs/v2.

Delivery trail (amendment infra-ansible#55/6993274712). The CnesData `production` environment admits only
`main`, so every caller binding in `caller_by_purpose` carries `ref` `refs/heads/main`, and every gate, the
source admission and the containment checks assert `main` (run `head_branch`, `GITHUB_REF`, the OIDC `ref`
claim, `compare/<source>...main`, `runs?branch=main`). The CnesData static-promotion validation of
`caller_by_purpose` and `producer.workflow_sha == binding.shared_source_sha` must agree with this fragment,
so both change in one hand-off (CnesData R3). The pinned `static-promotion.tf` below is a snapshot of
CnesData `main` `258e55c58ea9109c4c4a35fc519ab9292027a4b0` (release-by-tree CnesData#532, tree equal to
develop `6a235cef091089c5b237c9625c9fad08fc795473`); it validates `main` and is never edited here. The `source-develop-checks` name in `provenance.BASE_CHECKS` is a check
name emitted by CnesData evidence and is renamed only together with the CnesData emitter.

OIDC subject. CnesData uses GitHub's default `sub` template. Each delivery trust therefore matches the
default `sub` (`repo:VINIClUS/CnesData:environment:production` for the jobs with an environment,
`repo:VINIClUS/CnesData:ref:refs/heads/main` for the host gate, which declares none) and a separate
`token.actions.githubusercontent.com:job_workflow_ref` `StringEquals` condition with the reusable at its
sha. The runners compare the same two claims before asking STS; the host gate gained the `job_workflow_ref`
comparison because the sha used to live only inside its `sub`.

The raw enabled Terraform input has exactly five required fields
`role_name/workflow_sha/source_closure_sha256/enabled_until/delegations` and only
optional `predecessor_read`. Raw shape is validated before Terraform can discard
extra object fields; the protected `application_configuration` is also validated
by the consumer. Absent/null selector produces no `predecessor_reads` output.
A selected history requires that non-null field and its exact eight fields.
Selector and protected full reference must appear together; parser and public
admission use the same closed reference validator, including exact integer types.

The producer `source_closure_sha256` (#55 second-slice amendment 6886977054, decision 1)
is `sha256(canonical({"files": {path: sha256(bytes)}}))` over the 19 PYBOOT files
(`tools/cnesdata_delivery/*`, including `runtime-requirements.txt`) plus
`.github/workflows/reusable-cnesdata-application-gate.yml`, all read at
`gate_shas.application`, never at `workflow_sha`, which inside a reusable can be the
caller's SHA. `application_gate closure --pin <sha>` prints it from a checkout with
`git cat-file`, before and without admission. Right after admission, `preflight`,
`credentials` and `execute` recompute it from the executing files and from the reusable
read through the contents API at the pin (blob SHA-1 checked), and refuse any
difference with `application producer closure`. A governance still carrying the 64-zero
sentinel therefore refuses there; the explicit sentinel refusal in `session_owner` and
`variables.tf` lands only with the final wiring PR, so the `cnesdata-delivery` plan keeps
working until the private tfvars switches to the value computed on that PR's head.
The legacy planned/applied or lifecycle terminal inventory is derived from the
original source/run/attempt/status/purpose, never the current application purpose.
The parser independently derives the original GetObject/Decrypt policy and checks
its digest as well as the ordered ARN inventory. There are no free keys,
ListBucket, version reads, history writes or state access.

The no-history output is a catalog shape, not an admission exception. Application
preflight requires the protected full predecessor reference before STS; the
Keeper still authenticates its original private bytes before acquiring. Readiness
requires an original successful lifecycle terminal. No missing-key or empty-list
observation is treated as proof of historical absence.

The application managed session policy is unattached and independently pinned
and read back by the original owner protocol. It supplies existing static
coordination/IAM/delegation permissions and only the selected predecessor reads.
Inline permissions supply this run's evidence and the current output step.
Keeper sessions deny all product role assumption; operation sessions deny lease
writes, historical reads and assumption outside their approved exact role/session
pairs. The shared ceiling contains the six original roles plus mode_seed,
mode_dispatch, mode_audit_launch and mode_observe; product provisioning remains
owned by the product prepare flow. Fourteen closed `mc-<code>-<digest40>`
algorithms match the ratified canonical vectors. Readiness operation sessions
exclude static/fence roles, promotion codes and manual audit launch. Session
names are protected dispatcher outputs after context/preparation validation;
this policy builder and its offline IAM evaluations are not preparation receipts.
The `close-drain` and `closed-ready` operation sessions are minted in process by the keeper (R20, PR-G).

The application consumer parses the exact private v4 fragment from protected
governance. Its original owner `policy-evaluation` measurement must commit
`application_fragment_sha256`; the complete fragment is never placed in a public
artifact. Account, region, immutable producer/closure, caller, provider, exact
coordination/evidence loci, ten delegation ARNs and historical inventory must
agree with the protected catalog. IAM readbacks verify the original trust and
inline policy bytes, no attached policy or boundary, and the independently
pinned managed session policy. Repeated identity/policy reads reject replacement
or drift. These checks require a bounded guard and full session expiry/freeze.

Source admission measures the caller workflow bytes at the original product SHA
against the protected closure, checks its exact reusable invocation and the
current GitHub job/step, and validates the purpose/context bijection. OIDC claims
must agree on caller workflow_ref/workflow_sha, source, event, environment and
run/attempt before STS. IAM continues binding the reusable subject; it does not
pretend to constrain caller path. Infrastructure lifecycle credentials also
require the original application owner proof/fragment before their own exchange.
The current descriptor adds application_purpose and caller_binding_sha256;
protected governance carries context_kind, the product source manifest/closure
and exact producer_job/job_name/admission_steps for each lifecycle step.

Adapter source preflight verifies the fixed
`scripts/promotion/promote_api.py` entry against a protected canonical manifest
of the entire tracked product tree. Each checkout file must match its original
Git blob and digest. Missing helpers, symlinks, dirty, ignored or untracked
files fail closed, including files that could shadow imports. Preflight does
not import or execute the adapter. The execution context and dispatcher still
need integration; source authentication alone is not a domain success proof.

## Evidence boundaries and historical entry

Completed producer jobs are authenticated by source, run/attempt, job identity,
artifact name, digest, creation interval and original archive bytes. Private
indexes bind owner/generation, application_purpose/context_kind/caller_binding_sha256
and exact step; caller-selected URLs, keys and
commands are not an interface.

The predecessor before the first lifecycle plan belongs to its original run.
The keeper authenticates the original successful publication with
`runtime.previous_success`, then acquires once and commits its historical
checkpoint digest and the immutable digest of the protected historical
reference. The current caller fields travel atomically through the lease,
checkpoint and publication and cannot change between checkpoints. Historical
records keep their old shape; a current caller-bound request cannot consume an
index that omits that binding. The Keeper does not read state or relabel
historical bytes as current-run.
The protected `historical_entry` plan step authenticates the original public
receipt and completed job before credentials, reads only the exact historical
checkpoint, and compares actual state identity/object with it. The original
bytes travel in the saved plan; deploy receives no historical read grant.
Later checkpoints are current-run and historical entry cannot be reused after
sequence 0. Missing source, job, generation, bytes or original state proof fails
closed. Offline entry tests do not claim an enabled production path.

## Terminal requirement

Unit/CLOSED is intermediate and never releases the keeper. Acceptance requires
OPEN observed, all three activation revisions accepted by their own canaries,
strong route readbacks, clean state and complete delegate/process/AWS
quiescence. A failed CLOSED recovery can release only after the ratified
restoration and quiescence proofs within the original deadline. Its receipt
preserves promotion failure; a successful publication job does not make the
failed run automatically reacquirable. Unknown retains HELD.

The terminal bundle contains the original assessment, state checkpoint and full
CAS journal. Verification follows the ETag chain rather than sorting timestamps,
which may tie. The final checkpoint, owner/generation, deadline, input commitments
and release must agree. Publication uses a released-owner guard that cannot
renew or mutate the product. Three exact private objects are read back before
publishing the public `lifecycle-terminal` index. A subsequent acquisition
authenticates the completed successful original run, approved reusable, exact
keeper job/attempt and all bytes. Failed or cancelled runs and failed terminal
results require reviewed recovery; they are not automatically reacquired.

First static publication without a previous pair may leave public residual
objects on a failed, CLOSED, quiescent outcome; it does not claim rollback of a
nonexistent pair or successful promotion. Maintenance occurs in a later manual
run after authenticated accepted-open, without extending promotion F.

## Integration state at X*

This section records the delivery contract as it stands at X*, the merge commit of P20. The
sha256 of this document is the `contract_sha256` that governance pins; no closure file changes
after X*. Each item below merged to `main` with RED-first tests and an independent audit.

Implemented on `main`:
- Readbacks per stage with identity-derived parameters (G4, P05), the drift catalog and the G5
  envelope (P06), the Phase A G3 handoff, `public_safe` and envelope (P07), and the per-cycle
  G6 HMAC with the authenticated cost source.
- The product source manifest from an authenticated artifact (P10), with `source_closure` and
  `lifecycle_steps` hydrated from it (P37); the independent lifecycle audit and
  `approval.json` (P11); the lifecycle catalog, the absence proof and the specified callers
  (P12).
- Plan and deploy reusables with a single `execute` job each: `validate` is folded into
  `execute` (P34), and pre-approved jobs wait for their stage without a credential (P35).
- The keeper: the API stage with closed-ready and the host handoff (P14); the static stage
  with its broker, STS session and publish-static (P15) and its authenticated inputs (P15b);
  governed stage windows and the fixed deadline (P36); the mode-canary oracle and the `unit`,
  `phase-c-recovery` and `phase-c-audit` stages (P16); the mode broker, mode sessions,
  ModeReadback and the phase-c element (P16b); terminal, restoration, reopen,
  terminal-readback and release (P17).
- Producers: proof, observer, cost, `phase_a_graph` and the owner CLI (P18); the application
  governance producers (P19); the observer, phase-inputs writer and audit roles (P22); the
  in-job rehearsal plan with bucket-key state decryption (P21b); read-only calibration and
  the governance size measurement (P21); the recovery runbook, HMAC custody and drills (P32).
- Formal models checked in CI: lease and terminal (F1), keeper stages (F2), X*/K pins and
  trusts (F3), and stage windows with pre-approved jobs (F4).

Unit-start open (P16b follow-up, #118). unit-start has no gate left in the mode broker or in
the stage capability; it gets the same refusals as the other effects. Its sequence is:
- The plan reads the single ECS cluster of the state machine definition in the unit-start
  readbacks and requires it to equal the prepared `cluster_arn`, before the seed check and
  before any STS. A service ARN, a missing cluster, two clusters or an invalid definition
  refuse with `mode unit cluster`.
- `ux` reserves, admits, claims and starts the execution. `uw` polls DescribeExecution to a
  terminal status, then calls DescribeTasks only when the execution names task ARNs, then
  reads each RUNUNIT item of the unit run in order with a strongly consistent GetItem. C1
  admits on `uw` only the exact DescribeExecution, the expected DescribeTasks whose `cluster`
  equals the prepared `cluster_arn`, and the next exact RUNUNIT read; on `ux` it admits no
  describe call. The `uw` session policy grants GetItem only with LeadingKeys equal to the
  partition key of the owner's unit run.
- `dispatch_unit` returns `{execution, tasks, failures, outputs}`. The execution keeps
  `executionArn`, `stateMachineArn`, `name`, `status`, `input` and, when present, `output`;
  the dates are dropped. Tasks and failures are bounded projections. The outputs come from
  the product `unit_outputs`. If the product refuses the RUNUNIT items, the operation fails
  with `mode_unit_outputs=refused`: the lease stays held, the receipts already written stay
  durable and no mode-result is written.
- The reply is kept in its own slot, apart from the recovery and audit `described`. The
  `unit-execution`, `unit-task` and `unit-output` step receipts must equal the slot element
  at the same position, in child order.
- unit-observe's `observed` input is derived by the keeper from this lease's single
  unit-start journal, which must be neither failed nor unknown: the one `unit-execution` and
  the `unit-task` and `unit-output` receipts in journal order, as the product's three-field
  `observed`. The origin re-checks the readback cluster against the prepared `cluster_arn`,
  the third of the three cluster checks.

STS session capacity (P41, #117). Every session policy fits in 1998 characters, inline
document plus managed ARN. The changes are:
- Operation sessions of the application role (every non-keeper session) carry the managed
  `<application role>-ops-session` policy. It allows the IAM role and policy reads, a
  read-only GetObject of the lease and the state-key KMS calls under the state bucket
  encryption context, and it denies every IAM policy mutation. Keeper sessions keep the
  application managed policy.
- Delegation is an Allow of `sts:AssumeRole` per alias, on the exact governed product role and
  with `sts:RoleSessionName` equal to that alias's exact session name. The keeper session
  denies `sts:AssumeRole`.
- The managed `delivery_session` policy of the plan, deploy and audit roles reads the lease and
  never writes it. Among those roles' sessions, the only lease Put left is in the legacy plan
  and deploy build/request sessions, on the exact lease key. The keeper's application managed
  policy still grants the lease Put.
- The inverse deletion inventory is bounded by the largest scheduler closure of the recovery
  and audit modes instead of a fixed count, and each ARN is at most 104 characters.
- The activation read uses the managed `<plan role>-activation-session` policy, and each
  activation object key is at most 273 bytes (N=273).
- The managed plan and audit session policies carry a static Deny of the lifecycle deletions;
  the forward request adds that Deny only for deploy, and the inverse keeps its exact
  `NotResource` inventory.
- The ops and activation pins are paired with the role pin (same `observed_at`, `expires_at`,
  `frozen_until` and owner producer) and committed in the proof measurement. They are applied
  together with the managed documents in apply #1, and until then authentication fails closed.
  Application authentication refuses with `original owner session pin absent` when the ops pin
  is missing, and with `original owner application_ops session policy commitment` when the pin
  does not match its measured fact or its pairing. Plan authentication applies the same two
  refusals to the `plan_activation` pin when governance has `activation_read`. Without
  `activation_read` the plan authority has no activation pin, and an activation read refuses
  with `activation session pin absent`.

Real terminal brokers (P17b, #119). `terminal_capability` connects reopen, terminal-readback
and rollback-api-static to production brokers. A refusal fails the journal and the lease stays
held. The changes are:
- reopen and terminal-readback run on the fence session of the authenticated PreparedFence.
  Before STS the capability recomputes the scope from the prepared policy, binds the prepared
  activation, the `fence_operator` delegation and the current owner, and evaluates the
  operation session's effective IAM locally.
- terminal-readback (FenceReadBroker) reads FENCE and SEMAPHORE strongly and probes, with
  `METADATA_ONLY`, only the `execution_ref` of a TERMINAL member of the frozen close-drain
  membership. Its `membership` input must be that frozen set, or the empty set before the close.
- reopen (ClosedReadyBroker) is pinned to the P17c call vector. At `final` it makes one CAS
  UpdateItem of the owner's fence, CLOSED to OPEN at version + 1, after a strong FENCE read,
  under a session policy that grants the strong reads and UpdateItem on FENCE only. At
  `recovery` it only reads and the CAS is refused. Its four inputs are `activation`, `routing`,
  `canaries` and `membership`; at `recovery`, `routing` is the recovery routes and `canaries`
  is null.
- rollback-api-static runs in StaticBroker under the existing static `recovery` alias, session
  `sp-rollback-<digest40>`, in the `recovery` stage. Before STS it checks that the static plan
  is the one the keeper holds, binds the run against the operational carrier and reads the
  recovery role facts of the operational deploy. Its calls are a CopyObject of each planned
  rollback key and version (SHA256 checksum, metadata copied) and the plan invalidation. The
  session policy grants GetObjectVersion and PutObject on the rollback keys only, plus the
  invalidation, and its effective IAM is checked under the copy-source and creation
  conditions of the #498 policy (the IAM evaluator gains `Bool`).
- At `final`, the terminal input source serves reopen's `routing` as the closed projection of
  the three mode routes of the authenticated phase-c-audit element, which the C deploy job read
  back after apply (ruling 1g). Every other request still refuses with
  `terminal_inputs=source_unconnected`.
- When a prepare fails before the PreparedFence exists, the fence capability refuses with
  `terminal_broker=prepared_absent` before STS; the journal fails and the lease stays held.
- The production `operation_session` of `execute` admits reopen, terminal-readback and
  rollback-api-static.

Mode operation sessions (P16f, #120). The production `operation_session` of `execute` also
admits the eight promotion mode operations of `MODE_SESSION_OPERATIONS`: `unit-seed`,
`unit-start`, `unit-observe`, `recovery-seed`, `recovery-start`, `recovery-observe`,
`audit-start` and `audit-observe`.
- The delegation is chosen by `role_arn`. When the role is the governed delegation of the
  operation's mode alias (`mode_seed`, `mode_dispatch`, `mode_audit_launch` or
  `mode_observe`), the session delegates to that alias with the role's exact
  `mc-<code>-<digest40>` session name, which is the restriction the mode broker evaluates.
- Any other role takes the fence path with `fence_operator`, which is accepted only for the
  three mode observes. A mode effect under another role is refused with
  `operation session delegation`.
- The readiness-drill operations (`drill-*`) stay refused with `operation session operation`.

Plan inputs (P40, #115). The keeper publishes each plan's `inputs.json` as a private payload
with a public index. The changes are:
- Composition. The base is the governed `product_inputs` plus the six original Phase A inputs,
  and the reserved keys `static_promotion` and `mode_canary` are always explicit; the bytes are
  at most 131072. The observer-bootstrap plan carries the `observer-bootstrap` static_promotion
  (no plan, no inventory, empty lists, `static_plan_sha256` null) and a null `mode_canary`.
  The operational plan carries the `operational` static_promotion built from the static plan
  and the inventory, and the `mode_canary` object relayed from the static-inventory job
  artifact. Both bind the authenticated candidate, the owner and the application gate pin, with
  the window of the original application fragment. Every other plan carries only the base.
  `static_plan_sha256` is null only in observer-bootstrap mode, and the carrier binding refuses
  any other pairing.
- Storage. The keeper session writes `<run>/plan-inputs-<plan step>/inputs.json`, reads it back
  and then uploads the public index artifact `cnesdata-plan-inputs-<plan step>-<run>-<attempt>`.
  The keeper session policy adds one bounded PutObject resource, `<run>/plan-inputs-*/inputs.json`,
  whatever the number of plans. Plan step names must not start with `plan-inputs-` and must fit
  in 64 characters with that prefix, lifecycle and application sessions refuse a reserved step,
  and the evidence prefix is at most 32 characters. Every session document fits in 2048
  characters at the governed maxima, so none is refused there.
- Publication. Before any write the publisher checks the six Phase A inputs against custody and
  requires the consuming plan job to be `in_progress`. The plan that opens a stage publishes
  before the stage-open marker. The operational inputs publish after the inventory upload, only
  once the static-inventory probe completed with success and the operational plan job is
  `in_progress`. That wait is guarded, polls one jobs listing every 5 s and refuses at the
  preparation deadline minus `P40_PUBLISH_RESERVE_SECONDS` (100 s), with
  `operational_inputs=static_inventory_failed`, `static_inventory_timeout` or
  `consumer_not_started`.
- Reading. The plan gate adds the keeper `inputs.json` to its private payload and refuses any
  other source of that name. The reader requires its own job `in_progress`, the unique artifact
  created after that job started, matching metadata and digest, the private index of step
  `plan-inputs-<plan step>` with the lease owner and generation, and `inputs.json` as the only
  member. The P35 wait checks the artifact's presence in its same conditional listing.
- REST budget. The model adds 55 point reads and the wait's polling. The governed worst rolling
  hour is about 2530 of 3000 requests at the measured hit rates and 3727 of 4500 without the
  jobs credit (60 and 90 percent of the assumed 5000 per hour).
- Checkpoint origins. The deploy checkpoint gains `previous_checkpoint_sha256`, equal to the
  approval's `checkpoint_sha256`. `bootstrap_hop` admits a one-hop chain: the checkpoint of this
  run's observer-bootstrap deploy, or of the same-chain operational plan that republishes it,
  linked to the window checkpoint. A step that reads the checkpoint of a same-chain
  historical-entry plan uses the historical Phase A checks.

Mode preparation has an isolated eight-address structural gate and an
exclusive `runtime-iam/mode-canary.tf` source resolver, including all four inline
policies on no-op plans. Its native closed-Deny fixture proves source grammar
and address binding only. A finite internal IAM reader compares two identical
GetRole/GetRolePolicy observations, at least ten seconds apart, within the
original preparation deadline and under the existing lease guard. It reports
`iam-readback-and-evaluation`, never propagation.

The adopted context wrapper is the exact object `{canonical_utf8, sha256}`.
Its digest commits the inner product-canonical UTF-8 bytes with one trailing LF,
not the wrapper. The complete generated request remains bounded to 131072 bytes.
Semantic validation checks all fifteen manifest fields against the protected
originals and current owner/purpose, preserves the original predecessor and
1200-second promotion or 14400-second readiness context deadline, and derives
the exact eight promotion or six readiness sessions. The fourteen session
algorithms retain their separate ASCII canonical codec. This pure validator
does not authenticate its producer arguments or authorize STS/apply.

Commitments that are not authenticated:
- `scenario_plan_sha256` in the mode-canary record (`MODE_PRODUCT_COMMITTED`) is a
  product-bound commitment. No producer emits it under authentication and no consumer checks
  it against other bytes; it proves nothing beyond the product's own record.
- `rehearsal_plan_sha256` in the `drift-baseline` measurement is the identity of the plan the
  observer generates inside its own job (P21b). That plan is never stored or uploaded, carries
  timestamps and cannot be reproduced; the gate checks only that the value is a sha256 digest
  (`drift_handoff`).

Window duties at a new X*:
- `CATALOG_SHA256` is computed from the drift catalog document, and P38 changed it (prefix
  `8d5b62af`). `drift_handoff` refuses a handoff with another `catalog_sha256`, so the
  rehearsal drift handoff must be regenerated at X*. The closure is recomputed too, because
  `drift_catalog` is part of `APPLICATION_PYBOOT`.
- P39 changed the `policy_sha256` outputs of the application role and of the delivery roles.
  Any governance record that holds the old digests must be regenerated from the outputs of
  apply #1 in the window.

No offline vector or local test is an operational acceptance receipt: acceptance comes only
from the authenticated runs of the window.


## Adapter boundary implementation checkpoint

ABI2 request/result codecs bind the complete original inputs, owner, checkpoint,
activation and stage. The shared journal preserves observation bytes and links
them to call receipts; a returned flag cannot erase pending/unknown or invent
registered observations. These checks establish transport integrity, not domain
acceptance.

The fixed adapter subprocess authenticates its complete Git closure before and
after invocation, receives no inherited AWS/GitHub credentials, uses bounded
canonical IPC, and terminates its process group on timeout/failure. An active
descendant group prevents acceptance. This is credential/transport isolation,
not an operating-system sandbox. Only the fixed promote_api entrypoint can run.
Read, guard, observe and a read-only `evidence_snapshot()` are implemented.
The getter takes no arguments and returns a canonical copy of only
`call_receipts_sha256`, `pending` and `unknown`. It performs no IO, samples no
clock, refreshes no guard and cannot clear poison or advance an ordinal. The
product must put those fields into its original result; shared never rewrites
the result. A stale snapshot, later call or omitted uncertainty fails validation.

The shared-only SDK journal can now retain bounded canonical intent/response
bytes, request ID/Date, monotonic samples, session commitments and original
owner/stage guard bindings. A pending native call prevents adapter completion;
timeout, invalid response or lost guard preserves pending/unknown and poisons
the context, including late responses. Credential fields and unfiltered
execution payload fields are rejected before retention. This is an in-memory
evidence component joined to the finite closed-ready broker: conditional private
intent publication and exact readback precede each native call, and response plus
receipt publication/readback precede its return.
The begin/complete/fail methods are not exposed through child IPC and confer no
SDK or STS permission.

A finite fence-role reader now compares eight guarded IAM reads in two rounds
separated by at least ten seconds inside the original preparation deadline.
It requires one exact inline policy, no attached policy or boundary, unchanged
RoleId and source/state document equality, retaining original SDK metadata.
Its expected documents still require an authenticated producer linking original
Phase A release/source to the current owner/caller/activation/checkpoint. The
reader alone is not a prepared-role authority and cannot open the broker.

F2 parameter validators admit only strong GetItem of the original prod FENCE/SEM
and exact frozen-member DescribeExecution with METADATA_ONLY. Unexpected
nonempty execution input/output is rejected before serialization; only identity,
status and timestamps survive response filtering. These validators do not yet
execute the original CLOSED-ready producer or prove fresh post-B admission.
The original API180/1440-second capacity rule, full static baseline F3,
terminal domain producers and application workflow wiring remain required.


## Inactive prepared-fence contract and durable evidence (V13)

The current authority is application_fragment schema4, with exact current
callers and ten aliases. Original Phase A bytes retain their historical form.
The fixed prepared observation producer is operational application-prepare
advance in deploy reusable job execute, step gate; logical caller target
application-prepare-operational / execute is not yet integrated in the product.
Publication must occur inside its running gate after successful apply/state/
readbacks; consumption requires that exact job and named steps completed-success.
`fence_prepared_payload` adds original archive/pin/step and public-index checks
before private reads, reusing lifecycle_artifact and private_payload. It does
not replace independently authenticated schema4 owner/source authority.

FENCE_PREPARE_FILES and FENCE_SCHEMAS define eight bounded private documents:
checkpoint, approval, prepared, role, readbacks, origins, chain and evaluation.
The public index contains their names/sizes/hashes only. The package validator
is a codec against independently protected originals, never provenance or a
capability. Outcome is observed only. Role projection is compared with original
Phase A while the full current state is bound to current checkpoint, same
lineage and admissible ancestry; historical full state may legitimately differ.

Current H4 provides original envelope/checkpoint/drift and authenticated saved-
plan/input/candidate commitments; it does not supply raw planned-prefix files.
The read-only observation does not require raw plan.bin/candidate bytes. Existing
SourceResolver still needs historical plan.json/configuration and generated
inputs absent from H4. The focal fence_current_role_projection helper now uses original evidence and
current-run original plan/inputs/state with an explicit no-op SourceResolver
projection, original release/principal/RoleId, exact source closure and protected
checkpoint ancestry. Current plan commitments remain separate from historical
plan_receipt; the helper is an inactive producer measurement, not provenance.
No historical grant is broadened. `current_checkpoint_chain` authenticates
completed same-run plan/deploy jobs, artifact ZIPs, public indexes and private
checkpoint/approval bytes. The first historical plan supplies the actual
acquisition predecessor under the existing same-run read scope. Schema3 anchors
that raw checkpoint, including an established terminal, and walks every applied
checkpoint without treating a reference hash or embedded Phase A as that anchor.
Package production and full capability consumption remain disconnected from the
runtime entry.

ClosedReadyEvidence adds conditional own-run/closed-ready intent, response and
receipt storage through existing AWS.put/readback. Stable keys bind original
owner/caller/checkpoint and an internal ordinal; native call parameters are in the
complete intent but excluded from the key. Internal intent/receipt schema2 adds
`sequence` and `previous_receipt_sha256` to the intent. Every process starts at
zero/null, and only the original shared journal can advance after both response
and receipt conditional writes and exact readbacks. The next intent commits the
previous durable receipt wrapper. Ordinals are bounded to 0..8191; memory-only
completion, a changed call/order/proof/session or a restart cannot mint a ticket.
Persisted pending intent, crash or ambiguous outcome remains unknown; reentry
cannot mint another ticket or replay SDK. Complete receipts return historical
original bytes, not fresh readiness. The finite broker validates strong FENCE/SEM
reads and exact frozen-member metadata probes, then records real sanitized SDK
responses. Original-process repeated reads get distinct durable receipts; they
never reuse historical responses. Persistence failure poisons the context even
after in-memory SDK completion. The keeper polling/uncertainty connection remains
unfinished. Native shared IAM composition and a separately labelled synthetic
fence/freeze fixture exercise readonly isolation; legacy source without SFN remains denial. The integrated #500 source was also
compiled with the real resolver; that is code evidence only, with applied proof
and exact live IAM readback still required. Strong reads, METADATA_ONLY and frozen membership remain
SDK guard obligations, never invented IAM condition keys.

The application CLI now connects `credentials` to an own-role bootstrap after
public admission, complete product source authentication and the original
session-owner proof. It verifies native role/policy readbacks and exact
GetCallerIdentity before exporting masked credentials. Its session explicitly
denies every product AssumeRole; the operation session is a separate in-process exchange (R20, PR-G).
`execute` was closed in the first slice. The fixture subprocess exercises the
original sequence FENCE/SEM/FENCE/SEM/probe/FENCE/SEM through the real broker and
validators with external SDK/S3 fakes. This is boundary evidence, not an integrated
product adapter or completed application lifecycle.

Phase A custody uses the adopted version1 carrier containing exactly the original
checkpoint, drift and envelope bytes, their full legacy origin and hashes. Raw
files and their aggregate are bounded to 131072 bytes; the canonical carrier to
196608. The keeper conditionally publishes the version2 wrapper at its existing
`keeper/checkpoint.json` locus, and terminal checkpoints use version2 with the
same carrier and a 262144-byte cap checked before release. Established acquisition
uses the current predecessor provenance; old embedded timestamps stay historical.

## Plan activation read ceiling

`github_delivery.activation_read` is optional and null by default; null renders
byte-identical identity and managed documents for every role. When set, only the
plan identity and plan managed policy gain key-scoped GetObjectVersion and
GetObjectRetention on the three exact objects, the three bucket readbacks on the
exact bucket, and Decrypt/GenerateDataKey on the exact cipher key bound to
ViaService and the three object contexts. The prefix-scoped version/retention
Deny becomes a global NotResource Deny excluding only those objects, plus a
NotAction Deny on them; deploy and application receive nothing. Version-exact
access still comes only from the ephemeral sessions of `activation_request`.
Native tests prove the default documents are unchanged, no version or
retention Allow exists outside the keys, and the session intersections. The
plan identity reads its own role only if the governed `read_resource_arns` list
its ARN; no grant was added for this. The operator must list the plan role ARN
in the protected `read_resource_arns` (the only accepted path); an own-role
statement in the identity policy was declined as a widening.

Not yet proven: see "Merge scope and not-yet-proven" below.

## Operational inputs carrier (version 2)

`lifecycle_contract.inputs_envelope` decodes the closed version2 `inputs.json` of the
operational preparation plan: original owner, original preparation window, Terraform bytes
and the original EXT2 activation members, each with strict base64 and size/hash. The
deploy of `application-prepare` / `operational` has no bare-JSON fallback: it unwraps the
carrier, confronts the three object references with the protected `activation_read`
ceiling, passes only the Terraform bytes to the var-file. `activation_sha256` is the sha256 of the
raw signed payload bytes, equal to `activation.payload.sha256` and to the product's
Phase B comparison over the activation bytes; the hash of the whole `activation` object is
`activation_carrier_sha256`, internal only. The audit still commits the whole envelope.
The plan side produces the carrier (amendment 2026-11-13 item 9): the step carries a closed
`activation_selection` (`selection_version` 1 and the ten-field EXT2 reference); the profile is
the single `ext2.history` row whose reference is equal, and its bucket, cipher key and three keys
must equal the `activation_read` ceiling. The plan authenticates the public reference, opens a
receipt-only session, reads the receipt, opens a session with the three version pairs, runs the
complete historical `verify_ext2_reference` (the EXT2 gate configuration/invocation is never
called) and renders `render_ext2` only from that real `VerifiedActivation`. Each session policy
is measured before STS; 2049 encoded characters or more refuse. An operational plan step without
`activation_selection` still refuses before any AWS access. The deploy revalidates the profile
hash, the governed SPKI and the signature locally, without any EXT2 read, and still refuses
every bare `inputs.json`.

## EXT-3 API credential contract (slice 2A)

CnesData#473 amendment-5 moves the `central_api` credential to a `credential_process`
JSON file published by the EXT-3 host gate, without restarting the container. The host
side (infra-ansible#55 slice 2A) is in `tools/cnesdata_delivery/host_gate.py`:

- The root renewer publishes `aws-credentials.json` (v1, `Version` and `Expiration`)
  into `/run/personal-platform/credentials/cnesdata/current` (file root:10001 0440,
  directory root:10001 0710, parents root 0700). It renews with 1800 s or less left,
  from a 300-second timer, with the RA session fixed at 3600 s, and refuses a generation
  with less than 3300 s of life.
- The API container binds that directory read-only at `/run/credentials`. Its image owns
  the AWS profile; `validate_compose` refuses any `AWS_*` in the compose environment.
- No `docker restart`, fixed `container_id`, `health_url` or `readiness_sha256` remains
  in the cnesdata renewal.
- Adoption is proven one cycle behind from the container's JSON stdout event
  `aws_credentials_refreshed key_fp=<sha256[:12]> previous_fp=<fp|none> pid=<n>`, in
  the same container (`Id`, `StartedAt`, `RestartCount`). Only the last adopted
  container or one the accepted release chain names (a rolled-back deploy also admits
  the release it restored) can adopt, even before the first adoption after boot. A new
  container also needs its boot line `previous_fp=none`. `credential_adoption=missing|container_replaced|container_restarted`
  fails the unit after the lease is released; publication continues.
- The CRL `trust_deadline` in the host governance raises `credential_trust=expiring`
  seven days ahead.

The exact host behaviour, margins and the worst case of the host-wide lease against a
deploy are in [the host gate contract](cnesdata-delivery-host-gate.md). Production
acceptance needs two consecutive rotations adopted by the same container with no restart,
plus the negative test with the timer stopped closing in the mandatory window. Issuing and
renewing the host's RA leaf certificate is not automated anywhere yet.

## Merge scope and not-yet-proven

Controller amendment of 2026-11-13 (issue #55, item 11) lets this PR merge as disabled code
with `Refs #55` (it does not close the issue). In scope: raw-payload `activation_sha256`,
the fail-closed operational plan, the mode-canary v2 record byte vector shared with the
product (schema `cnesdata.mode-canary/v2`, `MODECANARY` entity, sorted compact UTF-8 JSON
with one trailing LF, `record_sha256` over the payload text; no materializer), and this
document. `execute` remains refused for every operational purpose and mode.

Follow-up (controller PR after #56, `Refs #55`): effective fence scope and evaluation
documents, the `application_coordination_policy` sensitive output, the pinned
historical-source reader and the Phase A `source_closure_sha256` codec check, the producer
job_id check, the eight-file producer inside the operational deploy, the closed-ready
capability factory, the terminal-proof validator registry, the EXT2 transport in the plan,
and the keeper loop. All of it stays disabled by default.

Design decisions of the follow-up, for audit: the terminal validator registry also admits
`decision` and `restoration` (failure-path proofs) besides the eight kinds of the amendment;
capability ancestry is strictly direct preparation -> B -> API (longer chains refuse); the
membership input uses a minimal shared codec (`frozen_membership_sha256`, `members`); the
expected IAM readback bodies are the historical Phase A `get_role` bodies; the evaluation
`evidence_arn` is the closed-ready intent key with the prepared checkpoint and sequence 0.
The effective fence scope has one derivation, `fence_policy_scope`, used by the prepared
evaluation and recomputed by the closed-ready capability from the same projected policy
(item 2). Before STS, the capability rebuilds the evaluated `fence_session` with the single
constructor at the preparation deadline `min(observed_at + 180, frozen_until)` and requires its
digest to equal the evaluation's; the API session then differs from it only in `DateLessThan`
(item 3).

Keeper loop and execute were inactive by design in the first slice; PR-F of the second slice connects
them up to the API stage (section "Execute wiring to the API stage" below). Every guard check of a
journal or broker is a keeper tick, so a quiet adapter child still renews the lease. The code-constant
registries `TERMINAL_VALIDATORS` and `KEEPER_EVENT_SOURCE` are never read from governance, environment
or request. `run_closed_ready` and `closed_ready_capability` still have no production call site. Only
`Keeper.acquire` writes a lifecycle lease, so the operational plan and deploy (items 6 and 9)
refuse on the owner check before any EXT2 read, STS or apply.

Window and stage triggers (second slice, amendment 6886977054 decisions 2 and 3, `Refs #55`).
`lifecycle_contract.close_window` derives the close CAS from the bytes of the `close-drain`
observation in the keeper journal, never from caller JSON: the closed host schema of
`close-drain.json`, with the idle `permit` and `decision` the host requires; `input_deadline` is the earliest original `input_expirations` entry (closed
kind set, unique and sorted by kind and object); `close` is `close_confirmed_at`; and
F = `min(close + 1800, input_deadline)` must equal the observation's own `fixed_deadline`, the
equality the host requires. An infra-known authenticated expiration earlier than
`input_deadline` refuses and is never adopted. `application_gate.infra_expiration_bound` is that
bound, the closed set of errata 6887682424: the application owner proof `expires_at`, the
authenticated artifact retention in `api.expiries`, the authenticated fragment `enabled_until`
and the authenticated pin `frozen_until`. All four are mandatory; a missing one refuses. Phase B
is born with `admitted_at = close` and `deadline = min(F, close + 360)`; its capacity check then
holds only when F = close + 1800, so every product input expiration must clear close + 1800.
`api_window` admits the API stage when the keeper observes the completed B publication
(`admitted_at = now`, `deadline = min(F, now + 180)`), with the B checkpoint. The constants of
6755178450:140 are tests.

`STAGE_TRIGGERS` is closed to the ratified transitions: `application-prepare` waits for the
`prepared` event (job `FENCE_PREPARE_PRODUCER`); the close CAS enters `phase-b` with no external
event; `phase-b` waits for the `phase-b` event (the unique protected deploy step `phase-b` /
`advance`). `stage_event_source` reads the same-run jobs inventory and returns no event while the
producer job is absent, queued, running or completed without success. Otherwise it requires the
unique job with the catalogue name, completed/success, and the unique `lifecycle-<step>`
artifact created strictly inside its interval, authenticated by `lifecycle_artifact` with equal
step, `owner_sha256` and `generation`; anything else refuses. It refuses
`stage trigger not connected stage=<x>` for the API and every later or recovery stage, and
`stage deadline elapsed stage=<x>` at the stage deadline (`terminal_deadline`), so a failed
producer cannot keep the lease renewed past F. The closed-ready `_phase_b_publication` uses the
same reader. `KEEPER_EVENT_SOURCE = stage_event_source` and `keeper_loop` accepts exactly the
`prepared` and `phase-b` kinds (PR-F). No dispatch and no reusable input or output was added; the
transitions after the API need their own amendment naming each event source.

Close-drain capability, freeze and child loader (second slice PR-C, amendment 6886977054
decision 4 and queue items 3a and 3c, corrections 6906038586 and 6906181994, `Refs #55`).
The state machine is exactly `cnesdata-prod` (CnesData `step_functions.tf:13`): the closed-ready
validator, `fence_policy_scope` and the session constructors refuse any suffix. `close-drain`
takes `activation expirations`. `application_gate.close_expirations` builds the `expirations`
input at call time from the authenticated originals of errata 6887682424 only: `credential` is
the owner proof (sha256 of its authenticated bytes, `Authority.proof_sha256`), `artifact` is each
`api.expiries` entry with its authenticated digest without prefix, and `platform` is the fragment
`enabled_until` and the pin `frozen_until` with the sha256 of each canonical document. The list is
sorted and unique by kind and object; a duplicate pair refuses, and its minimum equals
`infra_expiration_bound`. The product adds `envelope`. The digest is retained by
`lifecycle_runtime.ArtifactDigests`, only in the application admission, from the same
authenticated download; an expiry without its digest refuses.

`validate_close_drain_call` pins the product call vector (CnesData 2c66f62c,
`tests/production/delivery/close_drain_call_vector.json`, sha256 44d0cf91...4b63, a literal of
the lifecycle fixture): each call, normalized to the vector form, must hash into
`CLOSE_DRAIN_TEMPLATES`. Derived for the audit: the close Update sets `:state` CLOSED, `:entity`
PROMOTIONFENCE and `:promotion` equal to the owner's `owner_sha256`; the SEMAPHORE ConditionCheck
is rebuilt from the latest strong SEMAPHORE read in the journal itself (`#vN = :vN` with the read
value for each named attribute present, `attribute_not_exists` otherwise, sorted names covering
the read; `attribute_not_exists(pk)` only when nothing was read); writes are one transaction after
that read, then one confirm (`:closed` CLOSED) of the same `:version`, then none. Probes are any
16-hex dispatch of the exact machine with `METADATA_ONLY`. This is scope, not domain acceptance.
`fence_close_session_policy` grants GetItem on FENCE and SEMAPHORE, UpdateItem on FENCE,
ConditionCheckItem on SEMAPHORE and DescribeExecution on the execution prefix, each a subset of
the `promotion_fence_operator` role. DynamoDB has no `TransactWriteItems` IAM action; each item
of the transaction is authorized by its own action (Service Authorization Reference for Amazon
DynamoDB).

The journal, evidence and broker take their SDK set from the operation; closed-ready is
unchanged and its evidence keys keep their bytes, while close-drain has its own step namespace
and hash. DynamoDB writes return only an empty result. `ExecutionDoesNotExist` reaches the
product for a closed-ready `CANCEL_BEFORE_SEND` member or any validated close-drain probe.
R12 (correction 2, accepted risk): every other native error, including `ConditionalCheckFailed`
and `TransactionConflict` in the close, poisons the journal, keeps the intent as the unknown
witness and the lease held, and is never retried or returned; a transient conflict also falls
to recovery, and a retry needs its own amendment. `_assume_fence_session` for close-drain
requires `application-prepare` with close and decision unset, `deadline = preparation_deadline`,
and grants checked per item action. `close_drain_capability` checks, before STS, the lease,
the prepared manifest, role and evaluation, the activation, `preparation.admitted_at` and
`deadline` equal to the stage's, the fence_operator delegation, the owner, the `expirations`
input recomputed now and the scope recomputed by `fence_policy_scope`; the freeze reread is the
last check. Freeze (3a): `session_owner.application_unfrozen` refuses `freeze=attached` when
`arn:aws:iam::<account>:policy/cnesdata-budget-freeze` is attached (personal-infra-live#2
readback 6883013198, path `/`), at the admission in `verify_application` and in that reread;
any other attachment keeps the original refusal and `read_resource_arns` is unchanged. Any
failure poisons the journal and mints no credential. Child loader (3c): the adapter child maps
`cnes_domain` and `cnes_infra` to `packages/<name>/src/<name>`; a directory is a stub package
whose `__init__` never runs, a `.py` file loads by path, and any other name under those roots
fails closed without falling back to `sys.path`. The Git closure is still authenticated before
and after. R13 (resolved, 6955828414): CnesData `develop` 9cdd452f (PR #526) removes pydantic from the
close-drain import chain, and the product confirms the close in the second of the fence write
(`close_confirmed_at == fence.changed_at`), so F = close + 1800 and phase B is admissible.
`close_confirmed_at` stays the close of `close_window`; `tests/test_cnesdata_delivery_lifecycle.py`
pins that a close confirmed 30 s after the write leaves B without capacity. `close_drain_capability`
and `close_expirations` are called by the `prepared` handler of PR-F, the only production call site.

Terminal validators (second slice PR-D, amendment 6886977054 decision 6 without item 3b, and
6861676353 item 8, `Refs #55`). They are pure in-process functions in `application_gate`, with no
product import and no network. Each kind has a closed `source` map of role to sha256
(`TERMINAL_SOURCE_ROLES`). A journal role selects the keeper journal observation bytes under that
digest: the sha256 is rechecked, and the bytes must be canonical and at most 1 MiB. An artifact role
(`host-handoff`, `recovery-decision`) selects only the bytes its factory was built with, never the
journal. Every object must match its own closed field set and `version`/`kind` (the publication:
`schema`), so bytes of another kind refuse. The result sha256 is the digest of the canonical map.

- `routing`: `fence` (OPEN or CLOSED) and `routes_match` from the `routing` observation (reopen).
- `static`: the `publication` observation, with the closed fields and schema of CnesData 9cdd452f
  `_api_static_records.py` (`cnesdata.static-publication/v1`) and the field types of its
  `PublicationReceipt` (`uploaded` a list of string pairs, `already_published` a list of strings,
  `invalidation_id` a string or null), whose `closed_ready_sha256` equals the digest of the
  `closed-ready` observation (the item 6 equality); accepted.
- `membership`: the frozen `close-drain` members (host member shape, `frozen_membership_sha256`
  commitment) against the `terminal` readback members. Identity fields have the exact host types
  (`generation` an integer that is not a boolean, `execution_ref` a string or null, the others
  strings). `resolved` only with the same host identity tuples in the same order and every
  resolution TERMINAL, ABSENT_PROVEN or CANCEL_BEFORE_SEND.
- `quiescence`: a factory over `Keeper.uncertainty()`. `quiescent`, `state_clean`, `pending` and
  `observed_at` come from the `terminal` readback; `unknown` is the readback's plus the held
  uncertainty, never dropped.
- `host`: a factory over authenticated host-handoff bytes (host gate public handoff, version 1).
  The status is in the closed set, `closed_ready_sha256` equals the closed-ready observation digest
  and `caller` equals its `common.caller`; accepted only for `accepted`.
- `decision`: a factory over the authenticated `recovery-decision` input (host
  `validate_recovery_decision` fields). Its `choice_at`, `recovery_deadline` and `fixed_deadline`
  equal the lease decision `choice_at` and `deadline` and the window F; it adds no fact.

The `routing` and `terminal` shapes are SYNTHETIC: the product has neither handler (R3). The host,
closed-ready and publication field sets are copied literals, not shared code. `TERMINAL_VALIDATORS`
(PR-F, R3) holds the six providers `routing`, `static`, `membership`, `quiescence`, `host` and `decision`,
each with a `synthetic-<kind>` label, and `execute` registers them on the keeper before `acquire`. The
`host` and `decision` providers are lazy: when the validator is invoked, `authenticate_host_handoff`
authenticates the public `cnesdata-host-handoff-<run>-<attempt>` artifact and only then builds the
factory. It mirrors CnesData 9cdd452f `_api_static_handoff.py` as labelled literals: the run and attempt
of the owner, the unique job `host-gate / execute` with its three step names in order, a single
`host-handoff.json` of at most 32 KiB inside a zip of at most 64 KiB, canonical JSON, created inside the
job interval, with the artifact digest checked; `producer_sha` is the sha of the run's own
`referenced_workflows` entry for `reusable-cnesdata-host-deploy-gate.yml`, never a literal. The
`decision` bytes are `canonical(handoff["recovery_decision"])`. `_terminal_proof` reads only the latest
registered observation of each kind (`Keeper._latest_observation_bytes`, in attach order, a broker
counting once through its journal), so a source that points at an older observation of the same kind
refuses. The registry covers no terminal kind (R15, below).

Four types have no validator. Amendment 6886977054 decision 6 applies: with no validator for a
required type, `finish()` keeps refusing; no rule or source is invented.

- `unit`, `recovery`, `audit`: the proposal names the mode-canary v2 record plus the `phase-c-*`
  job checkpoint. The record (CnesData 9cdd452f `mode_canary.py:279`) has no verdict field, there
  is no `phase-c-unit` job, and no authority text says when a mode is accepted. Only
  `accepted-open` requires them, in the `final` stage, which this slice does not reach (R5 of
  6886977054).
- `restoration`: the proposal names the `rollback` and `routing` observations. The product
  rollback observation (`cnesdata.static-rollback/v1`, CnesData 9cdd452f `promote_api.py:166-187`)
  covers only the static channel, so `unit`, `recovery`, `audit`, `api` and `first_static_absent`
  do not follow from it. Both failure terminals require it.

Reachability gap, against decision 3: `failed-prepare-quiescent` requires `restoration`, `routing`
and `quiescence`, but the sources of the first two (`rollback-api-static`, `reopen`) are not
admitted in `application-prepare`, so that terminal does not close in this slice either. The
`terminal-readback` admitted there is no substitute: its closed input set requires `routing
membership host-receipt static-receipt decision`, none of which has an original producer before
close, and it reads `routing` back instead of producing it.

Execute wiring to the API stage (second slice PR-F, amendment 6886977054 decisions 1, 3 and 7,
ratification 6974253889, R15, R18, R19, `Refs #55`). `application_gate execute` is the one production
path, `main -> execute(admitted)`. Its order is the contract: the registry and event-source checks,
`application_release_sha256`, `authenticate_adapter_closure`, `session_owner.authenticate_lifecycle`,
the credential window, `lifecycle_runtime.AWS` with `_verify_session` (the exact own-role readback of
`credentials`), the binding, `S3LeaseStore`, `Keeper`, the validator registration, `acquire`, the
event source, the `operation_session` factory (R20, below), `stage_handlers` and `keeper_loop`. Nothing
reaches an AWS client, the lease or STS before the release refusal.

Sources of the three inputs (6974253889):
- `release`: `governance["release"]` is closed to `release_id source_sha candidate_sha256 canary_id
  binding_sha256 image_digest` and `release_sha256 = sha256(canonical(release))`; a missing or reshaped
  release refuses `application governance release`. `Keeper.acquire` also requires the release of the
  authenticated Phase A plan of the original fence (`phase_a_originals["envelope"]["plan"]["release"]`)
  to hash to `binding["release_sha256"]` before the CAS, for both predecessor protocols (`legacy-infra`,
  which the ratification calls `phase-a`, and `lifecycle`).
- `preparation_deadline = int(keeper.clock()) + 900`, read right before `acquire` from the clock
  injected into the Keeper. Accepted risk: a clock step back makes the prepared package refuse later
  with the lease held.
- `activation`: the plan step is `fence-origins.json` `current_plan["step"]`, which must be a
  `plan`/`application-prepare`/`operational` entry of `lifecycle_steps` with a job name. The same-run
  publication of that step must hash to `current_plan["index_sha256"]`; its private `inputs.json` must hash
  to `approval.json["inputs_sha256"]`; `lc.inputs_envelope` (not `operational_inputs`, which revalidates
  with the pinned openssl) decodes it against the full owner and the application-prepare window; and
  the payload must hash to the manifest `activation_sha256`.

`credential_limit` is the earliest of `AWS_CREDENTIAL_EXPIRATION` (present and in the future), the
owner proof `expires_at` and the fragment `enabled_until`.

Handlers (`stage_handlers`). `prepared`: `fence_prepared_payload` under a `KeeperGuard`, the activation
above, `close_expirations` (built only after both reads), the close-drain ABI2 request bound to the
keeper window as it is at the event (sequence 0 and the predecessor checkpoint: nothing compares the
close-drain request with the prepared checkpoint, only the evidence key derivation reads them), the
journal attached to the keeper, `close_drain_capability`, then `invoke_adapter` with the largest whole
second `phase_capacity` admits, `min(deadline - now - 158, credential_limit - now - 121)`, sampled after
the capability returns because STS, IAM and the operation exchange spend the margin. Whatever the outcome
of the capacity check and the child, the handler then drops the operation and fence clients (R20). The result must be exactly one
`close-drain` observation and no uncertainty. `close_window` then takes the observation bytes, the
checkpoint `sha(prepared checkpoint.json)` and `infra_expiration_bound`, and the keeper writes the
`phase-b` window. `phase-b`: the B publication is rederived, its approval must name the prepared
checkpoint hash and the B plan, its checkpoint must be `phase-b` with the same owner, the clock is read
again after that authentication and must still be before `terminal_deadline` of the window
(`phase-b stage deadline elapsed`, with no write), and only then `api_window` takes `sha(B checkpoint.json)`. The plan download is recorded in `api.expiries` and
`api.digests` as one more `artifact` entry of `close_expirations`, from the metadata
`lifecycle_artifact` already authenticated; the prepared-package download is authenticated by
`fence_prepared_payload` but is not an entry. The emitted kinds stay `credential`, `platform` and
`artifact`, inside the product `EXPIRATION_KINDS` (CnesData 9cdd452f `promote_close.py:32`; R6, pinned
by a labelled literal in `tests/test_cnesdata_stage_events.py`). A short retention of the plan artifact
lowers `input_deadline`, the minimum decision 2 asks for.

Stop at the API stage (R18). `keeper_loop` has no `finish`, no publication and no closed-ready dispatch.
After the `phase-b` handler the window is `api`, the next `next_event` refuses
`stage trigger not connected stage=api`, the lease stays held and the fence stays closed in DynamoDB.
A TTL is not a takeover (`coordination_lease.py:3` and `:45`), so every later run is blocked until a
reviewed recovery. Every production stage that runs `execute` after the candidate cut must plan that
recovery, including the Phase A proof list and items b.3 to b.6 of CnesData#522. R15: no registered
validator set closes a terminal kind (`accepted-open` needs `unit`, `recovery` and `audit`; the two
failure terminals need `restoration`), `failed-prepare-quiescent` is not closable and the API stop is
the only reachable end; `tests/test_cnesdata_application_gate.py` pins that `finish` refuses all three
with the production registry. R19: `CNESDATA_DELIVERY_GOVERNANCE` is one secret for the application,
plan and deploy gates. With `release` the legacy `bootstrap` and `acm-certificate` plans refuse
(`contract.py:617-618`, `runtime.py:709`); without it the application and Phase A refuse. The conflict
predates PR-F and the step that sets the secret after the merge must record the swap per purpose.

R20 and R20-b, the operation session (amendment 6984143043, option C, `Refs #55`; it reopens only the
"extra OIDC in the job" of 6979020298). Before this change `execute` composed `lifecycle_runtime.AWS`
from the credentials `credentials` exports: a keeper session requested without delegations, whose policy
denies `sts:AssumeRole` on `*` (`session_policy.py`). `close_drain_capability` reached
`_assume_fence_session`, so STS denied the fence assumption (R20). The same session also could not write the
SDK evidence (R20-b): its own write prefix is `keeper/*` and `terminal/*`, the managed session policy grants
S3 only on the lease, and `ClosedReadyEvidence` writes under `<run>/close-drain/`. The STS denial hid
the second failure. One mechanism closes both, with no change to the workflow, the 8/4 interface, IAM,
trust or tofu:
- `execute` composes the factory `operation_session(operation, role, stage)`, a closure over the admitted
  governance, request and run and the keeper client, and hands it to `stage_handlers`, then to
  `close_drain_capability` and, through the same explicit keyword, to `closed_ready_capability`, which still has no
  caller. `_assume_fence_session` has no `aws` parameter any more. The keeper client keeps the lease and the
  freeze reread; it is never an STS or evidence client of the fence.
- The factory accepts `close-drain`, `closed-ready`, the static operations (`inventory`,
  `publish-static`, `rollback-api-static`), the terminal fence operations (`reopen`,
  `terminal-readback`) and the promotion mode operations (P16f, in "Integration state at X*").
  It builds `application_request` with `step` equal to the operation and
  `application_purpose="promotion"`. A fence operation has `delegations=("fence_operator",)` and the
  exact session name of the authenticated `fence-role.json`; a static operation delegates to the
  aliases of its static session. It then makes a second
  `AssumeRoleWithWebIdentity` of the same job through `oidc_credentials(..., duration=900)`. That function
  keeps its claim checks and accepts only 900 or 3600 s, with 3600 for keeper, plan and deploy. The session
  has the same `Account`, `Arn` (so the same role and the same `cnesdata-<run>-<attempt>` name) and `UserId`
  as the keeper. It is never exported, never written to the journal, IPC or the child environment, and
  there is no new session name or principal.
- Order. Every check comes before the exchange: `lease.check`, the pure checks, the effective-IAM checks,
  the keeper `guard()` and the freeze reread. After the exchange the window and the credential limit are judged
  again, because the token request and two STS calls can take tens of seconds, and then the fence
  `sts:AssumeRole` runs through the operation client. That client is also the client of the broker and of every
  ledger, so every S3 write under `close-drain/` goes through it and a test fails if one goes through the keeper
  client. Any failure of the exchange (R21 included) closes before the fence STS, poisons the journal and keeps
  the lease held.
- Premise: the operation credential `Expiration` must be at least `stage["deadline"]`, with no tolerance, or the
  factory refuses before the fence STS. The deadline is `preparation_deadline <= admitted_at + 900` and the exchange
  happens after `admitted_at`, so a 900 s session covers it; an event at `acquire + 0` gets `Expiration ==
  deadline` and is admitted.
- The close-drain `effective_iam` is a local check over recomputed documents: the application identity
  (`application_identity_document`), the pinned managed policy and the inline the factory sends. It requires
  `sts:AssumeRole` of the fence with the exact session name, and denies the `-foreign` name, another delegation,
  `s3:PutObject` on the lease and on `keeper/`, and allows `s3:PutObject` under `close-drain/`.
  `fence-evaluation.json` (`lifecycle_runtime.py` `fence_evaluation_documents`) only attests the closed-ready
  session and its schema does not change. For `closed-ready` a test proves the inline the factory sends equals
  `evaluation["documents"]["application_session"]` by digest.
- The keeper retains the broker, which retains its client. After the child (and on any refusal after the
  capability) the `prepared` handler sets `broker.aws`, `session.evidence`, `session.client` and the `_aws` of
  each ledger to `None`. It keeps the broker, the ledgers (their state is the uncertainty) and the journal, which
  `_terminal_proof` reads. A test walks everything reachable from the keeper and finds neither the clients nor the
  credential strings.

R20 stops blocking at the merge and the swap of the pins below, but R18 stays: no production `execute` runs
without a reviewed recovery plan for the closed fence and the held lease at the API stage. That includes the Phase
A proof list and items b.3 to b.6 of CnesData#522. After this change the producer closure and the sha256 of this
document change, so the closure is computed again on the approved head and `source_closure_sha256` and
`workflow_sha` of the producer (which changes the trust of the application role, so it is not a variable-only
apply), `gate_shas.application` and the governance secret are replaced in the same pin (R8).

R21, a second token in the same job. GitHub does not document how long `ACTIONS_ID_TOKEN_REQUEST_TOKEN` lives
nor whether a job can request a second ID token. The exchange of the operation session happens after the
`prepared` event, which can be 20 minutes or more after the first token of the job. Before the first real
`execute`, a disposable workflow in a repository outside production, with `id-token: write`, must request two
tokens in the same job at least 20 minutes apart, with no AWS and no production role. Until then R21 stays open;
if it fails in production the exchange refuses before the fence STS, the journal is poisoned and the lease
stays held, which is the state R20 had.

Closure sentinel (decision 1): `session_owner.application_configuration` and the tofu variable
`application_promotion.source_closure_sha256` refuse the 64-zero placeholder; the value comes from
`application_gate closure --pin <head>`, computed on the approved head, and a value computed before the
last merge that touches the producer closure is invalid (R8).

Static stage (second slice PR-E, amendment 6886977054 decision 5 and queue items 3d, 3e, 3f and
6, refined by 6963763481 (R16, R17), `Refs #55`). `retire-static` is an ABI operation: its inputs are
`static-plan inventory publication routing` and its observation is `retirement`. In this slice it is
admitted in no stage, not even `final` (R16): `ADAPTER_STAGES["retire-static"]` is empty, so the request
and the journal refuse it everywhere.
`static_session` reproduces #498 `locals.static_sessions` byte for byte:
`sp-<op>-sha256(jsonencode(binding + operation) + LF)[:40]`. The inventory name commits to no plan
(`static_plan_sha256` null) and is written `i`. The fixture vector was evaluated by `tofu console` over
the pinned `static-promotion.tf` (sha256 15098669...1e). `static_sessions` maps each ABI operation to
its delegations:
- `inventory`: observer `sp-i-`.
- `publish-static`: normal `sp-publish-` plus observer `sp-i-`. This is 3e: the observer re-inventories
  in the static stage.
- `retire-static`: normal `sp-retire-` only.

A name is not an STS admission. This slice has no static broker and no static STS.

R17, the S3 catalogue. The ABI table rows of 6764564072 were never ratified. The authority is
CnesData#473 6869049996 item 3 plus #498, and the wire form is the product's at CnesData 9cdd452f
(`publish_dashboard.py`). `STATIC_SDK_METHODS` is the closed map from wire name to the only boto3 method
the native dispatch may call; any other name, including the snake_case one, refuses:

| Wire call | boto3 method | Role | Operations | IAM action on the source |
|---|---|---|---|---|
| `s3 ListObjectVersions` | `list_object_versions` | observer | inventory, publish-static | `s3:ListBucketVersions` |
| `s3 HeadObject` | `head_object` | observer | inventory, publish-static | `s3:GetObjectVersion` |
| `s3 ListMultipartUploads` | `list_multipart_uploads` | observer | inventory, publish-static | `s3:ListBucketMultipartUploads` |
| `s3 ListParts` | `list_parts` | observer | inventory, publish-static | `s3:ListMultipartUploadParts` |
| `s3 PutObject` | `put_object` | normal | publish-static | `s3:PutObject` |
| `s3 GetObject` | `get_object` | normal | publish-static | `s3:GetObject` |
| `cloudfront CreateInvalidation` | `create_invalidation` | normal | publish-static | `cloudfront:CreateInvalidation` |
| `s3 DeleteObject` | `delete_object` | normal | retire-static | `s3:DeleteObjectVersion` |

`publish-static` has no `DeleteObject`. `validate_static_call` binds every value:
- the bucket, which the caller authenticates;
- the decoded plan, from `static_plan`. That function closes `cnesdata.static-plan/v1` under the #498
  key, version, sort, rollback-pair and overlap rules.

What each call may carry:
- `ListObjectVersions`: only `Bucket`, or `Bucket` plus both markers.
- `HeadObject`: a key in the #498 namespace, a `VersionId` and `ChecksumMode` `ENABLED`.
- `ListMultipartUploads`: only `Bucket`.
- `ListParts`: a namespace key and an `UploadId`.
- `PutObject`: a candidate key, the 3d Body and checksum, and `IfNoneMatch` `*` exactly on non-entrypoints.
- `GetObject`: a candidate key, with no version.
- `CreateInvalidation`: the plan's distribution, the two entrypoint paths and a 32-hex `CallerReference`.
- `DeleteObject`: exactly `{Bucket, Key, VersionId}`, with the pair in `retire_versions`. This vector is
  SYNTHETIC: the product has no retire handler (R3).

On the source, every validated call is allowed by its #498 role. `DeleteObject` carries a `VersionId`,
so it needs `s3:DeleteObjectVersion`, which #498 grants per version to the normal role only.

Item 6, `publish_static_closed_ready`:
- It refuses first while `Keeper.uncertainty()` is not empty.
- The publish-static `host-receipt` must be the host handoff v1: canonical, at most 1 MiB, closed
  field set, `version` 1, `kind` `host-handoff`.
- Its `closed_ready_sha256` must equal the digest of the single `closed-ready` observation across the
  keeper journals. A broker and its own journal count once.
- Any failure poisons the publish-static journal and attaches it, so the lease stays held.
- The receipt's `status` and `caller` stay the product's check: CnesData 9cdd452f
  `promote_api.py:236-245` and `rollback_api_static.py:205-213`.

3d, the S3 `Body` on the broker:
- `s3_body_bytes` decodes `{"base64": ...}` strictly: ASCII only, `validate=True`, and re-encoding must
  give the same text. This is the product's `b64`.
- `s3_put_body` requires `ChecksumSHA256 = base64(sha256(bytes))` over the decoded bytes.
- `s3_body_value` reads a GetObject Body up to `maximum + 1` bytes and refuses anything past `maximum`.
- The request side adds no size of its own. The canonical native request limit of the journal (128 KiB)
  bounds the text, so a PutObject body above about 96 KiB cannot cross the existing journal.

R4, evaluated on the source only:
- `iam_boundary.effective_iam` runs over the #498 normal and observer policies. The model is checked by
  sha256 against the tofu renderings.
- The observer only reads the namespace and lists the bucket. Its document has no `DateLessThan`.
- The normal role writes and reads only the candidate keys and invalidates the distribution. It
  deletes only the exact `retire_versions` (`s3:VersionId`), and only before `enabled_until`.
- No static session policy exists, so each identity document stands as its own session. Applied IAM
  is not evaluated.

R16, the decision-5 budget does not fit (6963763481 decision 1: no admitted stage in this slice):
- The largest plan #498 admits is 43 `retire_versions`. The normal policy is limited to 10240 bytes;
  the smallest per-reference plan measures 616 + 221·n bytes, and tofu renders 43 at 10119 bytes and
  44 at 10340.
- The only SDK broker shape that exists does 10 AWS ops per call when durable and 1 when in memory. Each
  op sits behind `guard.check(20)` and the `+20`/`+40` window checks.
- Driving `lc.phase_capacity` and `STAGES["final"]` with an injected clock at 20 s per op (the
  `aws_boundary.bounded` timeout) completes 0 deletes, or 1 in memory under `KeeperGuard`.
- The nominal fit needs less than 7.0 ms, 93.9 ms, 69.8 ms or 0.93 s per op (durable or in memory, under
  `LifecycleWatchdog` or `KeeperGuard`). Reopen and finish share the same 60 s and are counted as 0 s.
- `retire-static`, the codecs, the catalogue validators and item 6 have no production call site.

Second slice, remaining: validators for `unit`, `recovery`, `audit` and `restoration`, which need a
source rule in their own amendment; a source for `failed-prepare-quiescent` in `application-prepare`;
the event sources and handlers for every transition after the API (R5), each in its own amendment.
Static stage, remaining:
- a static broker and STS for the static roles, with response sanitization for the catalogue calls;
- the R16 remedy, chosen by the post-API amendment: a per-run cap, a batched `DeleteObjects` (a new ABI
  operation) or a later `static-maintenance` run;
- a stage for `retire-static`, in that same amendment.

Not yet proven: the product adapter; real STS with Deny-only inline session policies
(real STS may require an Allow in every session policy, and `effective_iam` models managed
and inline documents as a union; the fence assumption of the operation session relies on this
premise); the second web-identity exchange of the same job against real GitHub OIDC and STS (R21)
and its 900 s credential against the preparation deadline; the global NotResource premise; quotas with real
VersionIds; Phase A with expired artifacts; the operational closed-ready producer; applied
IAM; static binding #498; the EXT2 profile's pinned `openssl_path`/`openssl_sha256` being
present on the plan and deploy runners (which may use another image than the EXT2 gate);
the `prepared` and `phase-b` handlers against real runs, S3 and the product `close-drain` handler; the close-drain capability
against real IAM, STS and DynamoDB (per-item authorization of the close transaction, the freeze
reread through the application identity, the product handler in the child); the event
producer against
real GitHub runs, including its request budget (one jobs read per poll, about 720 per hour at
the five-second poll, against the token's hourly limit); the terminal validators against real
product bytes (the routing and terminal-readback shapes are synthetic, and the host-handoff caller has
not met a real run); the static calls against
real S3 and CloudFront, real static STS, `retire-static` inside the `final` budget (R16), and product
assets above about 96 KiB through the journal. No
operational readiness, applied IAM, production acceptance or integrated-code status is implied.
