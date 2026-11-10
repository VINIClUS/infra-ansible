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
uses manual `readiness-production.yml`, both on develop/production. Readiness
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

The raw enabled Terraform input has exactly five required fields
`role_name/workflow_sha/source_closure_sha256/enabled_until/delegations` and only
optional `predecessor_read`. Raw shape is validated before Terraform can discard
extra object fields; the protected `application_configuration` is also validated
by the consumer. Absent/null selector produces no `predecessor_reads` output.
A selected history requires that non-null field and its exact eight fields.
Selector and protected full reference must appear together; parser and public
admission use the same closed reference validator, including exact integer types.
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

## Remaining integration gates

The #499 v4 contract now names the real mode execution, readiness and proof
paths. Its code is not inferred from the shared ten-alias ceiling. The existing
audit canary cannot prove unit/recovery, and a clone state machine cannot prove
production admission. Mode preparation now has an isolated eight-address structural gate and an
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
900-second promotion or 14400-second readiness context deadline, and derives
the exact eight promotion or six readiness sessions. The fourteen session
algorithms retain their separate ASCII canonical codec. This pure validator
does not authenticate its producer arguments or authorize STS/apply.

The complete mode-canary input/trust/policy/output oracle, its native product
fixtures, the readiness D14400 protocol and operational-pending terminal union
still require integration. Until those producers exist, these
paths remain closed; no offline vector is an operational acceptance receipt.
F2/F3 still require fresh post-B CLOSED-ready admission under the original API180
window and full current/prior static baseline bytes, including non-latest current.

The keeper polling loop, protected terminal assessment producer, application
reusable/dispatcher, concrete F2/F3 adapter flows
and complete initial/live/inverse native product plan fixtures remain
implementation work. Terminal publication and successor verification now have
offline integration tests, but are not yet connected to that polling/reusable
flow. The fragment consumer/readback and adapter source preflight are implemented
and tested but also require that integration. Current local tests do not make
this extension ready for deployment.


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
Read, guard and observe are implemented; SDK calls remain closed until the
protected broker and prepared-role proofs are integrated.

The shared-only SDK journal can now retain bounded canonical intent/response
bytes, request ID/Date, monotonic samples, session commitments and original
owner/stage guard bindings. A pending native call prevents adapter completion;
timeout, invalid response or lost guard preserves pending/unknown and poisons
the context, including late responses. Credential fields and unfiltered
execution payload fields are rejected before retention. This is an in-memory
evidence component: immutable private publication before IO still needs wiring.
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
No historical grant is broadened. Protected current checkpoint-chain transport
is also absent. Package production and privileged consumption remain disconnected.

ClosedReadyEvidence adds conditional own-run/closed-ready intent, response and
receipt storage through existing AWS.put/readback. Stable keys bind original
owner/caller/checkpoint/native call; changed prepared/session proofs collide.
Persisted pending intent, crash or ambiguous outcome remains unknown; reentry
cannot mint another ticket or replay SDK. Complete receipts return historical
original bytes, not fresh readiness. The internal helper executes no SDK call,
STS or IPC and does not itself update keeper uncertainty. Those integrations
remain closed. Native shared IAM composition and a separately labelled synthetic
fence/freeze fixture exercise readonly isolation; legacy source without SFN remains denial. The integrated #500 source was also
compiled with the real resolver; that is code evidence only, with applied proof
and exact live IAM readback still required. Strong reads, METADATA_ONLY and frozen membership remain
SDK guard obligations, never invented IAM condition keys.
