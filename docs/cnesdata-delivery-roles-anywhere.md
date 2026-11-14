# CnesData Roles Anywhere: identity and CRL handoff

This root implements **Code**, not production acceptance. It creates a public
offline-CA trust anchor, one API role and one singleton CnesData profile in
`opentofu/cnesdata-delivery`. No AWS operation is authorized by merging it.
Issue [#27](https://github.com/VINIClUS/infra-ansible/issues/27) stays open until
the operational checks below pass. The
[CRL amendment](https://github.com/VINIClUS/infra-ansible/issues/27#issuecomment-6713953217)
defines the external CRL operation and the IAM expiration control.

## Ownership and inputs

- Exclusive state key: `shared/cnesdata-delivery/prod/opentofu.tfstate`.
  The existing governed backend supplies the bucket and CMK; this root creates
  neither. Use `backend.hcl.example` only as a template, replacing placeholders
  from the audited private catalog. Do not override the key, encryption or lock.
- Backend Code baseline: personal-infra-live
  `05b4aae40dbfed5d3ae55096ed472f411114c381`. Its outputs are contracts, not
  evidence of a real backend, permissions, lease or apply.
- CnesData consumer inspected at `db4ebd7883de3fcd352bb01c6ade21304cabc5a1`:
  `runtime-iam` attaches the product API policy directly to the supplied role.
  This root therefore supplies **no product permissions, broker or extra
  AssumeRole identity**. No resources from LimnoPulse are adopted.
- Inputs `account_id`, `region`, `identity` and `ca_certificate_pem` come from
  the reviewed catalog. Names, CN and SAN URI are exact, without wildcards.
  Region is `us-east-2`; profile sessions are limited to an integer 900–3600
  seconds and the role maximum is 3600 seconds.
- The public CA is a single certificate. VINIClUS retains the private CA in
  two encrypted offline copies. Issuance, private material, operational leaf
  certificates and leaf credentials never enter Git, Terraform state, SSM,
  plans or artifacts. Operational leaf installation is a separate secure
  bootstrap. No AWS Private CA or signing KMS key is created.

All inputs/readbacks and the temporary operator identity must be ready before any
real operation. Local default AWS credentials are not an authorized fallback for
CI, runtime or tests. The root checks the caller account and, by default, requires
an STS assumed-role ARN, rejecting root and IAM user credentials even during
initialization. This does not choose or grant an operator role: the controller must
still verify its approved provenance.

### Local controller root exception (owner decision, 2026-11-13)

The executor role requires MFA and the account root cannot assume roles, so the
owner accepted the account root credential for the **local controller** plan/apply
of this root only (EPIC CnesData #465, Production stage). The exception is the
explicit input `local_controller_root_apply`, `bool`, default `false`, non-nullable:

| `local_controller_root_apply` | Accepted caller | Refused |
| --- | --- | --- |
| `false` (default) | `arn:aws:sts::<account>:assumed-role/<role>/<session>` | root, IAM users, other accounts |
| `true` | exactly `arn:aws:iam::<account>:root` | every assumed-role session, IAM users, other accounts/partitions |

The switch is either/or: a plan with the flag can only run as same-account root,
so a CI or runtime OIDC session that sets it fails the precondition, and a plan
without it can never run as root. No workflow or runtime tool sets the flag; a
test enforces that. Every root use is therefore visible in the saved plan inputs
and must be recorded in the controller ledger. Static AWS keys remain forbidden;
root never enters CI, runtime, artifacts or tests (fixtures use synthetic ARNs).
The Python gates (`aws_boundary.py`, `signing_gate.py`, `host_gate.py`) keep their
exact assumed-role identity checks unchanged.

## Closed initialization and activation

`activation_enabled` defaults to `false`. Initialization creates an enabled
anchor for the later controlled CRL import, a **disabled profile**, and a role
whose only trust Allow expired at `1970-01-01T00:00:00Z`. The
`roles_anywhere` output is null, so it cannot pass the consumer's v2 schema.
The separate `initialization` output contains identifiers for the operator;
it is not a product-ready shared output.

The trust Allow combines the Roles Anywhere service principal, exactly
`sts:AssumeRole`, `sts:SetSourceIdentity`, `sts:TagSession`, exact anchor
`aws:SourceArn`, `aws:SourceAccount`, `x509Subject/CN`, `x509SAN/URI` and
`DateLessThan` on `aws:CurrentTime`. When activated, that deadline is the literal
`nextUpdate` extracted from the signed CRL bytes. There is no `IfExists` or
alternative Allow. At equality or after the deadline, new sessions are denied.

[AWS documents](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html)
CreateSession as an X.509 wrapper around AssumeRole.
[`aws:CurrentTime`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-currenttime)
is always present in the IAM request context, and
[`DateLessThan`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Date)
is strictly before the specified time. The expiry control requires no update
or watchdog to run at the deadline. Already issued sessions retain their
bounded TTL; a session issued immediately before the deadline can outlive it.

The profile's `role_arns` is exactly the API role. SourceArn identifies the
**anchor**, not the profile. Wrong-profile acceptance depends on other profiles
not authorizing this role and on the protected client tuple
`{profile_arn, trust_anchor_arn, api_role_arn}`. Audit all relevant profiles and
their mutation permissions in production. An out-of-scope profile deliberately
configured to allow this role cannot be excluded by inventing a trust key.

AWS provider 6.54.0 has no CRL resource or attribute-mapping configuration.
The service's default mappings include CN and the first SAN URI. Read back and
verify these defaults, and issue each application leaf with a single application
URI. This code does not claim to manage those mappings explicitly.

## Exact external CRL operation

AWS [continues to use imported CRLs after nextUpdate](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html).
The signed deadline in IAM supplies the missing expiry restriction. CRLs are
imported/updated through the supported API/CLI outside Terraform, by the approved
temporary non-root operator, with a separate immutable operation plan reviewed
**before** execution. This document and helper do not execute that operation.

That plan records the producer HEAD, account/region, operator principal,
anchor/role/profile/CRL identities, exact public payload hashes, expected prior
state, CA fingerprint, signed CRL number/dates, intended API request, authorization
window and the required before/after readbacks. Initial
[`ImportCrl`](https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_ImportCrl.html)
binds `trustAnchorArn`, `crlData`, `name`, `enabled=true`.
[`UpdateCrl`](https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_UpdateCrl.html)
uses the exact prior `crlId` and new `crlData`; it does not enable a disabled CRL.
No automatic mutation wrapper or unreviewed retry is provided.

Collect fresh `GetCrl` and `GetTrustAnchor` JSON. The former includes base64
`crlData`, CRL ID/ARN, enabled flag and trust anchor ARN; it does **not** supply a
trusted `nextUpdate` field. Verify the public DER itself. Keep private keys and
leaf credentials out of all evidence.

### Offline verifier

`tools/cnesdata_delivery/crl_handoff.py` uses Python's standard library and the
existing OpenSSL executable. It performs no network or AWS calls. Missing
OpenSSL is a failure, not a skip. Example using only explicit public files:

```sh
rtk proxy python3 tools/cnesdata_delivery/crl_handoff.py \
  --ca public-ca.crt --crl signed-crl.der \
  --get-crl get-crl.json --get-trust-anchor get-trust-anchor.json \
  --expected expected.json > crl-handoff.tfvars.json
```

`expected.json` contains the following required fields, sourced from the reviewed
operation plan, never auto-discovered from a local default AWS profile:

| Field | Meaning |
| --- | --- |
| `operation` | Explicit `initialize` or `renew`; renewal requires accepted history even after closure |
| `account_id`, `region` | Exact expected account and `us-east-2` |
| `trust_anchor_arn`, `crl_id` | Exact existing identities |
| `ca_der_sha256` | SHA256 of the expected CA certificate DER |
| `crl_sha256` | SHA256 of the exact reviewed CRL DER |
| `previous_handoff` | Previous accepted `crl_handoff` object; null for initial import |
| `previous_handoff_sha256` | Independently pinned digest of that accepted manifest; null only for initial import |
| `authorized_deadline` | Current role trust deadline; historical sentinel for initial import |

The helper verifies enabled flags, ARN account/region/IDs, exact decoded CRL
readback bytes, CA certificate identity, issuer/signature, canonical DER, CA
validity and CRL signing usage, signed thisUpdate/nextUpdate and CRL number.
It rejects future thisUpdate, absent/expired CRLs, substituted data, stale numbers,
identity changes and dates shorter than the previous accepted/currently authorized
deadline. Only full direct CRLs are supported. Revoked serials are normalized from
DER hexadecimal to decimal strings. Every previously accepted revoked serial must
remain present on renewal: without a trusted leaf-expiration ledger, no serial is
pruned automatically. Missing prior serial history is rejected, even if trust has
been closed. Initial-import classification and the immutable previous manifest
must be verified against real before-state by the controller; changing a JSON
operation label is not proof of a fresh initialization.
The previous manifest must match its independently pinned accepted hash; edited
or truncated serial history cannot silently replace it. Preserve that accepted
artifact and digest through a closure, since the root's active digest output is
null while closed. Verify the preserved baseline against the operation ledger
before renewal; supplying both a fabricated history and its matching hash is not
proof of prior acceptance.
It emits only `crl_handoff` and its canonical SHA256. It does not set
`activation_enabled` or output any credentials.

The manifest includes hashes of canonical readback JSON, public CA PEM/DER, CRL
DER and previous accepted manifest. SHA256 of compact, sorted-key JSON of the
`crl_handoff` object is `crl_handoff_sha256`; this hash excludes a trailing newline.
Terraform checks this digest and its anchor/CA/account/date bindings before
activation. It cannot parse signatures or certify that supplied JSON came from AWS.

**The helper verifies consistency, not authenticity of an AWS response.** The
controller/operator must independently establish origin and freshness, confirm
the actual role/profile/anchor/CRL, and bind the exact manifest, source revision,
inputs and binary plan to the audit. A fabricated but internally consistent
readback is not production evidence. Fixture JSON is never live evidence.

### Activate, renew and close

1. Complete the closed initialization and audited CRL operation. Validate fresh
   readbacks and public payloads with the helper. Record all source/payload hashes.
2. Prepare and independently review the saved activation plan with explicit
   `activation_enabled=true` and the exact helper output. Apply only that binary;
   never replan, replace its inputs, bypass locking or authorize apply by merge.
3. Read back role trust, profile, mappings, anchor and enabled CRL. Test legitimate,
   revoked, cross-app and wrong-profile requests and the expiry boundary.
   IAM propagation is eventual: this code promises no undocumented global
   propagation bound or instantaneous revocation.
4. Renew before expiry: generate the next full signed CRL, preserve all previously
   accepted revoked serials, prohibit rollback/shorter deadlines, import/update
   first, obtain fresh readbacks, validate, then audit/apply the deadline extension.
   Never extend trust based solely on local CRL bytes before import. If renewal is
   missed, new sessions fail closed automatically. Alerts and timely renewal remain
   production availability requirements.
5. Before an authorized DisableCrl/DeleteCrl operation, close profile/trust with an
   audited plan (`activation_enabled=false`) and confirm readbacks/denied new
   sessions. Only then change/remove the CRL. The deadline does not detect premature
   CRL deletion, disabling, CA replacement, weakened trust or profile mutation.
   Mutations outside the controlled path are forbidden; production drift detection,
   alerting and recovery remain required.
6. CA/anchor rotation or pruning revocation history is a separate closed checkpoint,
   not CRL renewal. Prove
   recovery, revocation and correct mapping again before reopening. Existing
   sessions still require their bounded TTL to elapse.

## Output and acceptance

When activated, `roles_anywhere` contains exactly
`{api_role_arn, profile_arn, trust_anchor_arn, crl: {crl_id, enabled, next_update, sha256}}`.
It is only the v2 fragment. Reconcile the complete shared-output handoff with
schema v2 SHA256
`681e8855667dd2759d5e8deb40f5a3e9e808b20ce79995374c348be56c2c6c95`;
account/baseline/KMS/storage/Budget/GitHub fields belong to their producers.
No competing format or fabricated complete output is emitted.

Code tests use public synthetic fixtures and actual OpenTofu mock-provider plans.
They inspect rendered policies and singleton profile membership, signed CRL
validation and deadline boundaries. The policy oracle tests the narrow documented
IAM semantics; it is not an IAM simulator or a real CreateSession call. Native
tests need the existing complete provider cache and pinned checksum lock via
`CNESDATA_TEST_AWS_PROVIDER_DIR`. They sanitize credentials/configuration and use
user/network namespaces; missing tools/cache/isolation fail explicitly.

```sh
rtk proxy python3 -m pytest -q tests/test_cnesdata_delivery_roles_anywhere.py
```

Run local work serially under the agreed CPU/memory/I/O limits with a short private
0700 TMPDIR. Do not download/install providers locally or weaken isolation.
The existing hosted CI supplies broader validation; no workflows are changed.

Production still requires EXT-6 acceptance, private catalog readiness, backend
and CA custody checkpoints, approved temporary identity, exact-plan audits,
real readbacks, renewal/alert/recovery exercises and LimnoPulse smoke before/after
shared changes. USD 8 product / USD 15 aggregate budgets, FREE ACTIVE, Actions paid
USD 0 and disabled deploy-develop remain unchanged. A passing Code PR proves none
of these operational conditions.
