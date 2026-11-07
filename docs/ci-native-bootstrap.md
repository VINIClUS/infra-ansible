# Native bootstrap test contexts

The public baseline already collected 78 native bootstrap cases but did not
install their toolchain. Its Python test step therefore failed at
`offline_binaries_absent` before native assertions ran. This repair concerns
validation infrastructure, independently of Samba AD and real AWS operations.

## Public hosted validation

`pipeline.yml` prepares the tools on its ephemeral GitHub-hosted Linux x86-64
runner, then explicitly sets `CNESDATA_NATIVE_CONTEXT=public-ci`. It runs the
whole Python suite with `-ra`, so external-target reasons appear in the summary.
Of the existing 78 native cases, 71 remain native public checks. Seven cases
that inspect the private Budget target are reported as external:

- Budget resource/output contracts for cases `a` and `b` (2);
- Budget target prevent-destroy for state and logging buckets (2);
- Budget target foreign-account rejection (1);
- Budget target source/sink and foreign-prefix diagnostics (2).

Budget witness/mutation cases and every foundation case still execute with
OpenTofu, AWS mocks and the existing independent assertions. External target
classification never substitutes a witness or empty config for source.

`CNESDATA_NATIVE_CONTEXT` accepts only `public-ci` and `operator`. An unknown
value fails. The default is `operator`: an absent/empty private target fails
with `external_target_absent`. Operators explicitly provide its reviewed
bootstrap directory through `CNESDATA_TEST_BUDGET_SOURCE_DIR`; no developer
home path is assumed. Public CI neither checks out a private repository nor
receives cross-repository credentials, inventory or AWS credentials.

## Pinned, verified preparation

`python -m tools.ci.native_bootstrap` is a GitHub Actions-only prewarm command;
it refuses accidental local downloads. The workflow supplies a fresh directory
under `RUNNER_TEMP`, `GITHUB_ENV` and `GITHUB_PATH`. Each run builds its own
provider cache from the committed lock; no shared mutable cache is restored.

| Component | Pin | Verification source |
| --- | --- | --- |
| OpenTofu Linux amd64 | 1.13.2 | Official release asset SHA-256 `723bebb0df8411daff1e5fc3862e28ff5581fe5634087f4c29a9aa41d78208b5` |
| RTK Linux x86-64 musl | 1.1.0 | Official release asset SHA-256 `9454ad1b9489daa57ab0a9f4ebe2faaf4dc82b8a0f26c9e5135151abd7c9378d` |
| AWS provider | 6.54.0 | Committed `opentofu/cnesdata-bootstrap/foundation/.terraform.lock.hcl` |

Binary digests were read from the official GitHub release asset metadata on
2026-11-07: [OpenTofu 1.13.2](https://github.com/opentofu/opentofu/releases/tag/v1.13.2)
and [RTK 1.1.0](https://github.com/rtk-ai/rtk/releases/tag/v1.1.0).
The API asset IDs are respectively `tofu_1.13.2_linux_amd64.zip` at
[the OpenTofu release API](https://api.github.com/repos/opentofu/opentofu/releases/tags/v1.13.2)
and RTK asset [675762778](https://api.github.com/repos/rtk-ai/rtk/releases/assets/675762778).
The helper pins both URLs and digests, verifies archives before extracting one
regular binary, and verifies reported tool versions. RTK's existing raw
`proxy` invocation remains part of the harness; no compatibility shim is used.

The provider seed contains only exact tool/provider requirements and the
original lock. `init -backend=false -input=false -lockfile=readonly` downloads
only the provider through the registry, with no backend or resources/data
sources configured. The helper verifies the lock did not change and keeps it
above the resolved provider directory. Provider discovery accepts the original
unversioned name or AWS 6.54.0's versioned executable, rejects ambiguous files
and symlinks, and never renames or modifies the provider bytes.

Preparation and native subprocesses use an environment allowlist, an empty
HOME, disabled EC2 metadata, `/dev/null` AWS config/credential files and an
explicit CLI config. Before init, the helper executes the fixture's exact
`rtk proxy unshare --user --map-root-user --net tofu version -json` command.
Unavailable user/network namespaces fail with
`native_namespace_preflight_failed`; there is no fallback without isolation
and no production runner is used. Test init continues to use a filesystem-only
mirror with the original readonly lock; plans/tests remain inside that network
namespace with mocks and the existing command allowlist.

When updating a pin, review the official release metadata and archive digest,
update the matching fixture/root requirements and committed provider lock as
needed, and validate on a fresh hosted runner. Never regenerate the lock merely
to make a mismatch pass.

## Hosted Ubuntu namespace permission

The first hosted repair run, [42392131134](https://github.com/VINIClUS/infra-ansible/actions/runs/42392131134),
resolved `ubuntu-latest` to Ubuntu 26.04.1, image `20261101.186.1`. The exact
unprivileged preflight failed while writing `uid_map`, before provider init.
Ubuntu's AppArmor user-namespace restriction allows namespace creation but
blocks subsequent capabilities unless the application has an explicit profile;
[Ubuntu documents the application-specific userns allowance](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions).
The generic upstream [unshare profile is disabled by default](https://gitlab.com/apparmor/apparmor/-/merge_requests/1206).

Before prewarm, `tools/ci/prepare-hosted-userns.sh` loads a named profile attached
only to `/usr/bin/unshare`, using Ubuntu's `unconfined` profile flag plus the
`userns` permission. This authorizes the sandbox builder; it does not remove
its kernel namespaces. The exact preflight and every native test still run as
the unprivileged runner user. Only the AppArmor parser runs through `sudo`.

The script refuses local execution, self-hosted runners, root callers, other
repositories/jobs and images other than the observed `ubuntu26`. It logs the
image version and current AppArmor restriction, requires AppArmor to be active,
and loads one profile from runner-temporary storage without a persistent policy
cache. It changes no global sysctl, service or production policy. The VM is
discarded after validation. A future image change requires review; unavailable
permission or namespace isolation continues to fail closed. The runner scope
uses GitHub's documented [RUNNER_ENVIRONMENT variable](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).

## Required private consumer gate

The private consumer must configure a required integration gate **before
promoting a public revision**. This repository documents that requirement; it
does not create the gate, modify branch protection or claim it has run.

Use a trusted workflow in the private consumer, a fresh hosted Linux x86-64
runner, and an immutable public commit SHA that has completed public validation
and review. Check out that reviewed public SHA and the reviewed private source
revision separately. Never run arbitrary public pull-request code with private
source or credentials, including via `pull_request_target`.

The private consumer must prepare its own reviewed, scoped namespace permission
when its hosted image requires it. This public permission script intentionally
refuses other repositories; do not weaken its guard to reuse it on production.

Run this repository's prewarm helper from the reviewed public checkout with
fresh `RUNNER_TEMP`/GitHub output paths, then in the following step run from that
same public checkout (the provider directory and binary path come from prewarm):

```sh
CNESDATA_NATIVE_CONTEXT=operator \
CNESDATA_TEST_BUDGET_SOURCE_DIR=/reviewed-private-checkout/bootstrap \
python -m pytest -q -ra \
  tests/test_cnesdata_aws_bootstrap_foundation.py \
  tests/test_cnesdata_aws_bootstrap_backend.py \
  tests/test_cnesdata_aws_bootstrap_inputs.py
```

All 78 native cases, including the seven real Budget target cases, must pass
without external-target skips. Record both immutable revisions and the result
in the consumer's private gate evidence, and block promotion if it fails or is
absent. No AWS credentials, backend access or production apply are needed for
this gate. Source paths, provider cache, plans and logs must stay within that
private workflow's boundary; never upload them to the public PR.

## Local verification without downloads

```sh
python -m pytest -q tests/test_native_bootstrap_context.py \
  tests/test_github_workflow.py tests/test_local_workflow_validation.py
```

These tests use temporary synthetic files/archives, not real providers. Full
native execution, installation, registry availability and namespace support
must still be proved by hosted CI. The separate private gate must prove the
external target against the reviewed private revision.
