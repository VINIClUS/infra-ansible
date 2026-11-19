# Fixed IAM document oracles

`cnesdata_iam_policy_oracles.json` records complete documents reviewed against the
34 unchanged HCL blobs in `cnesdata_delivery_sources/source-manifest.json`, pinned
to CnesData `28597b30ef8e22d5fcdccba85503b2f2fc85d1bc`, except `static-promotion.tf`, pinned to
CnesData main `258e55c58ea9109c4c4a35fc519ab9292027a4b0`. These are test fixtures only.
They are never loaded by delivery authorization or transported as a new contract.

The review covers all nine bootstrap instances and seven Phase A policies, with
synthetic account `123456789012`, region `us-east-2`, release `c` repeated 32 times,
and new ECS revision 2. Scheduler bootstrap inputs remain null, so each scheduler
policy has its exact PassRole statement and no RunTask statement. The externally
governed API role is `arn:aws:iam::123456789012:role/api`. Execution roles have their
three ECR/log statements; Athena targets only the operator workgroup; runtime and
canary policies retain every LeadingKeys, prefix, retention and PassedToService
condition. The two processing policies target exact unit/audit revisions, and the
verifier policy retains the exact ECS cluster condition on RunTask and on
DescribeTasks, which targets only processor-cluster tasks. The promotion fence
operator holds ConditionCheckItem only on the SEMAPHORE leading key and
DescribeExecution only on executions of the `cnesdata-prod` state machine.

Expected bytes are fixed independently of each test's observed state/API values.
Tests derive a new expectation from source and bind identity leaves, then require
full equality with these fixtures. Widening any of the 16 policy documents, removing
a required API observation, or changing state role/name is rejected.
