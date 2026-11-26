"""Keeper terminal producer (P17): final, host recovery and failed prepare, restoration and released publication."""
import tempfile
from collections import namedtuple
from pathlib import Path

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ROLLBACK_SCHEMA = "cnesdata.static-rollback/v1"
ROLLBACK_FIELDS = "schema plan_sha256 restored residual invalidation_id"
HOST_RECOVERY_JOB = "host-recovery / execute"
HOST_RECOVERY_ARTIFACT = "cnesdata-host-recovery"
NULL = b"null"
RESTORED_OPERATIONS = {"static": ("publish-static",), "unit": ("unit-seed", "unit-start", "unit-observe"),
                       "recovery": ("recovery-seed", "recovery-start", "recovery-observe"),
                       "audit": ("audit-start", "audit-observe")}
MODES = ("unit", "recovery", "audit")


def publication_limit(kind, window):
    """Q4: F for accepted-open and failed-closed-quiescent, the preparation deadline for failed-prepare-quiescent."""
    prepare = window["close"] is None
    c.require(kind in {"accepted-open", "failed-closed-quiescent", "failed-prepare-quiescent"}
              and (kind == "failed-prepare-quiescent") == prepare, "terminal publication window")
    return window["preparation_deadline"] if prepare else window["fixed_deadline"]


def publication_guard(keeper, kind, *, credential_limit):
    """The released publication guard over the record finish wrote, bounded by the Q4 limit."""
    from tools.cnesdata_delivery.application_gate import ReleasedPublicationGuard
    record, etag = keeper.lease.store.get()
    return ReleasedPublicationGuard(keeper.lease, record, etag, deadline=publication_limit(kind, record["lifecycle"]),
                                    credential_deadline=credential_limit, clock=keeper.clock, monotonic=keeper.monotonic)


def _operations(keeper):
    from tools.cnesdata_delivery.application_gate import _journal_of
    return {_journal_of(item)._request["operation"] for item in keeper._contexts}


def _untouched(keeper):
    operations = _operations(keeper)
    return {fact: not operations & set(names) for fact, names in RESTORED_OPERATIONS.items()}


def _source(observations, source, role):
    digest = c.digest(source[role])
    raw = observations.get(digest)
    c.require(type(raw) is bytes and c.sha(raw) == digest, f"terminal restoration source role={role}")
    return raw


def _prepare_restoration(keeper, source, window, observations):
    c.require(window["close"] is None and window["stage"] == "application-prepare" and window["decision"] is None,
              "terminal restoration window")
    c.closed(source, "terminal")
    _source(observations, source, "terminal")
    untouched = _untouched(keeper)
    return {mode: untouched[mode] for mode in MODES} | {"api": True, "static": untouched["static"],
                                                        "first_static_absent": False}


def recovery_handoff(raw, window):
    """The host handoff bound to the lease recovery decision: decision times, F and its proof digest."""
    from tools.cnesdata_delivery.application_gate import HOST_HANDOFF_FIELDS, HOST_MEMBER_LIMIT, RECOVERY_DECISION_FIELDS
    c.require(type(raw) is bytes, "host recovery handoff bytes")
    handoff = c.closed(c.loads(raw, canonical=True, limit=HOST_MEMBER_LIMIT), HOST_HANDOFF_FIELDS)
    c.require(type(handoff["version"]) is int and handoff["version"] == 1 and handoff["kind"] == "host-handoff",
              "host recovery handoff kind")
    decision, bound = handoff["recovery_decision"], window["decision"]
    c.closed(decision, RECOVERY_DECISION_FIELDS)
    c.require(bound is not None and bound["choice_at"] == int(c.instant(decision["choice_at"]))
              and bound["deadline"] == int(c.instant(decision["recovery_deadline"]))
              and window["fixed_deadline"] == int(c.instant(decision["fixed_deadline"]))
              and handoff["recovery_proof_sha256"] == c.sha(c.canonical(decision)), "host recovery decision binding")
    return handoff


def _recovery_restoration(keeper, source, window, observations):
    c.require(window["close"] is not None and window["stage"] == "recovery" and window["decision"] is not None,
              "terminal restoration window")
    c.closed(source, "rollback host-recovery")
    rollback = c.closed(c.loads(_source(observations, source, "rollback"), canonical=True, limit=1024**2), ROLLBACK_FIELDS)
    c.digest(rollback["plan_sha256"])
    c.require(rollback["schema"] == ROLLBACK_SCHEMA and type(rollback["restored"]) is list
              and all(type(item) is list and len(item) == 2 and all(type(part) is str for part in item)
                      for item in rollback["restored"])
              and type(rollback["residual"]) is bool and type(rollback["invalidation_id"]) in (str, type(None)),
              "terminal restoration rollback")
    raw = keeper.host_recovery
    c.require(type(raw) is bytes and c.sha(raw) == c.digest(source["host-recovery"]), "terminal restoration host-recovery")
    handoff = recovery_handoff(raw, window)
    untouched = _untouched(keeper)
    return {mode: untouched[mode] for mode in MODES} | {"api": handoff["status"] == "rolled_back",
                                                        "static": rollback["residual"] is False,
                                                        "first_static_absent": False}


def restoration_validator(keeper):
    """Keeper restoration facts: the state before close (failed prepare) or the rollback and the rolled_back host."""
    def validator(source, *, owner, window, observations):
        c.require(type(source) is dict and type(observations) is dict, "terminal restoration source")
        if window["close"] is None:
            facts = _prepare_restoration(keeper, source, window, observations)
        else:
            facts = _recovery_restoration(keeper, source, window, observations)
        return {"sha256": c.sha(c.canonical(source)), "facts": facts}
    return validator


TerminalContext = namedtuple("TerminalContext", "governance authority state credential_limit operation_session clock")


def _fence_scope(journal, keeper, context, prepared):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr
    governance, operation = context.governance, journal._request["operation"]
    keeper.lease.check()
    owner = journal._request["owner"] | journal._identity
    manifest, role, evaluation = (c.loads(prepared[name], canonical=True)
                                  for name in ("fence-prepared.json", "fence-role.json", "fence-evaluation.json"))
    c.require(manifest["activation_sha256"] == journal._request["activation_sha256"], "prepared/request activation_sha256")
    c.require(role["role_arn"] == governance["application_delegations"]["fence_operator"], "fence_operator delegation")
    c.require(c.canonical(manifest["owner"]) == c.canonical(owner), "prepared current owner")
    cases = {case["case_id"]: case for case in evaluation["cases"]}
    derived = lr.fence_policy_scope(governance, role["policy"])
    c.require(cases["get-fence"]["resource"] == derived["control_table_arn"]
              and cases["probe-own"]["resource"] == derived["execution_prefix"] + "0" * 16,
              "capability scope recomputed from prepared policy")
    scope = {"account": governance["account_id"], "control_table_arn": derived["control_table_arn"],
             "machine_arn": derived["machine_arn"]}
    if operation == "terminal-readback":
        membership = journal._inputs["membership"]
        frozen = (c.canonical({"frozen_membership_sha256": c.sha(c.canonical([])), "members": []})
                  if journal._request["stage"]["close"] is None else ag._frozen_membership(context.state["close-drain"]))
        c.require(membership == frozen, "terminal-readback membership is the close-drain frozen set")
        scope["members"] = c.loads(membership, canonical=True)["members"]
    return role, scope


def terminal_fence_capability(*, journal, keeper, context):
    """reopen and terminal-readback on the fence session of the authenticated PreparedFence (P17b): the recomputed
    scope, the local operation-session effective IAM, the fence STS, then ClosedReadyBroker for reopen (the final CAS)
    and FenceReadBroker for terminal-readback. Every check precedes STS. Returns: the broker. Raises: ValueError."""
    from tools.cnesdata_delivery import application_gate as ag
    from tools.cnesdata_delivery.application_gate import ClosedReadyBroker, _assume_fence_session
    from tools.cnesdata_delivery.mode_broker import FenceReadBroker
    prepared = context.state.get("prepared")
    c.require(prepared is not None, "terminal_broker=prepared_absent")
    role, scope = _fence_scope(journal, keeper, context, prepared)
    ag._fence_operation_iam(context.governance, context.authority, journal, role, context.clock)
    journal.guard()
    prepared_sha256 = c.sha(prepared["fence-prepared.json"])
    session = _assume_fence_session(governance=context.governance, role=role, scope=scope, journal=journal,
                                    prepared_sha256=prepared_sha256, credential_limit=context.credential_limit,
                                    operation_session=context.operation_session, clock=context.clock)
    arguments = (session.evidence, context.governance, journal, session)
    if journal._request["operation"] == "reopen":
        broker = ClosedReadyBroker(*arguments, prepared_sha256=prepared_sha256, clock=context.clock)
    else:
        broker = FenceReadBroker(*arguments, prepared_sha256=prepared_sha256, clock=context.clock)
    keeper.attach(broker)
    return broker


def rollback_capability(*, journal, keeper, context):
    """rollback-api-static in StaticBroker under the static recovery alias (P17b): the static plan the keeper holds,
    the run binding against the operational carrier, the recovery role facts of the operational deploy, the
    sp-rollback STS. Every check precedes STS. Returns: StaticBroker. Raises: ValueError."""
    from tools.cnesdata_delivery import application_gate as ag, static_inputs
    from tools.cnesdata_delivery.application_gate import StaticBroker, _assume_static_session
    state, governance = context.state, context.governance
    keeper.lease.check()
    plan = lc.static_plan(journal._inputs["static-plan"], bucket=ag.STATIC_BUCKET)
    c.require(journal._inputs["static-plan"] == state.get("static-plan")
              and plan["inventory_sha256"] == c.sha(journal._inputs["inventory"])
              and plan["distribution_arn"].split(":")[4] == governance["account_id"], "terminal rollback static plan")
    binding = ag._static_binding(governance, journal, candidate=(keeper.static_inputs or {}).get("candidate"))
    ag._compare_carrier(binding, static_inputs.carrier_binding(state["terraform"]))
    roles = static_inputs.static_role_facts(state["prepared"]["checkpoint.json"], state["prepared"]["approval.json"],
                                            governance=governance, aliases=("recovery",))
    session = _assume_static_session(governance=governance, journal=journal, binding=binding, roles=roles,
                                     credential_limit=context.credential_limit,
                                     operation_session=context.operation_session, clock=context.clock)
    broker = StaticBroker(session.evidence, governance, journal, session, clock=context.clock)
    keeper.attach(broker)
    return broker


def terminal_capability(*, journal, keeper, guard, context):
    """Production broker of reopen, terminal-readback and rollback-api-static (P17b): the fence session for the first
    two, StaticBroker under the recovery alias for the rollback. A refusal fails the journal and the lease stays held.
    Returns: the attached broker. Raises: ValueError."""
    try:
        c.require(type(context) is TerminalContext, "terminal_broker=unconnected")
        if journal._request["operation"] == "rollback-api-static":
            return rollback_capability(journal=journal, keeper=keeper, context=context)
        return terminal_fence_capability(journal=journal, keeper=keeper, context=context)
    except BaseException:
        journal._failed = True
        raise


def final_routes(keeper):
    """Routes document of reopen at final (ruling 1g): the closed projection of the routes of the authenticated
    phase-c-audit element, which the C deploy job read back after apply. Raises: ValueError."""
    elements = getattr(keeper, "phase_c_elements", None)
    raw = elements.get("phase-c-audit") if type(elements) is dict else None
    element = c.loads(raw) if type(raw) is bytes else None
    routes = element.get("routes") if type(element) is dict else None
    c.require(element is not None and element.get("kind") == "phase-c-audit" and type(routes) is dict
              and set(routes) == set(MODES) and all(type(routes[mode]) is str for mode in MODES), "terminal final routing")
    return c.canonical({mode: routes[mode] for mode in MODES})


def terminal_input_source(*, keeper, owner, window, operation, names):
    """The keeper-held originals of a terminal operation: only routing of reopen at final. Raises: ValueError."""
    c.require(operation == "reopen" and window["stage"] == "final" and list(names) == ["routing"],
              "terminal_inputs=source_unconnected")
    return {"routing": final_routes(keeper)}


def recovery_routes(state):
    """Routes document of the observe-only reopen at recovery: the closed projection of the plan carrier revisions
    the prepared stage kept. It checks carrier consistency, not live routes. Raises: ValueError."""
    revisions = state.get("revisions")
    c.require(type(revisions) is dict and set(revisions) == set(MODES)
              and all(type(revisions[mode]) is str for mode in MODES), "terminal recovery routing revisions")
    return c.canonical({mode: revisions[mode] for mode in MODES})


def run_terminal_operation(keeper, operation, *, inputs, activation, invoke, credential_limit, clock, context=None):
    """One terminal operation: journal under the keeper guard, the injected capability before the child, timeout
    from the keeper window. Returns: the single observation bytes. Raises: ValueError."""
    from tools.cnesdata_delivery import application_gate as ag
    from tools.cnesdata_delivery.application_gate import KeeperGuard
    record = keeper.lease.check()
    window, owner = record["lifecycle"], lc.owner_binding(record)
    c.closed(inputs, lc.ADAPTER_INPUTS[operation])
    guard = KeeperGuard(keeper)
    journal = ag.AdapterJournal(ag._operation_request(operation, owner=owner, window=window, inputs=inputs,
                                                      activation=activation),
                                operation=operation, owner=owner, window=window, inputs=inputs,
                                activation_sha256=c.sha(activation), guard=guard)
    keeper.attach(journal)
    broker = terminal_capability(journal=journal, keeper=keeper, guard=guard, context=context)
    try:
        invoke(journal=journal, timeout=lc.adapter_seconds(window, now=clock(), credential_deadline=credential_limit,
                                                            operation=operation))
    finally:
        ag._drop_operation_clients(broker)
    kind = lc.ADAPTER_OBSERVATIONS[operation]
    observed = [entry for entry in journal._observations if entry["kind"] == kind]
    c.require(len(journal._observations) == len(observed) == 1 and not keeper.uncertainty(),
              f"{operation} single observation without uncertainty")
    return journal._observation_bytes[observed[0]["sha256"]]


def _observation(keeper, operation):
    from tools.cnesdata_delivery import application_gate as ag
    journals = ag._operation_journals(keeper, operation)
    c.require(len(journals) <= 1, f"terminal single {operation} journal")
    if not journals:
        return None
    (entry,) = journals[0]._observations
    return journals[0]._observation_bytes[entry["sha256"]]


def _mode_canaries(keeper, owner):
    from tools.cnesdata_delivery import application_gate as ag
    values = []
    for mode in MODES:
        digest, _ = ag.mode_observation(keeper, mode, owner)
        values.append(c.loads(ag._mode_journal(keeper, mode)._observation_bytes[digest], canonical=True))
    return c.canonical(values)


def enter_recovery(keeper, raw, *, ready, state, clock):
    """DD-3 amendment: a recovery_required host handoff of the keeper closed-ready, bound to its own decision, moves the
    api stage to recovery with the lease decision. Returns: the recovery window. Raises: ValueError."""
    from tools.cnesdata_delivery.application_gate import HOST_HANDOFF_FIELDS, RECOVERY_DECISION_FIELDS
    value = c.closed(c.loads(raw, canonical=True), HOST_HANDOFF_FIELDS)
    decision = value["recovery_decision"]
    c.require(value["status"] == "recovery_required" and value["closed_ready_sha256"] == ready
              and type(decision) is dict, "host recovery_required handoff with the decision of the keeper closed-ready")
    c.closed(decision, RECOVERY_DECISION_FIELDS)
    c.require(not keeper.uncertainty(), "host handoff with unresolved keeper uncertainty")
    window = keeper.lease.check()["lifecycle"]
    choice, admitted = int(c.instant(decision["choice_at"])), int(clock())
    deadline = min(window["fixed_deadline"], choice + 420)
    c.require(window["stage"] == "api" and window["decision"] is None and window["close"] <= choice <= admitted,
              "recovery follows the api stage")
    stage_deadline = min(deadline - 120, choice + 300)
    recovery = window | {"sequence": window["sequence"] + 1, "stage": "recovery", "admitted_at": admitted,
                         "deadline": stage_deadline,
                         "decision": {"choice_at": choice, "deadline": deadline,
                                      "checkpoint_sha256": c.digest(decision["checkpoint_sha256"])}}
    recovery_handoff(raw, recovery)
    c.require(admitted < stage_deadline, "recovery stage deadline elapsed")
    keeper.lease.checkpoint(recovery)
    state.update({"recovery-decision": c.canonical(decision), "host-recovery-receipt": raw})
    return recovery


class TerminalSteps:
    """The three terminal sequences of the keeper; each closes with finish and the released publication."""
    def __init__(self, *, keeper, api, governance, run, state, product, credential_limit, clock, authority,
                 operation_session):
        self.keeper, self.api, self.governance, self.run = keeper, api, governance, run
        self.state, self.product, self.credential_limit, self.clock = state, product, credential_limit, clock
        self.context = TerminalContext(governance=governance, authority=authority, state=state,
                                       credential_limit=credential_limit, operation_session=operation_session, clock=clock)

    def _operation(self, keeper, operation, inputs, *, activation=None):
        from tools.cnesdata_delivery import application_gate as ag
        owner = lc.owner_binding(keeper.lease.check())

        def invoke(*, journal, timeout):
            return ag.invoke_adapter(product=self.product, source=owner["source_sha"],
                                     manifest=self.governance["application_product_source_manifest"],
                                     manifest_sha256=self.governance["application_product_source_closure_sha256"],
                                     journal=journal, timeout=timeout)
        return run_terminal_operation(keeper, operation, inputs=inputs,
                                      activation=self.state["activation"] if activation is None else activation,
                                      invoke=invoke, credential_limit=self.credential_limit, clock=self.clock,
                                      context=self.context)

    def _reopen(self, keeper, extra, *, routing=None):
        if routing is None:
            record = keeper.lease.check()
            owner, window = lc.owner_binding(record), record["lifecycle"]
            routes = dict(terminal_input_source(keeper=keeper, owner=owner, window=window, operation="reopen",
                                                names=["routing"]))
            routing = c.closed(routes, "routing")["routing"]
        return self._operation(keeper, "reopen", {"activation": self.state["activation"], "routing": routing} | extra)

    def _close(self, keeper, kind, checkpoint_raw, sources):
        from tools.cnesdata_delivery.application_gate import publish_terminal
        files = keeper.finish({"kind": kind, "checkpoint_raw": checkpoint_raw, "sources": sources})
        terminal = c.loads(files["terminal.json"], canonical=True)
        guard = publication_guard(keeper, kind, credential_limit=self.credential_limit)
        with tempfile.TemporaryDirectory(prefix="cnesdata-terminal-") as directory:
            temp = Path(directory)
            temp.chmod(0o700)
            receipt = publish_terminal(keeper.evidence_aws, self.api, self.governance, files, guard, temp)
        return {"kind": kind, "promotion_status": terminal["promotion_status"], "receipt": receipt}

    def final(self, keeper):
        """accepted-open at the final stage: reopen, terminal-readback, finish, publication."""
        from tools.cnesdata_delivery.application_gate import _frozen_membership, mode_observation
        window = keeper.lease.check()["lifecycle"]
        c.require(window["stage"] == "final" and window["decision"] is None, "terminal final stage")
        owner = lc.owner_binding(keeper.lease.check())
        membership = _frozen_membership(self.state["close-drain"])
        routing = self._reopen(keeper, {"canaries": _mode_canaries(keeper, owner), "membership": membership})
        publication, host, ready = _observation(keeper, "publish-static"), self.state["host-receipt"], self.state["closed-ready"]
        c.require(publication is not None, "terminal final publication")
        readback = self._operation(keeper, "terminal-readback", {"routing": routing, "membership": membership,
                                                                 "host-receipt": host, "static-receipt": publication,
                                                                 "decision": NULL})
        sources = {mode: {"mode": mode_observation(keeper, mode, owner)[0]} for mode in MODES}
        sources |= {"host": {"host-handoff": c.sha(host), "closed-ready": ready},
                    "static": {"publication": c.sha(publication), "closed-ready": ready},
                    "routing": {"routing": c.sha(routing)},
                    "membership": {"close-drain": c.sha(self.state["close-drain"]), "terminal": c.sha(readback)},
                    "quiescence": {"terminal": c.sha(readback)}}
        return self._close(keeper, "accepted-open", self.state["checkpoint"], sources)

    def host_recovery(self, keeper, reference):
        """failed-closed-quiescent: the rolled_back host-recovery handoff bound to the lease decision, then
        rollback-api-static, the observe-only reopen and terminal-readback at recovery, finish, publication."""
        from tools.cnesdata_delivery import application_gate as ag
        from tools.cnesdata_delivery.application_gate import KeeperGuard
        c.closed(reference, "job_id")
        record = keeper.lease.check()
        owner, window = lc.owner_binding(record), record["lifecycle"]
        decision = self.state.get("recovery-decision")
        c.require(window["stage"] == "recovery" and decision is not None, "host-recovery follows the keeper recovery decision")
        c.require("publish-static" not in _operations(keeper), "rollback publication null with a publish-static attempt")
        routes = recovery_routes(self.state)
        raw = ag.authenticate_host_handoff(self.api, owner, guard=KeeperGuard(keeper), job=HOST_RECOVERY_JOB,
                                           artifact=HOST_RECOVERY_ARTIFACT)
        handoff = recovery_handoff(raw, window)
        c.require(handoff["status"] == "rolled_back" and handoff["closed_ready_sha256"] == self.state["closed-ready"]
                  and c.canonical(handoff["recovery_decision"]) == decision and not keeper.uncertainty(),
                  "host-recovery rolled_back bound to the keeper decision")
        keeper.host_recovery = raw
        rollback = self._operation(keeper, "rollback-api-static", {
            "static-plan": self.state["static-plan"], "inventory": keeper.static_inventory, "publication": NULL,
            "host-recovery-receipt": self.state["host-recovery-receipt"], "recovery-decision": decision})
        membership = ag._frozen_membership(self.state["close-drain"])
        routing = self._reopen(keeper, {"canaries": NULL, "membership": membership}, routing=routes)
        readback = self._operation(keeper, "terminal-readback", {"routing": routing, "membership": membership,
                                                                 "host-receipt": raw, "static-receipt": rollback,
                                                                 "decision": decision})
        sources = {"decision": {"recovery-decision": c.sha(decision)},
                   "restoration": {"rollback": c.sha(rollback), "host-recovery": c.sha(raw)},
                   "routing": {"routing": c.sha(routing)},
                   "membership": {"close-drain": c.sha(self.state["close-drain"]), "terminal": c.sha(readback)},
                   "quiescence": {"terminal": c.sha(readback)}}
        return self._close(keeper, "failed-closed-quiescent", self.state["checkpoint"], sources)

    def prepare_failure(self, keeper, error):
        """failed-prepare-quiescent after a refusal before the close: terminal-readback with no members, finish over
        the predecessor checkpoint, publication. With keeper uncertainty the original refusal stands."""
        window = keeper.lease.check()["lifecycle"]
        c.require(window["close"] is None and window["stage"] == "application-prepare" and window["sequence"] == 0,
                  "failed prepare window")
        if keeper.uncertainty():
            raise error
        activation = self.state.get("activation") or c.canonical(self.governance["release"])
        empty = c.canonical({"frozen_membership_sha256": c.sha(c.canonical([])), "members": []})
        readback = self._operation(keeper, "terminal-readback", {"routing": NULL, "membership": empty, "host-receipt": NULL,
                                                                 "static-receipt": NULL, "decision": NULL},
                                   activation=activation)
        sources = {"restoration": {"terminal": c.sha(readback)}, "quiescence": {"terminal": c.sha(readback)}}
        return self._close(keeper, "failed-prepare-quiescent", keeper.predecessor["raw"], sources)
