"""Window and stage triggers of the application lifecycle (#55 2nd slice amendment 6886977054, decisions 2 and 3)."""
import io
import json
import zipfile
from types import SimpleNamespace

import pytest

from tools.cnesdata_delivery import contract as c

IDENTITY = {"application_purpose": "promotion", "context_kind": "promotion", "caller_binding_sha256": "c" * 64}
PREVIOUS = {"sequence": 0, "preparation_deadline": 1900, "close": None, "fixed_deadline": None, "input_deadline": None,
            "stage": "application-prepare", "admitted_at": 900, "deadline": 1900, "decision": None,
            "checkpoint_sha256": "a" * 64, "predecessor_sha256": "e" * 64, **IDENTITY}
OWNER = {"source_sha": "b" * 40, "run_id": 4242, "run_attempt": 1, "owner_sha256": "4" * 64, "generation": 7}
RUN = {"id": 4242, "run_attempt": 1, "head_sha": "b" * 40}
ROOT = f"repos/{c.REPOSITORY}/actions"
JOBS = ROOT + "/runs/4242/attempts/1/jobs?per_page=100&page=1"
ARTIFACTS = ROOT + "/runs/4242/artifacts?per_page=100&page=1"
PHASE_B = {"role": "deploy", "purpose": "phase-b", "direction": "advance", "job_name": "phase-b / execute"}
GOVERNANCE = {"lifecycle_steps": {"phase-b-advance": PHASE_B,
                                  "phase-b-retreat": PHASE_B | {"direction": "retreat", "job_name": "phase-b-retreat / execute"},
                                  "phase-b-plan": PHASE_B | {"role": "plan", "job_name": "phase-b-plan / execute"}}}


def _close_drain(**changes):
    value = {"version": 1, "kind": "close-drain", "common": {}, "fence": {}, "close_confirmed_at": c.utc(1000),
             "drain_observed_at": c.utc(1010), "frozen_membership_sha256": "7" * 64, "members": [], "proofs": [],
             "permit": None, "input_expirations": [
                 {"kind": "activation", "object_sha256": "1" * 64, "expires_at": c.utc(4000)},
                 {"kind": "plan", "object_sha256": "2" * 64, "expires_at": c.utc(5000)}],
             "fixed_deadline": c.utc(2800), "decision": None}
    return value | changes


def _close(value=None, previous=PREVIOUS, *, infra_bound=4000, now=1005):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    raw = c.canonical(_close_drain() if value is None else value)
    return lc.close_window(dict(previous), raw, checkpoint_sha256="f" * 64, infra_bound=infra_bound, now=now)


def test_stage_constants_are_the_ratified_ones():
    """6755178450:140: F=min(close+1800, expirations); API180; later840; recovery reserve420."""
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.STAGES == {"phase-b": (360, 1020), "api": (180, 840), "static": (180, 660), "unit": (120, 540),
                         "phase-c-recovery": (240, 300), "phase-c-audit": (240, 60), "final": (60, 0)}
    names = list(lc.STAGES)
    for index, name in enumerate(names):
        assert lc.STAGES[name][1] == sum(lc.STAGES[later][0] for later in names[index + 1:]), name
    assert lc.STAGES["api"][1] == 180 + 120 + 240 + 240 + 60
    window = {"close": 940, "fixed_deadline": 2740, "input_deadline": 4000, "stage": "api", "admitted_at": 1300,
              "deadline": 1480, "decision": None, "preparation_deadline": 1900}
    lc.phase_capacity(window, now=1300, credential_deadline=9000, operation_seconds=20)
    assert window["fixed_deadline"] - 1300 == (window["deadline"] - 1300) + 840 + 420
    with pytest.raises(ValueError, match="phase remaining capacity"):
        lc.phase_capacity(window | {"fixed_deadline": 2739, "input_deadline": 2739}, now=1300, credential_deadline=9000,
                          operation_seconds=20)


def test_close_window_derives_fixed_deadline_from_the_journal_close_drain():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    current = _close()
    assert current == PREVIOUS | {"sequence": 1, "close": 1000, "fixed_deadline": 2800, "input_deadline": 4000,
                                  "stage": "phase-b", "admitted_at": 1000, "deadline": 1360, "checkpoint_sha256": "f" * 64}
    assert all(type(current[key]) is int for key in ("close", "fixed_deadline", "input_deadline", "admitted_at", "deadline"))
    lc.checkpoint_transition(PREVIOUS, current)
    lc.phase_capacity(current, now=1005, credential_deadline=9000, operation_seconds=20)
    lc.phase_capacity(current, now=1300, credential_deadline=9000, operation_seconds=20)


def test_close_window_takes_the_earliest_original_expiration():
    """F is the minimum, and a B born at close then has no capacity: products must clear close + 1800."""
    from tools.cnesdata_delivery import lifecycle_contract as lc
    expirations = [{"kind": "activation", "object_sha256": "1" * 64, "expires_at": c.utc(5000)},
                   {"kind": "credential", "object_sha256": "3" * 64, "expires_at": c.utc(2500)},
                   {"kind": "plan", "object_sha256": "2" * 64, "expires_at": c.utc(2600)}]
    current = _close(_close_drain(input_expirations=expirations, fixed_deadline=c.utc(2500)), infra_bound=2500)
    assert (current["input_deadline"], current["fixed_deadline"], current["deadline"]) == (2500, 2500, 1360)
    lc.checkpoint_transition(PREVIOUS, current)
    with pytest.raises(ValueError, match="phase remaining capacity"):
        lc.phase_capacity(current, now=1005, credential_deadline=9000, operation_seconds=20)


def test_close_window_bounds_phase_b_by_f_when_inputs_expire_before_close_plus_360():
    expirations = [{"kind": "activation", "object_sha256": "1" * 64, "expires_at": c.utc(1300)}]
    current = _close(_close_drain(input_expirations=expirations, fixed_deadline=c.utc(1300)), infra_bound=1300)
    assert (current["input_deadline"], current["fixed_deadline"], current["deadline"]) == (1300, 1300, 1300)


def test_close_window_admits_infra_bound_equal_to_input_deadline():
    assert _close(infra_bound=4000)["input_deadline"] == 4000


_CLOSE_REFUSALS = {
    "infra-bound": ({}, {"infra_bound": 3999}, "infra-known authenticated expiration precedes input deadline"),
    "doc-fixed": ({"fixed_deadline": c.utc(2801)}, {}, "original fixed deadline"),
    "doc-fixed-input": ({"fixed_deadline": c.utc(4000)}, {}, "original fixed deadline"),
    "kind": ({"input_expirations": [{"kind": "routing", "object_sha256": "1" * 64, "expires_at": c.utc(4000)}]}, {},
             "original input expiration kind"),
    "unsorted": ({"input_expirations": list(reversed(_close_drain()["input_expirations"]))}, {},
                 "unique original input expirations"),
    "duplicate": ({"input_expirations": [_close_drain()["input_expirations"][0]] * 2}, {}, "unique original input expirations"),
    "empty": ({"input_expirations": []}, {}, "original input expirations"),
    "not-list": ({"input_expirations": {"kind": "plan"}}, {}, "original input expirations"),
    "expiry-field": ({"input_expirations": [_close_drain()["input_expirations"][0] | {"extra": 1}]}, {}, "closed object fields"),
    "object-digest": ({"input_expirations": [_close_drain()["input_expirations"][0] | {"object_sha256": "x"}]}, {}, "^digest$"),
    "expiry-time": ({"input_expirations": [_close_drain()["input_expirations"][0] | {"expires_at": 4000}]}, {}, "UTC timestamp"),
    "permit": ({"permit": {"holder": "other"}}, {}, "original idle permit/decision"),
    "decision": ({"decision": {"choice": "rollback"}}, {}, "original idle permit/decision"),
    "version": ({"version": 2}, {}, "close-drain observation version/kind"),
    "version-type": ({"version": True}, {}, "close-drain observation version/kind"),
    "doc-kind": ({"kind": "closed-ready"}, {}, "close-drain observation version/kind"),
    "early": ({"close_confirmed_at": c.utc(899), "fixed_deadline": c.utc(2699)}, {}, "close inside the preparation stage"),
    "future": ({}, {"now": 999}, "close inside the preparation stage"),
    "late": ({"close_confirmed_at": c.utc(1900), "fixed_deadline": c.utc(3700)}, {"now": 1950}, "close inside the preparation stage"),
}


@pytest.mark.parametrize("mutation", sorted(_CLOSE_REFUSALS))
def test_close_window_refuses_anything_but_the_original_close_drain(mutation):
    changes, kwargs, message = _CLOSE_REFUSALS[mutation]
    with pytest.raises(ValueError, match=message):
        _close(_close_drain(**changes), **kwargs)


def test_close_window_refuses_extra_fields_and_non_canonical_bytes():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    with pytest.raises(ValueError, match="closed object fields"):
        _close(_close_drain(extra=1))
    raw = c.canonical(_close_drain()).replace(b'"version":1', b'"version": 1')
    with pytest.raises(ValueError):
        lc.close_window(dict(PREVIOUS), raw, checkpoint_sha256="f" * 64, infra_bound=4000, now=1005)
    with pytest.raises(ValueError):
        lc.close_window(dict(PREVIOUS), _close_drain(), checkpoint_sha256="f" * 64, infra_bound=4000, now=1005)


@pytest.mark.parametrize("previous", [PREVIOUS | {"stage": "phase-b", "close": 1000, "fixed_deadline": 2800, "input_deadline": 4000},
                                      PREVIOUS | {"stage": "phase-b"},
                                      PREVIOUS | {"close": 950, "fixed_deadline": 2750, "input_deadline": 4000},
                                      PREVIOUS | {"decision": {"choice_at": 1000}}])
def test_close_window_only_leaves_the_open_preparation_stage(previous):
    with pytest.raises(ValueError, match="close inside the preparation stage"):
        _close(previous=previous)


@pytest.mark.parametrize("bad", [{"checkpoint_sha256": "x"}, {"infra_bound": 4000.0}, {"infra_bound": True}])
def test_close_window_requires_typed_checkpoint_and_infra_bound(bad):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    arguments = {"checkpoint_sha256": "f" * 64, "infra_bound": 4000, "now": 1005} | bad
    with pytest.raises(ValueError):
        lc.close_window(dict(PREVIOUS), c.canonical(_close_drain()), **arguments)


def test_api_window_is_admitted_when_the_keeper_observes_b_never_at_close():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    phase_b = _close()
    current = lc.api_window(dict(phase_b), checkpoint_sha256="9" * 64, now=1300.7)
    assert current == phase_b | {"sequence": 2, "stage": "api", "admitted_at": 1300, "deadline": 1480, "checkpoint_sha256": "9" * 64}
    assert type(current["admitted_at"]) is int and type(current["deadline"]) is int
    lc.checkpoint_transition(phase_b, current)
    lc.phase_capacity(current, now=1300, credential_deadline=9000, operation_seconds=20)
    short = lc.api_window(phase_b | {"fixed_deadline": 1400, "input_deadline": 1400}, checkpoint_sha256="9" * 64, now=1300)
    assert short["deadline"] == 1400


@pytest.mark.parametrize("change", [{"stage": "application-prepare"}, {"stage": "api"}, {"close": None},
                                    {"decision": {"choice_at": 1200}}, {"admitted_at": 1301}])
def test_api_window_only_follows_the_closed_phase_b(change):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    with pytest.raises(ValueError, match="API follows the closed phase-b stage"):
        lc.api_window(_close() | change, checkpoint_sha256="9" * 64, now=1300)
    with pytest.raises(ValueError):
        lc.api_window(_close(), checkpoint_sha256="x", now=1300)


def test_stage_triggers_are_the_closed_ratified_table():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert lc.STAGE_TRIGGERS == {"application-prepare": ("prepared", "phase-b"), "phase-b": ("phase-b", "api")}
    order = ["application-prepare", *lc.STAGES]
    for stage, (_, following) in lc.STAGE_TRIGGERS.items():
        assert order.index(following) == order.index(stage) + 1


def _authority(**changes):
    from tools.cnesdata_delivery.session_owner import Authority
    values = {"pin": {"frozen_until": c.utc(5500)}, "expires_at": 5000.0, "application_fragment": {"enabled_until": c.utc(5200)}}
    values |= changes
    return Authority(values["pin"], values["expires_at"], None, values["application_fragment"])


def _expiries(*values):
    return SimpleNamespace(expiries={("VINIClUS/CnesData", index): value for index, value in enumerate(values, 1)})


def test_infra_expiration_bound_is_the_earliest_of_the_four_authenticated_expirations():
    """Errata 6887682424: owner proof, api.expiries, fragment enabled_until and pin frozen_until."""
    from tools.cnesdata_delivery import application_gate as ag
    bound = ag.infra_expiration_bound(_authority(), _expiries(6000.0, 7000.0))
    assert bound == 5000 and type(bound) is int
    assert ag.infra_expiration_bound(_authority(), _expiries(6000.0, 4500.0)) == 4500
    assert ag.infra_expiration_bound(_authority(application_fragment={"enabled_until": c.utc(4400)}), _expiries(6000.0)) == 4400
    assert ag.infra_expiration_bound(_authority(pin={"frozen_until": c.utc(4300)}), _expiries(6000.0)) == 4300


@pytest.mark.parametrize("missing", ["expiries", "fragment", "enabled_until", "pin", "frozen_until", "authority-type"])
def test_infra_expiration_bound_refuses_when_any_source_is_missing(missing):
    from tools.cnesdata_delivery import application_gate as ag
    authority, api = _authority(), _expiries(6000.0)
    if missing == "expiries": api = _expiries()
    if missing == "fragment": authority = _authority(application_fragment=None)
    if missing == "enabled_until": authority = _authority(application_fragment={"fragment": True})
    if missing == "pin": authority = _authority(pin=None)
    if missing == "frozen_until": authority = _authority(pin={"observed_at": c.utc(900)})
    if missing == "authority-type":
        authority = SimpleNamespace(pin={"frozen_until": c.utc(5500)}, expires_at=5000.0, application_fragment={"enabled_until": c.utc(5200)})
    with pytest.raises(ValueError, match="application authenticated expirations"):
        ag.infra_expiration_bound(authority, api)


def _bound_api(*values):
    keys = [("VINIClUS/CnesData", index) for index in range(1, len(values) + 1)]
    return SimpleNamespace(expiries=dict(zip(keys, values)), digests={key: str(key[1]) * 64 for key in keys})


def _close_authority(**changes):
    from dataclasses import replace
    return replace(_authority(**changes), proof_sha256="3" * 64)


def test_close_expirations_are_the_authenticated_originals_and_their_minimum_is_the_infra_bound():
    """Correction 6906038586 item 1: credential, artifact and platform originals, sorted and unique."""
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    authority, api = _close_authority(), _bound_api(6000.0, 4800.0)
    raw = ag.close_expirations(authority, api)
    value = c.loads(raw, canonical=True)
    assert raw == c.canonical(value) and value == [
        {"kind": "artifact", "object_sha256": "1" * 64, "expires_at": c.utc(6000)},
        {"kind": "artifact", "object_sha256": "2" * 64, "expires_at": c.utc(4800)},
        {"kind": "credential", "object_sha256": "3" * 64, "expires_at": c.utc(5000)},
        *sorted([{"kind": "platform", "object_sha256": c.sha(c.canonical(authority.application_fragment)), "expires_at": c.utc(5200)},
                 {"kind": "platform", "object_sha256": c.sha(c.canonical(authority.pin)), "expires_at": c.utc(5500)}],
                key=lambda item: item["object_sha256"])]
    assert {item["kind"] for item in value} <= lc.CLOSE_EXPIRATION_KINDS - {"envelope"}
    bound = ag.infra_expiration_bound(authority, api)
    assert min(int(c.instant(item["expires_at"])) for item in value) == bound == 4800
    envelope = {"kind": "envelope", "object_sha256": "9" * 64, "expires_at": c.utc(2800)}
    product = sorted([*value, envelope], key=lambda item: (item["kind"], item["object_sha256"]))
    window = _close(_close_drain(input_expirations=product), infra_bound=bound)
    assert window["input_deadline"] == 2800 and window["fixed_deadline"] == 2800


@pytest.mark.parametrize("mutation", ["no-proof", "proof-digest", "no-digests", "missing-digest", "extra-digest", "digest-prefix",
                                      "duplicate-artifact", "duplicate-platform", "no-expiries"])
def test_close_expirations_refuse_unbound_or_duplicate_originals(mutation):
    from dataclasses import replace
    from tools.cnesdata_delivery import application_gate as ag
    authority, api = _close_authority(), _bound_api(6000.0, 7000.0)
    first, second = list(api.expiries)
    if mutation == "no-proof": authority = replace(authority, proof_sha256=None)
    if mutation == "proof-digest": authority = replace(authority, proof_sha256="3" * 63)
    if mutation == "no-digests": del api.digests
    if mutation == "missing-digest": api.digests.pop(second)
    if mutation == "extra-digest": api.digests[("VINIClUS/CnesData", 9)] = "9" * 64
    if mutation == "digest-prefix": api.digests[first] = "sha256:" + "1" * 64
    if mutation == "duplicate-artifact": api.digests[second] = api.digests[first]
    if mutation == "duplicate-platform": authority = replace(authority, pin={"enabled_until": c.utc(5200), "frozen_until": c.utc(5200)},
                                                            application_fragment={"enabled_until": c.utc(5200), "frozen_until": c.utc(5200)})
    if mutation == "no-expiries": api = SimpleNamespace(expiries={}, digests={})
    with pytest.raises(ValueError):
        ag.close_expirations(authority, api)


def _archive(index):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as output:
        output.writestr(zipfile.ZipInfo("index.json", date_time=(2026, 1, 1, 0, 0, 0)), c.canonical(index))
    return buffer.getvalue()


class _GitHub:
    def __init__(self, job_name, step, mutation=None, index=None):
        index = index or {"step": step, "owner_sha256": OWNER["owner_sha256"], "generation": OWNER["generation"]}
        index |= {"owner": {"owner_sha256": "5" * 64}, "generation": {"generation": 8}, "generation-type": {"generation": "7"},
                  "step": {"step": "other-step"}}.get(mutation, {})
        archive = _archive(index)
        job = {"id": 77, "run_id": 4242, "run_attempt": 1, "head_sha": "b" * 40, "name": job_name, "status": "completed",
               "conclusion": "success", "started_at": c.utc(1100), "completed_at": c.utc(1250)}
        job |= {"queued": {"status": "queued", "conclusion": None}, "in_progress": {"status": "in_progress", "conclusion": None},
                "failure": {"conclusion": "failure"}, "cancelled": {"conclusion": "cancelled"}}.get(mutation, {})
        metadata = {"id": 78, "name": "lifecycle-" + step, "digest": "sha256:" + c.sha(archive),
                    "workflow_run": {"id": 4242, "head_sha": "b" * 40}, "expired": False, "expires_at": c.utc(9000),
                    "created_at": c.utc(1200)}
        jobs = {"absent": [], "other-job": [job | {"name": "other / execute"}], "two-jobs": [job, job | {"id": 80}]}.get(mutation, [job])
        artifacts = {"no-artifact": [], "two-artifacts": [metadata, metadata | {"id": 79}],
                     "at-start": [metadata | {"created_at": c.utc(1100)}], "at-end": [metadata | {"created_at": c.utc(1250)}],
                     "other-name": [metadata | {"name": "lifecycle-other"}]}.get(mutation, [metadata])
        self.responses = {
            JOBS: {"jobs": jobs, "total_count": len(jobs) + (mutation == "incomplete-jobs")},
            ARTIFACTS: {"artifacts": artifacts, "total_count": len(artifacts) + (mutation == "incomplete-artifacts")},
            ROOT + "/runs/4242/attempts/1": RUN | {"event": "workflow_dispatch", "repository": {"full_name": c.REPOSITORY},
                                                   "path": ".github/workflows/promote-production.yml"},
            ROOT + "/jobs/77": job | ({"run_attempt": 2} if mutation == "other-attempt" else {}),
            ROOT + "/artifacts/78": metadata, ROOT + "/artifacts/78/zip": archive}
        self.reads, self.reference = [], {"job_id": 77, "artifact_id": 78, "artifact_digest": metadata["digest"]}

    def read(self, path, **_):
        self.reads.append(path)
        return self.responses[path]


class _Guard:
    def __init__(self):
        self.checks = []

    def check(self, seconds=0):
        self.checks.append(seconds)


def _window(stage, **changes):
    if stage == "application-prepare":
        return PREVIOUS | changes
    return _close() | {"stage": stage, "sequence": 2} | changes


def _source(api, *, clock=lambda: 1300, guard=None):
    from tools.cnesdata_delivery import application_gate as ag
    return ag.stage_event_source(api=api, governance=GOVERNANCE, run=dict(RUN), owner=dict(OWNER),
                                 guard=_Guard() if guard is None else guard, clock=clock)


_TRIGGERS = {"application-prepare": ("prepared", "application-prepare-operational / execute", "application-prepare-operational"),
             "phase-b": ("phase-b", "phase-b / execute", "phase-b-advance")}


@pytest.mark.parametrize("stage", sorted(_TRIGGERS))
def test_stage_event_source_emits_the_unique_completed_same_run_publication(stage):
    kind, job_name, step = _TRIGGERS[stage]
    api, guard = _GitHub(job_name, step), _Guard()
    event = _source(api, guard=guard)(_window(stage))
    assert event == {"kind": kind, "reference": api.reference}
    assert api.reads[:2] == [JOBS, ARTIFACTS] and len(api.reads) == 6
    assert guard.checks[0] == 20


@pytest.mark.parametrize("mutation", ["absent", "other-job", "queued", "in_progress", "failure", "cancelled"])
@pytest.mark.parametrize("stage", sorted(_TRIGGERS))
def test_stage_event_source_waits_while_the_producer_is_not_completed_success(stage, mutation):
    _, job_name, step = _TRIGGERS[stage]
    api = _GitHub(job_name, step, mutation)
    assert _source(api)(_window(stage)) is None
    assert api.reads == [JOBS]


_SOURCE_REFUSALS = {"two-jobs": "unique {kind} producer job", "incomplete-jobs": "complete {kind} publication inventory",
                    "incomplete-artifacts": "complete {kind} publication inventory",
                    "no-artifact": "unique {kind} publication in job interval",
                    "two-artifacts": "unique {kind} publication in job interval",
                    "at-start": "unique {kind} publication in job interval", "at-end": "unique {kind} publication in job interval",
                    "other-name": "unique {kind} publication in job interval",
                    "other-attempt": "completed original producer job required",
                    "owner": "{kind} original owner", "generation": "{kind} original owner",
                    "generation-type": "{kind} original owner", "step": "{kind} original owner"}


@pytest.mark.parametrize("mutation", sorted(_SOURCE_REFUSALS))
@pytest.mark.parametrize("stage", sorted(_TRIGGERS))
def test_stage_event_source_refuses_a_publication_that_can_never_be_the_trigger(stage, mutation):
    kind, job_name, step = _TRIGGERS[stage]
    with pytest.raises(ValueError, match=_SOURCE_REFUSALS[mutation].format(kind=kind)):
        _source(_GitHub(job_name, step, mutation))(_window(stage))


@pytest.mark.parametrize("stage, decision", [(stage, None) for stage in ("api", "static", "unit", "phase-c-recovery",
                                                                         "phase-c-audit", "final", "recovery")]
                         + [("phase-b", {"choice_at": 1200, "deadline": 1620, "checkpoint_sha256": "9" * 64})])
def test_stage_event_source_refuses_every_transition_without_ratified_trigger(stage, decision):
    window = _window(stage, decision=decision)
    api = _GitHub("phase-b / execute", "phase-b-advance")
    with pytest.raises(ValueError, match=f"stage trigger not connected stage={window['stage']}$"):
        _source(api)(window)
    assert api.reads == []


@pytest.mark.parametrize("stage, deadline", [("application-prepare", 1900), ("phase-b", 1360)])
def test_stage_event_source_refuses_after_the_stage_deadline(stage, deadline):
    api = _GitHub(*_TRIGGERS[stage][1:])
    for late in (deadline, deadline + 1):
        with pytest.raises(ValueError, match=f"stage deadline elapsed stage={stage}$"):
            _source(api, clock=lambda: late)(_window(stage))
    assert api.reads == []
    assert _source(api, clock=lambda: deadline - 1)(_window(stage))["kind"] == _TRIGGERS[stage][0]


@pytest.mark.parametrize("stage, close", [("application-prepare", (1000, 2800, 4000)), ("phase-b", (None, None, None))])
def test_stage_event_source_refuses_a_stage_inconsistent_with_close(stage, close):
    window = _window(stage, **dict(zip(("close", "fixed_deadline", "input_deadline"), close)))
    api = _GitHub("phase-b / execute", "phase-b-advance")
    with pytest.raises(ValueError, match="stage/close consistency"):
        _source(api)(window)
    assert api.reads == []


@pytest.mark.parametrize("steps", [{}, {"a": PHASE_B, "b": PHASE_B | {"job_name": "other / execute"}}])
def test_stage_event_source_needs_the_unique_protected_phase_b_advance_step(steps):
    from tools.cnesdata_delivery import application_gate as ag
    api = _GitHub("phase-b / execute", "phase-b-advance")
    source = ag.stage_event_source(api=api, governance={"lifecycle_steps": steps}, run=dict(RUN), owner=dict(OWNER),
                                   guard=_Guard(), clock=lambda: 1300)
    with pytest.raises(ValueError, match="unique protected phase-b advance step"):
        source(_window("phase-b"))
    assert api.reads == []


def test_phase_b_publication_reads_only_the_b_checkpoint_and_approval():
    """The closed-ready reader keeps the private selection through the shared same-run reader."""
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr
    files = {"checkpoint.json": b'{"checkpoint":1}', "approval.json": b'{"approval":1}', "plan.json": b'{"plan":1}'}
    index = {"version": 1, "source_sha": "b" * 40, "run_id": 4242, "run_attempt": 1, "step": "phase-b-advance",
             "owner_sha256": OWNER["owner_sha256"], "generation": 7, **IDENTITY,
             "files": [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in sorted(files.items())]}
    governance = GOVERNANCE | {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence", "context_kind": "promotion"}
    request = {"source_sha": "b" * 40, "step": "closed-ready", "application_purpose": "promotion", "caller_binding_sha256": "c" * 64}
    prefix = lr.namespace(governance, request, RUN, "phase-b-advance")
    reads = []
    class Store:
        def get(self, bucket, key, maximum=None):
            reads.append(key)
            return files[key.removeprefix(prefix)], None
    result = ag._phase_b_publication(_GitHub("phase-b / execute", "phase-b-advance", index=index), Store(), governance, request,
                                     dict(RUN), dict(OWNER), _Guard(), 1300)
    assert result == {name: files[name] for name in ("checkpoint.json", "approval.json")}
    assert reads == [prefix + "approval.json", prefix + "checkpoint.json"]


PLAN_STEP = {"role": "plan", "purpose": "application-prepare", "mode": "operational", "direction": "advance",
             "job_name": "application-prepare-plan / execute"}
PREPARED_REFERENCE = {"job_id": 71, "artifact_id": 72, "artifact_digest": "sha256:" + "8" * 64}
PREPARED_CHECKPOINT = b'{"prepared":"checkpoint"}'
B_REFERENCE = {"job_id": 91, "artifact_id": 92, "artifact_digest": "sha256:" + "6" * 64}
PRIOR_ARTIFACT = (c.REPOSITORY, 31)


class _Clock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


def _stage_world(monkeypatch, *, plan_step=PLAN_STEP, origins=None, approval=None, manifest=None, carrier=None,
                 observations=1, pending=False, capability=None, capability_seconds=5, credential_limit=6000,
                 omit_earliest=False, noncanonical=()):
    """Real Keeper/Lease/windows and real same-run reads; GitHub, S3, fence payload, capability and child are fakes."""
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from test_cnesdata_delivery_lifecycle import _envelope_case
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc, lifecycle_runtime as lr
    from tools.cnesdata_delivery.session_owner import Authority
    keeper, store = _prepare_stage_keeper()
    clock = _Clock(1100)
    keeper.clock = keeper.lease.clock = keeper.monotonic = keeper.lease.monotonic = clock
    record = keeper.lease.check()
    owner, window = lc.owner_binding(record), record["lifecycle"]
    _, envelope, _, _, _ = _envelope_case(owner=owner, window=window)
    raw_carrier = c.canonical(envelope) if carrier is None else carrier(owner, window)
    activation = b"p" * 40
    index = {"version": 1, "source_sha": owner["source_sha"], "run_id": 4242, "run_attempt": 1, "step": "application-prepare-plan",
             "owner_sha256": owner["owner_sha256"], "generation": owner["generation"], **lc.application_identity(owner),
             "files": [{"name": "inputs.json", "size": len(raw_carrier), "sha256": c.sha(raw_carrier)}]}
    github = _GitHub(PLAN_STEP["job_name"], "application-prepare-plan", index=index)
    github.expiries = {PRIOR_ARTIFACT: 6000.0}
    from tools.cnesdata_delivery.lifecycle_runtime import ArtifactDigests
    api = ArtifactDigests(github)
    api.digests[PRIOR_ARTIFACT] = "9" * 64
    current_plan = {"step": "application-prepare-plan", "index_sha256": c.sha(c.canonical(index)),
                    "inputs_sha256": c.sha(raw_carrier)} | (origins or {})
    def dump(name, value):
        return json.dumps(value, indent=1).encode() if name in noncanonical else c.canonical(value)
    prepared = lr.PreparedFence({
        "fence-prepared.json": dump("fence-prepared.json", {"activation_sha256": c.sha(activation)} | (manifest or {})),
        "fence-origins.json": dump("fence-origins.json", {"current_plan": current_plan}),
        "approval.json": dump("approval.json", {"inputs_sha256": c.sha(raw_carrier)} | (approval or {})),
        "checkpoint.json": PREPARED_CHECKPOINT})
    governance = GOVERNANCE | {"lifecycle_steps": GOVERNANCE["lifecycle_steps"] | ({"application-prepare-plan": plan_step} if plan_step else {}),
        "evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence", "context_kind": "promotion",
        "application_product_source_manifest": {"fixture": "manifest"}, "application_product_source_closure_sha256": "0" * 64}
    request = {"source_sha": owner["source_sha"], "step": "application", "application_purpose": "promotion",
               "caller_binding_sha256": owner["caller_binding_sha256"]}
    prefix = lr.namespace(governance, request, dict(RUN), "application-prepare-plan")
    world = SimpleNamespace(keeper=keeper, store=store, clock=clock, owner=owner, window=window, github=github, api=api,
                            governance=governance, request=request, prepared=prepared, activation=activation, events=[],
                            payload=[], capability=[], invoke=[], reads=[], phase_b=[], raw_carrier=raw_carrier,
                            authority=Authority({"frozen_until": c.utc(5500)}, 5000.0, None, {"enabled_until": c.utc(5200)}, "3" * 64))
    class AWS:
        def get(self, bucket, key, maximum=None):
            world.reads.append((bucket, key))
            assert (bucket, key) == ("evidence", prefix + "inputs.json")
            return raw_carrier, None
    world.aws = AWS()

    def fence_prepared_payload(*args, **kwargs):
        world.events.append("fence_prepared_payload")
        world.payload.append((args, kwargs))
        return prepared
    monkeypatch.setattr(lr, "fence_prepared_payload", fence_prepared_payload)

    def close_drain_capability(**kwargs):
        world.events.append("close_drain_capability")
        world.capability.append(kwargs | {"reads": list(github.reads), "expirations": kwargs["journal"]._inputs["expirations"]})
        clock.value += capability_seconds
        if capability is not None:
            raise ValueError(capability)
    monkeypatch.setattr(ag, "close_drain_capability", close_drain_capability)

    def invoke_adapter(**kwargs):
        world.events.append("invoke_adapter")
        world.invoke.append(kwargs)
        journal = kwargs["journal"]
        expirations = c.loads(journal._inputs["expirations"], canonical=True)
        if omit_earliest:
            expirations = [item for item in expirations if c.instant(item["expires_at"]) > 5000]
        raw = c.canonical(_close_drain(input_expirations=expirations, close_confirmed_at=c.utc(1050), fixed_deadline=c.utc(2850)))
        for _ in range(observations):
            journal._observations.append({"kind": "close-drain", "sha256": c.sha(raw), "size": len(raw)})
        journal._observation_bytes[c.sha(raw)] = raw
        journal._pending = [{"kind": "sdk-call", "reference_sha256": "f" * 64}] if pending else []
        clock.value += 10
    monkeypatch.setattr(ag, "invoke_adapter", invoke_adapter)

    def phase_b_publication(*args):
        world.phase_b.append(args)
        return world.b_files
    monkeypatch.setattr(ag, "_phase_b_publication", phase_b_publication)
    world.b_checkpoint = {"owner": owner, "purpose": "phase-b", "plan_sha256": "9" * 64}
    world.b_approval = {"checkpoint_sha256": c.sha(PREPARED_CHECKPOINT), "plan_sha256": "9" * 64}
    world.b_files = {"checkpoint.json": c.canonical(world.b_checkpoint), "approval.json": c.canonical(world.b_approval)}
    world.handlers = ag.stage_handlers(keeper=keeper, aws=world.aws, api=api, governance=governance, request=request, run=dict(RUN),
                                       authority=world.authority, product="product", credential_limit=credential_limit, clock=clock)
    return world


def _lifecycle(world):
    return world.store.get()[0]["lifecycle"]


def test_stage_handlers_are_exactly_the_two_ratified_triggers(monkeypatch):
    world = _stage_world(monkeypatch)
    assert set(world.handlers) == {"prepared", "phase-b"} and all(callable(item) for item in world.handlers.values())


def test_prepared_handler_closes_the_window_from_the_authenticated_plan_activation(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    world = _stage_world(monkeypatch)
    before = _lifecycle(world)
    world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert world.events == ["fence_prepared_payload", "close_drain_capability", "invoke_adapter"]
    (args, kwargs), = world.payload
    assert args == (world.api, world.aws, world.governance, world.request, RUN, PREPARED_REFERENCE)
    assert kwargs.keys() == {"owner", "now", "predecessor_raw", "predecessor_reference", "guard"}
    assert kwargs["owner"] == world.owner and kwargs["now"] == 1100 and type(kwargs["guard"]) is ag.KeeperGuard
    assert kwargs["predecessor_raw"] == world.keeper.predecessor["raw"]
    assert kwargs["predecessor_reference"] == world.keeper.predecessor_reference
    (capability,) = world.capability
    assert capability["reads"][:2] == [JOBS, ARTIFACTS] and world.reads
    journal = capability["journal"]
    assert type(journal) is ag.AdapterJournal and journal._request["operation"] == "close-drain"
    assert journal._request["stage"] == {key: before[key] for key in lc.ADAPTER_STAGE_FIELDS.split()}
    assert journal._request["checkpoint_sha256"] == before["checkpoint_sha256"] and journal._inputs["activation"] == world.activation
    assert type(journal._guard) is ag.KeeperGuard and any(item is journal for item in world.keeper._contexts)
    assert capability["expirations"] == ag.close_expirations(world.authority, world.api)
    kinds = [(item["kind"], item["expires_at"]) for item in c.loads(capability["expirations"], canonical=True)]
    assert kinds.count(("artifact", c.utc(9000))) == 1 and kinds.count(("artifact", c.utc(6000))) == 1 and len(kinds) == 5
    assert {key: value for key, value in capability.items() if key not in {"journal", "reads", "expirations"}} == {
        "aws": world.aws, "api": world.api, "governance": world.governance, "authority": world.authority,
        "keeper": world.keeper, "prepared": world.prepared, "credential_limit": 6000, "clock": world.clock}
    (invoked,) = world.invoke
    assert invoked == {"product": "product", "source": world.owner["source_sha"], "manifest": {"fixture": "manifest"},
                       "manifest_sha256": "0" * 64, "journal": journal, "timeout": 1900 - 1105 - 158}
    assert _lifecycle(world) == before | {"sequence": 1, "close": 1050, "fixed_deadline": 2850, "input_deadline": 5000,
                                          "stage": "phase-b", "admitted_at": 1050, "deadline": 1410,
                                          "checkpoint_sha256": c.sha(PREPARED_CHECKPOINT)}
    assert world.store.get()[0]["status"] == "held" and world.keeper.uncertainty() == []


def test_prepared_handler_records_the_plan_download_beside_its_expiry_in_the_original_api(monkeypatch):
    world = _stage_world(monkeypatch)
    inner = world.github
    before = (dict(inner.expiries), dict(world.api.digests))
    world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    key = (c.REPOSITORY, 78)
    assert inner.expiries == before[0] | {key: float(c.instant(c.utc(9000)))}
    assert world.api.digests == before[1] | {key: world.github.reference["artifact_digest"].removeprefix("sha256:")}
    assert set(world.api.digests) == set(world.api.expiries) and len(inner.expiries) == 2


def _foreign_owner_carrier(owner, window):
    from test_cnesdata_delivery_lifecycle import _envelope_case
    return c.canonical(_envelope_case(owner=owner | {"generation": owner["generation"] + 1}, window=window)[1])


def _foreign_window_carrier(owner, window):
    from test_cnesdata_delivery_lifecycle import _envelope_case
    return c.canonical(_envelope_case(owner=owner, window=window | {"admitted_at": window["admitted_at"] + 1})[1])


_PREPARED_REFUSALS = {
    "step-absent": ({"plan_step": None}, "activation plan step"),
    "step-role": ({"plan_step": PLAN_STEP | {"role": "deploy"}}, "activation plan step"),
    "step-purpose": ({"plan_step": PLAN_STEP | {"purpose": "phase-b"}}, "activation plan step"),
    "step-mode": ({"plan_step": PLAN_STEP | {"mode": "mode-canary"}}, "activation plan step"),
    "step-name": ({"origins": {"step": "foreign-plan"}}, "activation plan step"),
    "index": ({"origins": {"index_sha256": "5" * 64}}, "activation plan index"),
    "inputs": ({"approval": {"inputs_sha256": "5" * 64}}, "activation plan inputs"),
    "activation": ({"manifest": {"activation_sha256": "5" * 64}}, "activation bytes"),
    "origins-noncanonical": ({"noncanonical": {"fence-origins.json"}}, "noncanonical JSON bytes"),
    "approval-noncanonical": ({"noncanonical": {"approval.json"}}, "noncanonical JSON bytes"),
    "manifest-noncanonical": ({"noncanonical": {"fence-prepared.json"}}, "noncanonical JSON bytes"),
    "carrier-owner": ({"carrier": _foreign_owner_carrier}, "envelope original owner"),
    "carrier-window": ({"carrier": _foreign_window_carrier}, "envelope original preparation window"),
}


@pytest.mark.parametrize("mutation", sorted(_PREPARED_REFUSALS))
def test_prepared_handler_refuses_a_plan_activation_the_prepared_package_does_not_commit_to(monkeypatch, mutation):
    changes, message = _PREPARED_REFUSALS[mutation]
    world = _stage_world(monkeypatch, **changes)
    before = world.store.get()
    with pytest.raises(ValueError, match=message):
        world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert world.events == ["fence_prepared_payload"] and world.capability == [] and world.invoke == []
    assert _lifecycle(world) == before[0]["lifecycle"] and world.store.get()[0]["status"] == "held"


@pytest.mark.parametrize("capability_seconds, credential_limit, expected", [
    (5, 6000, 1900 - 1105 - 158), (5, 1105 + 121 + 300, 300), (5, 1105 + 121 + 1, 1)])
def test_prepared_handler_bounds_the_close_drain_timeout_by_the_deadline_and_the_credential(
        monkeypatch, capability_seconds, credential_limit, expected):
    world = _stage_world(monkeypatch, capability_seconds=capability_seconds, credential_limit=credential_limit)
    world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert world.invoke[0]["timeout"] == expected


@pytest.mark.parametrize("capability_seconds, credential_limit", [(5, 1105 + 121), (5, 1000), (1900 - 1100 - 158, 6000), (800, 6000)])
def test_prepared_handler_refuses_without_capacity_after_the_capability_and_never_runs_the_child(
        monkeypatch, capability_seconds, credential_limit):
    world = _stage_world(monkeypatch, capability_seconds=capability_seconds, credential_limit=credential_limit)
    with pytest.raises(ValueError, match="close-drain capacity"):
        world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert world.events == ["fence_prepared_payload", "close_drain_capability"] and world.invoke == []
    assert _lifecycle(world)["stage"] == "application-prepare" and world.store.get()[0]["status"] == "held"


def test_prepared_handler_never_runs_the_child_when_the_capability_refuses(monkeypatch):
    world = _stage_world(monkeypatch, capability="capability refused before STS")
    with pytest.raises(ValueError, match="capability refused before STS"):
        world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert world.invoke == [] and _lifecycle(world)["stage"] == "application-prepare" and world.store.get()[0]["status"] == "held"


@pytest.mark.parametrize("flags", [{"observations": 0}, {"observations": 2}, {"pending": True}])
def test_prepared_handler_needs_one_close_drain_observation_and_no_uncertainty(monkeypatch, flags):
    world = _stage_world(monkeypatch, **flags)
    with pytest.raises(ValueError, match="close-drain single observation without uncertainty"):
        world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert _lifecycle(world)["stage"] == "application-prepare" and world.store.get()[0]["status"] == "held"


def test_prepared_handler_refuses_an_observation_that_omits_the_earliest_known_expiration(monkeypatch):
    world = _stage_world(monkeypatch, omit_earliest=True)
    with pytest.raises(ValueError, match="infra-known authenticated expiration precedes input deadline"):
        world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert _lifecycle(world)["stage"] == "application-prepare" and world.store.get()[0]["status"] == "held"


def _prepared_world(monkeypatch, **flags):
    world = _stage_world(monkeypatch, **flags)
    world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    world.clock.value = 1130
    world.keeper.tick()
    return world


def test_phase_b_handler_admits_the_api_window_from_the_authenticated_b_checkpoint(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    world = _prepared_world(monkeypatch)
    before = _lifecycle(world)
    world.handlers["phase-b"](world.keeper, dict(B_REFERENCE))
    (args,) = world.phase_b
    assert args[:5] == (world.api, world.aws, world.governance, world.request, RUN) and args[5] == world.owner
    assert type(args[6]) is ag.KeeperGuard and args[7] == 1130
    assert _lifecycle(world) == before | {"sequence": 2, "stage": "api", "admitted_at": 1130, "deadline": 1310,
                                          "checkpoint_sha256": c.sha(world.b_files["checkpoint.json"])}
    assert world.store.get()[0]["status"] == "held"


_PHASE_B_REFUSALS = {
    "approval-checkpoint": (lambda w: w.b_approval | {"checkpoint_sha256": "5" * 64}, None),
    "approval-plan": (lambda w: w.b_approval | {"plan_sha256": "5" * 64}, None),
    "purpose": (None, lambda w: w.b_checkpoint | {"purpose": "application-prepare"}),
    "owner": (None, lambda w: w.b_checkpoint | {"owner": w.owner | {"generation": w.owner["generation"] + 1}}),
}


@pytest.mark.parametrize("mutation", sorted(_PHASE_B_REFUSALS))
def test_phase_b_handler_refuses_a_checkpoint_that_is_not_the_child_of_the_prepared_one(monkeypatch, mutation):
    world = _prepared_world(monkeypatch)
    approval, checkpoint = _PHASE_B_REFUSALS[mutation]
    if approval: world.b_files["approval.json"] = c.canonical(approval(world))
    if checkpoint: world.b_files["checkpoint.json"] = c.canonical(checkpoint(world))
    before = _lifecycle(world)
    with pytest.raises(ValueError, match="preparation -> B checkpoint ancestry"):
        world.handlers["phase-b"](world.keeper, dict(B_REFERENCE))
    assert _lifecycle(world) == before and world.store.get()[0]["status"] == "held"


def test_phase_b_handler_refuses_a_keeper_that_never_handled_the_prepared_stage(monkeypatch):
    world = _stage_world(monkeypatch)
    with pytest.raises(ValueError, match="phase-b follows the prepared stage handled by this keeper"):
        world.handlers["phase-b"](world.keeper, dict(B_REFERENCE))
    assert world.phase_b == [] and _lifecycle(world)["stage"] == "application-prepare"


# CnesData 9cdd452f scripts/promotion/promote_close.py:32, as a labelled literal: the product close-drain contract.
PRODUCT_EXPIRATION_KINDS = frozenset({"artifact", "platform", "cost", "credential", "activation", "plan"})


def test_close_expirations_kinds_stay_inside_the_product_close_drain_contract_after_the_plan_read(monkeypatch):
    """R6: the extra plan download adds an artifact entry; no kind outside the product EXPIRATION_KINDS is ever emitted."""
    from tools.cnesdata_delivery import lifecycle_contract as lc
    world = _stage_world(monkeypatch)
    world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    emitted = {item["kind"] for item in c.loads(world.capability[0]["expirations"], canonical=True)}
    assert emitted == {"artifact", "credential", "platform"} and emitted <= PRODUCT_EXPIRATION_KINDS
    assert lc.CLOSE_EXPIRATION_KINDS - {"envelope"} == PRODUCT_EXPIRATION_KINDS


def test_keeper_stops_at_the_api_stage_with_the_lease_held_the_fence_closed_and_nothing_dispatched(monkeypatch):
    """R18 and R15: the only reachable end of this slice, and its ancestry from the prepared checkpoint to the closed-ready stage."""
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    world = _stage_world(monkeypatch)
    for name in ("closed_ready_capability", "run_closed_ready", "publish_terminal", "published_terminal", "publish_static_closed_ready"):
        monkeypatch.setattr(ag, name, lambda *a, _name=name, **kw: pytest.fail(_name + " reached before the API stage ends the slice"))
    world.keeper.finish = lambda reference: pytest.fail("finish reached before the API stage ends the slice")
    statuses = []
    put = world.store.put
    world.store.put = lambda value, etag: statuses.append(value["status"]) or put(value, etag)
    real = ag.stage_event_source(api=world.api, governance=world.governance, run=dict(RUN), owner=world.owner,
                                 guard=_Guard(), clock=world.clock)
    triggers = {"application-prepare": {"kind": "prepared", "reference": dict(PREPARED_REFERENCE)},
                "phase-b": {"kind": "phase-b", "reference": dict(B_REFERENCE)}}
    with pytest.raises(ValueError, match="^stage trigger not connected stage=api$"):
        ag.keeper_loop(world.keeper, next_event=lambda window: triggers.get(window["stage"]) or real(window),
                       handlers=world.handlers, sleep=lambda seconds: None)
    record = world.store.get()[0]
    assert record["status"] == "held" and set(statuses) == {"held"} and record["lifecycle"]["stage"] == "api"
    assert len(world.invoke) == len(world.capability) == 1 and world.keeper.uncertainty() == []
    window = record["lifecycle"]
    assert window["checkpoint_sha256"] == c.sha(world.b_files["checkpoint.json"]) and window["close"] == 1050
    assert window["sequence"] == 2 and window["admitted_at"] == 1115 and window["deadline"] == 1295
    inputs = {name: c.canonical({"fixture_only": name}) for name in ("activation", "close-drain", "phase-b", "membership")}
    request = {"abi_version": 2, "operation": "closed-ready", "repository": c.REPOSITORY, "source_sha": world.owner["source_sha"],
               "owner": {key: world.owner[key] for key in [*lc.OWNER_FIELDS, "owner_sha256"]},
               "checkpoint_sha256": window["checkpoint_sha256"], "activation_sha256": "1" * 64,
               "stage": {key: window[key] for key in lc.ADAPTER_STAGE_FIELDS.split()},
               "inputs": {name: {"sha256": c.sha(raw), "size": len(raw)} for name, raw in inputs.items()}}
    lc.validate_adapter_request(c.canonical(request), operation="closed-ready", owner=world.owner, window=window, inputs=inputs,
                                activation_sha256="1" * 64)
