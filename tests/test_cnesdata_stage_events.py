"""Window and stage triggers of the application lifecycle (#55 2nd slice amendment 6886977054, decisions 2 and 3)."""
import io
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


def _archive(index):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as output:
        output.writestr(zipfile.ZipInfo("index.json", date_time=(2026, 1, 1, 0, 0, 0)), c.canonical(index))
    return buffer.getvalue()


class _GitHub:
    def __init__(self, job_name, step, mutation=None):
        index = {"step": step, "owner_sha256": OWNER["owner_sha256"], "generation": OWNER["generation"]}
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
