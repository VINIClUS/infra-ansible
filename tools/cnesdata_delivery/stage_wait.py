"""Credential-free wait for the stage-open marker, and the keeper-side publication of it (E1, DD-2)."""
import os
import time

from tools.cnesdata_delivery import contract as c

POLL_SECONDS = 5
ASSUMED_RATE_LIMIT = 5000
MARKER_UPLOAD_SECONDS = 30
STAGE_OPEN_LATENCY_SECONDS = MARKER_UPLOAD_SECONDS + POLL_SECONDS
TIMEOUT_MINUTES = 90
CEILING_MARGIN_SECONDS = 900
MAX_WAIT_SECONDS = TIMEOUT_MINUTES * 60 - CEILING_MARGIN_SECONDS
PREPARATION_ALLOWANCE_SECONDS = 1800
STAGES_WITH_EXTERNAL_FIRST_JOB = ("application-prepare", "phase-b", "phase-c-recovery", "phase-c-audit")
WINDOW_ORDER = ("phase-b", "api", "static", "unit", "phase-c-recovery", "phase-c-audit", "final")
INDEX_FIELDS = "version owner_sha256 generation run_attempt stage sequence checkpoint_sha256 admitted_at deadline"


class NoReservation:
    """Guard for same-run reads made before a lease is held."""
    def check(self, seconds=0):
        return None


def stage_open_name(stage, run_id, attempt):
    return f"cnesdata-stage-open-{stage}-{run_id}-{attempt}"


def wait_ceiling(stage, windows):
    """Seconds a job may wait: preparation allowance plus every governed window up to its own stage."""
    c.require(stage in STAGES_WITH_EXTERNAL_FIRST_JOB, f"stage_wait=stage value={stage}")
    if stage == "application-prepare":
        return min(MAX_WAIT_SECONDS, PREPARATION_ALLOWANCE_SECONDS)
    through = WINDOW_ORDER[:WINDOW_ORDER.index(stage) + 1]
    return min(MAX_WAIT_SECONDS, PREPARATION_ALLOWANCE_SECONDS + sum(windows["stages"][name] for name in through))


def timing_line(stage, *, setup_seconds, wait_seconds, rate=None):
    line = f"stage_wait stage={stage} setup_seconds={setup_seconds} wait_seconds={wait_seconds}"
    if rate:
        line += f" x_ratelimit_limit={rate['limit']} x_ratelimit_used={rate['used']} x_ratelimit_remaining={rate['remaining']}"
    return line


def require_rate_limit(api):
    """Fail closed unless the first REST response reported at least the assumed GITHUB_TOKEN limit."""
    rate = getattr(api, "rate", None)
    c.require(rate is not None and rate["limit"] >= ASSUMED_RATE_LIMIT,
              f"github=rate_limit value={rate['limit'] if rate else 'na'}")


def own_job(api, run, runner_name):
    """The unique in-progress job of this run attempt that runs on this runner."""
    jobs = api.read(f"{_root()}/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100&page=1")
    c.require(jobs["total_count"] == len(jobs["jobs"]) <= 100, "complete own job inventory")
    found = [job for job in jobs["jobs"] if job["status"] == "in_progress" and job.get("runner_name") == runner_name]
    c.require(len(found) == 1, "own in-progress job")
    return found[0]


def _root():
    return f"repos/{c.REPOSITORY}/actions"


def _index(raw_index, *, stage, run):
    try:
        return _checked_index(raw_index, stage=stage, run=run)
    except ValueError as error:
        raise ValueError(f"stage-open marker index: {error}") from error


def _checked_index(raw_index, *, stage, run):
    index = c.closed(raw_index, INDEX_FIELDS)
    c.require(type(index["version"]) is int and index["version"] == 1 and index["stage"] == stage
              and type(index["run_attempt"]) is int and index["run_attempt"] == run["run_attempt"], "binding")
    c.digest(index["owner_sha256"])
    c.digest(index["checkpoint_sha256"])
    c.integer(index["generation"])
    c.integer(index["sequence"], 0)
    c.integer(index["admitted_at"])
    c.require(c.integer(index["deadline"]) > index["admitted_at"], "deadline")
    return index


def _marker(api, run, job, *, stage, now):
    """The unique marker inside this job's interval: None while it is not listed, ValueError on anything else."""
    from tools.cnesdata_delivery.provenance import unzip
    name = stage_open_name(stage, run["id"], run["run_attempt"])
    listing = api.read_conditional(f"{_root()}/runs/{run['id']}/artifacts?per_page=100&page=1")
    c.require(listing["total_count"] == len(listing["artifacts"]) <= 100, "complete stage-open inventory")
    found = [item for item in listing["artifacts"] if item["name"] == name]
    c.require(len(found) <= 1, "unique stage-open marker")
    if not found:
        return None
    path = f"{_root()}/artifacts/{found[0]['id']}"
    metadata = api.read(path)
    c.require(metadata["id"] == found[0]["id"] and metadata["name"] == name and metadata["digest"] == found[0]["digest"]
              and metadata["workflow_run"]["id"] == run["id"] and metadata["workflow_run"]["head_sha"] == run["head_sha"]
              and metadata.get("expired") is False, "stage-open marker metadata")
    c.require(c.instant(job["started_at"]) <= c.instant(metadata["created_at"]) <= now, "stage-open marker interval")
    raw = api.read(path + "/zip", raw=True)
    c.require("sha256:" + c.sha(raw) == metadata["digest"], "stage-open marker archive bytes")
    files = unzip(raw)
    c.require(set(files) == {"index.json"}, "stage-open marker members")
    return _index(c.loads(files["index.json"], canonical=True), stage=stage, run=run)


def wait_for_stage(api, run, *, job, stage, windows, clock=time.time, sleep=time.sleep):
    """Poll for the stage-open marker without any AWS credential; fail closed at the ceiling.

    Args: GitHub reader, run, own in-progress job, stage, governed windows, clock and sleep.
    Returns: the authenticated closed index. Raises: ValueError.
    """
    ceiling = wait_ceiling(stage, windows)
    started = clock()
    while True:
        index = _marker(api, run, job, stage=stage, now=int(clock()))
        if index is not None:
            return index
        c.require(clock() - started < ceiling, f"stage_wait=ceiling stage={stage} seconds={ceiling}")
        sleep(POLL_SECONDS)


def payload_names(payloads, input_jobs):
    """Name-only payload shape against the governed input jobs; returns the producer of each payload name."""
    c.require(set(payloads) == set(input_jobs), "complete payload inventory")
    for name, named in payloads.items():
        c.closed(named, "step")
        c.require(named["step"] == input_jobs[name]["step"], "payload producer step")
    return {name: input_jobs[name] for name in payloads}


def payload_publication(job, artifacts, step):
    """The one publication predicate: None while the producer job is missing or unfinished, ValueError on anything else.

    Args: producer job or None, run artifact listing, producer step.
    Returns: the unique lifecycle-<step> artifact created strictly inside the completed-success job interval.
    """
    if job is None or job["status"] != "completed":
        return None
    c.require(job["conclusion"] == "success", "completed payload producer")
    found = [item for item in artifacts if item["name"] == "lifecycle-" + step
             and c.instant(job["started_at"]) < c.instant(item["created_at"]) < c.instant(job["completed_at"])]
    c.require(len(found) == 1, "unique payload publication in job interval")
    return found[0]


def _jobs_by_name(api, run):
    """The run attempt's jobs listing (one conditional read), keyed by job name; a duplicated name is refused."""
    listing = api.read_conditional(f"{_root()}/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100&page=1")
    c.require(listing["total_count"] == len(listing["jobs"]) <= 100, "complete payload publication inventory")
    names = [job["name"] for job in listing["jobs"]]
    c.require(len(names) == len(set(names)), "unique payload producer job")
    return {job["name"]: job for job in listing["jobs"]}


def wait_for_payloads(api, run, *, producers, ceiling, clock=time.time, sleep=time.sleep):
    """Credential-free wait: poll the artifacts listing until every producer artifact is listed, then decide with
    payload_publication over one jobs listing per poll (conditional GETs on both)."""
    started = clock()
    while True:
        listing = api.read_conditional(f"{_root()}/runs/{run['id']}/artifacts?per_page=100&page=1")
        c.require(listing["total_count"] == len(listing["artifacts"]) <= 100, "complete payload publication inventory")
        listed = {item["name"] for item in listing["artifacts"]}
        if all("lifecycle-" + producer["step"] in listed for producer in producers):
            jobs = _jobs_by_name(api, run)
            published = [payload_publication(jobs.get(producer["name"]), listing["artifacts"], producer["step"])
                         for producer in producers]
            if all(item is not None for item in published):
                return
        c.require(clock() - started < ceiling, f"stage_wait=ceiling payloads seconds={ceiling}")
        sleep(POLL_SECONDS)


KEEPER_POLL_SECONDS = 5
HANDLER_READS_PER_STAGE = 12
SESSION_OWNER_READS_PER_JOB = 6
ADMISSION_PREFLIGHT_READS = 9
ADMISSION_FULL_READS = 9
LIFECYCLE_ARTIFACT_READS = 4
PAYLOAD_READS_PER_ADMISSION = 2 + LIFECYCLE_ARTIFACT_READS
PRODUCERS_READS = 3
MARKER_HIT_READS = 3
UPLOAD_READBACK_SECONDS = 30
POST_STEP_ALLOWANCE_SECONDS = 60
COMPLETION_LAG_SECONDS = 60
PRODUCER_TAIL_SECONDS = UPLOAD_READBACK_SECONDS + POST_STEP_ALLOWANCE_SECONDS + COMPLETION_LAG_SECONDS
PROBE_POLL_SECONDS = 5
PROBE_ARTIFACT_READS_PER_POLL = 1
PROBE_JOBS_READS_PER_MINUTE = 1
REST_BUDGET = 60 * ASSUMED_RATE_LIMIT // 100
REST_BUDGET_NO_JOBS_CREDIT = 90 * ASSUMED_RATE_LIMIT // 100
MEASURED_HIT_RATES = {"jobs": 0.141, "artifacts": 0.929}
G_JOBS = {"application-prepare": 6, "phase-b": 3, "phase-c-recovery": 3, "phase-c-audit": 3}
PAYLOAD_CONSUMERS = {"application-prepare": 4, "phase-b": 2, "phase-c-recovery": 2, "phase-c-audit": 2}
CODE_BOUND_WINDOW_SECONDS = 360
PROBE_END_STAGES = {"closed-ready": "api"}
HOUR_SECONDS = 3600


def _stage_opens():
    opens, now = {"application-prepare": 0}, PREPARATION_ALLOWANCE_SECONDS
    for stage in WINDOW_ORDER:
        opens[stage] = now
        now += CODE_BOUND_WINDOW_SECONDS
    return opens, now


def rest_model(hit_rates=None, *, include_keeper=True):
    """Pure per-run GITHUB_TOKEN REST read count (one bucket per repository) at the code-bound windows.

    A 304 is free only at the passed hit rate of its listing; every other read counts one. Counted constants come
    from fixtures and the code; HANDLER_READS_PER_STAGE and SESSION_OWNER_READS_PER_JOB stay estimates.

    Args: 304 hit rate per listing (jobs, artifacts; 0 unless measured), whether the keeper term is counted.
    Returns: dict with the worst rolling-hour count and the per-component totals.
    """
    rates = {"jobs": 0.0, "artifacts": 0.0} | (hit_rates or {})
    jobs, artifacts = 1 - rates["jobs"], 1 - rates["artifacts"]
    opens, end = _stage_opens()
    seconds = [0.0] * (end + 1)
    totals = {"keeper": 0.0, "marker_waiters": 0.0, "payload_waiters": 0.0, "admission": 0.0, "probes": 0.0}

    def add(component, start, stop, cost, every=POLL_SECONDS):
        for second in range(int(start), min(int(stop), end), every):
            seconds[second] += cost
            totals[component] += cost

    def point(component, at, cost):
        seconds[min(int(at), end)] += cost
        totals[component] += cost

    if include_keeper:
        add("keeper", 0, end, jobs, KEEPER_POLL_SECONDS)
        for stage in opens:
            point("keeper", opens[stage], HANDLER_READS_PER_STAGE)
    for stage, count in G_JOBS.items():
        for _ in range(count):
            add("marker_waiters", 0, opens[stage], artifacts)
            point("marker_waiters", opens[stage], MARKER_HIT_READS)
            point("admission", opens[stage], ADMISSION_PREFLIGHT_READS + 2 * ADMISSION_FULL_READS + SESSION_OWNER_READS_PER_JOB)
        window = PREPARATION_ALLOWANCE_SECONDS if stage == "application-prepare" else CODE_BOUND_WINDOW_SECONDS
        for _ in range(PAYLOAD_CONSUMERS[stage]):
            add("payload_waiters", opens[stage], opens[stage] + window, artifacts)
            add("payload_waiters", opens[stage] + window - PRODUCER_TAIL_SECONDS, opens[stage] + window, jobs)
            point("payload_waiters", opens[stage], PRODUCERS_READS)
            point("admission", opens[stage], 2 * PAYLOAD_READS_PER_ADMISSION)
    for stage in PROBE_END_STAGES.values():
        add("probes", 0, opens[stage], PROBE_ARTIFACT_READS_PER_POLL * artifacts, PROBE_POLL_SECONDS)
        add("probes", 0, opens[stage], PROBE_JOBS_READS_PER_MINUTE * jobs, 60)
    prefix = [0.0]
    for value in seconds:
        prefix.append(prefix[-1] + value)
    worst = max(prefix[min(start + HOUR_SECONDS, len(seconds))] - prefix[start] for start in range(len(seconds)))
    return {"worst_rolling_hour": worst, "components": totals, "run_seconds": end}


def first_job_name(governance, stage):
    """Job name of the unique governed plan step that opens the stage (observer-bootstrap for preparation)."""
    found = [step["job_name"] for step in governance["lifecycle_steps"].values()
             if step["role"] == "plan" and step["purpose"] == stage and step["direction"] == "advance"
             and (stage != "application-prepare" or step.get("mode") == "observer-bootstrap")]
    c.require(len(found) == 1, "stage-open first job unique")
    return found[0]


def publish_stage_open(*, keeper, guard, api, run, owner, window, first_job, credential_limit, clock=time.time):
    """DD-2 extension: upload the stage-open marker from the keeper job while the stage's first job is in progress.

    Args: original keeper, its guard, GitHub reader, run, owner binding, the just-opened window, the first job name, credential limit.
    Returns: the verified upload receipt. Raises: ValueError before any upload without that job in progress.
    """
    from tools.cnesdata_delivery import application_gate as gate
    stage = window["stage"]
    c.require(stage in STAGES_WITH_EXTERNAL_FIRST_JOB, f"stage_wait=stage value={stage}")
    job = gate._same_run_job(api, run, kind="stage-open", job_name=first_job, guard=guard)
    c.require(job is not None and job["status"] == "in_progress", "stage-open first job in progress before publication")
    index = {"version": 1, "owner_sha256": owner["owner_sha256"], "generation": owner["generation"],
             "run_attempt": owner["run_attempt"], "stage": stage, "sequence": window["sequence"],
             "checkpoint_sha256": window["checkpoint_sha256"], "admitted_at": window["admitted_at"],
             "deadline": window["deadline"]}
    _index(index, stage=stage, run=run)
    name = stage_open_name(stage, owner["run_id"], owner["run_attempt"])
    return gate._upload_keeper_artifact(keeper, api, run, name=name, files={"index.json": c.canonical(index)}, guard=guard,
                                        credential_limit=credential_limit, clock=clock)


def _producers(api, run, governance, request):
    """Governed producers of the request payloads, from the authenticated catalog (GITHUB_TOKEN only)."""
    from tools.cnesdata_delivery.provenance import lifecycle_objects, product_source_manifest
    manifest = product_source_manifest(api, governance, time.time())
    step = lifecycle_objects(api, governance, manifest)["lifecycle_steps"].get(request["step"])
    c.require(type(step) is dict, "governed step")
    return list(payload_names(request["payloads"], step["input_jobs"]).values())


def main():
    """Workflow entry: wait for the marker, export the bound owner for the later lease check, print one timing line."""
    import json
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.provenance import GitHub
    stage = os.environ["PURPOSE"]
    if stage not in STAGES_WITH_EXTERNAL_FIRST_JOB:
        return
    run = {"id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
           "head_sha": os.environ["EXPECTED_SOURCE_SHA"]}
    api = GitHub()
    began = time.time()
    job = own_job(api, run, os.environ["RUNNER_NAME"])
    setup = int(began - c.instant(job["started_at"]))
    try:
        require_rate_limit(api)
        _wait_and_export(api, run, job, stage, lc.stage_windows(json.loads(os.environ["CNESDATA_DELIVERY_GOVERNANCE"])), began)
    finally:
        print(timing_line(stage, setup_seconds=setup, wait_seconds=int(time.time() - began), rate=getattr(api, "rate", None)))


def _wait_and_export(api, run, job, stage, windows, began):
    import json
    index = wait_for_stage(api, run, job=job, stage=stage, windows=windows)
    producers = _producers(api, run, json.loads(os.environ["CNESDATA_DELIVERY_GOVERNANCE"]),
                           json.loads(os.environ["REQUEST_DESCRIPTOR"]))
    wait_for_payloads(api, run, producers=producers, ceiling=max(0, wait_ceiling(stage, windows) - int(time.time() - began)))
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as handle:
        handle.write(f"STAGE_OPEN_OWNER_SHA256={index['owner_sha256']}\nSTAGE_OPEN_GENERATION={index['generation']}\n")


if __name__ == "__main__":
    main()
