"""Insumos estaticos autenticados, operacao inventory do keeper e corpo por digest (#55, P15b)."""
import base64
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

from tools.cnesdata_delivery import contract as c

from test_cnesdata_static_stage import (BODIES, BUCKET, DISTRIBUTION, EVIDENCE_GOVERNANCE, GATE_SHA, KEYS, TYPES, _Evidence,
                                        _Guard, _Native, _b64, _frame)

SOURCE = "b" * 40
VERIFY_RUN = 3131
DASHBOARD_ID = 901
REPO = f"repos/{c.REPOSITORY}/actions"
BIG_KEY = "assets/index-DmPMWKvL.css"
BIG = (bytes(range(256)) * 1212)[:310126]


def _tar(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for key, raw in sorted(files.items()):
            info = tarfile.TarInfo("./" + key)
            info.size, info.mtime, info.mode = len(raw), 0, 0o644
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def _zip(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, raw in sorted(members.items()):
            archive.writestr(zipfile.ZipInfo(name, (2026, 11, 1, 0, 0, 0)), raw)
    return buffer.getvalue()


def _r2(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _release_id():
    return f"candidate-{SOURCE}-{VERIFY_RUN}-1"


def _candidate(dist, artifact, **changes):
    value = {"schema_version": 1, "repository": c.REPOSITORY, "source_sha": SOURCE, "release_id": _release_id(),
             "dashboard_sha256": c.sha(dist), "artifacts": {"production-dashboard": {
                 "id": DASHBOARD_ID, "sha256": c.sha(artifact), "expires_at": c.utc(9000), "source_sha": SOURCE,
                 "run_id": VERIFY_RUN, "run_attempt": 1}}} | changes
    return _r2(value)


def _archive(**manifest):
    buffer = io.BytesIO()
    raw = c.canonical({"source_sha": SOURCE, "static_release": _release_id()} | manifest)
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("release-manifest.json")
        info.size, info.mtime = len(raw), 0
        archive.addfile(info, io.BytesIO(raw))
    return gzip.compress(buffer.getvalue(), mtime=0)


def _baseline(**changes):
    return c.canonical({"schema": "cnesdata.static-baseline/v1", "current": None, "prior": None} | changes)


def _inventory(inputs, **changes):
    return c.canonical({"schema": "cnesdata.static-inventory/v1", "candidate_sha256": c.sha(inputs["candidate"]),
                        "dashboard_sha256": c.sha(inputs["dashboard-artifact"]),
                        "baseline": json.loads(inputs["static-baseline"]), "outcome": "PLANNED", "upload_order": list(KEYS),
                        "already_published": [], "retire": [], "retire_latest": [], "rollback_versions": [],
                        "multipart_keys": [], "projected_bytes": 4096} | changes)


def _plan(inventory, **changes):
    return c.canonical({"schema": "cnesdata.static-plan/v1", "bucket": BUCKET, "distribution_arn": DISTRIBUTION,
                        "inventory_sha256": c.sha(inventory), "candidate_keys": sorted(KEYS), "rollback_versions": [],
                        "retire_versions": [], "multipart_keys": []} | changes)


def _values(files=None):
    dist = _tar(BODIES if files is None else files)
    artifact = _zip({"dist.tar": dist, "SHA256SUMS": f"{c.sha(dist)}  dist.tar\n".encode()})
    candidate = _candidate(dist, artifact)
    inputs = {"candidate": candidate, "dashboard-artifact": dist, "archive": _archive(), "static-baseline": _baseline()}
    inventory = _inventory(inputs)
    return SimpleNamespace(dist=dist, artifact=artifact, candidate=candidate, inputs=inputs, inventory=inventory,
                           plan=_plan(inventory))


def _release(candidate):
    return {"release_id": _release_id(), "source_sha": SOURCE, "candidate_sha256": c.sha(candidate), "canary_id": "canary-1",
            "binding_sha256": "7" * 64, "image_digest": "sha256:" + "8" * 64}


def _binding(owner, plan, **changes):
    return {"release_id": "r" + hashlib.sha256(_release_id().encode()).hexdigest()[:31], "run_id": owner["run_id"],
            "run_attempt": owner["run_attempt"], "generation": owner["generation"], "product_source_sha": owner["source_sha"],
            "shared_source_sha": GATE_SHA, "static_plan_sha256": c.sha(plan)} | changes


def _terraform(binding):
    return c.canonical({"canary_release_id": "r1", "static_promotion": {"mode": "operational", "binding": binding}})


def _dashboard_metadata(values, **changes):
    return {"id": DASHBOARD_ID, "name": "production-dashboard", "digest": "sha256:" + c.sha(values.artifact),
            "workflow_run": {"id": VERIFY_RUN, "head_sha": SOURCE}, "expired": False, "expires_at": c.utc(9000),
            "created_at": c.utc(500)} | changes


class _Api:
    def __init__(self, responses):
        self.responses, self.reads = dict(responses), []

    def read(self, path, **_):
        self.reads.append(path)
        return self.responses[path]


def _dashboard_api(values, metadata=None, served=None):
    return _Api({f"{REPO}/artifacts/{DASHBOARD_ID}": _dashboard_metadata(values) if metadata is None else metadata,
                 f"{REPO}/artifacts/{DASHBOARD_ID}/zip": values.artifact if served is None else served})


def test_candidato_so_entra_com_o_digest_da_release_da_governanca():
    from tools.cnesdata_delivery import static_inputs as si
    values = _values()
    governance = {"release": _release(values.candidate)}
    assert si.authenticated_candidate(values.candidate, governance)["dashboard_sha256"] == c.sha(values.dist)
    with pytest.raises(ValueError, match="^static_inputs=candidate_digest$"):
        si.authenticated_candidate(values.candidate.replace(b'"schema_version":1', b'"schema_version":2'), governance)
    with pytest.raises(ValueError, match="R2 canonical candidate bytes"):
        si.authenticated_candidate(values.candidate.rstrip(b"\n"), {"release": _release(values.candidate.rstrip(b"\n"))})


def _dist_flip(values):
    flipped = _tar({**BODIES, "assets/app.js": b"console.log(2)\n"})
    artifact = _zip({"dist.tar": flipped, "SHA256SUMS": f"{c.sha(flipped)}  dist.tar\n".encode()})
    candidate = json.loads(values.candidate)
    candidate["artifacts"]["production-dashboard"]["sha256"] = c.sha(artifact)
    return SimpleNamespace(**{**vars(values), "artifact": artifact, "candidate": _r2(candidate)})


@pytest.mark.parametrize("mutation, message", [
    ("digest", "static_inputs=dashboard_artifact"), ("zip", "static_inputs=dashboard_artifact"),
    ("expired", "static_inputs=dashboard_artifact"), ("run", "static_inputs=dashboard_artifact"),
    ("name", "static_inputs=dashboard_artifact"), ("dist", "static_inputs=dashboard_sha256")])
def test_dashboard_so_entra_pelo_zip_e_pelo_dist_tar_que_o_candidato_fixa(mutation, message):
    from tools.cnesdata_delivery import static_inputs as si
    values = _values()
    candidate = json.loads(values.candidate)
    assert si.dashboard_artifact(_dashboard_api(values), candidate, guard=_Guard(), now=1000) == values.dist
    api = {"digest": lambda: _dashboard_api(values, _dashboard_metadata(values, digest="sha256:" + "0" * 64)),
           "zip": lambda: _dashboard_api(values, served=values.artifact[:40] + bytes([values.artifact[40] ^ 1])
                                         + values.artifact[41:]),
           "expired": lambda: _dashboard_api(values, _dashboard_metadata(values, expired=True)),
           "run": lambda: _dashboard_api(values, _dashboard_metadata(values, workflow_run={"id": 7, "head_sha": SOURCE})),
           "name": lambda: _dashboard_api(values, _dashboard_metadata(values, name="production-config"))}
    if mutation == "dist":
        flipped = _dist_flip(values)
        with pytest.raises(ValueError, match=f"^{message}$"):
            si.dashboard_artifact(_dashboard_api(flipped, _dashboard_metadata(flipped)), json.loads(flipped.candidate),
                                  guard=_Guard(), now=1000)
        return
    with pytest.raises(ValueError, match=f"^{message}$"):
        si.dashboard_artifact(api[mutation](), candidate, guard=_Guard(), now=1000)


def test_archive_e_baseline_so_entram_amarrados_ao_candidato():
    from tools.cnesdata_delivery import static_inputs as si
    candidate = json.loads(_values().candidate)
    assert si.archive_bytes(_archive(), candidate) == _archive()
    for archive in (_archive(source_sha="a" * 40), _archive(static_release="candidate-other"), b"not-gzip"):
        with pytest.raises(ValueError, match="^static_inputs=archive_binding$"):
            si.archive_bytes(archive, candidate)
    assert si.baseline_bytes(_baseline()) == _baseline()
    for baseline in (_baseline(schema="cnesdata.static-baseline/v2"), _baseline(extra=1), b"[]"):
        with pytest.raises(ValueError, match="^static_inputs=baseline$"):
            si.baseline_bytes(baseline)


def test_static_plan_so_entra_pelo_binding_do_portador_e_pelo_inventario_do_keeper():
    from tools.cnesdata_delivery import static_inputs as si
    values = _values()
    binding = {"static_plan_sha256": c.sha(values.plan)}
    assert si.static_plan_bytes(values.plan, binding=binding, inventory=values.inventory) == values.plan
    with pytest.raises(ValueError, match="^static_inputs=static_plan_binding$"):
        si.static_plan_bytes(values.plan, binding={"static_plan_sha256": "0" * 64}, inventory=values.inventory)
    other = _plan(values.inventory + b" ")
    with pytest.raises(ValueError, match="^static_inputs=static_plan_inventory$"):
        si.static_plan_bytes(other, binding={"static_plan_sha256": c.sha(other)}, inventory=values.inventory)


def test_binding_do_portador_vem_do_static_promotion_do_inputs_autenticado():
    from tools.cnesdata_delivery import static_inputs as si
    owner = {"run_id": 4242, "run_attempt": 1, "generation": 2, "source_sha": SOURCE}
    binding = _binding(owner, b"plan")
    assert si.carrier_binding(_terraform(binding)) == binding
    for terraform in (c.canonical({"canary_release_id": "r1"}), c.canonical({"static_promotion": None}), b"{ }"):
        with pytest.raises(ValueError, match="^static_binding=carrier_absent$"):
            si.carrier_binding(terraform)
    si.compare_binding(binding, dict(binding))
    for field in ("release_id", "generation", "shared_source_sha", "static_plan_sha256"):
        with pytest.raises(ValueError, match=f"^static_binding=carrier_mismatch field={field}$"):
            si.compare_binding(binding, binding | {field: "other"})


def test_membro_do_dist_tar_so_sai_com_o_tamanho_e_o_sha_da_referencia():
    from tools.cnesdata_delivery import lifecycle_contract as lc, static_inputs as si
    dist = _tar({BIG_KEY: BIG, "index.html": BODIES["index.html"]})
    reference = {"member": BIG_KEY, "size": len(BIG), "sha256": c.sha(BIG)}
    assert si.tar_member(dist, reference) == BIG
    with pytest.raises(ValueError, match=f"^static_body=member_digest key={BIG_KEY}$"):
        si.tar_member(dist, reference | {"sha256": c.sha(BIG[:-1] + b"\0")})
    with pytest.raises(ValueError, match=f"^static_body=member_digest key={BIG_KEY}$"):
        si.tar_member(dist, reference | {"size": len(BIG) - 1})
    with pytest.raises(ValueError, match="^static_body=member_absent key=assets/none.js$"):
        si.tar_member(dist, reference | {"member": "assets/none.js"})
    assert lc.STATIC_MEMBER_LIMIT == 1024**2


def _digest_put(key, raw):
    content_type, cache = TYPES.get(key, ("text/css", "public, max-age=31536000, immutable"))
    parameters = {"Bucket": BUCKET, "Key": key, "Body": {"member": key, "size": len(raw), "sha256": c.sha(raw)},
                  "ContentType": content_type, "CacheControl": cache,
                  "ChecksumSHA256": _b64(hashlib.sha256(raw).digest())}
    return ("normal", "s3", "PutObject", parameters | ({} if key in ("index.html", "theme-init.js") else {"IfNoneMatch": "*"}))


def _digest_broker(files):
    from test_cnesdata_static_stage import _journal, _session
    from tools.cnesdata_delivery import application_gate as ag
    keys = sorted(files)
    dist = _tar(files)
    journal, owner, window, inputs = _journal(plan={"candidate_keys": keys}, dashboard=dist)
    evidence = _Evidence()
    clients = {"observer": _Native("observer"), "normal": _Native("normal")}
    broker = ag.StaticBroker(evidence, EVIDENCE_GOVERNANCE, journal, _session(journal, clients, evidence),
                             clock=lambda: window["admitted_at"] + 5)
    return ag, broker, journal, clients, evidence


def test_arquivo_de_310126_bytes_publica_pelo_caminho_de_digest_sem_passar_pelo_journal():
    ag, broker, journal, clients, evidence = _digest_broker({BIG_KEY: BIG, "index.html": BODIES["index.html"],
                                                             "theme-init.js": BODIES["theme-init.js"]})
    frame = _frame(*_digest_put(BIG_KEY, BIG))
    assert len(frame) < 1024
    reply, _ = ag._adapter_message(frame, journal)
    (call,) = clients["normal"].calls
    assert call[:3] == ("s3", "put_object", "us-east-2") and call[3]["Body"] == BIG and type(call[3]["Body"]) is bytes
    assert reply["kind"] == "sdk-result" and broker.uncertainty == [] and journal.unknown == []
    reply, _ = ag._adapter_message(_frame("normal", "s3", "GetObject", {"Bucket": BUCKET, "Key": BIG_KEY}), journal)
    assert reply["value"]["Body"] == {"sha256": c.sha(BIG), "size": len(BIG)}
    assert all(len(raw) < 64 * 1024 for raw in [*evidence.objects.values(), *journal.call_bytes.values()])


def test_referencia_com_sha_diferente_do_membro_e_recusada_antes_da_evidencia_e_do_put_object():
    ag, broker, journal, clients, evidence = _digest_broker({BIG_KEY: BIG, "index.html": BODIES["index.html"],
                                                             "theme-init.js": BODIES["theme-init.js"]})
    forged = BIG[:-1] + b"\0"
    role, service, operation, parameters = _digest_put(BIG_KEY, forged)
    with pytest.raises(ValueError, match=f"^static_body=member_digest key={BIG_KEY}$"):
        ag._adapter_message(_frame(role, service, operation, parameters), journal)
    assert clients["normal"].calls == [] and evidence.writes == [] and journal.call_receipts == []


@pytest.mark.parametrize("body", [{"base64": _b64(b"console.log(1)\n")},
                                  {"member": "assets/app.js", "size": 15},
                                  {"member": "assets/other.js", "size": 15, "sha256": c.sha(b"console.log(1)\n")},
                                  {"member": "assets/app.js", "size": 1024**2 + 1, "sha256": c.sha(b"x")}])
def test_put_object_so_aceita_a_referencia_do_membro_com_o_teto_por_arquivo(body):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    raw = b"console.log(1)\n"
    parameters = {"Bucket": BUCKET, "Key": "assets/app.js", "Body": body, "ContentType": "text/javascript",
                  "CacheControl": "public, max-age=31536000, immutable", "ChecksumSHA256": _b64(hashlib.sha256(raw).digest())}
    with pytest.raises(ValueError):
        lc.s3_put_body(parameters)
    assert lc.s3_put_body(parameters | {"Body": {"member": "assets/app.js", "size": len(raw), "sha256": c.sha(raw)}}) == {
        "member": "assets/app.js", "size": len(raw), "sha256": c.sha(raw)}


def test_binding_divergente_do_portador_e_recusado_antes_do_sts(monkeypatch):
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from test_cnesdata_static_roles import role_files
    from test_cnesdata_static_stage import _journal
    from tools.cnesdata_delivery import application_gate as ag
    keeper, store = _prepare_stage_keeper()
    journal, owner, window, inputs = _journal()
    binding = ag._static_binding(EVIDENCE_GOVERNANCE, journal)
    sessions = []
    monkeypatch.setattr(ag, "_assume_static_session", lambda **kwargs: sessions.append(kwargs))
    with pytest.raises(ValueError, match="^static_binding=carrier_mismatch field=release_id$"):
        ag.static_capability(governance=EVIDENCE_GOVERNANCE, journal=journal, keeper=keeper, credential_limit=6000,
                             operation_session=lambda *args: pytest.fail("no STS before the binding check"),
                             clock=lambda: 1505, carrier=binding | {"release_id": "r" + "0" * 31}, prepared=role_files())
    assert sessions == [] and journal._failed is True and journal in keeper._contexts
    assert store.get()[0]["status"] == "held"


OBSERVER_STEP = {"role": "deploy", "purpose": "application-prepare", "mode": "observer-bootstrap", "direction": "advance",
                 "job_name": "application-prepare-observer-bootstrap / execute"}


@pytest.mark.parametrize("mutation, emitted", [("absent", False), ("in_progress", False), ("failure", False),
                                               ("queued", False), (None, True)])
def test_gatilho_do_inventario_so_dispara_no_deploy_observer_bootstrap_concluido_com_sucesso(mutation, emitted):
    from test_cnesdata_stage_events import GOVERNANCE, OWNER, RUN, _GitHub, _window
    from tools.cnesdata_delivery import application_gate as ag
    api = _GitHub(OBSERVER_STEP["job_name"], "application-prepare-observer-bootstrap", mutation=mutation)
    governance = GOVERNANCE | {"lifecycle_steps": GOVERNANCE["lifecycle_steps"]
                               | {"application-prepare-observer-bootstrap": OBSERVER_STEP}}
    source = ag.stage_event_source(api=api, governance=governance, run=dict(RUN), owner=dict(OWNER), guard=_Guard(),
                                   keeper=SimpleNamespace(static_inventory=None), clock=lambda: 1300)
    event = source(_window("application-prepare"))
    assert (event is not None) is emitted
    if emitted:
        assert event == {"kind": "observer-bootstrap", "reference": api.reference}
    assert "observer-bootstrap" in ag.KEEPER_EVENTS


def test_com_o_inventario_liquidado_o_gatilho_do_prepare_volta_a_ser_o_prepared():
    from test_cnesdata_stage_events import GOVERNANCE, OWNER, RUN, _GitHub, _window
    from tools.cnesdata_delivery import application_gate as ag
    api = _GitHub("application-prepare-operational / execute", "application-prepare-operational")
    source = ag.stage_event_source(api=api, governance=GOVERNANCE, run=dict(RUN), owner=dict(OWNER), guard=_Guard(),
                                   keeper=SimpleNamespace(static_inventory=b"settled"), clock=lambda: 1300)
    assert source(_window("application-prepare")) == {"kind": "prepared", "reference": api.reference}


def test_tabela_de_gatilho_de_operacao_e_a_do_inventario_no_prepare():
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_contract as lc
    assert lc.OPERATION_TRIGGERS == {"inventory": ("application-prepare", "observer-bootstrap"),
                                     "rollback-api-static": ("recovery", "host-recovery")}
    assert ag.KEEPER_EVENTS == ("observer-bootstrap", "prepared", "phase-b", "host", "phase-c-recovery", "phase-c-audit",
                                "host-recovery")
    assert lc.STAGE_TRIGGERS["application-prepare"] == ("prepared", "phase-b")


def test_static_inputs_entra_no_pyboot_do_application():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert "static_inputs.py" in lc.APPLICATION_PYBOOT
    assert "tools/cnesdata_delivery/static_inputs.py" in lc.APPLICATION_CLOSURE_PATHS


def _inventory_world(monkeypatch, *, probe="in_progress", observation=None, observations=1, capability=None):
    from test_cnesdata_stage_events import JOBS, _stage_world
    from tools.cnesdata_delivery import application_gate as ag
    world = _stage_world(monkeypatch, static_inventory=None)
    world.clock.value = 1040
    values = _values()
    world.values = values
    world.governance.update({key: value for key, value in EVIDENCE_GOVERNANCE.items() if key not in world.governance})
    world.governance["release"] = _release(values.candidate)
    listing = world.github.responses[JOBS]
    if probe != "absent":
        listing["jobs"] = listing["jobs"] + [{"id": 85, "run_id": 4242, "run_attempt": 1, "head_sha": SOURCE,
                                              "name": ag.INVENTORY_PROBE, "status": probe, "conclusion": None,
                                              "started_at": c.utc(1001), "completed_at": None}]
        listing["total_count"] += 1
    world.inventory_requests, world.inventory_capability, world.observer_publication = [], [], []

    def publication(*args):
        from test_cnesdata_static_roles import role_files
        world.events.append("observer_publication")
        world.observer_publication.append(args)
        return role_files(("observer",))
    monkeypatch.setattr(ag, "_observer_publication", publication)

    def source(**kwargs):
        world.events.append("inventory_inputs")
        world.inventory_requests.append(kwargs)
        return dict(values.inputs)
    monkeypatch.setattr(ag, "inventory_input_source", source)

    def inventory_capability(**kwargs):
        world.events.append("inventory_capability")
        world.inventory_capability.append(kwargs)
        journal = kwargs["journal"]
        if capability is not None:
            journal._failed = True
            kwargs["keeper"].attach(journal)
            raise ValueError(capability)
        broker = ag.StaticBroker.__new__(ag.StaticBroker)
        broker.aws, broker.evidence, broker.journal, broker.child_deadline = "operation-client", [], journal, None
        broker.clock = world.clock
        broker.session = SimpleNamespace(clients={"observer": "observer-client"}, evidence="operation-client")
        journal._broker = broker
        kwargs["keeper"].attach(broker)
        return broker
    monkeypatch.setattr(ag, "inventory_capability", inventory_capability)
    inner = ag.invoke_adapter

    def invoke(**kwargs):
        journal = kwargs["journal"]
        if journal._request["operation"] != "inventory":
            return inner(**kwargs)
        world.events.append("invoke_adapter")
        world.invoke.append(kwargs)
        raw = values.inventory if observation is None else observation
        for _ in range(observations):
            journal._observations.append({"kind": "inventory", "sha256": c.sha(raw), "size": len(raw)})
        journal._observation_bytes[c.sha(raw)] = raw
        world.clock.value += 10
    monkeypatch.setattr(ag, "invoke_adapter", invoke)
    return world


def test_observer_bootstrap_roda_o_inventory_e_publica_o_resultado_para_os_inputs_do_plan_operacional(monkeypatch):
    from tools.cnesdata_delivery import application_gate as ag
    world = _inventory_world(monkeypatch)
    before = world.store.get()[0]["lifecycle"]
    world.handlers["observer-bootstrap"](world.keeper, dict(world.github.reference))
    from test_cnesdata_static_roles import role_files
    assert world.events == ["inventory_inputs", "observer_publication", "inventory_capability", "invoke_adapter", "upload",
                            "verify_upload"]
    assert world.inventory_capability[0]["publication"] == role_files(("observer",))
    assert world.uploads == [("cnesdata-inventory-4242-1", {"inventory.json": world.values.inventory})]
    assert world.keeper.static_inventory == world.values.inventory
    assert world.keeper.static_inputs == {name: world.values.inputs[name] for name in ("candidate", "dashboard-artifact")}
    assert world.store.get()[0]["lifecycle"] == before and before["stage"] == "application-prepare"
    (journal,) = [item for item in world.keeper._contexts if type(item) is ag.AdapterJournal
                  and item._request["operation"] == "inventory"]
    request = c.loads(c.canonical(journal._request), canonical=True)
    assert set(request["inputs"]) == {"candidate", "dashboard-artifact", "archive", "static-baseline"}
    assert request["activation_sha256"] == c.sha(c.canonical(world.governance["release"]))
    assert world.invoke[0]["timeout"] <= ag.INVENTORY_SECONDS_CAP
    assert journal._broker.session.clients is None and journal._broker.aws is None


@pytest.mark.parametrize("probe", ["absent", "queued", "completed"])
def test_inventario_so_e_publicado_com_a_sonda_dos_inputs_em_andamento(monkeypatch, probe):
    world = _inventory_world(monkeypatch, probe=probe)
    with pytest.raises(ValueError, match="^inventory probe in progress before publication$"):
        world.handlers["observer-bootstrap"](world.keeper, dict(world.github.reference))
    assert world.uploads == [] and world.keeper.static_inventory is None and world.keeper.static_inputs is None


@pytest.mark.parametrize("change", [{"observations": 2}, {"observation": b"{}"}, {"capability": "static_sessions"}])
def test_inventario_so_liquida_com_uma_observacao_amarrada_aos_insumos(monkeypatch, change):
    world = _inventory_world(monkeypatch, **change)
    with pytest.raises(ValueError):
        world.handlers["observer-bootstrap"](world.keeper, dict(world.github.reference))
    assert world.uploads == [] and world.keeper.static_inventory is None and world.keeper.static_inputs is None


def test_prepared_recusa_sem_o_inventario_liquidado_do_keeper(monkeypatch):
    from test_cnesdata_stage_events import PREPARED_REFERENCE, _stage_world
    world = _stage_world(monkeypatch, static_inventory=None)
    with pytest.raises(ValueError, match="^prepared=inventory_unsettled$"):
        world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert world.events == []


def test_prepared_autentica_o_static_plan_do_portador_antes_do_close_drain(monkeypatch):
    from test_cnesdata_stage_events import PREPARED_REFERENCE, RUN, _stage_world
    from tools.cnesdata_delivery import application_gate as ag
    world = _stage_world(monkeypatch)
    world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    (requested,) = world.static_plan_requests
    assert type(requested.pop("guard")) is ag.KeeperGuard
    assert requested == {"keeper": world.keeper, "owner": world.owner, "api": world.api, "run": RUN, "now": 1100,
                         "terraform": base64.b64decode(c.loads(world.raw_carrier, canonical=True)["terraform"]["bytes_base64"])}


def test_static_plan_recusado_no_prepared_nunca_fecha_a_janela(monkeypatch):
    from test_cnesdata_stage_events import PREPARED_REFERENCE, _stage_world
    from tools.cnesdata_delivery import application_gate as ag
    world = _stage_world(monkeypatch)
    before = world.store.get()[0]["lifecycle"]

    def refused(**kwargs):
        raise ValueError("static_inputs=static_plan_binding")
    monkeypatch.setattr(ag, "static_plan_source", refused)
    with pytest.raises(ValueError, match="^static_inputs=static_plan_binding$"):
        world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert world.events == ["fence_prepared_payload"] and world.invoke == []
    assert world.store.get()[0]["lifecycle"] == before and before["close"] is None


def test_inventario_observado_so_e_aceito_amarrado_aos_insumos_do_inventory():
    from tools.cnesdata_delivery import static_inputs as si
    values = _values()
    assert si.inventory_observation(values.inventory, values.inputs) == values.inventory
    for raw in (_inventory(values.inputs, candidate_sha256="0" * 64), _inventory(values.inputs, schema="other"),
                _inventory(values.inputs, baseline={"schema": "x"}), values.inventory + b" "):
        with pytest.raises(ValueError, match="^static_inputs=inventory_observation$"):
            si.inventory_observation(raw, values.inputs)


_CALLER_MUTATIONS = {
    "candidate": {"candidate.json": _values().candidate.replace(b'"schema_version":1', b'"schema_version":3')},
    "archive": {"archive.tgz": _archive(source_sha="c" * 40)},
    "static-baseline": {"static-baseline.json": _baseline(schema="cnesdata.static-baseline/v2")},
}
_RETAINED_MUTATIONS = {
    "retained-candidate": {"candidate": _values().candidate + b" "},
    "retained-dashboard": {"dashboard-artifact": _values().dist + bytes(512)},
}


def _production_base(monkeypatch, mutation=None):
    """Stage world before prepared: caller artifacts, pinned dashboard, retained inventory inputs, real plan source."""
    from test_cnesdata_stage_events import ARTIFACTS, JOBS, _stage_world
    from test_cnesdata_delivery_lifecycle import _envelope_case
    from tools.cnesdata_delivery import application_gate as ag
    values, real = _values(), ag.static_plan_source

    def carrier(owner, window):
        binding = _binding(owner, values.plan, **({"release_id": "r" + "0" * 31} if mutation == "binding" else {}))
        return c.canonical(_envelope_case(owner=owner, window=window, terraform=_terraform(binding))[1])
    ready = {"handoff": {"closed_ready_sha256": "0" * 64}} if mutation == "host-receipt" else None
    world = _stage_world(monkeypatch, carrier=carrier, ready=ready,
                         static_inventory=None if mutation == "inventory" else values.inventory)
    monkeypatch.setattr(ag, "static_plan_source", real)
    world.values = values
    world.governance["release"] = _release(values.candidate)
    world.governance.update({key: value for key, value in EVIDENCE_GOVERNANCE.items() if key not in world.governance})
    world.keeper.static_inputs = {"candidate": values.candidate, "dashboard-artifact": values.dist} \
        | _RETAINED_MUTATIONS.get(mutation, {})
    plan = _plan(values.inventory, multipart_keys=["assets/x.js"]) if mutation == "static-plan" else values.plan
    members = {"cnesdata-static-inputs-4242-1": (601, 86, ag.STATIC_INPUTS_JOB, {
                   "candidate.json": values.candidate, "archive.tgz": values.inputs["archive"],
                   "static-baseline.json": values.inputs["static-baseline"]} | _CALLER_MUTATIONS.get(mutation, {})),
               "cnesdata-static-plan-4242-1": (602, 85, ag.INVENTORY_PROBE, {"static-plan.json": plan})}
    if mutation == "caller":
        del members["cnesdata-static-inputs-4242-1"]
    listing, artifacts = world.github.responses[JOBS], world.github.responses[ARTIFACTS]
    for name, (artifact_id, job_id, job_name, files) in members.items():
        archive = _zip(files)
        job = {"id": job_id, "run_id": 4242, "run_attempt": 1, "head_sha": SOURCE, "name": job_name, "status": "completed",
               "conclusion": "success", "started_at": c.utc(1001), "completed_at": c.utc(1090)}
        metadata = {"id": artifact_id, "name": name, "digest": "sha256:" + c.sha(archive),
                    "workflow_run": {"id": 4242, "head_sha": SOURCE}, "expired": False, "expires_at": c.utc(9000),
                    "created_at": c.utc(1050)}
        listing["jobs"] = listing["jobs"] + [job]
        listing["total_count"] += 1
        artifacts["artifacts"] = artifacts["artifacts"] + [metadata]
        artifacts["total_count"] += 1
        world.github.responses.update({f"{REPO}/jobs/{job_id}": job, f"{REPO}/artifacts/{artifact_id}": metadata,
                                       f"{REPO}/artifacts/{artifact_id}/zip": archive})
    dashboard = _dashboard_metadata(values, digest="sha256:" + "0" * 64) if mutation == "dashboard-artifact" else \
        _dashboard_metadata(values)
    world.github.responses.update({f"{REPO}/artifacts/{DASHBOARD_ID}": dashboard,
                                   f"{REPO}/artifacts/{DASHBOARD_ID}/zip": values.artifact})
    return world


def _production_world(monkeypatch, mutation=None):
    from test_cnesdata_stage_events import B_REFERENCE, PREPARED_REFERENCE
    from test_cnesdata_static_stage import _install_static
    world = _production_base(monkeypatch, mutation)
    world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    world.clock.value = 1130
    world.keeper.tick()
    world.handlers["phase-b"](world.keeper, dict(B_REFERENCE))
    world.clock.value = 1200
    world.keeper.tick()
    return _install_static(monkeypatch, world, {"capability": "real", "source": "production", "versions": (),
                                                "unit": "real"})


def test_insumos_de_producao_do_inventory_vem_do_artefato_static_inputs_e_do_dashboard_fixado(monkeypatch):
    from test_cnesdata_stage_events import RUN
    from tools.cnesdata_delivery import application_gate as ag
    world = _production_base(monkeypatch)
    inputs = ag.inventory_input_source(api=world.api, governance=world.governance, run=dict(RUN), owner=world.owner,
                                       guard=_Guard(), now=1100)
    assert inputs == world.values.inputs


@pytest.mark.parametrize("mutation, message", [
    ("candidate", "static_inputs=candidate_digest"), ("dashboard-artifact", "static_inputs=dashboard_artifact"),
    ("archive", "static_inputs=archive_binding"), ("static-baseline", "static_inputs=baseline"),
    ("caller", "static_inputs=caller_artifact job=static-inputs")])
def test_cada_insumo_do_inventory_recusa_fonte_nao_autenticada(monkeypatch, mutation, message):
    from test_cnesdata_stage_events import RUN
    from tools.cnesdata_delivery import application_gate as ag
    world = _production_base(monkeypatch, mutation)
    with pytest.raises(ValueError, match=f"^{message}$"):
        ag.inventory_input_source(api=world.api, governance=world.governance, run=dict(RUN), owner=world.owner,
                                  guard=_Guard(), now=1100)


@pytest.mark.parametrize("mutation, message", [("static-plan", "static_inputs=static_plan_binding"),
                                               ("inventory", "prepared=inventory_unsettled")])
def test_static_plan_de_producao_so_entra_no_prepared_amarrado_ao_portador_e_ao_inventario(monkeypatch, mutation, message):
    from test_cnesdata_stage_events import PREPARED_REFERENCE
    world = _production_base(monkeypatch, mutation)
    before = world.store.get()[0]["lifecycle"]
    with pytest.raises(ValueError, match=f"^{message}$"):
        world.handlers["prepared"](world.keeper, dict(PREPARED_REFERENCE))
    assert "close_drain_capability" not in world.events and world.invoke == []
    assert world.store.get()[0]["lifecycle"] == before and world.store.get()[0]["status"] == "held"


@pytest.mark.parametrize("mutation, message", [
    ("retained-candidate", "static_inputs=candidate_digest"), ("retained-dashboard", "static_inputs=dashboard_sha256"),
    ("host-receipt", "host handoff accepted for the keeper closed-ready"),
    ("binding", "static_binding=carrier_mismatch field=release_id")])
def test_cada_insumo_do_publish_static_recusa_fonte_nao_autenticada_e_nunca_roda_o_child(monkeypatch, mutation, message):
    from test_cnesdata_stage_events import HOST_REFERENCE
    world = _production_world(monkeypatch, mutation)
    with pytest.raises(ValueError, match=f"^{message}$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    assert "invoke_adapter" not in world.events[world.events.index("authenticate_host_handoff"):]
    assert world.store.get()[0]["status"] == "held" and world.store.get()[0]["lifecycle"]["stage"] in {"api", "static"}


def test_execute_de_producao_chega_ao_unit_e_o_modo_unit_recusa_o_primeiro_original_nao_autenticado(monkeypatch):
    """Ruling 4 item 6: the host starts the real unit mode run in the unit window; it refuses at the first original it
    cannot authenticate (the fixture manifest, with no product checkout in this world), before any mode child, and the
    lease stays held at unit."""
    from test_cnesdata_stage_events import HOST_REFERENCE
    from tools.cnesdata_delivery import application_gate as ag
    world = _production_world(monkeypatch)
    reads = list(world.github.reads)
    with pytest.raises(ValueError, match="^mode fixture original$"):
        world.handlers["host"](world.keeper, dict(HOST_REFERENCE))
    lifecycle = world.store.get()[0]["lifecycle"]
    assert lifecycle["stage"] == "unit" and lifecycle["sequence"] == 4 and world.store.get()[0]["status"] == "held"
    assert [item._request["operation"] for item in world.keeper._contexts if type(item) is ag.AdapterJournal][-1:] == [
        "publish-static"]
    assert world.github.reads == reads
    (journal,) = [item for item in world.keeper._contexts if type(item) is ag.AdapterJournal
                  and item._request["operation"] == "publish-static"]
    assert journal._inputs["inventory"] == world.values.inventory and journal._inputs["static-plan"] == world.values.plan
    assert journal._inputs["dashboard-artifact"] == world.values.dist and journal.unknown == [] and journal.pending == []
    assert [call[1] for client in world.clients.values() for call in client.calls].count("put_object") == 3


def _inventory_journal():
    from test_cnesdata_application_gate import _adapter_case
    from test_cnesdata_static_stage import _static_inputs
    from tools.cnesdata_delivery import application_gate as ag
    _, owner, window, _ = _adapter_case("inventory")
    base = _static_inputs(owner["source_sha"])
    inputs = {"candidate": base["candidate"], "dashboard-artifact": base["dashboard-artifact"], "archive": _archive(),
              "static-baseline": _baseline()}
    request = ag._operation_request("inventory", owner=owner, window=window, inputs=inputs, activation=b"release")
    journal = ag.AdapterJournal(request, operation="inventory", owner=owner, window=window, inputs=inputs,
                                activation_sha256=c.sha(b"release"), guard=_Guard())
    return journal, owner, window


def test_sessao_do_inventory_assume_so_o_observer_sp_i_ate_o_prazo_da_preparacao(monkeypatch):
    from datetime import datetime, timezone
    from test_cnesdata_static_stage import ACCOUNT, ROLES
    from tools.cnesdata_delivery import application_gate as ag, aws_boundary, lifecycle_contract as lc, session_policy
    journal, owner, window = _inventory_journal()
    binding = ag._static_binding(EVIDENCE_GOVERNANCE, journal)
    assert binding["static_plan_sha256"] is None
    names = lc.static_sessions(binding, "inventory")
    assumed = ROLES["observer"].replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/" + names["observer"]
    user = "AROA" + "OBSERVER".ljust(17, "X") + ":" + names["observer"]
    calls, factory_calls = [], []

    class Operation:
        def call(self, service, operation, **parameters):
            calls.append((service, operation, parameters))
            return {"PackedPolicySize": 10, "AssumedRoleUser": {"Arn": assumed, "AssumedRoleId": user}, "Credentials": {
                "AccessKeyId": "observer", "SecretAccessKey": "synthetic-secret", "SessionToken": "synthetic-token",
                "Expiration": datetime.fromtimestamp(2000, timezone.utc)}}
    operation = Operation()

    class Delegated:
        def __init__(self, governance, *, credentials):
            self.identity = {"Account": ACCOUNT, "Arn": assumed, "UserId": user}
    monkeypatch.setattr(aws_boundary, "AWS", Delegated)

    def factory(name, role, stage):
        factory_calls.append((name, dict(role), dict(stage)))
        return operation
    from test_cnesdata_static_roles import ROLE_FACTS
    session = ag._assume_static_session(governance=EVIDENCE_GOVERNANCE, journal=journal, binding=binding, credential_limit=2000,
                                        operation_session=factory, clock=lambda: 1100,
                                        roles={"observer": ROLE_FACTS["observer"]})
    stage = journal._request["stage"]
    assert factory_calls == [("inventory", {"observer": names["observer"]}, stage)]
    policy = session_policy.static_session_policy("observer", bucket_arn="arn:aws:s3:::" + BUCKET, distribution_arn=None,
                                                  deadline=window["preparation_deadline"])
    assert calls == [("sts", "assume_role", {"RoleArn": ROLES["observer"], "RoleSessionName": names["observer"],
                                             "DurationSeconds": 900, "Policy": c.canonical(policy).decode().strip()})]
    assert set(session.clients) == {"observer"} and session.scope["plan"] is None
    assert session.deadline == window["preparation_deadline"] and session.evidence is operation


def test_politica_do_observer_sem_distribuicao_e_a_mesma_e_o_normal_exige_a_distribuicao():
    from tools.cnesdata_delivery import session_policy
    bucket = "arn:aws:s3:::" + BUCKET
    assert session_policy.static_session_policy("observer", bucket_arn=bucket, distribution_arn=None, deadline=2000) == \
        session_policy.static_session_policy("observer", bucket_arn=bucket, distribution_arn=DISTRIBUTION, deadline=2000)
    with pytest.raises(ValueError, match="^static session distribution$"):
        session_policy.static_session_policy("normal", bucket_arn=bucket, distribution_arn=None, deadline=2000)


def test_broker_do_inventory_despacha_so_o_catalogo_do_observer_com_evidencia_no_namespace_inventory():
    from test_cnesdata_static_stage import ACCOUNT, PAIR, _put
    from tools.cnesdata_delivery import application_gate as ag
    journal, owner, window = _inventory_journal()
    evidence = _Evidence()
    request = c.sha(c.canonical(journal._request))
    with pytest.raises(ValueError, match="one original admitted static broker"):
        ag.StaticBroker(evidence, EVIDENCE_GOVERNANCE, journal, ag._StaticSession(
            {"observer": _Native("observer"), "normal": _Native("normal")}, "9" * 64,
            {"account": ACCOUNT, "bucket": BUCKET, "plan": None}, 1900, request, evidence))
    observer = _Native("observer", versions=PAIR)
    session = ag._StaticSession({"observer": observer}, "9" * 64, {"account": ACCOUNT, "bucket": BUCKET, "plan": None}, 1900,
                                request, evidence)
    broker = ag.StaticBroker(evidence, EVIDENCE_GOVERNANCE, journal, session, clock=lambda: 1100)
    reply, _ = ag._adapter_message(_frame("observer", "s3", "ListObjectVersions", {"Bucket": BUCKET}), journal)
    assert reply["kind"] == "sdk-result" and [key for key, _ in PAIR] == [item["Key"] for item in reply["value"]["Versions"]]
    assert len(evidence.writes) == 3 and all("/inventory/sdk-" in key for key in evidence.writes)
    with pytest.raises(ValueError):
        ag._adapter_message(_frame(*_put("assets/app.js")), journal)
    assert len(observer.calls) == 1 and len(evidence.writes) == 3 and broker.uncertainty == []


def test_capability_do_inventory_assume_o_sp_i_sem_plano_e_falha_fechada_retendo_o_lease(monkeypatch):
    from test_cnesdata_application_gate import _prepare_stage_keeper
    from test_cnesdata_static_stage import ACCOUNT
    from tools.cnesdata_delivery import application_gate as ag
    journal, owner, window = _inventory_journal()
    keeper, store = _prepare_stage_keeper()
    seen = []

    def assume(**kwargs):
        seen.append(kwargs)
        return ag._StaticSession({"observer": _Native("observer")}, "9" * 64, {"account": ACCOUNT, "bucket": BUCKET, "plan": None},
                                 1900, c.sha(c.canonical(journal._request)), "operation-client")
    from test_cnesdata_static_roles import ROLE_FACTS, role_files
    monkeypatch.setattr(ag, "_assume_static_session", assume)
    broker = ag.inventory_capability(governance=EVIDENCE_GOVERNANCE, journal=journal, keeper=keeper, credential_limit=2000,
                                     operation_session="factory", clock=lambda: 1100, publication=role_files(("observer",)))
    (call,) = seen
    assert call["roles"] == {"observer": ROLE_FACTS["observer"]}
    assert call["binding"] == ag._static_binding(EVIDENCE_GOVERNANCE, journal) and call["binding"]["static_plan_sha256"] is None
    assert call["operation_session"] == "factory" and call["credential_limit"] == 2000
    assert type(broker) is ag.StaticBroker and broker in keeper._contexts and journal._broker is broker
    other, _, _ = _inventory_journal()
    monkeypatch.setattr(ag, "_assume_static_session", lambda **kwargs: (_ for _ in ()).throw(ValueError("static STS refused")))
    with pytest.raises(ValueError, match="^static STS refused$"):
        ag.inventory_capability(governance=EVIDENCE_GOVERNANCE, journal=other, keeper=keeper, credential_limit=2000,
                                operation_session="factory", clock=lambda: 1100, publication=role_files(("observer",)))
    assert other._failed is True and other in keeper._contexts and store.get()[0]["status"] == "held"


def test_fabrica_de_sessao_de_operacao_serve_o_inventory_so_com_o_observer(monkeypatch):
    from test_cnesdata_application_gate import _operation_factory_case
    factory, admitted, world, stage, seen, client, credentials = _operation_factory_case(monkeypatch)
    sessions = {"observer": "sp-i-" + "1" * 40}
    assert factory("inventory", dict(sessions), stage) is client
    assert seen[0][1:] == ((admitted[0], "b" * 40, 4242, 1, "inventory"),
                           {"application_purpose": "promotion", "delegations": ("observer",), "sessions": sessions})
    with pytest.raises(ValueError, match="closed object fields"):
        factory("inventory", dict(sessions, normal="sp-publish-" + "2" * 40), stage)
