"""P16b ruling 6 (design 6 and 8 item 3 amended): the keeper-side phase-c element from the pinned product builder."""
import json
import os
import pathlib

import pytest

from test_cnesdata_phase_c_routes import PREFIX, REV, _after, _machine, _schedule, _task
from test_cnesdata_stage_events import _close_drain
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery import lifecycle_runtime as lr

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "cnesdata_phase_c_product"
STUBS = {
    "scripts/__init__.py": "",
    "scripts/promotion/accept_routing.py": "def observe_gate(*args):\n    raise AssertionError\n"
                                           "def read_routes(*args):\n    raise AssertionError\n",
    "scripts/promotion/phase_b.py": "def _assert_task_revisions_unchanged(*args):\n    raise AssertionError\n"
                                    "def _context_from_admitted(*args):\n    raise AssertionError\n",
    "scripts/promotion/_stage_windows.py": "def close_windows(*args):\n    raise AssertionError\n",
    "scripts/promotion/mode_canary.py": "RESULT_FIELDS = ()\nRESULT_SCHEMA = 1\n",
    "scripts/promotion/rollback_api_static.py": "CONVERGENCE_SECONDS = 1\nRECOVERY_SECONDS = 1\n",
    "packages/cnes_infra/src/cnes_infra/aws/mode_canary.py": "def canonical_text(value):\n    raise AssertionError\n",
}
CLOSE = _close_drain(common={"release_id": "release-fixture", "source_sha": "b" * 40})
OBSERVED = "2026-11-25T10:20:30Z"
APPLY = b"Apply complete! Resources: 0 added, 1 changed, 0 destroyed.\n"
PLAN = "2" * 64
RENDERED = {"unit": PREFIX + "unit:7", "recovery": PREFIX + "recovery:7", "audit": PREFIX + "audit:7"}


PHASE_C_ORIGIN = {"commit": "b5f6f9d643562dde69efe4aad4f6bb988ef245dd"}


def test_pin_do_elemento_e_a_copia_do_produto_no_commit_de_merge_do_p16d():
    from test_cnesdata_mode_frames import PRODUCT_FRAMES_ORIGIN
    assert PHASE_C_ORIGIN["commit"] == PRODUCT_FRAMES_ORIGIN["commit"]
    assert lc.PHASE_C_PRODUCT_FILES == {"scripts/promotion/" + name: c.sha((FIXTURE / name).read_bytes())
                                        for name in ("phase_c_recovery.py", "_phase_c_core.py")}


def _runtime():
    python, target = os.environ.get("CNESDATA_PHASE_C_PYTHON"), os.environ.get("CNESDATA_PHASE_C_TARGET")
    if not python or not target:
        pytest.fail("CNESDATA_PHASE_C_PYTHON and CNESDATA_PHASE_C_TARGET name the pinned phase-c child runtime")
    return lr.PhaseCRuntime(python, target)


def _product(tmp_path, change=None):
    product = tmp_path / "product"
    for name, text in STUBS.items():
        (product / name).parent.mkdir(parents=True, exist_ok=True)
        (product / name).write_text(text)
    for name in ("phase_c_recovery.py", "_phase_c_core.py"):
        raw = (FIXTURE / name).read_bytes()
        (product / "scripts/promotion" / name).write_bytes(raw + (b"\n" if change == name else b""))
    return product


def _point(serial, version):
    return {"state": {"lineage": "lineage-fixture", "serial": serial, "state_sha256": str(serial) * 64},
            "state_object": {"version_id": version}}


def _b_checkpoint(**changes):
    return c.canonical(_point(6, "v6") | {"purpose": "phase-b", "plan_sha256": "9" * 64, "readbacks": [_machine()]} | changes)


def _sources(mode="recovery", readbacks=None, **changes):
    purpose = "phase-c-" + mode
    phase_b = changes.pop("phase_b", _b_checkpoint())
    before = phase_b if mode == "recovery" else c.canonical(
        _point(7, "v7") | {"purpose": "phase-c-recovery", "plan_sha256": "e" * 64, "readbacks": _after("recovery")})
    before = changes.pop("before", before)
    delta = {"purpose": purpose, "direction": "advance", "mode": "operational",
             "before": {"scheduler_recovery_task_definition_arn": RENDERED["recovery"],
                        "scheduler_audit_task_definition_arn": RENDERED["audit"]}}
    approval = {"purpose": purpose, "checkpoint_sha256": c.sha(before), "plan_sha256": PLAN, "delta": delta} | changes.pop(
        "approval", {})
    checkpoint = _point(8, "v8") | {"purpose": purpose, "plan_sha256": PLAN,
                                    "readbacks": _after(mode) if readbacks is None else readbacks} | changes.pop("checkpoint", {})
    published = {"checkpoint.json": c.canonical(checkpoint), "approval.json": c.canonical(approval),
                 "apply-output.bin": APPLY} | changes.pop("published", {})
    for name in changes.pop("absent", ()):
        published.pop(name)
    return lr.PhaseCSources(changes.pop("purpose", purpose), published, before, phase_b,
                            changes.pop("close", c.canonical(CLOSE)), changes.pop("observed_at", OBSERVED))


def _element(tmp_path, sources, *, product=None, run=None):
    return lr.phase_c_element(sources, product=product or _product(tmp_path), runtime=_runtime(), run=run)


def _product_text(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _expected(sources, routes, close=CLOSE):
    before, checkpoint = (c.loads(raw, canonical=True) for raw in (sources.before_raw, sources.published["checkpoint.json"]))
    point = dict(before["state"]) | {"object_version": before["state_object"]["version_id"]}
    after = dict(checkpoint["state"]) | {"object_version": "v8"}
    return _product_text({"version": 1, "kind": sources.purpose, "common": close["common"],
                          "close_drain_sha256": c.sha(_product_text(close)), "before": point, "after": after,
                          "plan_sha256": PLAN, "audit_sha256": c.sha(sources.published["approval.json"]),
                          "apply_sha256": c.sha(APPLY), "routes": routes, "observed_at": OBSERVED})


def test_elemento_phase_c_recovery_e_o_do_construtor_do_produto_com_as_rotas_lidas(tmp_path):
    sources = _sources()
    assert _element(tmp_path, sources) == _expected(sources, REV | {"audit": None})


def test_elemento_phase_c_audit_tem_as_tres_rotas_lidas_e_o_checkpoint_do_recovery_como_antes(tmp_path):
    sources = _sources("audit")
    raw = _element(tmp_path, sources)
    assert raw == _expected(sources, REV)
    assert json.loads(raw)["before"]["object_version"] == "v7"


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_rotas_vem_das_leituras_do_checkpoint_e_nunca_do_delta_aprovado(tmp_path, mode):
    """P17 ruling 1g: the readback :8 wins over the rendered :7 the approval delta carries."""
    drifted = PREFIX + "recovery:8"
    readbacks = [row for row in _after(mode) if row["operation"] not in ("get_schedule", "describe_task_definition")]
    recovery = _task("recovery")
    recovery["observed"]["taskDefinition"]["taskDefinitionArn"] = drifted
    readbacks += [_schedule("recovery", drifted), _task("unit"), recovery] + ([_schedule("audit")] if mode == "audit" else [])
    sources = _sources(mode, readbacks=readbacks)
    element = json.loads(_element(tmp_path, sources))
    assert element["routes"] == {"unit": REV["unit"], "recovery": drifted, "audit": REV["audit"] if mode == "audit" else None}
    assert RENDERED["recovery"] not in json.dumps(element)


def test_saida_do_apply_do_elemento_e_o_membro_publicado(tmp_path):
    other = b"Apply complete! Resources: 2 added, 0 changed, 0 destroyed.\n"
    sources = _sources(published={"apply-output.bin": other})
    assert json.loads(_element(tmp_path, sources))["apply_sha256"] == c.sha(other)


def test_observed_at_do_elemento_e_o_momento_autenticado_recebido(tmp_path):
    sources = _sources(observed_at="2026-11-25T10:21:00Z")
    assert json.loads(_element(tmp_path, sources))["observed_at"] == "2026-11-25T10:21:00Z"


@pytest.mark.parametrize("observed_at", [1_795_430_000, "2026-11-25T10:20:30.5Z", "2026-11-25 10:20:30"])
def test_observed_at_fora_do_formato_utc_recusa_antes_do_filho(tmp_path, observed_at):
    seen = []
    with pytest.raises(ValueError):
        _element(tmp_path, _sources(observed_at=observed_at), run=lambda *args: seen.append(args))
    assert seen == []


@pytest.mark.parametrize("change", [{"published": {"plan.json": b"{}\n"}}, {"absent": ["apply-output.bin"]},
                                    {"absent": ["approval.json"]}], ids=["plan-json", "sem-apply", "sem-approval"])
def test_membros_da_publicacao_c_sao_fechados(tmp_path, change):
    seen = []
    with pytest.raises(ValueError, match="^phase_c=element_members$"):
        _element(tmp_path, _sources(**change), run=lambda *args: seen.append(args))
    assert seen == []


@pytest.mark.parametrize("purpose", ["phase-b", "application-prepare"])
def test_proposito_fora_dos_dois_c_recusa(tmp_path, purpose):
    with pytest.raises(ValueError, match="^phase_c=element_purpose$"):
        _element(tmp_path, _sources(purpose=purpose))


@pytest.mark.parametrize("name", ["phase_c_recovery.py", "_phase_c_core.py"])
def test_produto_fora_do_pin_recusa_antes_do_filho(tmp_path, name):
    seen = []
    with pytest.raises(ValueError, match=f"^phase_c=product_pin file=scripts/promotion/{name}$"):
        _element(tmp_path, _sources(), product=_product(tmp_path, name), run=lambda *args: seen.append(args))
    assert seen == []


ANCESTRY = {
    "checkpoint-anterior": ("recovery", {"approval": {"checkpoint_sha256": "0" * 64}}),
    "proposito-aprovado": ("recovery", {"approval": {"purpose": "phase-c-audit"}}),
    "plano-aprovado": ("recovery", {"approval": {"plan_sha256": "0" * 64}}),
    "proposito-checkpoint": ("recovery", {"checkpoint": {"purpose": "phase-b"}}),
    "plano-checkpoint": ("recovery", {"checkpoint": {"plan_sha256": "0" * 64}}),
    "antes-do-recovery-nao-e-o-b": ("recovery", {"before": _b_checkpoint(plan_sha256="8" * 64)}),
    "antes-do-audit-e-o-b": ("audit", {"before": _b_checkpoint()}),
    "b-fora-da-phase-b": ("audit", {"phase_b": _b_checkpoint(purpose="phase-c-recovery")}),
}


@pytest.mark.parametrize("case", sorted(ANCESTRY))
def test_elemento_fora_da_ancestralidade_recusa_antes_do_filho(tmp_path, case):
    mode, changes = ANCESTRY[case]
    seen = []
    with pytest.raises(ValueError, match="^phase_c=element_ancestry$"):
        _element(tmp_path, _sources(mode, **changes), run=lambda *args: seen.append(args))
    assert seen == []


@pytest.mark.parametrize("mode", ["recovery", "audit"])
def test_maquina_diferente_da_phase_b_recusa_antes_do_filho(tmp_path, mode):
    seen = []
    phase_b = _b_checkpoint(readbacks=[_machine(stateMachineArn=REV["unit"])])
    changes = {"phase_b": phase_b} | ({"before": phase_b} if mode == "recovery" else {})
    with pytest.raises(ValueError, match="^phase_c=routes field=machine$"):
        _element(tmp_path, _sources(mode, **changes), run=lambda *args: seen.append(args))
    assert seen == []


def test_close_drain_fora_da_forma_recusa_antes_do_filho(tmp_path):
    seen = []
    close = c.canonical({key: value for key, value in CLOSE.items() if key != "members"})
    with pytest.raises(ValueError):
        _element(tmp_path, _sources(close=close), run=lambda *args: seen.append(args))
    assert seen == []


@pytest.mark.parametrize("change", ["kind", "routes", "apply_sha256", "ascii"])
def test_bytes_do_filho_diferentes_do_elemento_esperado_recusam(tmp_path, change):
    sources = _sources()
    expected = json.loads(_expected(sources, REV | {"audit": None}))

    def run(product, runtime, request):
        value = dict(expected)
        if change == "kind":
            value["kind"] = "phase-c-audit"
        if change == "routes":
            value["routes"] = REV
        if change == "apply_sha256":
            value["apply_sha256"] = "0" * 64
        raw = _product_text(value)
        return raw if change != "ascii" else raw.replace(b'"version":1', b'"version": 1')
    with pytest.raises(ValueError, match="^phase_c=element_parity$"):
        _element(tmp_path, sources, run=run)


def test_filho_recebe_o_produto_e_o_runtime_pinado(tmp_path):
    sources, seen = _sources(), []
    product = _product(tmp_path)

    def run(*args):
        seen.append(args)
        return _expected(sources, REV | {"audit": None})
    assert lr.phase_c_element(sources, product=product, runtime=_runtime(), run=run) == _expected(sources, REV | {"audit": None})
    ((given, runtime, request),) = seen
    assert given == product and runtime == _runtime() and request["observed_at"] == OBSERVED


def test_recusa_do_construtor_do_produto_vira_falha_do_filho(tmp_path):
    with pytest.raises(ValueError, match="^phase_c=element_child$"):
        _element(tmp_path, _sources(checkpoint=_point(6, "v8")))


def test_filho_roda_isolado_so_com_o_alvo_pinado_no_caminho(tmp_path):
    product = _product(tmp_path)
    probe = "import sys, json\nsys.stdout.write(json.dumps({'path': sys.path[:2], 'site': 'site' in sys.modules}))\n"
    (product / "scripts/promotion/phase_c_recovery.py").write_text(probe + "raise SystemExit(0)\n")
    value = json.loads(lr._phase_c_child(product, _runtime(), {"probe": True}))
    assert value == {"path": [str(product.resolve()), _runtime().target], "site": False}


def test_filho_alem_do_prazo_recusa_como_falha_do_filho(tmp_path, monkeypatch):
    import subprocess
    calls = []

    def expired(*args, **kwargs):
        calls.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    monkeypatch.setattr(lr.subprocess, "run", expired)
    with pytest.raises(ValueError, match="^phase_c=element_child$"):
        lr._phase_c_child(_product(tmp_path), _runtime(), {})
    assert calls == [20]


def test_close_drain_com_texto_nao_ascii_tem_o_digest_do_canonico_do_produto(tmp_path):
    close = CLOSE | {"common": {"release_id": "liberação-fixture", "source_sha": "b" * 40}}
    sources = _sources(close=c.canonical(close))
    raw = _element(tmp_path, sources)
    element = json.loads(raw)
    assert element["close_drain_sha256"] == c.sha(_product_text(close)) != c.sha(c.canonical(close))
    assert element["common"] == close["common"] and b"\\u00e7" in raw and raw.isascii()


def test_runtime_do_filho_vem_do_ambiente_do_job_com_python_3_13():
    runtime = _runtime()
    assert lr.phase_c_runtime({"CNESDATA_PHASE_C_PYTHON": runtime.python, "CNESDATA_PHASE_C_TARGET": runtime.target}) == runtime


@pytest.mark.parametrize("version, accepted", [((3, 12, 9, "final", 0), False), ((3, 13, 1, "final", 0), True),
                                               ((3, 14, 0, "final", 0), False)], ids=["3.12", "3.13", "3.14"])
def test_runtime_do_filho_exige_exatamente_3_13_de_um_interpretador_que_responde_ao_predicado(tmp_path, version, accepted):
    """NIT 7: the stub evaluates the runtime predicate itself under the reported version, so 3.12 and 3.14 exit 1 by the
    exact (3, 13) comparison and the 3.13 control exits 0."""
    import sys
    stub = tmp_path / "python"
    stub.write_text(f"#!{sys.executable} -I\nimport sys\nassert sys.argv[1:4] == ['-I', '-S', '-c']\n"
                    f"sys.version_info = {version!r}\nexec(compile(sys.argv[4], 'stub', 'exec'), {{'__name__': '__main__'}})\n")
    stub.chmod(0o755)
    environ = {"CNESDATA_PHASE_C_PYTHON": str(stub), "CNESDATA_PHASE_C_TARGET": str(tmp_path)}
    if accepted:
        assert lr.phase_c_runtime(environ) == lr.PhaseCRuntime(str(stub), str(tmp_path))
        return
    with pytest.raises(ValueError, match="^phase_c=runtime$"):
        lr.phase_c_runtime(environ)


@pytest.mark.parametrize("case", ["sem-python", "sem-alvo", "python-relativo", "alvo-ausente", "outra-versao"])
def test_runtime_do_filho_fora_do_provisionado_recusa(tmp_path, case):
    runtime = _runtime()
    other = tmp_path / "python"
    other.write_text("#!/bin/sh\nexit 1\n")
    other.chmod(0o755)
    environ = {"CNESDATA_PHASE_C_PYTHON": runtime.python, "CNESDATA_PHASE_C_TARGET": runtime.target}
    environ = {"sem-python": {"CNESDATA_PHASE_C_TARGET": runtime.target},
               "sem-alvo": {"CNESDATA_PHASE_C_PYTHON": runtime.python},
               "python-relativo": environ | {"CNESDATA_PHASE_C_PYTHON": "python3.13"},
               "alvo-ausente": environ | {"CNESDATA_PHASE_C_TARGET": str(tmp_path / "absent")},
               "outra-versao": environ | {"CNESDATA_PHASE_C_PYTHON": str(other)}}[case]
    with pytest.raises(ValueError, match="^phase_c=runtime$"):
        lr.phase_c_runtime(environ)
