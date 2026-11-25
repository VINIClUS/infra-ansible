"""P16b c-1124-p16b-next item 4 (design 6, P17 ruling 1g): the phase-c.json element from the pinned product builder."""
import json
import pathlib

import pytest

from test_cnesdata_phase_c_routes import PREFIX, REV, _after, _machine, _schedule
from test_cnesdata_stage_events import _close_drain
from tools.cnesdata_delivery import contract as c
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
OBSERVED = 1_795_430_000
APPLY = b"Apply complete! Resources: 0 added, 1 changed, 0 destroyed.\n"
PLAN = b"reviewed-plan-binary"


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


def _deploy(mode="recovery", readbacks=None, rendered=None, **changes):
    purpose = "phase-c-" + mode
    previous = c.canonical(_point(7, "v7") | {"purpose": "phase-b", "plan_sha256": "e" * 64, "readbacks": [_machine()]})
    variables = {"processor_active_unit_task_definition_arn": REV["unit"],
                 "scheduler_recovery_task_definition_arn": (rendered or REV)["recovery"],
                 "scheduler_audit_task_definition_arn": (rendered or REV)["audit"]}
    approval = {"purpose": purpose, "checkpoint_sha256": c.sha(previous), "plan_sha256": c.sha(PLAN)} | changes.pop(
        "approval", {})
    checkpoint = _point(8, "v8") | {"purpose": purpose, "plan_sha256": c.sha(PLAN),
                                    "readbacks": _after(mode) if readbacks is None else readbacks} | changes.pop(
        "checkpoint", {})
    payload = {"plan.bin": PLAN, "plan.json": c.canonical({"variables": {name: {"value": value}
                                                                         for name, value in variables.items()}}),
               "checkpoint.json": previous, "approval.json": c.canonical(approval)}
    return lr.PhaseCDeploy(changes.pop("purpose", purpose), payload, c.canonical(checkpoint), APPLY)


def _publication(tmp_path, deploy, *, product=None, close=CLOSE, phase_b=None, run=None):
    return lr.phase_c_publication(deploy, product=product or _product(tmp_path), close_raw=c.canonical(close),
                                  phase_b=[_machine()] if phase_b is None else phase_b, observed_at=OBSERVED, run=run)


def _product_text(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _expected(deploy, routes):
    previous, checkpoint = (c.loads(raw, canonical=True) for raw in (deploy.payload["checkpoint.json"], deploy.checkpoint_raw))
    point = {key: value for key, value in previous["state"].items()} | {"object_version": "v7"}
    after = {key: value for key, value in checkpoint["state"].items()} | {"object_version": "v8"}
    return _product_text({"version": 1, "kind": deploy.purpose, "common": CLOSE["common"],
                          "close_drain_sha256": c.sha(_product_text(CLOSE)), "before": point, "after": after,
                          "plan_sha256": c.sha(PLAN), "audit_sha256": c.sha(deploy.payload["approval.json"]),
                          "apply_sha256": c.sha(APPLY), "routes": routes, "observed_at": c.utc(OBSERVED)})


def test_elemento_phase_c_recovery_e_o_do_construtor_do_produto_com_as_rotas_lidas(tmp_path):
    deploy = _deploy()
    assert _publication(tmp_path, deploy) == {"phase-c.json": _expected(deploy, REV | {"audit": None})}


def test_elemento_phase_c_audit_tem_as_tres_rotas_lidas(tmp_path):
    deploy = _deploy("audit")
    assert _publication(tmp_path, deploy) == {"phase-c.json": _expected(deploy, REV)}


def test_rota_lida_entra_no_elemento_mesmo_quando_difere_do_alvo_renderizado(tmp_path):
    """P17 ruling 1g: the readback :8 wins over the rendered :9 of the plan variables; routes_match decides downstream."""
    drifted = PREFIX + "recovery:8"
    readbacks = [row for row in _after("recovery") if row["operation"] != "get_schedule"] + [_schedule("recovery", drifted)]
    readbacks = [row for row in readbacks if row["operation"] != "describe_task_definition"]
    from test_cnesdata_phase_c_routes import _task
    unit, recovery = _task("unit"), _task("recovery")
    recovery["observed"]["taskDefinition"]["taskDefinitionArn"] = drifted
    deploy = _deploy(readbacks=readbacks + [unit, recovery])
    element = c.loads(_publication(tmp_path, deploy)["phase-c.json"])
    assert element["routes"] == {"unit": REV["unit"], "recovery": drifted, "audit": None}
    assert c.loads(deploy.payload["plan.json"])["variables"]["scheduler_recovery_task_definition_arn"]["value"] == REV["recovery"]


@pytest.mark.parametrize("purpose", ["phase-b", "application-prepare"])
def test_publicacao_fora_dos_dois_propositos_c_nao_ganha_phase_c(tmp_path, purpose):
    assert _publication(tmp_path, _deploy(purpose=purpose)) == {}


@pytest.mark.parametrize("name", ["phase_c_recovery.py", "_phase_c_core.py"])
def test_produto_fora_do_pin_recusa_antes_do_filho(tmp_path, name):
    seen = []
    with pytest.raises(ValueError, match=f"^phase_c=product_pin file=scripts/promotion/{name}$"):
        _publication(tmp_path, _deploy(), product=_product(tmp_path, name), run=lambda *args: seen.append(args))
    assert seen == []


@pytest.mark.parametrize("changes", [{"approval": {"checkpoint_sha256": "0" * 64}}, {"approval": {"purpose": "phase-c-audit"}},
                                     {"approval": {"plan_sha256": "0" * 64}}, {"checkpoint": {"purpose": "phase-b"}},
                                     {"checkpoint": {"plan_sha256": "0" * 64}}],
                         ids=["checkpoint-anterior", "proposito-aprovado", "plano-aprovado", "proposito-checkpoint",
                              "plano-checkpoint"])
def test_elemento_fora_da_ancestralidade_do_deploy_recusa_antes_do_filho(tmp_path, changes):
    seen = []
    with pytest.raises(ValueError, match="^phase_c=element_ancestry$"):
        _publication(tmp_path, _deploy(**changes), run=lambda *args: seen.append(args))
    assert seen == []


def test_maquina_diferente_da_phase_b_recusa_antes_do_filho(tmp_path):
    seen = []
    with pytest.raises(ValueError, match="^phase_c=routes field=machine$"):
        _publication(tmp_path, _deploy(), phase_b=[_machine(stateMachineArn=REV["unit"])], run=lambda *args: seen.append(args))
    assert seen == []


def test_close_drain_fora_da_forma_recusa_antes_do_filho(tmp_path):
    with pytest.raises(ValueError):
        _publication(tmp_path, _deploy(), close={key: value for key, value in CLOSE.items() if key != "members"})


@pytest.mark.parametrize("change", ["kind", "routes", "apply_sha256", "ascii"])
def test_bytes_do_filho_diferentes_do_elemento_esperado_recusam(tmp_path, change):
    deploy = _deploy()
    expected = c.loads(_expected(deploy, REV | {"audit": None}))

    def run(product, request):
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
        _publication(tmp_path, deploy, run=run)


def test_recusa_do_construtor_do_produto_vira_falha_do_filho(tmp_path):
    deploy = _deploy(checkpoint=_point(7, "v8"))
    with pytest.raises(ValueError, match="^phase_c=element_child$"):
        _publication(tmp_path, deploy)

