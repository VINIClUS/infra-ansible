"""P16b C2 (ruling 3): vendored product ledger builders, byte-pinned to CnesData P16c and to its product vector."""
import builtins
import collections
import datetime
import hashlib
import json
import sys
from pathlib import Path

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "cnesdata_delivery"
VECTOR_RAW = (ROOT / "tests" / "fixtures" / "cnesdata_mode_canary_frames_vector.json").read_bytes()
VECTOR = json.loads(VECTOR_RAW)
CASES = {case["name"]: case for case in VECTOR["cases"]}
BUILT = sorted(name for name, case in CASES.items() if "refusal" not in case)
REFUSED = sorted(name for name, case in CASES.items() if "refusal" in case)
FRAMES_PATH = "packages/cnes_infra/src/cnes_infra/aws/mode_canary_frames.py"
DISPATCH_PATH = "packages/cnes_infra/src/cnes_infra/aws/mode_canary_dispatch.py"
PRODUCT_FRAMES_ORIGIN = {
    "commit": "06849119a24e33e2b847a9d3d1bab2d76a8cf2fa",
    "packages/cnes_infra/src/cnes_infra/control_plane/dynamodb_keys.py":
        ("cnes_infra.control_plane.dynamodb_keys", "product_dynamodb_keys.py",
         "5810031c6ed6fae18f7a70e578c5255b9297ce63f0745b237eca191688ca19eb"),
    "packages/cnes_domain/src/cnes_domain/orchestration/mode_canary.py":
        ("cnes_domain.orchestration.mode_canary", "product_mode_canary.py",
         "255431e9f02f0f26554c42370ee0b0c55b1ab9287a79422c24be377df45571d2"),
    FRAMES_PATH:
        ("cnes_infra.aws.mode_canary_frames", "product_mode_canary_frames.py",
         "35cd96e6362a53c835369f0683e8eaec8b3eb9d3ea134f02e1689437df08cf33"),
    DISPATCH_PATH:
        ("cnes_infra.aws.mode_canary_dispatch", "product_mode_canary_dispatch.py",
         "5952a2c4afd66872d82efcdf15efb3937e5227df9ad8d05734698dd64c63793c"),
    "tests/production/delivery/mode_canary_frames_vector.json":
        (None, "tests/fixtures/cnesdata_mode_canary_frames_vector.json",
         "cdc60395fcd1e6ae52dac4ed354eb5bda03f779095b29a83a2bc8bdf02e9bd45")}
VENDORED = [value for key, value in PRODUCT_FRAMES_ORIGIN.items() if key != "commit" and value[0] is not None]
REUSABLE_LISTS = {"application-gate": 1, "infra-audit-gate": 1, "infra-deploy-gate": 1, "infra-plan-gate": 1, "observer": 2}
Holder = collections.namedtuple("Holder", "dispatch_id run_id tenant_id")


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _record(frames, text):
    return frames.ModeCanaryRecord.from_mapping(json.loads(text))


def _binding(frames, text):
    record = _record(frames, text)
    return frames.ModeCanaryBinding(f"prod-canary-{record.canary_id}", record.run_ids, record.owner_sha256,
                                    hashlib.sha256(text.encode()).hexdigest(), record.phase, record.context_kind)


def _effect(frames, case, binding):
    value = case["effect"]
    if "dispatch" in value:
        return frames.dispatch_effect(binding, _record(frames, case["record"]), Holder(**value["dispatch"]),
                                      tuple(value["unit_ids"]))
    return frames.ledger_effect(value["kind"], value["request_sha256"], value["target_sha256"])


def _build(case):
    frames = _mb().product_frames()
    builder, text, table = case["builder"], case["record"], VECTOR["table"]
    if builder == "record_item":
        return frames.record_item(_record(frames, text), text)
    if builder == "initial_control":
        return frames.initial_control(_record(frames, text), datetime.datetime.fromisoformat(case["admitted_at"]))
    binding = _binding(frames, text)
    if builder == "transition":
        return frames.transition(table, binding, (case["effect_id"], case["ticket"]), tuple(case["change"]))
    state = frames.LedgerState(binding, _record(frames, text), case["control"], case["ticket"])
    plan = frames.admission(table, state, _effect(frames, case, binding), datetime.datetime.fromisoformat(case["now"]))
    return {"effect_id": plan.effect_id, "items": plan.items}


def test_formatos_vendorizados_sao_os_quatro_arquivos_do_produto_no_commit_de_merge_do_p16c():
    assert _mb().PRODUCT_FRAMES == tuple(VENDORED)
    assert [name for name, _, _ in VENDORED] == ["cnes_infra.control_plane.dynamodb_keys",
                                                 "cnes_domain.orchestration.mode_canary",
                                                 "cnes_infra.aws.mode_canary_frames",
                                                 "cnes_infra.aws.mode_canary_dispatch"]


def test_conjunto_vendorizado_e_a_closure_que_o_vetor_do_produto_declara():
    assert {path: value[2] for path, value in PRODUCT_FRAMES_ORIGIN.items()
            if path != "commit" and value[0] is not None} == VECTOR["closure"]


@pytest.mark.parametrize("vendored", VENDORED, ids=[item[1] for item in VENDORED])
def test_arquivo_vendorizado_tem_os_bytes_exatos_da_origem_registrada(vendored):
    assert hashlib.sha256((TOOLS / vendored[1]).read_bytes()).hexdigest() == vendored[2]


def test_vetor_vendorizado_e_o_do_produto_e_aponta_para_a_fonte_fixada_dos_formatos():
    assert hashlib.sha256(VECTOR_RAW).hexdigest() == PRODUCT_FRAMES_ORIGIN[
        "tests/production/delivery/mode_canary_frames_vector.json"][2]
    assert VECTOR["source"] == {"path": FRAMES_PATH, "sha256": PRODUCT_FRAMES_ORIGIN[FRAMES_PATH][2]}
    assert set(BUILT) == {"dispatch-unit", "dispatch-unit-replay", "ledger-admit", "ledger-unknown", "ledger-settle",
                          "ledger-settle-replay", "record-item", "initial-control"}
    assert {CASES[name]["refusal"] for name in REFUSED} == {
        f"reason={reason} field=tenant_id" for reason in ("ticket_conflict", "budget_exhausted", "ticket_settled",
                                                          "ticket_mismatch")}


def test_teto_de_tentativas_do_ledger_vem_dos_formatos_vendorizados_e_do_vetor_do_produto():
    """Ruling 3 item 2: the keeper never hand-writes the bound; it is the vendored product constant."""
    assert VECTOR["attempts"] == _mb().product_frames().ATTEMPTS == 3


@pytest.mark.parametrize("name", BUILT)
def test_formatos_vendorizados_reproduzem_os_bytes_do_vetor_do_produto(name):
    built = _build(CASES[name])
    assert built == CASES[name]["result"]
    assert json.dumps(built, sort_keys=True) == json.dumps(CASES[name]["result"], sort_keys=True)


@pytest.mark.parametrize("name", REFUSED)
def test_formatos_vendorizados_recusam_como_o_vetor_do_produto(name):
    frames = _mb().product_frames()
    with pytest.raises(frames.SyntheticContextRequired) as refused:
        _build(CASES[name])
    assert str(refused.value) == CASES[name]["refusal"]


@pytest.mark.parametrize("tampered", [item[1] for item in VENDORED])
def test_carregador_recusa_byte_divergente_antes_de_executar_qualquer_arquivo(tmp_path, tampered):
    for _, name, _ in VENDORED:
        raw = (TOOLS / name).read_bytes()
        prefix = b"import builtins\nbuiltins.MODE_FRAMES_EXECUTED = True\n" if name == tampered else b""
        (tmp_path / name).write_bytes(prefix + raw)
    with pytest.raises(ValueError, match=f"^mode product frames sha256 file={tampered}$"):
        _mb()._load_product_frames(tmp_path)
    assert not hasattr(builtins, "MODE_FRAMES_EXECUTED")


def test_carregador_executa_os_bytes_verificados_sem_deixar_modulos_do_produto_em_sys_modules():
    names = [name for name, _, _ in VENDORED]
    assert not set(names) & set(sys.modules)
    modules = _mb()._load_product_frames(TOOLS)
    assert not set(names) & set(sys.modules)
    assert list(modules) == names and all(modules[name].__name__ == name for name in names)
    frames, dispatch = modules["cnes_infra.aws.mode_canary_frames"], modules["cnes_infra.aws.mode_canary_dispatch"]
    assert frames.tenant_partition("prod-canary-x") == "TENANT#" + "prod-canary-x".encode().hex()
    assert frames.ModeCanaryRecord.__module__ == "cnes_domain.orchestration.mode_canary"
    assert dispatch.refuse is frames.refuse and dispatch.dispatch_key.__module__ == "cnes_infra.control_plane.dynamodb_keys"


def test_acessores_devolvem_os_formatos_e_o_dispatch_pelo_nome_do_modulo_e_nao_pela_posicao():
    mb = _mb()
    assert mb.product_frames().__name__ == "cnes_infra.aws.mode_canary_frames"
    assert mb.product_dispatch().__name__ == "cnes_infra.aws.mode_canary_dispatch"
    assert mb.product_dispatch().refuse is mb.product_frames().refuse
    assert mb.product_dispatch().PRODUCTION_MAX_CONCURRENCY == 1


def test_formatos_do_produto_carregam_uma_vez_por_processo():
    mb = _mb()
    assert mb.product_frames() is mb.product_frames() and mb.product_dispatch() is mb.product_dispatch()


@pytest.mark.parametrize("vendored", VENDORED, ids=[item[1] for item in VENDORED])
def test_formatos_vendorizados_entram_no_pyboot_nas_quatro_listas_dos_gates_e_nas_duas_do_observador(vendored):
    """Fix round 1 item 4: the five lists carry every module under tools/cnesdata_delivery; the observer closure counts
    the frames mode_broker loads by exec."""
    name = vendored[1]
    assert name in lc.APPLICATION_PYBOOT
    assert "tools/cnesdata_delivery/" + name in lc.APPLICATION_CLOSURE_PATHS
    for reusable, count in REUSABLE_LISTS.items():
        text = (ROOT / ".github" / "workflows" / f"reusable-cnesdata-{reusable}.yml").read_text()
        assert text.count(f'"{name}"') == count, reusable


def test_copia_do_produto_nao_carrega_texto_privado():
    for _, name, _ in VENDORED:
        text = (TOOLS / name).read_text()
        assert c.ACCOUNT_LIKE.search(text) is None and c.PRIVATE_TEXT.search(text) is None, name


@pytest.mark.parametrize("version", [(3, 11, 9, "final", 0), (3, 10, 0, "final", 0), (2, 7, 18, "final", 0)])
def test_carregador_recusa_python_anterior_a_3_12_antes_de_ler_ou_executar_qualquer_arquivo(tmp_path, monkeypatch,
                                                                                              version):
    """Ruling 4 item 7: the vendored frames use PEP 695 `type`; an older runner refuses fail-closed."""
    for _, name, _ in VENDORED:
        (tmp_path / name).write_bytes(b"import builtins\nbuiltins.MODE_FRAMES_EXECUTED = True\n")
    monkeypatch.setattr(sys, "version_info", version)
    with pytest.raises(ValueError, match="^mode_frames=python_version$"):
        _mb()._load_product_frames(tmp_path)
    assert not hasattr(builtins, "MODE_FRAMES_EXECUTED")


def test_formatos_do_produto_recusam_python_anterior_a_3_12_sem_cache(monkeypatch):
    mb = _mb()
    monkeypatch.setattr(mb, "_PRODUCT", {})
    monkeypatch.setattr(sys, "version_info", (3, 11, 9, "final", 0))
    with pytest.raises(ValueError, match="^mode_frames=python_version$"):
        mb.product_frames()
    assert mb._PRODUCT == {}


def test_carregador_admite_python_3_12_no_limite(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 12, 0, "final", 0))
    modules = _mb()._load_product_frames(TOOLS)
    assert modules["cnes_infra.aws.mode_canary_frames"].__name__ == "cnes_infra.aws.mode_canary_frames"
