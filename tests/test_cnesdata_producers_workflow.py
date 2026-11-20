"""Reusable do observador: identidade, permissoes, busca em X_R e lista de modulos (P18)."""
import ast
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/reusable-cnesdata-observer.yml"
TOOLS = ROOT / "tools/cnesdata_delivery"
ENTRIES = ("producers/observer.py", "producers/assembler.py")


@pytest.fixture(scope="module")
def document():
    return yaml.safe_load(WORKFLOW.read_text())


@pytest.fixture(scope="module")
def text():
    return WORKFLOW.read_text()


def triggers(document):
    return document.get("on", document.get(True))


def test_reusable_so_e_chamavel_e_declara_x_star_e_os_secrets(document):
    call = triggers(document)["workflow_call"]
    assert set(call) == {"inputs", "secrets", "outputs"} or set(call) == {"inputs", "secrets"}
    assert call["inputs"]["x_star"]["required"] is True
    assert set(call["secrets"]) == {"report_hmac_key", "observer_config", "observer_role_arn"}
    assert all(item["required"] is True for item in call["secrets"].values())
    assert set(triggers(document)) == {"workflow_call"}


def test_inputs_publicos_nao_carregam_arn_conta_nem_segredo(document):
    names = set(triggers(document)["workflow_call"]["inputs"])
    assert {"purpose", "role", "source_sha", "x_star", "request"} <= names
    assert not any("arn" in name or "secret" in name or "account" in name for name in names)


def test_permissoes_do_topo_sao_vazias_e_so_o_observe_pede_id_token(document):
    assert document["permissions"] == {}
    jobs = document["jobs"]
    assert set(jobs) == {"observe", "assemble"}
    assert jobs["observe"]["permissions"] == {"actions": "read", "contents": "read", "id-token": "write"}
    assert "id-token" not in jobs["assemble"]["permissions"]
    assert jobs["assemble"]["needs"] == "observe"


def test_observe_declara_o_environment_e_roda_em_runner_hospedado(document):
    observe = document["jobs"]["observe"]
    assert observe["environment"] == "cnesdata-observer" and observe["runs-on"] == "ubuntu-latest"
    assert "environment" not in document["jobs"]["assemble"] and document["jobs"]["assemble"]["runs-on"] == "ubuntu-latest"


def test_segredos_so_sao_lidos_no_job_observe(text):
    observe, _, assemble = text.partition("  assemble:")
    assert "secrets." in observe and "secrets." not in assemble


def test_assemble_nao_tem_credencial_aws_nem_chave(text):
    assemble = text.partition("  assemble:")[2]
    assert "secrets." not in assemble and "AWS_" not in assemble and "report_hmac_key" not in assemble


def test_modulos_sao_buscados_no_sha_do_reusable_e_comparados_com_x_star(text):
    assert "referenced_workflows" in text and "refs.length !== 1" in text
    assert "reusable-cnesdata-observer.yml" in text and "inputs.x_star" in text and "refs[0].sha !== process.env.X_STAR" in text
    assert "github.sha" not in text and "refs[0].sha" in text
    assert re.search(r"/\^\[a-f0-9\]\{40\}\$/", text)


def listed(text):
    found = re.findall(r"modules = (\[[^\]]*\])", text)
    assert len(found) == 2
    return [ast.literal_eval(value) for value in found]


def imports_of(path, seen):
    tree = ast.parse(path.read_text())
    for node in ast.iter_child_nodes(tree):
        names = []
        if isinstance(node, ast.ImportFrom) and node.module:
            base = node.module
            names = [base] + [base + "." + alias.name for alias in node.names]
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        for name in names:
            if name.startswith("tools.cnesdata_delivery"):
                relative = name.removeprefix("tools.cnesdata_delivery.").replace(".", "/") + ".py"
                target = TOOLS / relative
                if target.is_file() and relative not in seen:
                    seen.add(relative)
                    imports_of(target, seen)
    return seen


def test_lista_do_reusable_cobre_os_imports_transitivos_do_observador_e_do_montador(text):
    observe_list, assemble_list = listed(text)
    for modules, entry in ((observe_list, ENTRIES[0]), (assemble_list, ENTRIES[1])):
        needed = imports_of(TOOLS / entry, {entry})
        assert needed <= set(modules), sorted(needed - set(modules))
        assert len(modules) == len(set(modules)) and "producers/__init__.py" not in modules


def test_lista_so_cobre_arquivos_que_existem_no_repositorio(text):
    for modules in listed(text):
        assert all((TOOLS / name).is_file() for name in modules), modules


def test_producers_nao_e_importado_por_nenhum_modulo_do_gate():
    for path in TOOLS.glob("*.py"):
        assert re.search(r"^\s*(?:from|import)\s+[\w.]*producers", path.read_text(), re.M) is None, path.name


def test_artefatos_tem_retencao_de_30_dias_e_o_montador_espera_3s_depois_do_upload(text):
    assert len(re.findall(r"retention-days: 30", text)) == 2
    assert "sleep 3" in text.partition("  assemble:")[2]


def test_acoes_fixadas_por_sha_e_sem_develop(text):
    uses = re.findall(r"uses: (\S+)", text)
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", item) for item in uses)
    assert "develop" not in text and "uses: ./" not in text


def test_entrypoints_rodam_como_modulo(text):
    assert "-m tools.cnesdata_delivery.producers.observer" in text
    assert "-m tools.cnesdata_delivery.producers.assembler" in text


def test_nenhuma_lista_files_para_nao_confundir_a_guarda_dos_reusables_do_gate(text):
    assert not re.search(r"files = \[", text)
