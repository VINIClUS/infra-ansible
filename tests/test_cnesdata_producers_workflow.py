"""Reusable do observador: identidade, permissoes, busca em X_R e lista de modulos (P18)."""
import ast
import re
import subprocess
import sys
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


def closure(entry):
    seen, pending = {entry}, [entry]
    while pending:
        tree = ast.parse((TOOLS / pending.pop()).read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [node.module + "." + alias.name for alias in node.names]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            for name in names:
                relative = name.removeprefix("tools.cnesdata_delivery").lstrip(".").replace(".", "/") + ".py"
                if name.startswith("tools.cnesdata_delivery.") and (TOOLS / relative).is_file() and relative not in seen:
                    seen.add(relative)
                    pending.append(relative)
    return seen


def test_lista_do_reusable_e_igual_a_closure_ast_com_imports_de_funcao_do_observador_e_do_montador(text):
    observe_list, assemble_list = listed(text)
    for modules, entry in ((observe_list, ENTRIES[0]), (assemble_list, ENTRIES[1])):
        fetched = {name for name in modules if name.endswith(".py")}
        assert fetched == closure(entry), sorted(fetched ^ closure(entry))
        assert len(modules) == len(set(modules)) and "producers/__init__.py" not in modules


def test_montagem_com_exatamente_a_lista_do_assemble_le_pelo_github_sem_modulo_ausente(text, tmp_path):
    for name in listed(text)[1]:
        target = tmp_path / "tools/cnesdata_delivery" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((TOOLS / name).read_bytes())
    script = (
        "import sys; sys.path.insert(0, '.')\n"
        "import email.utils, time, urllib.request\n"
        "class Response:\n"
        "    headers = {'Date': email.utils.formatdate(time.time(), usegmt=True)}\n"
        "    def __enter__(self): return self\n"
        "    def __exit__(self, *a): return False\n"
        "    def read(self, n): return b'{\"ok\": true}'\n"
        "class Opener:\n"
        "    def open(self, request, timeout): return Response()\n"
        "urllib.request.build_opener = lambda *a: Opener()\n"
        "from tools.cnesdata_delivery import provenance\n"
        "assert provenance.GitHub(token='x').read('repos/a/b') == {'ok': True}\n"
    )
    done = subprocess.run([sys.executable, "-I", "-c", script], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr


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


def test_observe_mascara_cada_valor_da_configuracao_antes_de_qualquer_chamada_aws(text):
    observe = text.partition("  assemble:")[0]
    assert "::add-mask::" in observe and "OBSERVER_CONFIG" in observe
    assert observe.index("::add-mask::") < observe.index("producers.observer")


def test_segredos_ficam_no_env_do_passo_observe_e_nao_no_job(document):
    observe = document["jobs"]["observe"]
    assert not {"REPORT_HMAC_KEY", "OBSERVER_CONFIG", "OBSERVER_ROLE_ARN"} & set(observe.get("env", {}))
    holders = [step for step in observe["steps"] if "REPORT_HMAC_KEY" in step.get("env", {})]
    assert [step["name"] for step in holders] == ["Observe with the read-only role"]
    assert {"REPORT_HMAC_KEY", "OBSERVER_CONFIG", "OBSERVER_ROLE_ARN"} <= set(holders[0]["env"])
    masks = [step for step in observe["steps"] if "OBSERVER_CONFIG" in step.get("env", {}) and step is not holders[0]]
    assert masks and all("REPORT_HMAC_KEY" not in step["env"] for step in masks)


def test_observe_roda_nos_roles_plan_e_audit_e_o_assemble_aceita_observe_pulado(document):
    jobs = document["jobs"]
    assert "inputs.role" in jobs["observe"]["if"] and "plan" in jobs["observe"]["if"]
    assert "audit" in jobs["observe"]["if"] and "deploy" not in jobs["observe"]["if"]
    assert "audit" in triggers(document)["workflow_call"]["inputs"]["role"]["description"]
    condition = jobs["assemble"]["if"]
    assert "skipped" in condition and "success" in condition and "cancelled" in condition


def test_assemble_do_deploy_nao_baixa_o_artefato_de_observacao_do_proprio_run(document):
    steps = document["jobs"]["assemble"]["steps"]
    download = next(step for step in steps if step["name"].startswith("Download the observations"))
    assert "inputs.role" in download["if"] and "audit" in download["if"] and "deploy" not in download["if"]


def artifact_names_of(document):
    names = []
    for job in document["jobs"].values():
        for step in job["steps"]:
            name = (step.get("with") or {}).get("name")
            if type(name) is str and name.startswith("delivery-"):
                names.append(name)
    return names


def test_nomes_dos_artefatos_do_observe_e_do_assemble_levam_o_role_para_plan_e_audit_nao_colidirem(document):
    names = artifact_names_of(document)
    assert names and all("${{ inputs.role }}" in name for name in names)
    rendered = {role: {name.replace("${{ inputs.role }}", role) for name in names} for role in ("plan", "audit")}
    assert rendered["plan"].isdisjoint(rendered["audit"])


TOFU_SHA256 = "723bebb0df8411daff1e5fc3862e28ff5581fe5634087f4c29a9aa41d78208b5"


def observe_steps(document):
    return {step["name"]: index for index, step in enumerate(document["jobs"]["observe"]["steps"])}


def test_observe_instala_o_opentofu_1_13_2_com_o_mesmo_sha256_do_gate_de_plan(document, text):
    gate = (ROOT / ".github/workflows/reusable-cnesdata-infra-plan-gate.yml").read_text()
    assert f"{TOFU_SHA256}  " in gate
    observe = text.partition("  assemble:")[0]
    assert "v1.13.2" in observe and f"{TOFU_SHA256}  ${{RUNNER_TEMP}}/tofu.zip" in observe and "sha256sum -c -" in observe
    names = observe_steps(document)
    assert names["Install pinned OpenTofu"] < names["Observe with the read-only role"]


def test_observe_baixa_o_produto_no_sha_da_fonte_sem_credencial_persistida(document):
    steps = document["jobs"]["observe"]["steps"]
    checkout = next(step for step in steps if step["name"] == "Check out the product source at the pin")
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"] == {"repository": "VINIClUS/CnesData", "ref": "${{ inputs.source_sha }}",
                                "path": "product", "persist-credentials": False}
    names = observe_steps(document)
    assert names["Check out the product source at the pin"] < names["Observe with the read-only role"]


def test_observe_aponta_a_arvore_do_produto_so_no_passo_que_planeja(document):
    holders = [step["name"] for step in document["jobs"]["observe"]["steps"] if "PRODUCT_ROOT" in step.get("env", {})]
    assert holders == ["Observe with the read-only role"]
    step = document["jobs"]["observe"]["steps"][observe_steps(document)["Observe with the read-only role"]]
    assert step["env"]["PRODUCT_ROOT"] == "${{ github.workspace }}/product"


def test_observe_mascara_tambem_os_textos_do_shared_outputs(text):
    mask = text.partition("Fetch the pinned producer modules")[0]
    assert 'value["shared_outputs"]' in mask and "::add-mask::" in mask


def test_lista_de_modulos_do_observe_inclui_o_limite_de_subprocesso(text):
    assert "producers/rehearsal_plan.py" in listed(text)[0]
    assert "producers/rehearsal_plan.py" not in listed(text)[1]


def _script(document, name):
    step = next(item for item in document["jobs"]["observe"]["steps"] if item["name"] == name)
    return step["run"].split("<<'PY'\n", 1)[1].rsplit("PY", 1)[0]


def test_mascara_executada_cobre_texto_aninhado_do_shared_outputs_e_ignora_o_curto(document):
    import json
    text_value = "Zq7 shared output plain text"
    settings = {"account_id": "111122223333", "roles": {"plan": "role-plan-x"},
                "shared_outputs": {"a": {"b": [text_value, "short"]}}}
    done = subprocess.run([sys.executable, "-I", "-c", _script(document, "Mask every value of the private observer configuration")],
                          env={"OBSERVER_CONFIG": json.dumps(settings)}, capture_output=True, text=True, check=True)
    masked = {line.removeprefix("::add-mask::") for line in done.stdout.splitlines()}
    assert text_value in masked and "short" not in masked


def test_tofu_instalado_entra_no_path_dos_passos_seguintes(document):
    step = next(item for item in document["jobs"]["observe"]["steps"] if item["name"] == "Install pinned OpenTofu")
    assert 'echo "${RUNNER_TEMP}/observer-bin" >> "${GITHUB_PATH}"' in step["run"]
