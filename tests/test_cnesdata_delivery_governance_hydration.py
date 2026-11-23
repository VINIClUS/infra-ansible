"""P37 (DD-6 option a): catalog and source closure hydrated from the authenticated product source manifest."""
import ast
import base64
import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from fixtures import cnesdata_lifecycle_objects as objects
from test_cnesdata_product_source_manifest import ADAPTER, manifest_world
from tools.cnesdata_delivery import contract as c

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "b" * 40
VENDORED = ROOT / "tests/fixtures/cnesdata_delivery_sources"
REAL_SOURCE = "86ce51e8b386398ad7626fcaeb2686ae498ca505"
CONTRACT = b"contract"


def provenance():
    from tools.cnesdata_delivery import provenance as module
    return module


def world_manifest(closure=None):
    files = {ADAPTER: "c" * 64, "README.md": "e" * 64, "infra/opentofu-legacy/old.tf": "3" * 64,
             "infra/opentofu": "4" * 64}
    return {"version": 1, "source_sha": SOURCE, "files": files | dict(objects.CLOSURE if closure is None else closure)}


def catalog_steps():
    return {"keeper": {"role": "plan", "purpose": "application-prepare", "job_name": "promote / keeper",
                       "producer_job": "keeper", "input_jobs": {},
                       "admission_steps": ["Authenticate original caller", "Issue credentials"]},
            "operational-audit": {"role": "audit", "purpose": "application-prepare", "job_name": "audit / audit",
                                  "input_jobs": {}},
            "phase-b-advance": {"role": "deploy", "purpose": "phase-b", "direction": "advance", "mode": "operational",
                                "job_name": "phase-b / execute", "input_jobs": {}}}


class Contents:
    def __init__(self, served):
        self.served, self.reads = served, []

    def read(self, path, **_):
        self.reads.append(path)
        if path == objects.catalog_url(SOURCE):
            return objects.contents(self.served)
        raise AssertionError(path)


def unit_case(mutate=None):
    manifest = world_manifest()
    governance = {"source_sha": SOURCE}
    raw = objects.install(governance, manifest, catalog_steps())
    api = Contents(raw)
    if mutate:
        mutate(governance, manifest, api)
    return governance, manifest, api


def test_hidrata_catalogo_e_closure_do_manifesto_autenticado():
    governance, manifest, api = unit_case()
    hydrated = provenance().lifecycle_objects(api, governance, manifest)
    assert hydrated == {"lifecycle_steps": catalog_steps(), "source_closure": objects.CLOSURE}
    assert api.reads == [objects.catalog_url(SOURCE)]


def test_closure_derivada_exclui_caminhos_vizinhos_de_infra_opentofu():
    governance, manifest, api = unit_case()
    closure = provenance().source_closure(manifest)
    assert closure == objects.CLOSURE and "infra/opentofu-legacy/old.tf" not in closure and "infra/opentofu" not in closure


@pytest.mark.parametrize("key", ["lifecycle_steps", "source_closure"])
def test_recusa_objeto_inline_sem_ler_nada(key):
    governance, manifest, api = unit_case()
    governance[key] = {"inline": True}
    with pytest.raises(ValueError, match="inline lifecycle objects"):
        provenance().lifecycle_objects(api, governance, manifest)
    assert api.reads == []


def _byte(governance, manifest, api):
    api.served = api.served[:-1] + b"x"


def _manifest(governance, manifest, api):
    manifest["files"][objects.CATALOG_PATH] = "0" * 64


def _governance(governance, manifest, api):
    governance["lifecycle_steps_sha256"] = "0" * 64


@pytest.mark.parametrize("mutate", [_byte, _manifest, _governance], ids=["bytes", "manifesto", "governanca"])
def test_recusa_catalogo_com_um_byte_diferente_antes_de_interpretar(mutate):
    governance, manifest, api = unit_case(mutate)
    with pytest.raises(ValueError, match="lifecycle steps (manifest )?hash"):
        provenance().lifecycle_objects(api, governance, manifest)


def test_recusa_catalogo_ausente_do_manifesto_sem_ler_o_conteudo():
    governance, manifest, api = unit_case(lambda g, m, a: m["files"].pop(objects.CATALOG_PATH))
    with pytest.raises(ValueError, match="lifecycle steps manifest hash"):
        provenance().lifecycle_objects(api, governance, manifest)
    assert api.reads == []


@pytest.mark.parametrize("change", ["governanca", "manifesto", "arquivo-a-mais", "vazia"])
def test_recusa_closure_que_nao_bate_com_a_governanca(change):
    def mutate(governance, manifest, api):
        if change == "governanca":
            governance["source_closure_sha256"] = c.sha(b"other")
        if change == "manifesto":
            manifest["files"]["infra/opentofu/env/prod/main.tf"] = "9" * 64
        if change == "arquivo-a-mais":
            manifest["files"]["infra/opentofu/env/prod/extra.tf"] = "8" * 64
        if change == "vazia":
            for path in objects.CLOSURE:
                manifest["files"].pop(path)
    governance, manifest, api = unit_case(mutate)
    with pytest.raises(ValueError, match="source closure"):
        provenance().lifecycle_objects(api, governance, manifest)
    assert api.reads == []


def test_le_o_catalogo_no_sha_do_manifesto_e_recusa_codificacao_estranha():
    governance, manifest, api = unit_case()
    api.read = lambda path, **_: {"type": "file", "encoding": "utf-8", "content": "{}"}
    with pytest.raises(ValueError, match="lifecycle steps encoding"):
        provenance().lifecycle_objects(api, governance, manifest)
    governance, manifest, api = unit_case(lambda g, m, a: m.update(source_sha="d" * 40))
    with pytest.raises(ValueError, match="lifecycle objects source"):
        provenance().lifecycle_objects(api, governance, manifest)


def _repository(tmp_path, mutation=None):
    def git(*args):
        return subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True).stdout.decode().strip()
    git("init", "-q")
    shutil.copytree(VENDORED / "infra", tmp_path / "infra")
    extra = {ADAPTER: b"VALUE = 1\n", "README.md": b"readme\n", "infra/opentofu-legacy/old.tf": b"# legacy\n",
             "infra/README.md": b"infra\n", "infra/opentofu/scripts/check.sh": b"#!/bin/sh\nexit 0\n"}
    for name, raw in extra.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(raw)
    (tmp_path / "infra/opentofu/scripts/check.sh").chmod(0o755)
    git("add", ".")
    if mutation == "symlink":
        (tmp_path / "infra/opentofu/env/prod/link.tf").symlink_to("main.tf")
        git("add", "infra/opentofu/env/prod/link.tf")
    if mutation == "submodule":
        git("update-index", "--add", "--cacheinfo", "160000", "a" * 40, "infra/opentofu/vendor")
        (tmp_path / "infra/opentofu/vendor").mkdir()
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
    return git("rev-parse", "HEAD")


def test_derivacao_igual_ao_valor_inline_de_hoje_na_arvore_vendorizada(tmp_path):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    source = _repository(tmp_path)
    derived = provenance().source_closure(objects.product_manifest(tmp_path, source))
    inline = objects.inline_closure(tmp_path, source)
    assert c.canonical(derived) == c.canonical(inline)
    assert c.sha(c.canonical(derived)) == c.sha(c.canonical(inline))
    assert "infra/opentofu/scripts/check.sh" in derived and "infra/opentofu-legacy/old.tf" not in derived
    blobs = lr.authenticate_infrastructure_closure(tmp_path, source, derived)
    assert {name: c.sha(raw) for name, raw in blobs.items()} == derived


@pytest.mark.parametrize("mutation", ["symlink", "submodule"])
def test_derivacao_falha_fechada_com_symlink_ou_submodulo_em_infra_opentofu(tmp_path, mutation):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    source = _repository(tmp_path, mutation)
    with pytest.raises(ValueError, match="product_source=entry"):
        objects.product_manifest(tmp_path, source)
    lenient = objects.product_manifest(tmp_path, source, strict=False)
    derived = provenance().source_closure(lenient)
    with pytest.raises(ValueError, match="source file mode/path/inventory"):
        lr.authenticate_infrastructure_closure(tmp_path, source, derived)
    if mutation == "symlink":
        forged = derived | {"infra/opentofu/env/prod/link.tf": c.sha(b"main.tf")}
        with pytest.raises(ValueError, match="source file mode/path/inventory"):
            lr.authenticate_infrastructure_closure(tmp_path, source, forged)


@pytest.mark.skipif(not os.environ.get("CNESDATA_TEST_PRODUCT_CHECKOUT"),
                    reason="external_target_absent: set CNESDATA_TEST_PRODUCT_CHECKOUT to a CnesData clone")
def test_derivacao_igual_ao_valor_inline_na_arvore_real_do_cnesdata(tmp_path):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    product = tmp_path / "product"
    subprocess.run(["git", "clone", "-q", "--shared", "--no-checkout", os.environ["CNESDATA_TEST_PRODUCT_CHECKOUT"],
                    str(product)], check=True, capture_output=True, timeout=120)
    subprocess.run(["git", "checkout", "-q", "--detach", REAL_SOURCE], cwd=product, check=True, capture_output=True,
                   timeout=120)
    manifest = objects.product_manifest(product, REAL_SOURCE)
    derived = provenance().source_closure(manifest)
    inline = objects.inline_closure(product, REAL_SOURCE)
    assert len(derived) == 59 and c.canonical(derived) == c.canonical(inline)
    assert c.sha(c.canonical(derived)) == c.sha(c.canonical(inline))
    blobs = lr.authenticate_infrastructure_closure(product, REAL_SOURCE, derived)
    assert {name: c.sha(raw) for name, raw in blobs.items()} == derived


def admission_case(monkeypatch, *, steps=None, step_name="keeper", inline=None):
    from test_cnesdata_application_gate import _application_caller_fixture
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    from tools.cnesdata_delivery.provenance import application_caller
    gov, caller_api, run, step, _, _ = _application_caller_fixture(monkeypatch, "promotion", "plan")
    step.update(role="plan", purpose="application-prepare", input_jobs={})
    manifest = gov.pop("application_product_source_manifest")
    catalog = copy.deepcopy(steps) if steps else {"keeper": step}
    served = {"catalog": objects.install(gov, manifest, catalog)}
    world, world_api, _ = manifest_world(manifest, source=SOURCE)
    gov["application_product_source_manifest_artifact"] = world["application_product_source_manifest_artifact"]
    gov["application_product_source_closure_sha256"] = world["application_product_source_closure_sha256"]
    gov.update(activation_enabled=True, lifecycle_enabled=True, lifecycle_authority="infra-ansible#55/6755178450",
               lifecycle_contract={"repository": "VINIClUS/infra-ansible", "source_sha": "a" * 40,
                                   "path": "docs/cnesdata-delivery-application-lifecycle.md", "sha256": c.sha(CONTRACT)})
    observed = lr.source_admission(gov, caller_api, "plan", SOURCE, 44, 2)
    caller = application_caller(caller_api, gov | {"application_product_source_manifest": manifest}, observed, "plan", step)
    if inline:
        gov[inline] = {"inline": True}
    request = c.canonical({"schema_version": 1, "repository": c.REPOSITORY, "source_sha": SOURCE, "step": step_name,
                           "payloads": {}, "application_purpose": "promotion",
                           "caller_binding_sha256": c.sha(c.canonical(caller))})
    reads = []

    class API:
        def read(self, path, **kwargs):
            reads.append(path)
            if path == objects.catalog_url(SOURCE):
                return objects.contents(served["catalog"])
            if "/actions/artifacts/" in path:
                return world_api.read(path, **kwargs)
            if "docs/cnesdata-delivery-application-lifecycle.md" in path:
                return {"encoding": "base64", "content": base64.b64encode(CONTRACT).decode()}
            return caller_api.read(path, **kwargs)

        def artifact(self, reference, now, **options):
            reads.append("artifact:" + str(reference["artifact_id"]))
            return world_api.artifact(reference, now, **options)
    for key, value in {"CNESDATA_DELIVERY_GOVERNANCE": c.canonical(gov, limit=262144).decode(),
                       "REQUEST_DESCRIPTOR": request.decode(), "REQUEST_DESCRIPTOR_SHA256": c.sha(request),
                       "EXPECTED_SOURCE_SHA": SOURCE, "PURPOSE": "application-prepare",
                       "GITHUB_RUN_ID": "44", "GITHUB_RUN_ATTEMPT": "2",
                       "CONTRACT_REPOSITORY": "VINIClUS/infra-ansible", "CONTRACT_SOURCE_SHA": "a" * 40,
                       "CONTRACT_PATH": "docs/cnesdata-delivery-application-lifecycle.md",
                       "CONTRACT_SHA256": c.sha(CONTRACT)}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(lr, "GitHub", API)
    return lr, gov, served, reads


@pytest.mark.parametrize("key", ["lifecycle_steps", "source_closure"])
def test_admission_recusa_objeto_inline_antes_de_qualquer_leitura(monkeypatch, tmp_path, key):
    monkeypatch.chdir(tmp_path)
    lr, _, _, reads = admission_case(monkeypatch, inline=key)
    monkeypatch.setattr(lr, "GitHub", lambda: pytest.fail("inline governance must close before GitHub"))
    with pytest.raises(ValueError, match="inline lifecycle objects"):
        lr.admission("plan")
    assert reads == []


def test_admission_hidrata_antes_de_procurar_o_passo(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    lr, gov, served, reads = admission_case(monkeypatch)
    governance, _, step, _, _, _ = lr.admission("plan")
    assert governance["lifecycle_steps"] == c.loads(served["catalog"], canonical=True)
    assert governance["source_closure"] == objects.CLOSURE
    assert step == governance["lifecycle_steps"]["keeper"]
    assert reads.index("artifact:7001") < reads.index(objects.catalog_url(SOURCE))
    assert governance["lifecycle_steps_sha256"] == gov["lifecycle_steps_sha256"]


@pytest.mark.parametrize("change", ["bytes", "governanca", "closure"])
def test_admission_recusa_objeto_hidratado_com_um_byte_diferente(monkeypatch, tmp_path, change):
    monkeypatch.chdir(tmp_path)
    lr, gov, served, _ = admission_case(monkeypatch)
    if change == "bytes":
        served["catalog"] = served["catalog"][:-1] + b"x"
    if change in {"governanca", "closure"}:
        key = "lifecycle_steps_sha256" if change == "governanca" else "source_closure_sha256"
        gov[key] = "0" * 64
        monkeypatch.setenv("CNESDATA_DELIVERY_GOVERNANCE", c.canonical(gov, limit=262144).decode())
    expected = {"bytes": "lifecycle steps hash", "governanca": "lifecycle steps manifest hash",
                "closure": "source closure hash"}[change]
    with pytest.raises(ValueError, match=expected):
        lr.admission("plan")


def test_admission_procura_o_passo_no_catalogo_hidratado(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    lr, _, _, reads = admission_case(monkeypatch, step_name="missing")
    with pytest.raises(ValueError, match="governed step"):
        lr.admission("plan")
    assert objects.catalog_url(SOURCE) in reads


def test_leitores_recebem_o_catalogo_e_a_closure_hidratados(monkeypatch, tmp_path):
    from test_cnesdata_application_gate import _application_caller_fixture
    from tools.cnesdata_delivery import application_gate as ag
    monkeypatch.chdir(tmp_path)
    _, _, _, keeper, _, _ = _application_caller_fixture(monkeypatch, "promotion", "plan")
    steps = catalog_steps()
    steps["keeper"] = keeper | {"role": "plan", "purpose": "application-prepare", "input_jobs": {}}
    lr, gov, _, _ = admission_case(monkeypatch, steps=steps)
    governance = lr.admission("plan")[0]
    assert governance["lifecycle_steps"] == steps
    lr.admit_approval_origin(governance, "deploy", {"approval.json": "operational-audit"})
    assert ag._phase_b_step(governance) == ("phase-b-advance", steps["phase-b-advance"])
    assert c.sha(c.canonical(governance["source_closure"])) == gov["source_closure_sha256"]


READERS = {("lifecycle_runtime.py", "admission"), ("lifecycle_runtime.py", "current_checkpoint_chain"),
           ("lifecycle_runtime.py", "fence_prepare_package"), ("lifecycle_runtime.py", "execute"),
           ("lifecycle_runtime.py", "admit_approval_origin"), ("application_gate.py", "_phase_b_step"),
           ("application_gate.py", "_plan_activation")}


def _readers():
    found = set()
    for path in sorted((ROOT / "tools/cnesdata_delivery").glob("*.py")):
        tree = ast.parse(path.read_text())
        for function in ast.walk(tree):
            if not isinstance(function, ast.FunctionDef):
                continue
            for node in ast.walk(function):
                key = node.slice if isinstance(node, ast.Subscript) else None
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "get" and node.args:
                    key = node.args[0]
                if isinstance(key, ast.Constant) and key.value in {"lifecycle_steps", "source_closure"}:
                    found.add((path.name, function.name))
    return found


def test_inventario_de_leitores_das_chaves_hidratadas():
    assert _readers() == READERS


def test_so_a_admissao_do_lifecycle_le_o_secret_e_as_chaves_hidratadas():
    sources = {name: (ROOT / "tools/cnesdata_delivery" / name).read_text() for name, _ in READERS}
    assert "CNESDATA_DELIVERY_GOVERNANCE" not in sources["application_gate.py"]
    lifecycle = sources["lifecycle_runtime.py"]
    assert lifecycle.count("CNESDATA_DELIVERY_GOVERNANCE") == 1
    admission = ast.get_source_segment(lifecycle, next(node for node in ast.parse(lifecycle).body
                                                       if isinstance(node, ast.FunctionDef) and node.name == "admission"))
    assert admission.index("lifecycle_objects(") < admission.index('governance["lifecycle_steps"]')


def test_produtor_do_catalogo_emite_membro_canonico_e_referencia():
    from tools.cnesdata_delivery.producers import application
    steps = {"keeper": application.step("application", "application-prepare", job_name="promote / keeper",
                                         producer_job="keeper", admission_steps=["Authenticate original caller"])}
    steps["phase-b"] = application.step("deploy", "phase-b", job_name="phase-b / execute", producer_job="execute",
                                        admission_steps=["Repeat source gate"], mode="initial", direction="advance")
    raw, reference = application.catalog_member(steps)
    assert raw == c.canonical(application.catalog(steps))
    assert reference == {"lifecycle_steps_sha256": c.sha(raw)}
    steps["keeper"]["extra"] = True
    with pytest.raises(ValueError):
        application.catalog_member(steps)


def test_produtor_da_closure_usa_a_derivacao_do_gate():
    from tools.cnesdata_delivery.producers import application
    manifest = world_manifest()
    assert application.source_closure_reference(manifest) == {
        "source_closure_sha256": c.sha(c.canonical(provenance().source_closure(manifest)))}
    with pytest.raises(ValueError):
        application.source_closure_reference(manifest | {"extra": 1})


def test_montador_recusa_objetos_inline_e_aceita_as_referencias():
    from tools.cnesdata_delivery.producers import governance_assembly as ga
    assert {"lifecycle_steps", "source_closure"}.isdisjoint(ga.GOVERNANCE_KEYS)
    assert {"lifecycle_steps_sha256", "source_closure_sha256"} <= ga.GOVERNANCE_KEYS
    for key in ("lifecycle_steps", "source_closure"):
        with pytest.raises(ValueError, match=f"governance key={key}"):
            ga._closed_keys({key: {}})
    with pytest.raises(ValueError, match="digest"):
        ga.references({"lifecycle_steps_sha256": "x"})
    ga.references({"lifecycle_steps_sha256": "a" * 64, "source_closure_sha256": "b" * 64})


def test_cli_do_dono_emite_o_membro_do_catalogo_e_as_referencias(tmp_path, capsysbinary):
    from tools.cnesdata_delivery.producers import application, governance_assembly as ga
    steps = {"keeper": application.step("application", "application-prepare", job_name="promote / keeper",
                                         producer_job="keeper", admission_steps=["Authenticate original caller"]),
             "phase-b": application.step("deploy", "phase-b", job_name="phase-b / execute", producer_job="execute",
                                         admission_steps=["Repeat source gate"], mode="initial", direction="advance")}
    (tmp_path / "steps.json").write_text(json.dumps(steps))
    (tmp_path / "manifest.json").write_bytes(c.canonical(world_manifest()))
    member = tmp_path / "lifecycle-steps.json"
    assert ga.main(["lifecycle-objects", "--steps", str(tmp_path / "steps.json"),
                    "--manifest", str(tmp_path / "manifest.json"), "--output", str(member)]) == 0
    raw, reference = application.catalog_member(steps)
    assert member.read_bytes() == raw
    printed = c.loads(capsysbinary.readouterr().out, canonical=True)
    assert printed == reference | application.source_closure_reference(world_manifest())
    assert ga.main(["lifecycle-objects", "--steps", str(tmp_path / "steps.json"),
                    "--manifest", str(tmp_path / "manifest.json"), "--output", str(member)]) == 1


ACCOUNT = "111122223333"

MARKER = {"selection_version": 1, "ext2_post_upload_receipt_v1": {}}
RECEIPT = {"repository": c.REPOSITORY, "run_id": "123", "run_attempt": "1", "artifact_id": "456",
           "artifact_digest": "sha256:" + "a" * 64, "publisher_job_id": "789", "publisher_step_number": 2,
           "source_sha": "b" * 40, "caller_workflow_path": ".github/workflows/promote-production.yml",
           "reusable_workflow_sha": "c" * 40}


def receipt_case(receipts, marker=None):
    steps = catalog_steps()
    steps["operational-plan"] = {"role": "plan", "purpose": "application-prepare", "direction": "advance",
                                 "mode": "operational", "job_name": "operational-plan / execute", "input_jobs": {},
                                 "activation_selection": MARKER if marker is None else marker}
    manifest = world_manifest()
    governance = {"source_sha": SOURCE, "account_id": ACCOUNT}
    raw = objects.install(governance, manifest, steps)
    governance["activation_receipts"] = receipts
    return governance, manifest, Contents(raw), raw


def test_hidratacao_compoe_o_recibo_da_governanca_no_passo_do_plano_operacional():
    governance, manifest, api, raw = receipt_case({"operational-plan": RECEIPT})
    step = provenance().lifecycle_objects(api, governance, manifest)["lifecycle_steps"]["operational-plan"]
    assert step["activation_selection"] == {"selection_version": 1, "ext2_post_upload_receipt_v1": RECEIPT}
    assert c.sha(raw) == governance["lifecycle_steps_sha256"] and b"789" not in raw


def test_hidratacao_sem_recibo_deixa_o_marcador_fechado_que_o_consumidor_recusa():
    from tools.cnesdata_delivery import ext2_transport
    governance, manifest, api, _ = receipt_case({})
    step = provenance().lifecycle_objects(api, governance, manifest)["lifecycle_steps"]["operational-plan"]
    assert step["activation_selection"] == MARKER
    with pytest.raises(ValueError):
        ext2_transport.validate_reference(step["activation_selection"]["ext2_post_upload_receipt_v1"])


@pytest.mark.parametrize("receipts", [
    {"inexistente": RECEIPT},
    {"keeper": RECEIPT},
    {"operational-plan": {**RECEIPT, "run_id": "0"}},
    {"operational-plan": "ref"},
    ["operational-plan"],
], ids=["passo-ausente", "passo-sem-marcador", "recibo-invalido", "recibo-nao-dict", "lista"])
def test_hidratacao_recusa_recibo_para_passo_inadequado_ou_invalido(receipts):
    governance, manifest, api, _ = receipt_case(receipts)
    with pytest.raises(ValueError, match="lifecycle steps activation receipt"):
        provenance().lifecycle_objects(api, governance, manifest)


def test_hidratacao_recusa_marcador_que_ja_carrega_recibo():
    governance, manifest, api, _ = receipt_case(
        {"operational-plan": RECEIPT}, {"selection_version": 1, "ext2_post_upload_receipt_v1": RECEIPT})
    with pytest.raises(ValueError, match="lifecycle steps activation receipt"):
        provenance().lifecycle_objects(api, governance, manifest)
