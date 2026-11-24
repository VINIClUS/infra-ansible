"""Plano de ensaio em job: fronteira de subprocesso do observador (P21b)."""
import json
import os
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_producers import LOCK_BYTES, config
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers import aws_reader, rehearsal_plan

PLAN = b'{"format_version":"1.2","resource_changes":[]}'
INPUTS = c.canonical({"image_digest": "sha256:" + "1" * 64, "canary_release_id": None})
LEAK = b"AccessDenied arn:aws:iam::111122223333:role/x bucket cnesdata-state-4f6e21"


class Session:
    def get_credentials(self):
        frozen = SimpleNamespace(access_key="AKIAFIXTURE", secret_key="secret-fixture", token="token-fixture")
        return SimpleNamespace(get_frozen_credentials=lambda: frozen)


class Runner:
    def __init__(self, fail=None):
        self.fail, self.calls, self.files = fail, [], {}
        self.workspace, self.backend = "default", {"bucket": config()["state_bucket"],
                                                   "key": "cnesdata/prod/opentofu.tfstate", "region": "us-east-2"}

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[1] == "init":
            metadata = Path(kwargs["cwd"]) / ".terraform"
            metadata.mkdir(exist_ok=True)
            (metadata / "terraform.tfstate").write_text(json.dumps({"backend": {"type": "s3", "config": self.backend}}))
        if argv[1] == "workspace":
            return subprocess.CompletedProcess(argv, 0, (self.workspace + "\n").encode(), b"")
        for argument in argv:
            for prefix in ("-backend-config=", "-var-file="):
                if argument.startswith(prefix):
                    self.files[prefix] = Path(argument[len(prefix):]).read_bytes()
        if argv[1] == self.fail:
            return subprocess.CompletedProcess(argv, 1, b"", LEAK)
        return subprocess.CompletedProcess(argv, 0, PLAN if argv[1] == "show" else b"", b"")

    def command(self, name):
        return next(argv for argv, _ in self.calls if argv[1] == name)


@pytest.fixture
def job(monkeypatch, tmp_path):
    product = tmp_path / "product"
    (product / "infra/opentofu/env/prod").mkdir(parents=True)
    (product / "infra/opentofu/env/prod/.terraform.lock.hcl").write_bytes(LOCK_BYTES)
    scratch = tmp_path / "temp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    monkeypatch.setenv("PRODUCT_ROOT", str(product))
    monkeypatch.setenv("REPORT_HMAC_KEY", "5a" * 32)
    monkeypatch.setenv("OBSERVER_CONFIG", "{}")
    runner = Runner()
    monkeypatch.setattr(rehearsal_plan.subprocess, "run", runner)
    return SimpleNamespace(runner=runner, product=product, scratch=scratch, monkeypatch=monkeypatch)


def plan():
    return rehearsal_plan.plan(config(), INPUTS, Session())


def test_plano_de_ensaio_roda_init_somente_leitura_e_plan_sem_refresh_nem_lock(job):
    plan()
    init, planned = job.runner.command("init"), job.runner.command("plan")
    assert "-lockfile=readonly" in init and "-input=false" in init
    assert "-refresh=false" in planned and "-lock=false" in planned and "-input=false" in planned
    assert not any(argument.startswith("-lock-timeout") for argument in planned)
    assert not any(argument.startswith("-target") for argument in planned)
    root = job.product / "infra/opentofu/env/prod"
    assert all(kwargs["cwd"] == root for _, kwargs in job.runner.calls)


def test_plano_de_ensaio_grava_o_plano_binario_so_dentro_do_temp_do_job(job):
    plan()
    out = next(argument for argument in job.runner.command("plan") if argument.startswith("-out="))[len("-out="):]
    assert Path(out).is_relative_to(job.scratch) and not Path(out).is_relative_to(job.product)
    assert job.runner.command("show")[-1] == out
    assert not list(job.scratch.iterdir())


def test_plano_de_ensaio_devolve_o_json_sem_deixar_o_plano_em_disco(job, tmp_path):
    assert plan() == PLAN
    leftovers = [path for path in tmp_path.rglob("*") if path.is_file() and PLAN in path.read_bytes()]
    assert leftovers == [] and not list(job.product.rglob("*.json"))


def test_plano_de_ensaio_monta_backend_e_variaveis_a_partir_da_configuracao_e_dos_insumos(job):
    plan()
    settings = config()
    backend = json.loads(job.runner.files["-backend-config="])
    assert backend == {"bucket": settings["state_bucket"], "key": "cnesdata/prod/opentofu.tfstate",
                       "region": "us-east-2"}
    variables = json.loads(job.runner.files["-var-file="])
    assert variables == {"shared_outputs": settings["shared_outputs"]} | json.loads(INPUTS)


def test_plano_de_ensaio_passa_so_as_credenciais_do_observador_e_nada_do_ambiente_privado(job):
    plan()
    for _, kwargs in job.runner.calls:
        env = kwargs["env"]
        assert (env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"], env["AWS_SESSION_TOKEN"]) == (
            "AKIAFIXTURE", "secret-fixture", "token-fixture")
        assert env["TF_IN_AUTOMATION"] == "1" and env["AWS_CONFIG_FILE"] == "/dev/null"
        assert "REPORT_HMAC_KEY" not in env and "OBSERVER_CONFIG" not in env


@pytest.mark.parametrize("failing, later", [("init", ("workspace", "plan", "show")), ("plan", ("show",)), ("show", ())])
def test_plano_de_ensaio_recusa_falha_do_tofu_sem_vazar_a_saida_e_sem_seguir(job, failing, later):
    job.runner.fail = failing
    with pytest.raises(ValueError, match=f"tofu {failing} exit=1") as refused:
        plan()
    assert "arn:" not in str(refused.value) and "AccessDenied" not in str(refused.value)
    assert not any(argv[1] in later for argv, _ in job.runner.calls)
    assert not list(job.scratch.iterdir())


def test_plano_de_ensaio_recusa_arvore_do_produto_ausente(job):
    job.monkeypatch.delenv("PRODUCT_ROOT")
    with pytest.raises(ValueError, match="product tree"):
        plan()
    assert job.runner.calls == []


def test_plano_de_ensaio_recusa_lock_diferente_do_governado_antes_de_qualquer_subprocesso(job):
    settings = config() | {"toolchain": config()["toolchain"] | {"lock_sha256": "0" * 64}}
    with pytest.raises(ValueError, match="toolchain lock_sha256 mismatch"):
        rehearsal_plan.plan(settings, INPUTS, Session())
    assert job.runner.calls == [] and not list(job.scratch.iterdir())


def test_plano_de_ensaio_instala_so_os_providers_governados_pelo_cli_config_do_job(job):
    settings = config() | {"toolchain": config()["toolchain"] | {
        "providers": ["registry.opentofu.org/hashicorp/aws", "registry.opentofu.org/hashicorp/archive"]}}
    seen = []
    original = job.runner.__call__

    def watch(argv, **kwargs):
        path = Path(kwargs["env"]["TF_CLI_CONFIG_FILE"])
        seen.append((path.parent == job.scratch or job.scratch in path.parents, path.read_text()))
        return original(argv, **kwargs)

    job.monkeypatch.setattr(rehearsal_plan.subprocess, "run", watch)
    rehearsal_plan.plan(settings, INPUTS, Session())
    expected = ('provider_installation { direct { include = '
                '["registry.opentofu.org/hashicorp/aws", "registry.opentofu.org/hashicorp/archive"] } }\n')
    assert seen and all(inside and text == expected for inside, text in seen)


def test_plano_de_ensaio_recusa_workspace_efetivo_diferente_de_default_antes_do_plan(job):
    job.runner.workspace = "other"
    with pytest.raises(ValueError, match="effective workspace readback"):
        plan()
    assert not any(argv[1] in ("plan", "show") for argv, _ in job.runner.calls)


@pytest.mark.parametrize("field", ["bucket", "key", "region"])
def test_plano_de_ensaio_recusa_backend_efetivo_diferente_do_pedido_antes_do_plan(job, field):
    job.runner.backend = job.runner.backend | {field: "outro"}
    with pytest.raises(ValueError, match=f"effective backend field {field}"):
        plan()
    assert not any(argv[1] in ("plan", "show") for argv, _ in job.runner.calls)


def test_plano_de_ensaio_recusa_backend_local_sem_o_s3_efetivo(job):
    original = job.runner.__call__

    def local(argv, **kwargs):
        done = original(argv, **kwargs)
        if argv[1] == "init":
            (Path(kwargs["cwd"]) / ".terraform/terraform.tfstate").write_text(json.dumps({"backend": {"type": "local"}}))
        return done

    job.monkeypatch.setattr(rehearsal_plan.subprocess, "run", local)
    with pytest.raises(ValueError, match="effective remote backend/workspace"):
        plan()
    assert not any(argv[1] in ("plan", "show") for argv, _ in job.runner.calls)


def test_plano_de_ensaio_timeout_vira_value_error_nomeado_sem_vazar_a_saida(job):
    def slow(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"arn:aws:x", stderr=b"AccessDenied")

    job.monkeypatch.setattr(rehearsal_plan.subprocess, "run", slow)
    with pytest.raises(ValueError, match="tofu init timeout") as refused:
        plan()
    assert "arn:" not in str(refused.value) and "AccessDenied" not in str(refused.value)


def test_plano_de_ensaio_grava_arquivos_privados_em_0600(job):
    modes = {}
    original = job.runner.__call__

    def watch(argv, **kwargs):
        for argument in argv:
            for prefix in ("-backend-config=", "-var-file="):
                if argument.startswith(prefix):
                    modes[prefix] = os.stat(argument[len(prefix):]).st_mode & 0o777
        return original(argv, **kwargs)

    job.monkeypatch.setattr(rehearsal_plan.subprocess, "run", watch)
    plan()
    assert modes == {"-backend-config=": 0o600, "-var-file=": 0o600}


def test_plano_de_ensaio_endurece_o_ambiente_do_tofu(job):
    plan()
    for _, kwargs in job.runner.calls:
        env = kwargs["env"]
        assert env["HOME"].startswith(str(job.scratch))
        assert env["AWS_EC2_METADATA_DISABLED"] == "true" and env["TF_WORKSPACE"] == "default"


def test_plano_de_ensaio_tem_timeout_por_passo_e_soma_dentro_da_sessao_de_900_segundos(job):
    plan()
    assert [(argv[1], kwargs["timeout"]) for argv, kwargs in job.runner.calls] == [
        ("init", 120), ("workspace", 10), ("plan", 480), ("show", 60)]
    assert sum(rehearsal_plan.TIMEOUTS.values()) + 120 <= aws_reader.SESSION_SECONDS == 900


def test_plano_de_ensaio_sempre_captura_a_saida_do_tofu(job):
    plan()
    assert all(kwargs.get("capture_output") is True for _, kwargs in job.runner.calls)


def test_plano_de_ensaio_recusa_product_root_sem_a_arvore_do_produto(job, tmp_path):
    job.monkeypatch.setenv("PRODUCT_ROOT", str(tmp_path / "vazio"))
    with pytest.raises(ValueError, match="product tree"):
        plan()
    assert job.runner.calls == []
