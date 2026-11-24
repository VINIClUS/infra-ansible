"""Plano de ensaio em job: fronteira de subprocesso do observador (P21b)."""
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_producers import config
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.producers import rehearsal_plan

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

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
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


@pytest.mark.parametrize("failing, later", [("init", ("plan", "show")), ("plan", ("show",)), ("show", ())])
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
