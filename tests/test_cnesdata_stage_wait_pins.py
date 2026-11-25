"""P35 fix round 1: pins for the marker authentication, the wait entry point and the lease owner binding call site."""
import os

import pytest

from test_cnesdata_stage_wait import ARTIFACTS, INDEX, NAME, OWN, RUN, WINDOWS, Api, Clock, _wait
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import stage_wait


class Meta(Api):
    def __init__(self, *, listing=None, metadata=None, **kwargs):
        super().__init__(**kwargs)
        self.listing, self.metadata = listing or {}, metadata or {}

    def read(self, path, raw=False):
        value = super().read(path, raw=raw)
        if raw or path.endswith("/zip") or path.endswith("jobs?per_page=100&page=1"):
            return value
        if path == ARTIFACTS:
            return {"total_count": len(value["artifacts"]),
                    "artifacts": [item | self.listing for item in value["artifacts"]]}
        return value | self.metadata


@pytest.mark.parametrize("metadata", [{"workflow_run": {"id": 1, "head_sha": "b" * 40}},
                                      {"workflow_run": {"id": 4242, "head_sha": "c" * 40}},
                                      {"name": "cnesdata-stage-open-phase-b-4242-2"},
                                      {"expired": True}, {"id": 1}])
def test_metadado_do_marcador_com_run_sha_nome_ou_validade_diferentes_e_recusado(metadata):
    with pytest.raises(ValueError, match="stage-open marker metadata"):
        _wait(Meta(metadata=metadata))


@pytest.mark.parametrize("name", ["cnesdata-stage-open-phase-b-4242-2", "cnesdata-stage-open-phase-b-4243-1",
                                  "cnesdata-stage-open-phase-c-audit-4242-1", NAME + "x", "x" + NAME])
def test_marcador_so_e_achado_pelo_nome_exato_do_estagio_run_e_tentativa(name):
    clock = Clock()
    with pytest.raises(ValueError, match="stage_wait=ceiling"):
        _wait(Meta(listing={"name": name}), clock=clock)


class Pins:
    def __init__(self, monkeypatch, tmp_path, *, steps=("prepared",)):
        from tools.cnesdata_delivery import provenance
        self.env, self.calls = tmp_path / "env", []
        self.producers = [{"name": step + " / execute", "step": step} for step in steps]
        for key, value in {"PURPOSE": "phase-b", "GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "1",
                           "EXPECTED_SOURCE_SHA": "b" * 40, "RUNNER_NAME": "r", "GITHUB_ENV": str(self.env),
                           "CNESDATA_DELIVERY_GOVERNANCE": "{}", "REQUEST_DESCRIPTOR": "{}"}.items():
            monkeypatch.setenv(key, value)
        self.api = type("FakeApi", (), {"rate": {"limit": 5000, "used": 12, "remaining": 4988}})()
        monkeypatch.setattr(provenance, "GitHub", lambda: self.api)
        monkeypatch.setattr(stage_wait, "own_job", lambda api, run, runner: OWN)
        monkeypatch.setattr(stage_wait.lc if hasattr(stage_wait, "lc") else __import__(
            "tools.cnesdata_delivery.lifecycle_contract", fromlist=["x"]), "stage_windows", lambda governance: WINDOWS)
        monkeypatch.setattr(stage_wait, "wait_for_stage", lambda *a, **k: INDEX)
        monkeypatch.setattr(stage_wait, "_producers", lambda *a: self.producers)
        monkeypatch.setattr(stage_wait, "wait_for_payloads", lambda *a, **k: self.calls.append(k))


def test_entrada_da_espera_exporta_owner_e_geracao_do_marcador_para_o_github_env(monkeypatch, tmp_path, capsys):
    pins = Pins(monkeypatch, tmp_path)
    stage_wait.main()
    assert pins.env.read_text() == f"STAGE_OPEN_OWNER_SHA256={INDEX['owner_sha256']}\nSTAGE_OPEN_GENERATION=7\n"
    assert capsys.readouterr().out.startswith("stage_wait stage=phase-b setup_seconds=")


def test_entrada_da_espera_espera_os_produtores_antes_de_exportar_o_owner(monkeypatch, tmp_path):
    pins = Pins(monkeypatch, tmp_path, steps=("prepared", "audited"))
    stage_wait.main()
    (call,) = pins.calls
    assert call["producers"] == pins.producers and 0 <= call["ceiling"] <= stage_wait.MAX_WAIT_SECONDS


def test_entrada_da_espera_nao_exporta_o_owner_se_a_espera_dos_payloads_recusa(monkeypatch, tmp_path):
    pins = Pins(monkeypatch, tmp_path)
    def refuse(*args, **kwargs):
        raise ValueError("completed payload producer")
    monkeypatch.setattr(stage_wait, "wait_for_payloads", refuse)
    with pytest.raises(ValueError, match="completed payload producer"):
        stage_wait.main()
    assert not pins.env.exists()


def test_entrada_da_espera_ignora_estagio_sem_primeiro_job_externo(monkeypatch, tmp_path):
    pins = Pins(monkeypatch, tmp_path)
    monkeypatch.setenv("PURPOSE", "api")
    stage_wait.main()
    assert pins.calls == [] and not pins.env.exists()


class Lease:
    owner = {"owner_sha256": "4" * 64, "generation": 7, "source_sha": "s", "run_id": 1, "run_attempt": 1}


def _execute_until_binding(monkeypatch, environ):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    from tools.cnesdata_delivery import session_owner
    for key, value in environ.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AWS_CREDENTIAL_EXPIRATION", c.utc(9999999))
    step = {"mode": "observer-bootstrap", "purpose": "phase-b"}
    monkeypatch.setattr(lr, "admission", lambda role: ({"context_kind": "k"}, {"source_sha": "s", "application_purpose": "p",
                                                       "caller_binding_sha256": "x"}, step, "api",
                                                      {"id": 1, "run_attempt": 1}, {}))
    monkeypatch.setattr(lr, "AWS", lambda governance: "aws")
    monkeypatch.setattr(session_owner, "authenticate_lifecycle", lambda *a: "authority")
    monkeypatch.setattr(session_owner, "verify_managed", lambda *a: None)

    class Store:
        def __init__(self, aws):
            pass

        def get(self):
            return {"lifecycle": {}}, "etag"
    monkeypatch.setattr(lr, "S3LeaseStore", Store)
    monkeypatch.setattr(lr.lc, "owner_binding", lambda record: Lease.owner)
    after = []
    monkeypatch.setattr(lr.lc, "application_identity", lambda *a, **k: after.append("identity") or {})
    return lr, after


def test_execute_recusa_o_lease_de_outra_geracao_antes_de_qualquer_efeito(monkeypatch):
    lr, after = _execute_until_binding(monkeypatch, {"PURPOSE": "phase-b", "STAGE_OPEN_OWNER_SHA256": "4" * 64,
                                                     "STAGE_OPEN_GENERATION": "6"})
    with pytest.raises(ValueError, match="stage-open owner"):
        lr.execute("plan")
    assert after == []


def test_execute_segue_adiante_com_o_owner_e_a_geracao_do_marcador(monkeypatch):
    lr, after = _execute_until_binding(monkeypatch, {"PURPOSE": "phase-b", "STAGE_OPEN_OWNER_SHA256": "4" * 64,
                                                     "STAGE_OPEN_GENERATION": "7"})
    with pytest.raises(ValueError, match="original owner run/caller"):
        lr.execute("plan")
    assert after == ["identity"]


def test_teto_dos_payloads_desconta_exatamente_o_tempo_ja_gasto_na_espera_do_marcador(monkeypatch, tmp_path):
    pins = Pins(monkeypatch, tmp_path)
    times = iter([1000.0, 1600.0])
    monkeypatch.setattr(stage_wait, "time", type("T", (), {"time": staticmethod(lambda: next(times, 1600.0))}))
    stage_wait.main()
    (call,) = pins.calls
    assert call["ceiling"] == stage_wait.wait_ceiling("phase-b", WINDOWS) - 600


class ConditionalOnly(Api):
    def read(self, path, raw=False):
        if path == ARTIFACTS:
            raise AssertionError("marker listing polled without a conditional GET")
        return super().read(path, raw=raw)

    def read_conditional(self, path):
        return super().read(path)


def test_espera_do_marcador_sonda_a_listagem_so_com_get_condicional():
    assert _wait(ConditionalOnly()) == INDEX


def test_limite_abaixo_do_assumido_recusa_antes_de_qualquer_espera_e_registra_os_numeros(monkeypatch, tmp_path, capsys):
    pins = Pins(monkeypatch, tmp_path)
    pins.api.rate = {"limit": 1000, "used": 3, "remaining": 997}
    def waited(*args, **kwargs):
        raise AssertionError("waited before the limit check")
    monkeypatch.setattr(stage_wait, "wait_for_stage", waited)
    with pytest.raises(ValueError, match="github=rate_limit value=1000"):
        stage_wait.main()
    assert "x_ratelimit_limit=1000 x_ratelimit_used=3 x_ratelimit_remaining=997" in capsys.readouterr().out
    assert pins.calls == [] and not pins.env.exists()


def test_resposta_sem_numero_de_limite_recusa_do_mesmo_modo(monkeypatch, tmp_path):
    pins = Pins(monkeypatch, tmp_path)
    pins.api.rate = None
    with pytest.raises(ValueError, match="github=rate_limit value=na"):
        stage_wait.main()


def test_linha_de_tempo_da_saida_bem_sucedida_leva_os_numeros_de_limite(monkeypatch, tmp_path, capsys):
    Pins(monkeypatch, tmp_path)
    stage_wait.main()
    line = capsys.readouterr().out.strip().splitlines()[-1]
    assert line.startswith("stage_wait stage=phase-b setup_seconds=")
    assert line.endswith("x_ratelimit_limit=5000 x_ratelimit_used=12 x_ratelimit_remaining=4988")


@pytest.mark.parametrize("failing", ["wait_for_stage", "wait_for_payloads"])
def test_linha_de_tempo_sai_tambem_na_recusa_da_espera(monkeypatch, tmp_path, capsys, failing):
    Pins(monkeypatch, tmp_path)
    def refuse(*args, **kwargs):
        raise ValueError("stage_wait=ceiling")
    monkeypatch.setattr(stage_wait, failing, refuse)
    with pytest.raises(ValueError, match="stage_wait=ceiling"):
        stage_wait.main()
    assert "x_ratelimit_limit=5000" in capsys.readouterr().out


def test_estimador_de_limite_assumido_e_o_medido(monkeypatch):
    assert stage_wait.ASSUMED_RATE_LIMIT == 5000
