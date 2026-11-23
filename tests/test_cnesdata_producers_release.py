"""Superficie pinada, closure do pin, guarda X*..K, tetos de governanca e chave HMAC (P18)."""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from tools.cnesdata_delivery import application_gate, contract as c
from tools.cnesdata_delivery.producers import governance_assembly, hmac_key, pins, release_guard

ROOT = Path(__file__).resolve().parents[1]
OBSERVER = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-observer.yml"
CALLER = ".github/workflows/cnesdata-producers.yml"
ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def git(repo, *args):
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=ENV, check=True)
    return done.stdout.strip()


def commit(repo, files, message="c"):
    for name, text in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def caller(pin):
    return f"jobs:\n  observe:\n    uses: {OBSERVER}@{pin}\n"


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def release(repo, files=None, uses=None):
    x_star = commit(repo, {"tools/cnesdata_delivery/a.py": "x = 1\n", "docs/a.md": "a\n"})
    k = commit(repo, {CALLER: caller(uses or x_star), **(files or {})})
    return x_star, k


def test_superficie_pinada_tem_valor_exato():
    assert pins.PINNED_SURFACE == ("tools/cnesdata_delivery/**", ".github/workflows/reusable-cnesdata-*.yml")


@pytest.mark.parametrize("path, expected", [
    ("tools/cnesdata_delivery/producers/cost_ledger.py", True),
    ("tools/cnesdata_delivery/runtime-requirements.txt", True),
    (".github/workflows/reusable-cnesdata-observer.yml", True),
    (".github/workflows/cnesdata-producers.yml", False),
    (".github/workflows/reusable-other.yml", False),
    (".github/workflows/sub/reusable-cnesdata-x.yml", False),
    ("tools/cnesdata_delivery_extra/a.py", False),
    ("docs/cnesdata-delivery-producers.md", False),
])
def test_superficie_pinada_casa_caminhos(path, expected):
    assert pins.on_surface(path) is expected


def test_closure_do_pin_igual_a_application_gate_closure(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    head = git(ROOT, "rev-parse", "HEAD")
    application_gate.closure(head)
    printed = capsys.readouterr().out.strip()
    value = pins.producer_pins(pins.git_reader(ROOT), head)
    assert value == [{"repository": "VINIClUS/infra-ansible", "source_sha": head, "content_sha256": printed}]


def test_guarda_aceita_k_descendente_com_caller_em_x(repo):
    x_star, k = release(repo)
    release_guard.check(repo, x_star, k)


def test_guarda_aceita_diff_so_de_caller_e_docs(repo):
    x_star, k = release(repo, {"docs/b.md": "b\n"})
    release_guard.check(repo, x_star, k)


def test_guarda_recusa_x_que_nao_e_ancestral_de_k(repo):
    x_star, k = release(repo)
    git(repo, "checkout", "-q", "-b", "other", x_star + "~0")
    other = commit(repo, {"docs/c.md": "c\n"})
    with pytest.raises(ValueError, match="ancestor"):
        release_guard.check(repo, other, k)


def test_guarda_recusa_x_igual_a_k(repo):
    x_star, _ = release(repo)
    with pytest.raises(ValueError, match="ancestor"):
        release_guard.check(repo, x_star, x_star)


def test_guarda_recusa_uses_diferente_de_x(repo):
    x_star, k = release(repo, uses="b" * 40)
    with pytest.raises(ValueError, match="uses"):
        release_guard.check(repo, x_star, k)


def test_guarda_recusa_uses_local_e_caller_sem_uses(repo):
    x_star = commit(repo, {"tools/cnesdata_delivery/a.py": "x = 1\n"})
    k = commit(repo, {CALLER: "jobs:\n  observe:\n    uses: ./.github/workflows/reusable-cnesdata-observer.yml\n"})
    with pytest.raises(ValueError, match="uses"):
        release_guard.check(repo, x_star, k)
    k = commit(repo, {CALLER: "jobs: {}\n"})
    with pytest.raises(ValueError, match="uses"):
        release_guard.check(repo, x_star, k)


def test_guarda_recusa_um_uses_entre_varios_diferente_de_x(repo):
    x_star = commit(repo, {"tools/cnesdata_delivery/a.py": "x = 1\n"})
    text = caller(x_star) + f"  again:\n    uses: {OBSERVER}@{'c' * 40}\n"
    k = commit(repo, {CALLER: text})
    with pytest.raises(ValueError, match="uses"):
        release_guard.check(repo, x_star, k)


@pytest.mark.parametrize("path", [
    "tools/cnesdata_delivery/producers/new.py",
    "tools/cnesdata_delivery/runtime-requirements.txt",
    ".github/workflows/reusable-cnesdata-observer.yml",
])
def test_guarda_recusa_diff_que_toca_a_superficie_pinada(repo, path):
    x_star, k = release(repo, {path: "changed\n"})
    with pytest.raises(ValueError, match="pinned surface"):
        release_guard.check(repo, x_star, k)


def test_guarda_recusa_renomeacao_para_fora_da_superficie(repo):
    x_star = commit(repo, {"tools/cnesdata_delivery/a.py": "x = 1\n" * 20})
    (repo / "docs").mkdir()
    git(repo, "mv", "tools/cnesdata_delivery/a.py", "docs/a.py")
    k = commit(repo, {CALLER: caller(x_star)})
    with pytest.raises(ValueError, match="pinned surface"):
        release_guard.check(repo, x_star, k)


def test_guarda_recusa_ref_que_nao_e_sha_de_40_hex(repo):
    x_star, k = release(repo)
    with pytest.raises(ValueError):
        release_guard.check(repo, "main", k)
    with pytest.raises(ValueError):
        release_guard.check(repo, x_star, "HEAD")


def padded(size):
    base = len(c.canonical({"pad": ""}))
    return {"pad": "x" * (size - base)}


def test_governanca_no_teto_da_cli_e_aceita_e_acima_e_recusada():
    assert len(governance_assembly.render(padded(40960))) == 40960
    with pytest.raises(ValueError, match="ceiling"):
        governance_assembly.render(padded(40961))


def test_teto_do_secret_nao_pode_ser_ultrapassado_por_parametro():
    assert governance_assembly.SECRET_CEILING == 47952 and governance_assembly.CLI_CEILING == 40960
    assert len(governance_assembly.render(padded(47952), ceiling=47952)) == 47952
    with pytest.raises(ValueError, match="ceiling"):
        governance_assembly.render(padded(47953), ceiling=47953)


def test_render_emite_bytes_canonicos_com_lf():
    raw = governance_assembly.render({"b": 1, "a": 2})
    assert raw == b'{"a":2,"b":1}\n' and c.loads(raw, canonical=True) == {"a": 2, "b": 1}


def test_cruzamento_recusa_valor_de_shared_outputs_com_hash_diferente():
    value = {"account_id": "111122223333"}
    commitments = {"shared_outputs_sha256": c.sha(c.canonical(value))}
    governance_assembly.crosscheck({"product_inputs": {"shared_outputs": value}, "report_hmac_key": "5a" * 32},
                                   commitments)
    with pytest.raises(ValueError, match="shared outputs"):
        governance_assembly.crosscheck({"product_inputs": {"shared_outputs": {"x": 1}}, "report_hmac_key": "5a" * 32},
                                       commitments)


@pytest.mark.parametrize("key", ["", "zz" * 32, "ab" * 16, None])
def test_cruzamento_recusa_chave_hmac_malformada(key):
    value = {"account_id": "111122223333"}
    commitments = {"shared_outputs_sha256": c.sha(c.canonical(value))}
    with pytest.raises(ValueError):
        governance_assembly.crosscheck({"product_inputs": {"shared_outputs": value}, "report_hmac_key": key},
                                       commitments)


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs.get("input")))
        return subprocess.CompletedProcess(argv, 0, "", "")


def test_chave_hmac_tem_32_bytes_aleatorios_em_hex():
    key = hmac_key.new_key()
    assert len(bytes.fromhex(key)) == 32 and hmac_key.new_key() != key


def test_chave_hmac_vai_por_stdin_e_nunca_por_argv_ou_log(caplog):
    runner = Runner()
    custody = hmac_key.Custody(runner)
    key = hmac_key.new_key()
    caplog.set_level("DEBUG")
    custody.store(key)
    custody.deliver(key, "VINIClUS/infra-ansible", "cnesdata-observer")
    assert [argv[0] for argv, _ in runner.calls] == ["secret-tool", "gh"]
    assert all(key not in " ".join(argv) for argv, _ in runner.calls)
    assert [data for _, data in runner.calls] == [key, key]
    assert key not in caplog.text


def test_rotacao_gera_chave_nova_e_recusa_reutilizar_a_antiga():
    runner = Runner()
    custody = hmac_key.Custody(runner)
    previous = hmac_key.new_key()
    fresh = hmac_key.rotate(custody, previous)
    assert fresh != previous
    with pytest.raises(ValueError, match="reuse"):
        hmac_key.rotate(custody, previous, token_bytes=lambda size: bytes.fromhex(previous))


def test_falha_do_secret_service_nao_ecoa_a_chave():
    def failing(argv, **kwargs):
        raise subprocess.CalledProcessError(1, argv, output=kwargs.get("input"), stderr=kwargs.get("input"))
    key = hmac_key.new_key()
    with pytest.raises(ValueError) as caught:
        hmac_key.Custody(failing).store(key)
    assert key not in str(caught.value) and key not in repr(caught.value.__cause__ or "")


def test_cli_release_check_sai_com_erro_em_diff_proibido(repo, capsys):
    x_star, k = release(repo, {"tools/cnesdata_delivery/b.py": "y\n"})
    status = governance_assembly.main(["release-check", "--repo", str(repo), "--x-star", x_star, "--k", k])
    assert status == 1 and "pinned surface" in capsys.readouterr().err
    assert json.dumps(x_star) not in capsys.readouterr().out


@pytest.mark.parametrize("text", [
    f'jobs:\n  observe:\n    "uses": {OBSERVER}@' + "c" * 40 + "\n",
    f"jobs:\n  observe: {{uses: {OBSERVER}@" + "c" * 40 + "}\n",
    f"jobs:\n  observe:\n    uses: '{OBSERVER}@" + "c" * 40 + "'\n",
])
def test_guarda_le_o_yaml_do_caller_e_recusa_pin_diferente_em_qualquer_forma(repo, text):
    x_star = commit(repo, {"tools/cnesdata_delivery/a.py": "x = 1\n"})
    k = commit(repo, {CALLER: text})
    with pytest.raises(ValueError, match="uses"):
        release_guard.check(repo, x_star, k)


def test_guarda_aceita_pin_citado_igual_a_x_e_ignora_texto_de_script(repo):
    x_star = commit(repo, {"tools/cnesdata_delivery/a.py": "x = 1\n"})
    text = (f"jobs:\n  observe:\n    uses: '{OBSERVER}@{x_star}'\n  other:\n    runs-on: x\n    steps:\n"
            f"      - run: |\n          uses: {OBSERVER}@{'c' * 40}\n")
    k = commit(repo, {CALLER: text})
    release_guard.check(repo, x_star, k)


def document_with(**changes):
    value = {"product_inputs": {"shared_outputs": {"a": 1}}, "report_hmac_key": "5a" * 32}
    return value | changes


COMMITMENTS = {"shared_outputs_sha256": c.sha(c.canonical({"a": 1}))}
T0 = "2026-11-20T12:00:00Z"


def pin_at(**changes):
    return {"observed_at": T0, "expires_at": "2026-11-20T15:00:00Z", "frozen_until": "2026-11-20T16:00:00Z"} | changes


def test_cruzamento_recusa_chave_fora_do_conjunto_fechado_da_governanca():
    governance_assembly.crosscheck(document_with(), COMMITMENTS)
    with pytest.raises(ValueError, match="governance key=surprise"):
        governance_assembly.crosscheck(document_with(surprise=1), COMMITMENTS)


def test_conjunto_fechado_cobre_toda_chave_de_uma_governanca_valida_do_gate(monkeypatch, tmp_path):
    from fixtures.cnesdata_phase_a_replay import ReplayChain
    chain = ReplayChain(monkeypatch, tmp_path)
    assert set(chain.gov) <= governance_assembly.GOVERNANCE_KEYS


@pytest.mark.parametrize("pins", [
    {"plan": pin_at(), "deploy": pin_at(expires_at="2026-11-20T14:59:59Z")},
    {"plan": pin_at(frozen_until="2026-11-20T15:59:59Z"), "deploy": pin_at()},
    {"plan": pin_at(), "deploy": pin_at(observed_at="2026-11-20T12:00:01Z")},
])
def test_cruzamento_recusa_pins_fora_da_cadeia_de_expiracao(pins):
    with pytest.raises(ValueError, match="expiry chain"):
        governance_assembly.crosscheck(document_with(session_policy_pins=pins), COMMITMENTS)


def test_cruzamento_aceita_pins_na_cadeia_e_recusa_cloudfront_que_vence_antes_do_custo():
    pins = {"plan": pin_at(), "deploy": pin_at()}
    governance_assembly.crosscheck(document_with(session_policy_pins=pins), COMMITMENTS)
    cost = {"scope": "active", "expires_at": "2026-11-20T17:00:00Z",
            "cloudfront": {"expires_at": "2026-11-20T16:00:00Z"}}
    with pytest.raises(ValueError, match="expiry chain"):
        governance_assembly.crosscheck(document_with(session_policy_pins=pins, cost=cost), COMMITMENTS)


APPLICATION_PIN = {"observed_at": "2026-11-21T09:00:00Z", "expires_at": "2026-11-21T12:00:00Z",
                   "frozen_until": "2026-11-21T13:00:00Z"}


def test_cruzamento_aceita_documento_3_com_context_kind_e_pin_do_application_na_propria_cadeia():
    pins_ = {"plan": pin_at(), "deploy": pin_at(), "application": APPLICATION_PIN}
    governance_assembly.crosscheck(document_with(context_kind="promotion", session_policy_pins=pins_), COMMITMENTS)
    only = {"application": APPLICATION_PIN}
    governance_assembly.crosscheck(document_with(context_kind="promotion", session_policy_pins=only), COMMITMENTS)


def test_cruzamento_recusa_pin_de_role_fora_de_plan_deploy_e_application():
    with pytest.raises(ValueError, match="session pin role=other"):
        governance_assembly.crosscheck(document_with(session_policy_pins={"other": pin_at()}), COMMITMENTS)


@pytest.mark.parametrize("changes", [{"expires_at": "2026-11-21T11:59:59Z"}, {"frozen_until": "2026-11-21T12:59:59Z"}])
def test_cruzamento_recusa_pin_do_application_fora_da_propria_cadeia(changes):
    pins_ = {"application": APPLICATION_PIN | changes}
    with pytest.raises(ValueError, match="expiry chain violated element=pin role=application"):
        governance_assembly.crosscheck(document_with(session_policy_pins=pins_), COMMITMENTS)


RUNTIME_MANIFEST = "application_product_source_manifest"


def test_conjunto_fechado_cobre_as_chaves_de_topo_que_os_gates_de_entrega_leem():
    pattern = re.compile(r'\bgovernance(?:\[\s*"(\w+)"\s*\]|\.get\(\s*"(\w+)")')
    read = set()
    for path in (ROOT / "tools/cnesdata_delivery").glob("*.py"):
        if path.name not in {"host_gate.py", "signing_gate.py"}:
            read |= {first or second for first, second in pattern.findall(path.read_text())}
    closed = governance_assembly.GOVERNANCE_KEYS | governance_assembly.HYDRATED_KEYS | {RUNTIME_MANIFEST}
    assert "account_id" in read and read <= closed, sorted(read - closed)
    assert governance_assembly.HYDRATED_KEYS == {"lifecycle_steps", "source_closure"}
    assert governance_assembly.HYDRATED_KEYS.isdisjoint(governance_assembly.GOVERNANCE_KEYS)


def test_render_do_cli_valida_antes_de_emitir(tmp_path, capsys):
    document = tmp_path / "governance.json"
    commitments = tmp_path / "commitments.json"
    document.write_bytes(c.canonical(document_with(surprise=1)))
    commitments.write_bytes(c.canonical(COMMITMENTS))
    assert governance_assembly.main(["render", "--document", str(document), "--commitments", str(commitments)]) == 1
    seen = capsys.readouterr()
    assert seen.out == "" and "refused reason=governance key=surprise" in seen.err


def render_cli(tmp_path, document):
    path = tmp_path / "governance.json"
    commitments = tmp_path / "commitments.json"
    path.write_bytes(c.canonical(document))
    commitments.write_bytes(c.canonical(COMMITMENTS))
    return governance_assembly.main(["render", "--document", str(path), "--commitments", str(commitments)])


def test_render_do_cli_recusa_pin_deploy_antes_de_plan_sem_observed_at_com_motivo_chave_valor(tmp_path, capsys):
    plan = {key: item for key, item in pin_at().items() if key != "observed_at"}
    assert render_cli(tmp_path, document_with(session_policy_pins={"deploy": pin_at(), "plan": plan})) == 1
    seen = capsys.readouterr()
    assert seen.out == "" and seen.err == "refused reason=session pin fields role=plan\n"


@pytest.mark.parametrize(("document", "reason"), [
    ({"report_hmac_key": "5a" * 32}, "missing key=product_inputs"),
    (document_with(product_inputs=["x"]), "malformed type=TypeError"),
    (document_with(cost=["x"]), "malformed type=AttributeError"),
])
def test_render_do_cli_mapeia_erro_de_chave_ou_tipo_para_motivo_chave_valor(tmp_path, capsys, document, reason):
    assert render_cli(tmp_path, document) == 1
    seen = capsys.readouterr()
    assert seen.out == "" and seen.err == f"refused reason={reason}\n"


def test_guarda_recusa_yaml_do_caller_com_raiz_que_nao_e_mapa(repo, capsys):
    x_star = commit(repo, {"tools/cnesdata_delivery/a.py": "x = 1\n"})
    k = commit(repo, {CALLER: f"- uses: {OBSERVER}@{x_star}\n"})
    with pytest.raises(ValueError, match="caller yaml"):
        release_guard.check(repo, x_star, k)
    assert governance_assembly.main(["release-check", "--repo", str(repo), "--x-star", x_star, "--k", k]) == 1
    assert capsys.readouterr().err == "refused reason=caller yaml\n"


NO_YAML = """
import io, json, sys
sys.path.insert(0, sys.argv[1])
sys.modules["yaml"] = None
from tools.cnesdata_delivery.producers import governance_assembly, hmac_key
calls = []
class Custody:
    def __init__(self, run=None):
        pass
    def lookup(self):
        return "5a" * 32
    def store(self, key):
        calls.append("store")
    def deliver(self, key, repository, environment):
        calls.append("deliver")
hmac_key.Custody = Custody
out = io.BytesIO()
sys.stdout = type("W", (), {"buffer": out, "write": lambda self, text: None, "flush": lambda self: None})()
status = [governance_assembly.main(["render", "--document", sys.argv[2], "--commitments", sys.argv[3]]),
          governance_assembly.main(["key", "generate", "--repo", "VINIClUS/infra-ansible", "--environment", "x"]),
          governance_assembly.main(["baseline-inputs", "--private", sys.argv[4]])]
sys.stderr.write(json.dumps({"status": status, "calls": calls, "yaml": sys.modules["yaml"] is None,
                             "size": len(out.getvalue())}))
"""


def test_cli_do_dono_renderiza_gera_chave_e_emite_baseline_sem_pyyaml(tmp_path):
    import sys
    from test_cnesdata_producers_baseline import private
    paths = {name: tmp_path / f"{name}.json" for name in ("document", "commitments", "private")}
    paths["document"].write_bytes(c.canonical(document_with()))
    paths["commitments"].write_bytes(c.canonical(COMMITMENTS))
    paths["private"].write_text(json.dumps(private()))
    done = subprocess.run([sys.executable, "-I", "-c", NO_YAML, str(ROOT), *(str(paths[n]) for n in paths)],
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stderr)
    assert report["status"] == [0, 0, 0] and report["calls"] == ["store", "deliver"] and report["yaml"] is True
    assert report["size"] > len(c.canonical(document_with()))


def test_guarda_de_release_continua_lendo_o_caller_com_pyyaml(repo):
    x_star, k = release(repo)
    release_guard.check(repo, x_star, k)
