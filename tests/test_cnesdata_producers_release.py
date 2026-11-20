"""Superficie pinada, closure do pin, guarda X*..K, tetos de governanca e chave HMAC (P18)."""
import json
import os
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
