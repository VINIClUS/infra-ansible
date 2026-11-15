"""Producer closure of the application gate (#55 2nd slice amendment 6886977054, decision 1)."""
import ast
import base64
import hashlib
import re
import subprocess
from pathlib import Path

import pytest

from tools.cnesdata_delivery import contract as c

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/reusable-cnesdata-application-gate.yml"
WORKFLOW_URL = "repos/VINIClUS/infra-ansible/contents/" + WORKFLOW + "?ref="


def _pyboot():
    raw = (ROOT / WORKFLOW).read_text()
    lists = [ast.literal_eval(value) for value in re.findall(r"files = (\[[\s\S]*?\])", raw)]
    assert len(lists) == 1
    return lists[0]


def _paths():
    return sorted(["tools/cnesdata_delivery/" + name for name in _pyboot()] + [WORKFLOW])


def expected_closure(read):
    return c.sha(c.canonical({"files": {path: c.sha(read(path)) for path in _paths()}}))


def _blob(raw):
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()


def workflow_contents(raw, path=WORKFLOW):
    return {"type": "file", "path": path, "encoding": "base64", "size": len(raw), "sha": _blob(raw),
            "content": base64.b64encode(raw).decode()}


def _tree(tmp_path):
    files = {path: (ROOT / path).read_bytes() for path in _paths()}
    for path, raw in files.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_bytes(raw)
    return files


class _API:
    def __init__(self, raw, pin):
        self.raw, self.pin, self.calls, self.item = raw, pin, [], workflow_contents(raw)

    def read(self, path, **_):
        self.calls.append(path)
        assert path == WORKFLOW_URL + self.pin, path
        return dict(self.item)


def test_closure_paths_are_the_application_pyboot_list_plus_the_reusable():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    assert list(lc.APPLICATION_PYBOOT) == _pyboot()
    assert "runtime-requirements.txt" in lc.APPLICATION_PYBOOT
    assert lc.APPLICATION_GATE_WORKFLOW == WORKFLOW
    assert list(lc.APPLICATION_CLOSURE_PATHS) == _paths()


def test_application_source_closure_commits_to_every_file_by_path():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    files = {path: (ROOT / path).read_bytes() for path in _paths()}
    seen = []
    def read(path):
        seen.append(path)
        return files[path]
    baseline = lc.application_source_closure(read)
    assert baseline == expected_closure(files.__getitem__)
    assert sorted(seen) == _paths() and len(seen) == len(set(seen))
    for path in _paths():
        changed = dict(files, **{path: files[path] + b"\n"})
        assert lc.application_source_closure(changed.__getitem__) != baseline, path
    renamed = {path.replace("contract.py", "contract2.py"): raw for path, raw in files.items()}
    with pytest.raises(KeyError):
        lc.application_source_closure(renamed.__getitem__)


@pytest.mark.parametrize("bad", ["text", "oversized"])
def test_application_source_closure_refuses_non_bytes_and_oversized_files(bad):
    from tools.cnesdata_delivery import lifecycle_contract as lc
    files = {path: (ROOT / path).read_bytes() for path in _paths()}
    files[WORKFLOW] = files[WORKFLOW].decode() if bad == "text" else b"#" * (256 * 1024 + 1)
    with pytest.raises(ValueError, match="application closure file"):
        lc.application_source_closure(files.__getitem__)


@pytest.mark.parametrize("mutation", [None, "crlf", "governance", "zero", "python", "blob", "content", "type", "path", "size",
                                      "encoding", "size-type", "oversized"])
def test_verify_source_closure_reads_python_from_disk_and_reusable_at_gate_pin(tmp_path, mutation):
    from tools.cnesdata_delivery import application_gate as ag
    files = _tree(tmp_path)
    if mutation == "crlf":
        files["tools/cnesdata_delivery/outputs.py"] += b"# windows line\r\n"
        (tmp_path / "tools/cnesdata_delivery/outputs.py").write_bytes(files["tools/cnesdata_delivery/outputs.py"])
    if mutation == "oversized":
        files[WORKFLOW] = b"#" * (256 * 1024 + 1)
    pin = "a" * 40
    governance = {"gate_shas": {"application": pin}, "application_source_closure_sha256": expected_closure(files.__getitem__),
                  "application_configuration": {"workflow_sha": "b" * 40}}
    api = _API(files[WORKFLOW], pin)
    if mutation == "governance": governance["application_source_closure_sha256"] = "e" * 64
    if mutation == "zero": governance["application_source_closure_sha256"] = "0" * 64
    if mutation == "python": (tmp_path / "tools/cnesdata_delivery/application_gate.py").write_bytes(b"# edited\n")
    if mutation == "blob": api.item["sha"] = "0" * 40
    if mutation == "content": api.item["content"] = base64.b64encode(b"tampered\n").decode()
    if mutation == "type": api.item["type"] = "symlink"
    if mutation == "path": api.item["path"] = ".github/workflows/other.yml"
    if mutation == "size": api.item["size"] += 1
    if mutation == "encoding": api.item["encoding"] = "utf-8"
    if mutation == "size-type": api.item["size"] = str(api.item["size"])
    if mutation in {None, "crlf"}:
        assert ag.verify_source_closure(governance, api, root=tmp_path) == governance["application_source_closure_sha256"]
        assert api.calls == [WORKFLOW_URL + pin]
        return
    message = "application producer closure" if mutation in {"governance", "zero", "python"} else "application gate workflow"
    with pytest.raises(ValueError, match=message):
        ag.verify_source_closure(governance, api, root=tmp_path)


def test_verify_source_closure_accepts_the_contents_api_line_wrapped_base64(tmp_path):
    """The contents API wraps base64 every 60 characters; strict validation would refuse the real reusable."""
    from tools.cnesdata_delivery import application_gate as ag
    files = _tree(tmp_path)
    pin = "a" * 40
    governance = {"gate_shas": {"application": pin}, "application_source_closure_sha256": expected_closure(files.__getitem__)}
    api = _API(files[WORKFLOW], pin)
    encoded = api.item["content"]
    api.item["content"] = "\n".join(encoded[i:i + 60] for i in range(0, len(encoded), 60)) + "\n"
    assert "\n" in api.item["content"].rstrip("\n")
    assert ag.verify_source_closure(governance, api, root=tmp_path) == governance["application_source_closure_sha256"]


def test_verify_source_closure_default_root_is_the_executing_tree():
    from tools.cnesdata_delivery import application_gate as ag
    files = {path: (ROOT / path).read_bytes() for path in _paths()}
    pin = "a" * 40
    governance = {"gate_shas": {"application": pin}, "application_source_closure_sha256": expected_closure(files.__getitem__)}
    assert ag.verify_source_closure(governance, _API(files[WORKFLOW], pin)) == governance["application_source_closure_sha256"]


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True).stdout.decode().strip()


def test_closure_cli_prints_the_pin_closure_the_gate_recomputes(tmp_path, monkeypatch, capsys):
    from tools.cnesdata_delivery import application_gate as ag
    files = _tree(tmp_path)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "pin")
    pin = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / WORKFLOW).write_bytes(files[WORKFLOW] + b"# later commit is not the pin\n")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-am", "after the pin")
    assert _git(tmp_path, "rev-parse", "HEAD") != pin
    (tmp_path / "tools/cnesdata_delivery/contract.py").write_bytes(b"# working tree is not the pin\n")
    monkeypatch.chdir(tmp_path)
    assert ag.main(["closure", "--pin", pin]) is None
    printed = capsys.readouterr().out
    assert printed == expected_closure(files.__getitem__) + "\n"
    governance = {"gate_shas": {"application": pin}, "application_source_closure_sha256": printed.strip()}
    _tree(tmp_path)
    assert ag.verify_source_closure(governance, _API(files[WORKFLOW], pin), root=tmp_path) == printed.strip()


@pytest.mark.parametrize("operation", ["preflight", "credentials", "execute"])
def test_pin_is_refused_outside_closure_before_admission(monkeypatch, operation):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr
    monkeypatch.setattr(lr, "admission", lambda role: pytest.fail("a pinned non-closure operation never reaches admission"))
    with pytest.raises(ValueError, match="pin is closure-only"):
        ag.main([operation, "--pin", "a" * 40])


@pytest.mark.parametrize("argv", [["closure"], ["closure", "--pin", "A" * 40], ["closure", "--pin", "a" * 39]])
def test_closure_cli_requires_an_exact_pin(tmp_path, monkeypatch, argv):
    from tools.cnesdata_delivery import application_gate as ag
    monkeypatch.chdir(tmp_path)
    with pytest.raises((ValueError, SystemExit)):
        ag.main(argv)


def test_closure_cli_never_runs_admission(tmp_path, monkeypatch, capsys):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr
    _tree(tmp_path)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "pin")
    monkeypatch.setattr(lr, "admission", lambda role: pytest.fail("closure is computed before admission"))
    monkeypatch.chdir(tmp_path)
    ag.main(["closure", "--pin", _git(tmp_path, "rev-parse", "HEAD")])
    assert re.fullmatch(r"[0-9a-f]{64}\n", capsys.readouterr().out)


@pytest.mark.parametrize("operation", ["preflight", "credentials", "execute"])
def test_main_recomputes_closure_right_after_admission(monkeypatch, operation):
    from tools.cnesdata_delivery import application_gate as ag, lifecycle_runtime as lr, session_owner
    events, api = [], object()
    governance = {"marker": True}
    admitted = (governance, {"source_sha": "b" * 40}, {}, api, {}, {})
    monkeypatch.setattr(lr, "admission", lambda role: events.append("admission") or admitted)
    def verify(gov, client):
        assert gov is governance and client is api
        events.append("closure")
        raise ValueError("application producer closure")
    monkeypatch.setattr(ag, "verify_source_closure", verify)
    monkeypatch.setattr(session_owner, "application_fragment", lambda *a: events.append("fragment"))
    monkeypatch.setattr(ag, "credentials", lambda *a, **kw: pytest.fail("closure precedes credentials"))
    monkeypatch.setattr(ag, "execute", lambda *a, **kw: pytest.fail("closure precedes execute"))
    with pytest.raises(ValueError, match="application producer closure"):
        ag.main([operation])
    assert events == ["admission", "closure"]
