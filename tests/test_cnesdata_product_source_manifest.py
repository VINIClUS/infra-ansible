"""Product source manifest delivered by an authenticated artifact instead of the governance."""
import copy
import io
import time
import zipfile

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery.provenance import GitHub

SOURCE = "b" * 40
RUN_ID = 8001
ATTEMPT = 1
ARTIFACT_ID = 7001
MEMBER = "product-source-manifest.json"
WORKFLOW = ".github/workflows/product-source-manifest.yml"
ADAPTER = "scripts/promotion/promote_api.py"


def default_manifest(source=SOURCE):
    return {"version": 1, "source_sha": source,
            "files": {ADAPTER: "c" * 64, "README.md": "e" * 64}}


def _archive(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    return buffer.getvalue()


class WorldGitHub(GitHub):
    def __init__(self, world):
        super().__init__(token="fixture")
        self.world = world
        self.reads = []

    def read(self, path, *, raw=False, maximum=192 * 1024**2):
        self.reads.append(path)
        world = self.world
        prefix = f"repos/{c.REPOSITORY}/actions"
        if path == f"{prefix}/runs/{RUN_ID}/attempts/{ATTEMPT}":
            return world["run"]
        if path == f"{prefix}/artifacts/{ARTIFACT_ID}":
            return world["metadata"]
        if path == f"{prefix}/artifacts/{ARTIFACT_ID}/zip" and raw:
            return world["zip"]
        raise AssertionError(path)


def manifest_world(manifest=None, *, members=None, source=SOURCE, name=None, run_head=None,
                   closure=None, digest=None, expired=False):
    manifest = default_manifest(source) if manifest is None else manifest
    raw = c.canonical(manifest, limit=64 * 1024**2)
    archive = _archive({MEMBER: raw} if members is None else members)
    now = time.time()
    run = {"id": RUN_ID, "run_attempt": ATTEMPT, "head_sha": run_head or source,
           "repository": {"full_name": c.REPOSITORY}, "path": WORKFLOW + "@refs/heads/main",
           "status": "completed", "conclusion": "success",
           "run_started_at": c.utc(now - 100), "updated_at": c.utc(now - 10)}
    metadata = {"id": ARTIFACT_ID, "digest": digest or "sha256:" + c.sha(archive),
                "name": name or f"product-source-manifest-{source}-{RUN_ID}-{ATTEMPT}",
                "workflow_run": {"id": RUN_ID, "head_sha": run_head or source},
                "expired": expired, "created_at": c.utc(now - 50), "expires_at": c.utc(now + 86400)}
    governance = {
        "source_sha": source,
        "application_product_source_manifest_artifact": {
            "artifact_id": ARTIFACT_ID, "artifact_digest": "sha256:" + c.sha(archive),
            "run_id": RUN_ID, "run_attempt": ATTEMPT},
        "application_product_source_closure_sha256": closure or c.sha(raw)}
    api = WorldGitHub({"run": run, "metadata": metadata, "zip": archive})
    return governance, api, manifest


def _hydrate(governance, api):
    from tools.cnesdata_delivery.provenance import product_source_manifest
    return product_source_manifest(api, governance, time.time())


def test_hidrata_o_manifesto_do_membro_do_artefato_exato():
    governance, api, manifest = manifest_world()
    assert _hydrate(governance, api) == manifest
    assert any(path.endswith(f"/artifacts/{ARTIFACT_ID}/zip") for path in api.reads)
    assert api.expiries[c.REPOSITORY, ARTIFACT_ID] > time.time()


def test_deriva_o_nome_do_artefato_dos_campos_da_referencia():
    governance, api, _ = manifest_world(name=f"product-source-manifest-{SOURCE}-{RUN_ID}-2")
    with pytest.raises(ValueError, match="product source manifest artifact name"):
        _hydrate(governance, api)


def test_recusa_governanca_com_manifesto_inline():
    governance, api, manifest = manifest_world()
    governance["application_product_source_manifest"] = manifest
    with pytest.raises(ValueError, match="inline product source manifest"):
        _hydrate(governance, api)
    assert api.reads == []


def test_recusa_referencia_sem_chaves_fechadas():
    governance, api, _ = manifest_world()
    governance["application_product_source_manifest_artifact"]["repository"] = c.REPOSITORY
    with pytest.raises(ValueError, match="closed object fields"):
        _hydrate(governance, api)
    governance, api, _ = manifest_world()
    governance["application_product_source_manifest_artifact"].pop("run_attempt")
    with pytest.raises(ValueError, match="closed object fields"):
        _hydrate(governance, api)


def test_recusa_governanca_sem_referencia_do_artefato():
    governance, api, _ = manifest_world()
    governance.pop("application_product_source_manifest_artifact")
    with pytest.raises(KeyError):
        _hydrate(governance, api)


def test_recusa_artefato_de_outro_source_sha():
    governance, api, _ = manifest_world(run_head="a" * 40)
    with pytest.raises(ValueError):
        _hydrate(governance, api)
    other = default_manifest("a" * 40)
    governance, api, _ = manifest_world(other)
    with pytest.raises(ValueError, match="product source manifest content"):
        _hydrate(governance, api)


def test_recusa_hash_divergente_do_manifesto():
    governance, api, _ = manifest_world(closure="0" * 64)
    with pytest.raises(ValueError, match="product source manifest content"):
        _hydrate(governance, api)


def test_recusa_digest_do_arquivo_diferente_da_referencia():
    governance, api, _ = manifest_world(digest="sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="artifact metadata"):
        _hydrate(governance, api)


@pytest.mark.parametrize("members", [
    {MEMBER: b"{}", "extra.json": b"{}"},
    {"other.json": b"{}"},
    {},
])
def test_recusa_artefato_que_nao_tem_exatamente_o_membro_do_manifesto(members):
    governance, api, _ = manifest_world(members=members)
    with pytest.raises(ValueError, match="product source manifest member"):
        _hydrate(governance, api)


@pytest.mark.parametrize("mutation", ["extra-key", "missing-key", "version", "no-adapter", "empty",
                                      "bad-digest", "not-canonical"])
def test_recusa_manifesto_fora_do_formato_fechado(mutation):
    manifest = default_manifest()
    if mutation == "extra-key": manifest["mode"] = "100644"
    if mutation == "missing-key": manifest.pop("version")
    if mutation == "version": manifest["version"] = 2
    if mutation == "no-adapter": manifest["files"].pop(ADAPTER)
    if mutation == "empty": manifest["files"] = {}
    if mutation == "bad-digest": manifest["files"]["README.md"] = "E" * 64
    members = {MEMBER: b'{"version": 1}'} if mutation == "not-canonical" else None
    governance, api, _ = manifest_world(manifest, members=members)
    with pytest.raises(ValueError):
        _hydrate(governance, api)


def test_recusa_manifesto_acima_do_teto_de_4_mib():
    manifest = default_manifest()
    manifest["files"].update({f"dir/file-{index:06d}.txt": "f" * 64 for index in range(16000)})
    governance, api, _ = manifest_world(manifest)
    assert len(c.canonical(manifest, limit=64 * 1024**2)) < 4 * 1024**2
    assert _hydrate(governance, api) == manifest
    members = {MEMBER: b"x" * (4 * 1024**2 + 1)}
    governance, api, _ = manifest_world(members=members)
    with pytest.raises(ValueError):
        _hydrate(governance, api)


def test_manifesto_hidratado_nao_passa_pelo_limite_de_262144_da_governanca():
    manifest = default_manifest()
    manifest["files"].update({f"dir/file-{index:06d}.txt": "f" * 64 for index in range(5000)})
    governance, api, _ = manifest_world(manifest)
    assert len(c.canonical(manifest, limit=64 * 1024**2)) > 262144
    assert len(c.canonical(governance)) < 1024
    assert _hydrate(governance, api) == manifest
    inline = copy.deepcopy(governance) | {"application_product_source_manifest": manifest}
    with pytest.raises(ValueError):
        c.canonical(inline, limit=262144)


def test_referencia_do_artefato_cabe_em_cerca_de_350_bytes():
    governance, _, _ = manifest_world()
    reference = governance["application_product_source_manifest_artifact"]
    size = len(c.canonical({"application_product_source_manifest_artifact": reference,
                            "application_product_source_closure_sha256":
                            governance["application_product_source_closure_sha256"]}))
    assert size <= 350


def _checkout(tmp_path, mutation):
    import subprocess

    def git(*args):
        return subprocess.run(["git", *args], cwd=tmp_path, check=True,
                              capture_output=True).stdout.decode().strip()
    git("init", "-q")
    files = {ADAPTER: b"VALUE = 1\n", "README.md": b"readme\n"}
    for name, raw in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(raw)
    if mutation == "extra-file":
        (tmp_path / "extra.txt").write_bytes(b"extra\n")
    if mutation == "oversize":
        (tmp_path / "big.bin").write_bytes(b"0" * (8 * 1024**2 + 1))
        files["big.bin"] = (tmp_path / "big.bin").read_bytes()
    if mutation == "mode":
        (tmp_path / "README.md").chmod(0o755)
    git("add", ".")
    if mutation == "symlink":
        git("rm", "-q", "--cached", "README.md")
        (tmp_path / "README.md").unlink()
        (tmp_path / "README.md").symlink_to(ADAPTER.split("/")[-1])
        git("add", "README.md")
    if mutation == "submodule":
        git("rm", "-q", "--cached", "README.md")
        git("update-index", "--add", "--cacheinfo", "160000", "a" * 40, "README.md")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
    source = git("rev-parse", "HEAD")
    return source, files


@pytest.mark.parametrize("mutation", [None, "mode", "extra-file", "missing-file", "symlink", "submodule",
                                      "oversize", "swapped-bytes"])
def test_execute_confere_o_checkout_contra_o_manifesto_hidratado(tmp_path, mutation):
    from tools.cnesdata_delivery.application_gate import authenticate_adapter_closure
    source, files = _checkout(tmp_path, mutation)
    manifest = {"version": 1, "source_sha": source,
                "files": {name: c.sha(raw) for name, raw in files.items() if name != "extra.txt"}}
    if mutation == "missing-file": manifest["files"].pop("README.md")
    if mutation == "swapped-bytes": manifest["files"]["README.md"] = c.sha(b"other\n")
    governance, api, _ = manifest_world(manifest, source=source)
    hydrated = _hydrate(governance, api)
    closure = governance["application_product_source_closure_sha256"]
    if mutation in {None, "mode"}:
        assert set(authenticate_adapter_closure(tmp_path, source, hydrated, closure)) == set(manifest["files"])
    else:
        with pytest.raises(ValueError):
            authenticate_adapter_closure(tmp_path, source, hydrated, closure)
