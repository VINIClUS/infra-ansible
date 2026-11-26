"""P16b Falta 6 and 7: the (a) mode origins from the prepared package and the authenticated product
checkout, the readbacks origin the stage builds, and unit-start's keeper origins with no gate (follow-up item 5)."""
import copy
import json
from types import SimpleNamespace

import pytest

from fixtures.cnesdata_stage_open import stage_open_published  # noqa: F401

from test_cnesdata_mode_prepared_authority import _world
from test_cnesdata_mode_stages import _mode_case, _mode_world
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc

DIRECTORY = lc.MODE_FIXTURE_MANIFEST.rsplit("/", 1)[0]
FIXTURES = {"cnes-local-v1.parquet": ("CNES_LOCAL", b"PAR1 local synthetic\n"),
            "cnes-nacional-v1.parquet": ("CNES_NACIONAL", b"PAR1 nacional synthetic\n")}


def _ag():
    from tools.cnesdata_delivery import application_gate
    return application_gate


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


def _context(prepared, arguments, **changes):
    fields = {"governance": arguments["governance"], "authority": arguments["application"], "prepared": prepared,
              "credential_limit": 6000, "operation_session": "operation-session", "clock": "clock", "aws": "evidence",
              "activation_sha256": arguments["activation_sha256"], "product": "product"}
    return _ag().ModeContext(**(fields | changes))


def _source(operation, names, *, context, owner, keeper=None, prepared=None):
    window = _mode_case(operation)[2]
    if prepared is not None:
        window |= {"preparation_deadline": prepared["preparation_deadline"], "windows": prepared["windows"]}
    keeper = SimpleNamespace(_contexts=[]) if keeper is None else keeper
    return _ag().mode_input_source(keeper=keeper, owner=owner, window=window, operation=operation, names=names,
                                   context=context)


def test_contexto_de_modo_carrega_a_evidencia_a_ativacao_e_o_produto():
    assert _ag().ModeContext._fields == ("governance", "authority", "prepared", "credential_limit", "operation_session",
                                         "clock", "aws", "activation_sha256", "product")


@pytest.mark.parametrize("operation, name", [("unit-record", "mode-input"), ("recovery-record", "mode-input"),
                                             ("audit-record", "mode-input"), ("recovery-observe", "network"),
                                             ("audit-observe", "network")])
def test_mode_input_e_network_vem_do_pacote_preparado_revalidado_no_estagio(monkeypatch, operation, name):
    prepared, arguments, _, _ = _world(monkeypatch)
    inputs = _source(operation, [name], context=_context(prepared, arguments), owner=arguments["owner"],
                     prepared=arguments["window"])
    resources = c.loads(prepared["mode-input.json"], canonical=True)["mode_canary"]["resources"]
    expected = prepared["mode-input.json"] if name == "mode-input" else _mb().mode_network_input(resources)
    assert inputs == {name: expected}


@pytest.mark.parametrize("mutation, message", [("activation", "^mode prepared authority binding$"),
                                               ("evaluation", "^mode prepared evaluation recompute$"),
                                               ("no-context", "^mode prepared origin context$")])
def test_origem_a_recusa_pacote_que_nao_revalida_no_estagio(monkeypatch, mutation, message):
    prepared, arguments, _, _ = _world(monkeypatch)
    context = _context(prepared, arguments)
    if mutation == "activation":
        context = _context(prepared, arguments, activation_sha256="9" * 64)
    if mutation == "evaluation":
        evaluation = c.loads(prepared["mode-evaluation.json"], canonical=True)
        evaluation["cases"][0]["resource"] += "-other"
        context = _context(type(prepared)(dict(prepared) | {"mode-evaluation.json": c.canonical(evaluation)}), arguments)
    if mutation == "no-context":
        context = None
    with pytest.raises(ValueError, match=message):
        _source("recovery-record", ["mode-input"], context=context, owner=arguments["owner"], prepared=arguments["window"])


def _product(tmp_path, governance, *, change=None):
    root = tmp_path / "product"
    (root / DIRECTORY).mkdir(parents=True)
    entries = {name: {"manifest_id": "fixture-" + name.removesuffix(".parquet"), "origin": "docs/fixtures/data-plane/" + name,
                      "row_count": 5, "schema_version": "cnes-profissional-v1", "sha256": c.sha(raw), "size": len(raw),
                      "source_type": kind} for name, (kind, raw) in FIXTURES.items()}
    manifest = (json.dumps({"files": entries, "schema": "cnesdata.mode-canary-fixtures/v1"}, indent=2) + "\n").encode()
    files = {lc.MODE_FIXTURE_MANIFEST: manifest, **{f"{DIRECTORY}/{name}": raw for name, (_, raw) in FIXTURES.items()}}
    for path, raw in files.items():
        (root / path).write_bytes(raw)
    gov = copy.deepcopy(governance)
    gov["application_product_source_manifest"]["files"] |= {path: c.sha(raw) for path, raw in files.items()}
    if change is not None:
        change(root)
    return root, gov, files


@pytest.mark.parametrize("operation, names", [
    ("unit-record", ["fixture-manifest"]), ("recovery-record", ["fixture-manifest"]), ("audit-record", ["fixture-manifest"]),
    ("unit-seed", ["fixture-cnes-local", "fixture-cnes-nacional", "fixture-manifest"]),
    ("recovery-seed", ["fixture-cnes-local", "fixture-cnes-nacional", "fixture-manifest"])])
def test_originais_de_fixture_vem_do_checkout_autenticado_do_produto(monkeypatch, tmp_path, operation, names):
    prepared, arguments, _, _ = _world(monkeypatch)
    root, governance, files = _product(tmp_path, arguments["governance"])
    context = _context(prepared, arguments, governance=governance, product=str(root))
    expected = {"fixture-manifest": files[lc.MODE_FIXTURE_MANIFEST],
                "fixture-cnes-local": files[f"{DIRECTORY}/cnes-local-v1.parquet"],
                "fixture-cnes-nacional": files[f"{DIRECTORY}/cnes-nacional-v1.parquet"]}
    assert _source(operation, names, context=context, owner=arguments["owner"]) == {name: expected[name] for name in names}


def _rewrite(path, raw):
    path.write_bytes(raw)


@pytest.mark.parametrize("mutation", ["manifest-byte", "fixture-byte", "symlink", "missing", "kind", "extra", "entry-sha",
                                      "entry-size"])
def test_original_de_fixture_recusa_byte_fora_do_manifesto_de_fonte_ou_do_de_fixture(monkeypatch, tmp_path, mutation):
    prepared, arguments, _, _ = _world(monkeypatch)
    local = f"{DIRECTORY}/cnes-local-v1.parquet"

    def change(root):
        if mutation == "manifest-byte":
            _rewrite(root / lc.MODE_FIXTURE_MANIFEST, (root / lc.MODE_FIXTURE_MANIFEST).read_bytes() + b" ")
        if mutation == "fixture-byte":
            _rewrite(root / local, (root / local).read_bytes() + b"x")
        if mutation == "symlink":
            target = root / "elsewhere.parquet"
            target.write_bytes((root / local).read_bytes())
            (root / local).unlink()
            (root / local).symlink_to(target)
        if mutation == "missing":
            (root / local).unlink()
    root, governance, _ = _product(tmp_path, arguments["governance"], change=change)
    if mutation in ("kind", "extra", "entry-sha", "entry-size"):
        manifest = json.loads((root / lc.MODE_FIXTURE_MANIFEST).read_bytes())
        entry = manifest["files"]["cnes-local-v1.parquet"]
        if mutation == "kind":
            entry["source_type"] = "SIHD"
        elif mutation == "entry-sha":
            entry["sha256"] = "0" * 64
        elif mutation == "entry-size":
            entry["size"] += 1
        else:
            manifest["files"]["other.parquet"] = dict(manifest["files"]["cnes-local-v1.parquet"])
        raw = (json.dumps(manifest, indent=2) + "\n").encode()
        _rewrite(root / lc.MODE_FIXTURE_MANIFEST, raw)
        governance["application_product_source_manifest"]["files"][lc.MODE_FIXTURE_MANIFEST] = c.sha(raw)
    context = _context(prepared, arguments, governance=governance, product=str(root))
    with pytest.raises(ValueError, match="^mode fixture original$"):
        _source("unit-seed", ["fixture-cnes-local", "fixture-cnes-nacional", "fixture-manifest"], context=context,
                owner=arguments["owner"])


@pytest.mark.parametrize("names, message", [(["readbacks"], "^mode prepared origin context$"),
                                            (["mode-seed"], "^mode_inputs=source_unconnected$")],
                         ids=["readbacks-sem-contexto", "mode-seed-nao-ligado"])
def test_unit_start_na_producao_recusa_origem_sem_contexto_ou_nao_ligada(names, message):
    keeper = SimpleNamespace(_contexts=[])
    with pytest.raises(ValueError, match=message):
        _source("unit-start", names, context=None, owner={}, keeper=keeper)
    assert keeper._contexts == []


def test_unit_start_pede_ao_estagio_mode_start_previous_e_readbacks_depois_do_seed():
    from tools.cnesdata_delivery import application_gate as ag
    produced = set(lc.ADAPTER_OBSERVATIONS.values()) | {"record", "audit-event-ids"}
    known = {"activation", "close-drain", "phase-b", "recovery-result"}
    assert {"mode-start", "previous", "readbacks"} <= set(lc.ADAPTER_INPUTS["unit-start"].split()) - produced - known
    assert ag.MODE_RUNS["unit"].index("unit-start") > ag.MODE_RUNS["unit"].index("unit-seed")


def test_unit_start_na_producao_deriva_mode_start_e_previous_do_keeper():
    keeper = SimpleNamespace(_contexts=[])
    window = _mode_case("unit-start")[2]
    assert _source("unit-start", ["mode-start", "previous"], context=None, owner={}, keeper=keeper) == {
        "mode-start": c.canonical({"version": 1, "kind": "mode-start", "frozen": False,
                                   "started_at": c.utc(window["admitted_at"])}), "previous": b"null\n"}
    assert keeper._contexts == []


class _Readback:
    made = []

    def __init__(self, aws, governance, session, *, guard, mode, clock=None):
        self.args = (aws, governance, session, guard, mode, clock)
        self.mode, self.raw = mode, c.canonical({"fixture_readbacks": mode})
        guard.keeper.attach(self)
        _Readback.made.append(self)

    def read(self):
        return self.raw

    def original(self):
        return self.raw


def _readback_world(monkeypatch):
    from tools.cnesdata_delivery import mode_broker as mb
    world = _mode_world(monkeypatch)
    record = world.keeper.lease.check()
    sessions, authorities = [], []
    monkeypatch.setattr(mb, "mode_prepared_authority", lambda prepared, **kwargs: authorities.append(kwargs) or "authority")
    monkeypatch.setattr(mb, "assume_readback_session", lambda **kwargs: sessions.append(kwargs) or "readback-session")
    monkeypatch.setattr(mb, "ModeReadback", _Readback)
    _Readback.made = []
    context = _ag().ModeContext(governance="g", authority="a", prepared="p", credential_limit=6000, operation_session="o",
                                clock="k", aws="evidence", activation_sha256="1" * 64, product="product")
    return world, lc.owner_binding(record), record["lifecycle"], context, sessions, authorities


@pytest.mark.parametrize("mode", ["unit", "recovery", "audit"])
def test_origem_readbacks_constroi_anexa_e_le_o_mode_readback_no_start_e_o_observe_recebe_o_mesmo(monkeypatch, mode):
    from tools.cnesdata_delivery import application_gate as ag
    world, owner, window, context, sessions, authorities = _readback_world(monkeypatch)
    start = _mb().mode_input_source(keeper=world.keeper, owner=owner, window=window, operation=mode + "-start",
                                    names=["readbacks"], context=context)
    (made,) = _Readback.made
    assert start == {"readbacks": made.raw} and made in world.keeper._contexts
    assert made.args[0] == "evidence" and made.args[1] == "g" and made.args[2] == "readback-session"
    assert type(made.args[3]) is ag.KeeperGuard and made.args[3].keeper is world.keeper and made.args[4] == mode
    (session,) = sessions
    assert session["governance"] == "g" and session["application"] == "a" and session["authority"] == "authority"
    assert session["mode"] == mode and session["credential_limit"] == 6000 and session["operation_session"] == "o"
    assert authorities == [{"governance": "g", "application": "a", "owner": owner, "activation_sha256": "1" * 64,
                            "window": window}]
    observe = _mb().mode_input_source(keeper=world.keeper, owner=owner, window=window, operation=mode + "-observe",
                                      names=["readbacks"], context=context)
    assert observe == start and len(_Readback.made) == 1 and len(sessions) == 1
