"""P16b c-1125-p16b-repin: the readbacks origin is the keeper's ModeReadback of the mode, handed off by original()."""
import pytest

from test_cnesdata_mode_readback_context import SOURCE, _keys, _readback

OPERATIONS = ("unit-start", "unit-observe", "recovery-start", "recovery-observe", "audit-start", "audit-observe")


@pytest.mark.parametrize("operation", ["unit-start", "unit-observe"])
def test_origem_readbacks_entrega_os_bytes_relidos_pela_cadeia_do_readback_do_modo(monkeypatch, operation):
    readback, world, _, native, _ = _readback(monkeypatch)
    raw = readback.read()
    calls = len(native.calls)
    handed = []
    original = readback.original
    readback.original = lambda: handed.append(1) or original()
    found = SOURCE(keeper=world.keeper, owner={}, window={}, operation=operation, names=["readbacks"])
    assert found == {"readbacks": raw} and handed == [1] and len(native.calls) == calls


def test_origem_readbacks_recusa_cadeia_adulterada_sem_devolver_a_observacao_em_memoria(monkeypatch):
    readback, world, store, _, request = _readback(monkeypatch)
    readback.read()
    key = _keys(request, 0)["response"]
    store.objects[key] = store.objects[key] + b" "
    with pytest.raises(ValueError, match="^mode readback chain$"):
        SOURCE(keeper=world.keeper, owner={}, window={}, operation="unit-start", names=["readbacks"])


def test_origem_readbacks_recusa_sem_readback_do_modo_no_keeper(monkeypatch):
    readback, world, _, _, _ = _readback(monkeypatch)
    readback.read()
    with pytest.raises(ValueError, match="^readbacks original$"):
        SOURCE(keeper=world.keeper, owner={}, window={}, operation="recovery-start", names=["readbacks"])


def test_origem_readbacks_recusa_readback_ainda_nao_lido(monkeypatch):
    _, world, _, _, _ = _readback(monkeypatch)
    with pytest.raises(ValueError, match="^mode readback original observation$"):
        SOURCE(keeper=world.keeper, owner={}, window={}, operation="unit-start", names=["readbacks"])


def test_origem_readbacks_recusa_dois_readbacks_do_mesmo_modo(monkeypatch):
    readback, world, _, _, _ = _readback(monkeypatch)
    readback.read()
    world.keeper._contexts.append(readback)
    with pytest.raises(ValueError, match="^readbacks original$"):
        SOURCE(keeper=world.keeper, owner={}, window={}, operation="unit-start", names=["readbacks"])


@pytest.mark.parametrize("operation", ["unit-seed", "unit-record", "audit-record"])
def test_origem_readbacks_fica_fechada_fora_das_operacoes_que_a_recebem(monkeypatch, operation):
    readback, world, _, _, _ = _readback(monkeypatch)
    readback.read()
    with pytest.raises(ValueError, match="^mode_inputs=source_unconnected$"):
        SOURCE(keeper=world.keeper, owner={}, window={}, operation=operation, names=["readbacks"])


def test_origem_readbacks_e_aberta_exatamente_as_operacoes_com_entrada_readbacks():
    from tools.cnesdata_delivery import lifecycle_contract as lc
    from tools.cnesdata_delivery.mode_broker import MODE_KEEPER_ORIGINS
    assert MODE_KEEPER_ORIGINS["readbacks"] == OPERATIONS
    assert set(OPERATIONS) == {operation for operation, names in lc.ADAPTER_INPUTS.items() if "readbacks" in names.split()}
