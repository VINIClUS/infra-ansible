"""P16b design 4.1 and ruling 2 items 4 and C4: the bounded native wait with R = 30 s and its measured timing."""
import pytest


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


class _World:
    def __init__(self, start, *, terminal_at=None, latency=1, error_at=None):
        self.now, self.latency, self.terminal_at, self.error_at = start, latency, terminal_at, error_at
        self.polls, self.sleeps = [], []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def poll(self):
        self.polls.append(self.now)
        if self.error_at == len(self.polls):
            raise RuntimeError("native outcome unknown")
        self.now += self.latency
        stopped = self.terminal_at is not None and len(self.polls) >= self.terminal_at
        return {"tasks": [{"lastStatus": "STOPPED" if stopped else "RUNNING", "poll": len(self.polls)}]}


def _terminal(response):
    return response["tasks"][0]["lastStatus"] == "STOPPED"


def _wait(world, child_deadline):
    return _mb().mode_wait(world.poll, terminal=_terminal, child_deadline=child_deadline, clock=world.clock,
                           sleep=world.sleep)


def test_espera_limitada_usa_r_de_30_s_e_intervalo_de_5_s():
    assert (_mb().MODE_WAIT_RESERVE, _mb().MODE_WAIT_INTERVAL) == (30, 5)


def test_espera_para_no_primeiro_estado_terminal_e_devolve_so_a_resposta_final():
    world = _World(1000, terminal_at=3)
    response, timing = _wait(world, 1200)
    assert response == {"tasks": [{"lastStatus": "STOPPED", "poll": 3}]}
    assert world.polls == [1000, 1006, 1012] and world.sleeps == [5, 5]
    assert timing == {"kind": "wait", "started_at": 1000, "ended_at": 1013, "wait_end": 1170, "polls": 3, "terminal": True}


def test_espera_sem_terminal_termina_no_wait_end_30_s_antes_do_kill_com_resultado_pendente():
    world = _World(1000)
    response, timing = _wait(world, 1100)
    assert response["tasks"][0]["lastStatus"] == "RUNNING"
    assert timing["ended_at"] <= timing["wait_end"] == 1100 - 30 < timing["ended_at"] + 5
    assert timing["polls"] == len(world.polls) and timing["terminal"] is False
    assert all(later - earlier == 6 for earlier, later in zip(world.polls, world.polls[1:]))
    assert world.now <= 1100 - 30


def test_espera_nao_comeca_depois_do_wait_end_e_nao_faz_io():
    world = _World(1070)
    with pytest.raises(ValueError, match="^mode wait elapsed$"):
        _wait(world, 1100)
    assert world.polls == []


def test_espera_nao_repete_uma_leitura_de_resultado_desconhecido():
    world = _World(1000, error_at=2)
    with pytest.raises(RuntimeError, match="native outcome unknown"):
        _wait(world, 1200)
    assert len(world.polls) == 2


def test_espera_com_uma_leitura_so_quando_nao_cabe_outro_intervalo():
    world = _World(1066)
    response, timing = _wait(world, 1100)
    assert len(world.polls) == 1 and world.sleeps == [] and response["tasks"][0]["lastStatus"] == "RUNNING"
    assert timing == {"kind": "wait", "started_at": 1066, "ended_at": 1067, "wait_end": 1070, "polls": 1, "terminal": False}
