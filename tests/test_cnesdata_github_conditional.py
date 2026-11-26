"""P35 fix round 2: conditional GETs reuse the cached body and a rate limit is a distinct fail-closed refusal."""
import email.message
import io
import json
import urllib.error
import urllib.request
from email.utils import formatdate

import pytest

from tools.cnesdata_delivery import provenance

PATH = "repos/VINIClUS/CnesData/actions/runs/1/artifacts?per_page=100&page=1"


def _headers(**values):
    message = email.message.Message()
    message["Date"] = formatdate(usegmt=True)
    for key, value in values.items():
        message[key.replace("_", "-")] = value
    return message


class Response:
    def __init__(self, body, **headers):
        self.body, self.headers = body, _headers(**headers)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit=None):
        return self.body


def _error(code, **headers):
    return urllib.error.HTTPError("https://api.github.com/x", code, "x", _headers(**headers), io.BytesIO(b""))


class Opener:
    def __init__(self, *steps):
        self.steps, self.requests = list(steps), []

    def open(self, request, timeout=None):
        self.requests.append(request)
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def _api(monkeypatch, *steps):
    opener = Opener(*steps)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)
    return provenance.GitHub("t"), opener


def test_primeira_leitura_condicional_guarda_o_etag_e_a_segunda_o_envia(monkeypatch):
    api, opener = _api(monkeypatch, Response(b'{"a": 1}', ETag='"v1"'), _error(304, ETag='"v1"'))
    assert api.read_conditional(PATH) == {"a": 1}
    assert api.read_conditional(PATH) == {"a": 1}
    assert opener.requests[0].get_header("If-none-match") is None
    assert opener.requests[1].get_header("If-none-match") == '"v1"'


def test_corpo_novo_substitui_o_cache_e_o_etag(monkeypatch):
    api, opener = _api(monkeypatch, Response(b'{"a": 1}', ETag='"v1"'), Response(b'{"a": 2}', ETag='"v2"'),
                       _error(304, ETag='"v2"'))
    assert [api.read_conditional(PATH) for _ in range(3)] == [{"a": 1}, {"a": 2}, {"a": 2}]
    assert opener.requests[2].get_header("If-none-match") == '"v2"'


def test_304_nunca_vira_listagem_vazia(monkeypatch):
    api, _ = _api(monkeypatch, Response(json.dumps({"total_count": 1, "artifacts": [{"id": 1}]}).encode(), ETag='"v1"'),
                  _error(304, ETag='"v1"'))
    api.read_conditional(PATH)
    assert api.read_conditional(PATH)["artifacts"] == [{"id": 1}]


def test_304_sem_cache_e_recusado(monkeypatch):
    api, _ = _api(monkeypatch, _error(304, ETag='"v1"'))
    with pytest.raises(ValueError, match="GitHub HTTP failure"):
        api.read_conditional(PATH)


def test_leitura_comum_nao_envia_if_none_match(monkeypatch):
    api, opener = _api(monkeypatch, Response(b"{}", ETag='"v1"'))
    api.read(PATH)
    assert opener.requests[0].get_header("If-none-match") is None


@pytest.mark.parametrize("error", [
    _error(403, x_ratelimit_remaining="0", x_ratelimit_limit="1000", x_ratelimit_used="1000", x_ratelimit_resource="core",
           x_ratelimit_reset="9999999999"),
    _error(429, retry_after="60"),
    _error(403, retry_after="60"),
])
def test_limite_de_taxa_e_uma_recusa_distinta_e_nao_repete_a_leitura(monkeypatch, error):
    api, opener = _api(monkeypatch, error, Response(b"{}"))
    with pytest.raises(ValueError, match="github=rate_limited"):
        api.read(PATH)
    assert len(opener.requests) == 1


def test_recusa_de_limite_registra_uma_linha_so_com_numeros_sem_token_nem_url(monkeypatch, capsys):
    api, _ = _api(monkeypatch, _error(403, x_ratelimit_remaining="0", x_ratelimit_limit="1000", x_ratelimit_used="1000",
                                      x_ratelimit_resource="core"))
    with pytest.raises(ValueError):
        api.read(PATH + "&secret=q")
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines == ["github=rate_limited limit=1000 remaining=0 used=1000 resource=core"]


def test_403_sem_cabecalhos_de_limite_continua_falha_comum(monkeypatch):
    api, _ = _api(monkeypatch, _error(403))
    with pytest.raises(ValueError, match="GitHub HTTP failure"):
        api.read(PATH)


def test_leitura_registra_os_numeros_de_limite_da_ultima_resposta(monkeypatch):
    api, _ = _api(monkeypatch, Response(b"{}", x_ratelimit_limit="5000", x_ratelimit_used="7", x_ratelimit_remaining="4993"))
    assert api.rate is None
    api.read(PATH)
    assert api.rate == {"limit": 5000, "used": 7, "remaining": 4993}


def test_304_tambem_atualiza_os_numeros_de_limite(monkeypatch):
    api, _ = _api(monkeypatch, Response(b"{}", ETag='"v1"', x_ratelimit_limit="5000", x_ratelimit_used="7", x_ratelimit_remaining="4993"),
                  _error(304, ETag='"v1"', x_ratelimit_limit="5000", x_ratelimit_used="7", x_ratelimit_remaining="4993"))
    api.read_conditional(PATH)
    api.rate = None
    api.read_conditional(PATH)
    assert api.rate == {"limit": 5000, "used": 7, "remaining": 4993}


def test_resposta_sem_cabecalhos_de_limite_deixa_o_registro_vazio(monkeypatch):
    api, _ = _api(monkeypatch, Response(b"{}"))
    api.read(PATH)
    assert api.rate is None


def test_leitura_seguinte_substitui_os_numeros_de_limite_sem_zerar_o_registro(monkeypatch):
    api, _ = _api(monkeypatch, Response(b"{}", x_ratelimit_limit="5000", x_ratelimit_used="7", x_ratelimit_remaining="4993"),
                  Response(b"{}", x_ratelimit_limit="5000", x_ratelimit_used="9", x_ratelimit_remaining="4991"))
    api.read(PATH)
    api.read(PATH)
    assert api.rate == {"limit": 5000, "used": 9, "remaining": 4991}


@pytest.mark.parametrize("error,message", [
    (_error(403, x_ratelimit_remaining="0", x_ratelimit_limit="5000", x_ratelimit_used="5000", x_ratelimit_resource="core"),
     "github=rate_limited"),
    (_error(500), "GitHub HTTP failure"),
    (_error(401), "GitHub HTTP failure"),
    (_error(404), "GitHub HTTP failure"),
])
def test_erro_que_nao_e_304_com_corpo_em_cache_falha_fechado(monkeypatch, error, message):
    api, opener = _api(monkeypatch, Response(b'{"a": 1}', ETag='"v1"'), error, Response(b'{"a": 1}'))
    assert api.read_conditional(PATH) == {"a": 1}
    with pytest.raises(ValueError, match=message):
        api.read_conditional(PATH)
    assert len(opener.requests) == 2


def test_304_com_data_fora_da_tolerancia_e_recusado(monkeypatch):
    stale = _error(304, ETag='"v1"')
    stale.headers.replace_header("Date", formatdate(1_000_000_000, usegmt=True))
    api, _ = _api(monkeypatch, Response(b"{}", ETag='"v1"'), stale)
    api.read_conditional(PATH)
    with pytest.raises(ValueError, match="GitHub time uncertainty"):
        api.read_conditional(PATH)


def test_304_sem_data_e_recusado(monkeypatch):
    undated = _error(304, ETag='"v1"')
    del undated.headers["Date"]
    api, _ = _api(monkeypatch, Response(b"{}", ETag='"v1"'), undated)
    api.read_conditional(PATH)
    with pytest.raises(ValueError, match="authenticated Date missing"):
        api.read_conditional(PATH)


def test_304_dentro_da_tolerancia_continua_devolvendo_o_corpo_em_cache(monkeypatch):
    api, _ = _api(monkeypatch, Response(b'{"a": 1}', ETag='"v1"'), _error(304, ETag='"v1"'))
    api.read_conditional(PATH)
    sample = api.sample
    assert api.read_conditional(PATH) == {"a": 1}
    assert api.sample != sample
