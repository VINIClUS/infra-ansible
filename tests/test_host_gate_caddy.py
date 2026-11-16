"""Caddy proxy effect of the host gate; every OS, Docker and HTTP endpoint is a fixture."""

import pytest
from test_personal_platform_dispatcher import runtime

CADDY_KEYS = (
    "caddyfile_path",
    "caddy_container",
    "proxy_network",
    "caddy_ip",
    "previous_caddyfile_sha256",
    "previous_caddy_upstream",
)


def caddy_config(g, **overrides):
    config = {
        "slot": "green",
        "previous_slot": "blue",
        "port": 18081,
        "public_hostname": "api.example.test",
        "tunnel_health_url": "https://api.example.test/health/ready",
        "readiness_sha256": g.sha(b"auth/AWS-ready"),
        "proxy": "caddy",
        "caddyfile_path": "/srv/example/Caddyfile",
        "caddy_container": "example-caddy",
        "proxy_network": "example-proxy",
        "caddy_ip": "10.241.73.10",
        "previous_caddyfile_sha256": g.sha(b"previous"),
        "previous_caddy_upstream": "central-api:8000",
    }
    config.update(overrides)
    return config


@pytest.mark.parametrize("proxy", ["haproxy", "Caddy", "", None, 1, ["caddy"]])
def test_recusa_seletor_proxy_invalido_antes_de_qualquer_efeito(tmp_path, proxy):
    g = runtime()
    config = caddy_config(g, proxy=proxy)
    with pytest.raises(ValueError, match="proxy selector"):
        g.HostDriver(None, None, config, tmp_path)


@pytest.mark.parametrize("missing", CADDY_KEYS)
def test_recusa_proxy_caddy_sem_chave_obrigatoria(tmp_path, missing):
    g = runtime()
    config = caddy_config(g)
    del config[missing]
    with pytest.raises(ValueError, match="caddy config keys"):
        g.HostDriver(None, None, config, tmp_path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"caddyfile_path": "relative/Caddyfile"},
        {"caddy_ip": "not-an-ip"},
        {"caddy_ip": "fd00::10"},
        {"previous_caddyfile_sha256": "abc"},
        {"previous_caddy_upstream": "other-api:8000"},
        {"caddy_container": "bad name; rm"},
        {"proxy_network": ""},
    ],
)
def test_recusa_proxy_caddy_com_valor_malformado(tmp_path, overrides):
    g = runtime()
    config = caddy_config(g, **overrides)
    with pytest.raises(ValueError, match="caddy config keys"):
        g.HostDriver(None, None, config, tmp_path)


def test_aceita_proxy_caddy_sem_checkpoint_nginx(tmp_path):
    g = runtime()
    config = caddy_config(g)
    assert "previous_nginx_sha256" not in config
    g.HostDriver(None, None, config, tmp_path)


def test_proxy_ausente_ou_nginx_mantem_o_ramo_nginx(tmp_path):
    g = runtime()
    config = caddy_config(g, proxy="nginx")
    g.HostDriver(None, None, config, tmp_path)
    del config["proxy"]
    g.HostDriver(None, None, config, tmp_path)


HOSTNAME = "api.example.test"
CANDIDATE_UPSTREAM = "cnesdata-green-api-1:8000"
IMPORT_PREVIOUS = b"import agent_upstream central-api:8000"
IMPORT_CANDIDATE = b"import agent_upstream " + CANDIDATE_UPSTREAM.encode()

CADDYFILE = b"""# shared edge for two sites } with a stray brace in a comment {
{
\temail ops@example.test
}

(agent_upstream) {
\t# {args[0]} is the upstream; this } must not close the snippet
\treverse_proxy {args[0]} {
\t\theader_up Host {host}
\t}
}

# } outside any block
api.example.test {
\t# route to the API } still inside the block
\thandle /health {
\t\trespond "ok}"
\t}
\thandle {
\t\troute {
\t\t\timport agent_upstream central-api:8000
\t\t}
\t}
}

dev.example.test {
\thandle {
\t\timport agent_upstream dev-central-api:8000
\t}
}

www.example.test {
\troot * /srv/www
\tfile_server
}
"""


def render(g, previous=CADDYFILE, **overrides):
    arguments = {
        "hostname": HOSTNAME,
        "previous_upstream": "central-api:8000",
        "upstream": CANDIDATE_UPSTREAM,
    }
    arguments.update(overrides)
    return g.render_caddy(
        previous,
        arguments["hostname"],
        arguments["previous_upstream"],
        arguments["upstream"],
    )


def test_render_troca_so_o_upstream_do_bloco_do_hostname():
    g = runtime()
    assert IMPORT_PREVIOUS in CADDYFILE and CADDYFILE.count(IMPORT_PREVIOUS) == 1
    rendered = render(g)
    assert rendered == CADDYFILE.replace(IMPORT_PREVIOUS, IMPORT_CANDIDATE)


def test_render_mantem_identicos_os_bytes_dos_outros_sites():
    g = runtime()
    rendered = render(g)
    start = CADDYFILE.index(b"api.example.test {")
    end = CADDYFILE.index(b"dev.example.test {")
    assert rendered[:start] == CADDYFILE[:start]
    assert rendered[end - (len(CADDYFILE) - len(rendered)) :] == CADDYFILE[end:]
    assert b"dev-central-api:8000" in rendered


def test_render_nao_troca_upstream_que_contem_o_anterior_como_substring():
    g = runtime()
    previous = CADDYFILE.replace(
        b"\t\t\timport agent_upstream central-api:8000\n",
        b"\t\t\timport agent_upstream central-api:8000\n"
        b"\t\t\t# dev-central-api:8000 stays\n"
        b"\t\t\trespond /dev dev-central-api:8000\n",
    )
    rendered = render(g, previous)
    assert rendered.count(b"dev-central-api:8000") == 3
    assert rendered.count(IMPORT_CANDIDATE) == 1


def test_render_ignora_ocorrencia_do_upstream_em_comentario():
    g = runtime()
    previous = CADDYFILE.replace(
        b"\t# route to the API } still inside the block\n",
        b"\t# was central-api:8000 before the cutover\n",
    )
    rendered = render(g, previous)
    assert b"# was central-api:8000 before the cutover" in rendered
    assert rendered.count(IMPORT_CANDIDATE) == 1


def test_render_acha_o_fim_do_bloco_por_profundidade_com_dois_niveis():
    g = runtime()
    nested = b"""api.example.test {
\thandle /a {
\t\troute {
\t\t\trespond "a"
\t\t}
\t}
\thandle {
\t\troute {
\t\t\trespond "b"
\t\t}
\t}
\timport agent_upstream central-api:8000
}
"""
    assert render(g, nested) == nested.replace(IMPORT_PREVIOUS, IMPORT_CANDIDATE)


def test_render_ignora_chaves_em_comentario_e_em_string():
    g = runtime()
    tricky = b"""# } before
api.example.test {
\t# } inside { comment
\trespond "}{" 200
\thandle {
\t\t# }}}
\t\timport agent_upstream central-api:8000
\t}
}
# } after
other.example.test {
\trespond "x"
}
"""
    assert render(g, tricky) == tricky.replace(IMPORT_PREVIOUS, IMPORT_CANDIDATE)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw.replace(b"api.example.test {", b"api.example.test:443 {"),
        lambda raw: raw.replace(b"api.example.test {", b"x.api.example.test {"),
        lambda raw: raw + raw[raw.index(b"api.example.test {") :],
        lambda raw: raw.replace(IMPORT_PREVIOUS, b"respond ok"),
        lambda raw: raw.replace(
            IMPORT_PREVIOUS, IMPORT_PREVIOUS + b"\n\t\t\t" + IMPORT_PREVIOUS
        ),
        lambda raw: raw.replace(IMPORT_PREVIOUS, b"# " + IMPORT_PREVIOUS),
    ],
    ids=[
        "bloco-ausente-porta",
        "bloco-ausente-prefixo",
        "bloco-duplicado",
        "token-ausente",
        "token-duplicado",
        "token-so-em-comentario",
    ],
)
def test_render_recusa_bloco_ou_token_fora_de_uma_ocorrencia(mutation):
    g = runtime()
    with pytest.raises(ValueError, match="caddy block|caddy upstream token"):
        render(g, mutation(CADDYFILE))


@pytest.mark.parametrize(
    "overrides",
    [
        {"previous_upstream": "other-api:8000"},
        {"previous_upstream": "dev-central-api:8000"},
        {"previous_upstream": "central-api:9000"},
        {"upstream": "central-api:8000"},
        {"upstream": "cnesdata-green-api-1:8000", "previous_upstream": (
            "cnesdata-green-api-1:8000"
        )},
        {"upstream": "evil.example.test:8000"},
        {"hostname": "API.example.test"},
        {"hostname": "api.example.test {"},
    ],
)
def test_render_recusa_upstream_ou_hostname_invalido(overrides):
    g = runtime()
    with pytest.raises(ValueError, match="caddy upstream|caddy hostname"):
        render(g, **overrides)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw + b"}\n",
        lambda raw: raw + b"extra.example.test {\n",
        lambda raw: raw.replace(b"\t\t}\n\t}\n}\n\ndev", b"\t}\n}\n\ndev"),
        lambda raw: raw.replace(b'respond "ok}"', b'respond "ok}'),
        lambda raw: raw + b"\xff\xfe",
    ],
    ids=["fecha-demais", "abre-demais", "fecha-de-menos", "string-aberta", "nao-utf8"],
)
def test_render_recusa_chaves_desbalanceadas(mutation):
    g = runtime()
    with pytest.raises(ValueError, match="caddyfile braces|caddyfile encoding"):
        render(g, mutation(CADDYFILE))
