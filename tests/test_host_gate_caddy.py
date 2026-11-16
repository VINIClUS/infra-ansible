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
