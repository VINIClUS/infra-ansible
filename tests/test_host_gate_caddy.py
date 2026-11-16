"""Caddy proxy effect of the host gate; every OS, Docker and HTTP endpoint is a fixture."""

import copy
import json
import types

import pytest
from test_personal_platform_deployer import candidate_container
from test_personal_platform_dispatcher import H, runtime
from test_personal_platform_lease import owner

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


DOCKER = "/usr/bin/docker"
CADDY = "example-caddy"
NETWORK = "example-proxy"
CADDY_IP = "10.241.73.10"
CONTAINER_PATH = "/etc/caddy/Caddyfile"
TEMP_PREFIX = "/etc/caddy/.candidate-"
EXEC_VERBS = {
    "validate": "validate",
    "rm": "remove-temp",
    "cat": "readback",
    "reload": "reload",
    "sh": "write-temp",
}


def exec_arguments(argv):
    rest = argv[4:] if argv[2] == "-i" else argv[3:]
    return rest[1:] if rest[0] == "caddy" else rest


def label(argv):
    if argv[0] == "health":
        return ("tunnel" if argv[1].startswith("https") else "local") + "-health"
    if argv[1] == "network":
        return argv[2]
    if argv[1] == "compose":
        return "pull" if "pull" in argv else "up" if "up" in argv else "config"
    if argv[1] == "exec":
        return EXEC_VERBS[exec_arguments(argv)[0]]
    return argv[1]


class World:
    """Synthetic Docker daemon plus the bind-mounted Caddyfile seen by the container."""

    def __init__(self, live, connected_ip=None, on_command=None):
        self.live, self.connected_ip = live, connected_ip
        self.on_command = on_command
        self.commands, self.stdin, self.temp = [], {}, {}
        self.seen_by_container = None
        self.at_validate = None
        self.prior_ids = b"aabbccddeeff\n"
        self.log = None
        self.fail_validate = False

    def labels(self):
        return [label(argv) for argv in self.commands]

    def argv_of(self, name):
        return [argv for argv in self.commands if label(argv) == name]

    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def open(self, url, *_a, **_kw):
        self.commands.append(["health", url])
        if self.on_command:
            self.on_command(self, ["health", url])
        return self

    def read(self, _):
        return b"auth/AWS-ready"

    def container_inspect(self):
        networks = {}
        if self.connected_ip:
            networks[NETWORK] = {"IPAddress": self.connected_ip}
        mount = {"Type": "bind", "Source": str(self.live), "Destination": CONTAINER_PATH}
        return [
            {
                "State": {"Running": True},
                "Mounts": [mount],
                "NetworkSettings": {"Networks": networks},
            }
        ]

    def exec_caddy(self, argv, stdin):
        rest = exec_arguments(argv)
        if rest[0] == "sh":
            self.temp[rest[-1]] = stdin
        elif rest[0] == "validate":
            self.at_validate = self.live.read_bytes()
            if self.fail_validate or b"INVALID" in self.temp[rest[2]]:
                raise ValueError("caddy adapt failed")
        elif rest[0] == "rm":
            self.temp.pop(rest[2], None)
        elif rest[0] == "cat":
            if self.seen_by_container is not None:
                return self.seen_by_container
            return self.live.read_bytes()
        return b""

    def network(self, argv):
        if argv[2] == "inspect":
            subnet = {"Subnet": "10.241.73.0/24", "Gateway": "10.241.73.1"}
            return json.dumps([{"IPAM": {"Config": [subnet]}}]).encode()
        if argv[2] == "connect":
            self.connected_ip = argv[4]
        if argv[2] == "disconnect":
            self.connected_ip = None
        return b""

    def process(self, argv, guard, **kwargs):
        guard()
        self.commands.append(argv)
        if self.log:
            with self.log.open("a") as file:
                file.write(label(argv) + "\n")
        if self.on_command:
            self.on_command(self, argv)
        self.clock.advance(3)
        guard()
        candidate = candidate_container(argv, "cnesdata-green")
        if candidate is not None:
            return candidate
        if "--format" in argv:
            return json.dumps(self.normalized).encode()
        if argv[1:3] == ["image", "inspect"]:
            image = {"RepoDigests": [self.image], "Os": "linux"}
            return json.dumps([{**image, "Architecture": "amd64"}]).encode()
        if argv[1:3] == ["inspect", CADDY]:
            return json.dumps(self.container_inspect()).encode()
        if argv[1] == "network":
            return self.network(argv)
        if argv[1] == "exec":
            return self.exec_caddy(argv, kwargs.get("stdin"))
        if argv[1] == "ps":
            return self.prior_ids
        if argv[1] == "inspect":
            return b'[{"State":{"Running":false}}]'
        return b""


def compose_config(image):
    service = {
        "image": image,
        "ports": [{"host_ip": "127.0.0.1", "published": "18081", "target": 8000}],
        "networks": {"cnesdata": {}},
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": "512m",
        "cpus": "0.5",
        "pids_limit": 128,
        "logging": {
            "driver": "json-file",
            "options": {"max-size": "10m", "max-file": "3"},
        },
        "healthcheck": {"test": ["CMD", "true"]},
    }
    return {
        "services": {"api": service},
        "networks": {"cnesdata": {"name": "cnesdata"}},
    }


def build(tmp_path, monkeypatch, *, caddyfile=CADDYFILE, connected_ip=None, **extra):
    from test_personal_platform_dispatcher import closed_ready_fixture

    g, clock, gov, api, *_ = closed_ready_fixture()
    admission = g.admit_physical_action(gov["binding"], gov, api, clock)
    lease = g.HostLease(tmp_path / "host", clock)
    token, snapshot = lease.acquire(owner(), H)
    binding = copy.deepcopy(gov["binding"])
    binding["lease_owner_sha256"] = g.sha(token)
    host = g.Operation(lease, token, snapshot, binding, {"fixture": b"host"})
    host.bind_closed_ready(admission)
    window = admission.window(clock)
    live = tmp_path / "edge" / "Caddyfile"
    live.parent.mkdir()
    live.write_bytes(caddyfile)
    live.chmod(0o644)
    config = caddy_config(
        g,
        caddyfile_path=str(live),
        caddy_container=CADDY,
        proxy_network=NETWORK,
        caddy_ip=CADDY_IP,
        previous_caddyfile_sha256=g.sha(caddyfile),
    )
    world = World(live, connected_ip, extra.pop("on_command", None))
    world.clock, world.image = clock, binding["api_image"]
    world.normalized = compose_config(binding["api_image"])
    monkeypatch.setattr(g, "supervise", world.process)
    monkeypatch.setattr(g.urllib.request, "build_opener", lambda *_: world)
    config.update(extra)
    driver = g.HostDriver(host, g.Watchdog(host, window), config, tmp_path)
    return types.SimpleNamespace(
        g=g,
        clock=clock,
        host=host,
        window=window,
        driver=driver,
        world=world,
        live=live,
        binding=binding,
    )


def candidate_bytes(g):
    return g.render_caddy(
        CADDYFILE, HOSTNAME, "central-api:8000", CANDIDATE_UPSTREAM
    )


def temp_name(g, data):
    return TEMP_PREFIX + g.sha(data)[:16] + ".caddyfile"


def exec_argv(*rest, interactive=False):
    head = [DOCKER, "exec"] + (["-i"] if interactive else []) + [CADDY]
    return head + list(rest)


def dispatches(host):
    return {item["kind"]: item["state"] for item in host.record["dispatches"]}


def test_switch_completo_na_ordem_da_decisao_sem_efeito_nginx(tmp_path, monkeypatch):
    f = build(tmp_path, monkeypatch)
    g, world = f.g, f.world
    inode = f.live.stat().st_ino
    f.driver.run()
    candidate = candidate_bytes(g)
    temp = temp_name(g, candidate)
    labels = world.labels()
    switch = labels[labels.index("connect") :]
    assert switch[:6] == [
        "connect",
        "write-temp",
        "validate",
        "remove-temp",
        "readback",
        "reload",
    ]
    assert switch[6] == "tunnel-health"
    assert labels.index("pull") < labels.index("up") < labels.index("connect")
    assert world.argv_of("connect") == [
        [DOCKER, "network", "connect", "--ip", CADDY_IP, NETWORK, CADDY]
    ]
    assert world.argv_of("write-temp") == [
        exec_argv("sh", "-c", 'cat > "$1"', "sh", temp, interactive=True)
    ]
    assert world.argv_of("validate") == [
        exec_argv("caddy", "validate", "--config", temp, "--adapter", "caddyfile")
    ]
    assert world.argv_of("remove-temp") == [exec_argv("rm", "-f", temp)]
    assert world.argv_of("readback") == [exec_argv("cat", CONTAINER_PATH)]
    assert world.argv_of("reload") == [
        exec_argv("caddy", "reload", "--config", CONTAINER_PATH, "--adapter", "caddyfile")
    ]
    assert world.temp == {}
    assert world.at_validate == CADDYFILE
    assert f.live.read_bytes() == candidate
    assert f.live.stat().st_ino == inode
    assert not any("nginx" in part for argv in world.commands for part in argv)
    assert dispatches(f.host) == {
        "pull": "EFFECT_CONFIRMED",
        "start-candidate": "EFFECT_CONFIRMED",
        "caddy-switch": "EFFECT_CONFIRMED",
        "stop-prior": "EFFECT_CONFIRMED",
    }
    assert f.host.record["effect_possible"] is False
    kept = g.read_private(f.host.directory / "previous-Caddyfile")
    assert kept == CADDYFILE


def test_switch_caddy_selado_e_aceito_pelo_receipt(tmp_path, monkeypatch):
    f = build(tmp_path, monkeypatch)
    f.driver.run()
    response = f.host.seal(H, f.window, f.driver.processes)
    receipt = f.g.accept_response(
        response,
        binding=f.binding,
        channel_nonce=H,
        now=f.clock.t,
        fixed_deadline=2460,
    )["receipt"]
    assert receipt["result"] == "accepted" and receipt["reopen_verified_at"] is None


def refuses_before_any_effect(f, reason):
    with pytest.raises(ValueError, match=reason):
        f.driver.run()
    labels = f.world.labels()
    assert not {"pull", "up", "connect", "write-temp", "reload"} & set(labels)
    assert f.host.record["dispatches"] == []
    assert f.host.record["effect_possible"] is False


def test_recusa_checkpoint_divergente_antes_do_pull(tmp_path, monkeypatch):
    f = build(tmp_path, monkeypatch)
    f.live.write_bytes(CADDYFILE + b"# edited by hand\n")
    refuses_before_any_effect(f, "previous caddyfile exact checkpoint")


def test_recusa_render_sem_bloco_antes_do_pull(tmp_path, monkeypatch):
    mutated = CADDYFILE.replace(b"api.example.test {", b"api.example.test:443 {")
    f = build(tmp_path, monkeypatch, caddyfile=mutated)
    refuses_before_any_effect(f, "caddy block")


def test_recusa_ja_conectado_com_outro_ip_antes_do_pull(tmp_path, monkeypatch):
    f = build(tmp_path, monkeypatch, connected_ip="10.241.73.99")
    refuses_before_any_effect(f, "caddy already connected")


def test_recusa_ip_fora_da_sub_rede_antes_do_pull(tmp_path, monkeypatch):
    f = build(tmp_path, monkeypatch, caddy_ip="10.241.74.10")
    refuses_before_any_effect(f, "caddy ip subnet")


def test_recusa_arquivo_que_nao_e_o_mount_do_container(tmp_path, monkeypatch):
    other = tmp_path / "other-Caddyfile"
    other.write_bytes(CADDYFILE)
    f = build(tmp_path, monkeypatch, caddyfile_path=str(other))
    refuses_before_any_effect(f, "caddy mount")


def test_ja_conectado_com_o_mesmo_ip_nao_reconecta(tmp_path, monkeypatch):
    f = build(tmp_path, monkeypatch, connected_ip=CADDY_IP)
    f.driver.run()
    assert "connect" not in f.world.labels()
    assert dispatches(f.host)["caddy-switch"] == "EFFECT_CONFIRMED"


def assert_unknown_switch(f):
    assert dispatches(f.host)["caddy-switch"] == "OUTCOME_UNKNOWN"
    assert f.host.record["effect_possible"] is True
    assert f.host.record["state"] == "RECOVERY_REQUIRED"
    assert "restore-previous" not in dispatches(f.host)
    kept = f.g.read_private(f.host.directory / "previous-Caddyfile")
    assert f.g.sha(kept) == f.driver.config["previous_caddyfile_sha256"]


def test_validate_que_falha_nao_escreve_no_arquivo_vivo(tmp_path, monkeypatch):
    f = build(tmp_path, monkeypatch, caddyfile=CADDYFILE + b"# INVALID\n")
    with pytest.raises(ValueError, match="caddy adapt failed"):
        f.driver.run()
    labels = f.world.labels()
    assert labels[-2:] == ["validate", "remove-temp"]
    assert not {"readback", "reload"} & set(labels)
    assert f.live.read_bytes() == CADDYFILE + b"# INVALID\n"
    assert f.world.temp == {}
    assert_unknown_switch(f)


def test_troca_de_inode_recusa_sem_escrever(tmp_path, monkeypatch):
    swapped = b"# replaced by another process\n"

    def swap(world, argv):
        if label(argv) == "validate":
            fresh = world.live.with_name("Caddyfile.new")
            fresh.write_bytes(swapped)
            fresh.replace(world.live)

    f = build(tmp_path, monkeypatch, on_command=swap)
    with pytest.raises(ValueError, match="caddyfile inode changed"):
        f.driver.run()
    assert f.live.read_bytes() == swapped
    assert not {"readback", "reload"} & set(f.world.labels())
    assert_unknown_switch(f)


def test_sha_visto_de_dentro_do_container_divergente_recusa_sem_reload(
    tmp_path, monkeypatch
):
    f = build(tmp_path, monkeypatch)
    f.world.seen_by_container = CADDYFILE
    with pytest.raises(ValueError, match="caddy container readback"):
        f.driver.run()
    assert "reload" not in f.world.labels()
    assert f.live.read_bytes() == candidate_bytes(f.g)
    assert_unknown_switch(f)


@pytest.mark.parametrize(
    ("point", "reloads"),
    [("connect", 0), ("write-temp", 0), ("readback", 0), ("reload", 1), ("tunnel-health", 1)],
)
def test_falha_entre_before_send_e_outcome_deixa_outcome_unknown(
    tmp_path, monkeypatch, point, reloads
):
    def fault(world, argv):
        if label(argv) == point:
            raise TimeoutError("synthetic lost response")

    f = build(tmp_path, monkeypatch, on_command=fault)
    with pytest.raises(TimeoutError):
        f.driver.run()
    labels = f.world.labels()
    assert labels.count("reload") == reloads
    assert "disconnect" not in labels
    assert_unknown_switch(f)


def test_before_send_antecede_o_primeiro_efeito_do_switch(tmp_path, monkeypatch):
    seen = {}

    def snapshot(world, argv):
        if label(argv) in {"connect", "write-temp", "reload"}:
            seen.setdefault(label(argv), dispatches(f.host).get("caddy-switch"))

    f = build(tmp_path, monkeypatch, on_command=snapshot)
    f.driver.run()
    assert seen == dict.fromkeys(("connect", "write-temp", "reload"), "SEND_PENDING")


TWO_PRIORS = b"aabbccddeeff\nbbccddeeff00\n"
ROLLBACK_LABELS = [
    "write-temp",
    "validate",
    "remove-temp",
    "readback",
    "reload",
    "tunnel-health",
]


def failed_after_switch(tmp_path, monkeypatch, **kwargs):
    f = build(tmp_path, monkeypatch, **kwargs)
    f.world.prior_ids = TWO_PRIORS
    with pytest.raises(ValueError, match="prior container scope"):
        f.driver.run()
    assert f.host.record["effect_possible"] is False
    assert f.live.read_bytes() == candidate_bytes(f.g)
    return f


@pytest.mark.parametrize("connected_ip", [None, CADDY_IP])
def test_rollback_restaura_o_backup_conferido_e_desconecta_so_se_conectou(
    tmp_path, monkeypatch, connected_ip
):
    f = failed_after_switch(tmp_path, monkeypatch, connected_ip=connected_ip)
    inode = f.live.stat().st_ino
    before = len(f.world.commands)
    f.driver.restore_previous()
    labels = [label(argv) for argv in f.world.commands[before:]]
    expected = ROLLBACK_LABELS + (["disconnect"] if connected_ip is None else [])
    assert labels == expected
    assert f.live.read_bytes() == CADDYFILE and f.live.stat().st_ino == inode
    assert f.world.argv_of("disconnect") == (
        [[DOCKER, "network", "disconnect", NETWORK, CADDY]] if not connected_ip else []
    )
    assert f.world.temp == {}
    assert dispatches(f.host)["restore-previous"] == "EFFECT_CONFIRMED"
    assert f.host.record["state"] == "ROLLED_BACK"


def test_rollback_confere_o_sha_do_backup_antes_de_qualquer_efeito(
    tmp_path, monkeypatch
):
    f = failed_after_switch(tmp_path, monkeypatch)
    (f.host.directory / "previous-Caddyfile").write_bytes(b"tampered")
    before = len(f.world.commands)
    with pytest.raises(ValueError, match="rollback exact checkpoint"):
        f.driver.restore_previous()
    assert len(f.world.commands) == before
    assert "restore-previous" not in dispatches(f.host)
    assert f.live.read_bytes() == candidate_bytes(f.g)


def test_rollback_com_sha_divergente_dentro_do_container_nao_recarrega(
    tmp_path, monkeypatch
):
    f = failed_after_switch(tmp_path, monkeypatch)
    f.world.seen_by_container = candidate_bytes(f.g)
    reloads = len(f.world.argv_of("reload"))
    with pytest.raises(ValueError, match="caddy container readback"):
        f.driver.restore_previous()
    assert len(f.world.argv_of("reload")) == reloads
    assert "disconnect" not in f.world.labels()
    assert dispatches(f.host)["restore-previous"] == "OUTCOME_UNKNOWN"


def test_rollback_com_validate_que_falha_nao_escreve_no_arquivo_vivo(
    tmp_path, monkeypatch
):
    f = failed_after_switch(tmp_path, monkeypatch)
    f.world.fail_validate = True
    with pytest.raises(ValueError, match="caddy adapt failed"):
        f.driver.restore_previous()
    assert f.live.read_bytes() == candidate_bytes(f.g)
    assert f.world.labels()[-2:] == ["validate", "remove-temp"]


def test_rollback_recusa_troca_de_inode(tmp_path, monkeypatch):
    f = failed_after_switch(tmp_path, monkeypatch)
    fresh = f.live.with_name("Caddyfile.new")
    fresh.write_bytes(b"# replaced\n")
    fresh.replace(f.live)
    reloads = len(f.world.argv_of("reload"))
    with pytest.raises(ValueError, match="caddyfile inode changed"):
        f.driver.restore_previous()
    assert f.live.read_bytes() == b"# replaced\n"
    assert len(f.world.argv_of("reload")) == reloads


def test_rollback_antes_do_switch_nao_desconecta_rede_que_nao_conectou(
    tmp_path, monkeypatch
):
    def gone(world, argv):
        if "status=running" in argv:
            raise ValueError("candidate container gone")

    f = build(tmp_path, monkeypatch, on_command=gone)
    with pytest.raises(ValueError, match="candidate container gone"):
        f.driver.run()
    assert f.host.record["effect_possible"] is False
    f.driver.restore_previous()
    assert "disconnect" not in f.world.labels()
    assert "connect" not in f.world.labels()
    assert f.live.read_bytes() == CADDYFILE


def test_rollback_recusa_efeito_incerto(tmp_path, monkeypatch):
    def fault(world, argv):
        if label(argv) == "reload":
            raise TimeoutError("synthetic lost response")

    f = build(tmp_path, monkeypatch, on_command=fault)
    with pytest.raises(TimeoutError):
        f.driver.run()
    with pytest.raises(ValueError, match="uncertain effect cannot auto-rollback"):
        f.driver.restore_previous()


def real_host(tmp_path, monkeypatch, *, fault):
    """Actual host_main over real kernel pipes; the Docker daemon is synthetic."""
    import base64
    import io
    import os
    from pathlib import Path

    from test_personal_platform_dispatcher import closed_ready_fixture

    g, clock, gov, api, *_ = closed_ready_fixture()
    root = g.private_directory(tmp_path / "host")
    runner = g.private_directory(tmp_path / "runner")
    staged = g.private_directory(tmp_path / "stage")
    live = tmp_path / "edge" / "Caddyfile"
    live.parent.mkdir()
    live.write_bytes(CADDYFILE)
    gov["host"] = caddy_config(
        g,
        caddyfile_path=str(live),
        caddy_container=CADDY,
        proxy_network=NETWORK,
        caddy_ip=CADDY_IP,
        previous_caddyfile_sha256=g.sha(CADDYFILE),
    )
    envelope = {"release_manifest": {"requested_action": "deploy"}}
    raw = g.canonical(envelope)
    gov["binding"]["original_bytes"]["envelope_sha256"] = g.sha(raw)
    gov["binding"]["original_bytes"]["archive_sha256"] = g.sha(b"original archive")
    gov["binding"]["api_image"] = "registry.example/api@sha256:" + H
    hostkey = b"synthetic public host key"
    fingerprint = base64.b64encode(g.hashlib.sha256(hostkey).digest()).decode()
    gov["binding"]["platform"]["host_key_fingerprint"] = "SHA256:" + fingerprint.rstrip("=")
    binary = b"synthetic cloudflared"
    gov["runner"] = {
        "ssh_hostname": "host.example.test",
        "known_hosts": "host.example.test ssh-ed25519 "
        + base64.b64encode(hostkey).decode(),
        "cloudflared": {"version": "2026.1.0", "sha256": g.sha(binary)},
        "ssm_parameters": {
            name: "arn:aws:ssm:us-east-2:111111111111:parameter/cnesdata/deploy/" + name
            for name in ("ssh-key", "cloudflare-client-id", "cloudflare-client-secret")
        },
    }
    for name in ("platform", "baseline"):
        original = ("original " + name).encode()
        g.durable(root / ("original-" + name + ".json"), original)
        gov["binding"]["original_bytes"][name + "_sha256"] = g.sha(original)
    admission = g.admit_physical_action(gov["binding"], gov, api, clock)
    request = g.Request(
        envelope, raw, b"original archive", bytearray(b"synthetic-token"), admission
    )
    monkeypatch.setattr(g, "ROOT", root)
    monkeypatch.setattr(g, "Clock", lambda: clock)
    monkeypatch.setattr(g.time, "time", lambda: clock.t)
    monkeypatch.setattr(g, "load_governance", lambda: gov)
    monkeypatch.setattr(g, "GitHub", lambda *_: api)
    monkeypatch.setattr(
        g, "authenticate_request", lambda *_: (copy.deepcopy(gov["binding"]), {})
    )
    monkeypatch.setattr(g, "verify_original_activation", lambda *_: None)
    monkeypatch.setattr(g, "verify_runtime_probes", lambda *_: None)
    monkeypatch.setattr(g, "stage_archive", lambda *_: staged)
    private_dir = g.private_directory
    monkeypatch.setattr(
        g,
        "private_directory",
        lambda p: (
            private_dir(staged)
            if str(p) == "/run/personal-platform/staging"
            else private_dir(p)
        ),
    )
    world = World(live, on_command=fault)
    world.clock, world.image = clock, gov["binding"]["api_image"]
    world.normalized = compose_config(world.image)
    world.log = tmp_path / "commands.log"
    monkeypatch.setattr(g, "supervise", world.process)
    monkeypatch.setattr(g.urllib.request, "build_opener", lambda *_: world)
    return types.SimpleNamespace(
        g=g,
        clock=clock,
        gov=gov,
        api=api,
        root=root,
        runner=runner,
        live=live,
        world=world,
        request=request,
        binary=binary,
        io=io,
        os=os,
        Path=Path,
    )


def ssh_process(f, tmp_path):
    g, clock, root, os = f.g, f.clock, f.root, f.os

    class SSHProcess:
        def __init__(self, argv, **kwargs):
            assert argv[0] == "/usr/bin/ssh"
            input_r, input_w = os.pipe()
            output_r, output_w = os.pipe()
            self.pid = os.fork()
            self.returncode = None
            if self.pid == 0:
                os.setsid()
                os.close(input_w)
                os.close(output_r)
                g.sys = types.SimpleNamespace(
                    stdin=types.SimpleNamespace(
                        buffer=os.fdopen(input_r, "rb", buffering=0)
                    ),
                    stdout=types.SimpleNamespace(
                        buffer=os.fdopen(output_w, "wb", buffering=0)
                    ),
                )
                os.environ["SSH_ORIGINAL_COMMAND"] = "deploy"
                try:
                    status = g.host_main()
                except BaseException:  # noqa: BLE001 -- the child endpoint must exit
                    import traceback

                    (root / "child-error.txt").write_text(traceback.format_exc())
                    status = 1
                (root / "child-clock").write_text(str(clock.t))
                os._exit(status)
            os.close(input_r)
            os.close(output_w)
            self.stdin = os.fdopen(input_w, "wb", buffering=0)
            self.stdout = os.fdopen(output_r, "rb", buffering=0)

        def wait(self, timeout=None):
            if self.returncode is None:
                _, status = os.waitpid(self.pid, 0)
                self.returncode = os.waitstatus_to_exitcode(status)
                returned = int((root / "child-clock").read_text())
                clock.advance(returned - clock.t)
            return self.returncode

        def poll(self):
            if self.returncode is None:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
                if pid:
                    self.returncode = os.waitstatus_to_exitcode(status)
            return self.returncode

    return SSHProcess


def execute_runner(f, monkeypatch, tmp_path):
    g = f.g

    class SSM:
        def get_parameter(self, Name, WithDecryption):
            return {
                "Parameter": {"ARN": Name, "Type": "SecureString", "Value": "synthetic"}
            }

    monkeypatch.setattr(g.subprocess, "Popen", ssh_process(f, tmp_path))
    monkeypatch.setattr(
        g.urllib.request,
        "urlopen",
        lambda *_a, **_kw: __import__("contextlib").closing(f.io.BytesIO(f.binary)),
    )
    monkeypatch.setattr(g, "runner_request", lambda *_: f.request)
    monkeypatch.setattr(g, "runner_clients", lambda _: (None, SSM()))
    monkeypatch.setattr(g, "runner_handoff", lambda *_: None)
    monkeypatch.setattr(
        g.sys, "stdin", types.SimpleNamespace(buffer=f.io.BytesIO(b"synthetic-token"))
    )
    monkeypatch.setenv("CNESDATA_HOST_GOVERNANCE", g.canonical(f.gov).decode())
    monkeypatch.setenv("RUNNER_TEMP", str(f.runner))
    monkeypatch.setenv("GITHUB_OUTPUT", str(f.runner / "outputs"))
    return g.runner_main("execute")


def final_record(f):
    g = f.g
    authority = g.host_json(g.read_private(f.root / "authority.json"))
    directory = f.root / "cnesdata" / authority["head"]["operation_id"]
    name = authority["head"]["record_sha256"] + ".json"
    return g.host_json(g.read_private(directory / name)), directory


def test_host_main_restaura_automaticamente_apos_falha_conhecida_pos_switch(
    tmp_path, monkeypatch
):
    def two_priors(world, argv):
        if argv[1:2] == ["ps"] and "-aq" in argv:
            world.prior_ids = TWO_PRIORS

    f = real_host(tmp_path, monkeypatch, fault=two_priors)
    assert execute_runner(f, monkeypatch, tmp_path) == 2
    record, directory = final_record(f)
    kinds = {d["kind"]: d["state"] for d in record["dispatches"]}
    assert record["state"] == "ROLLED_BACK"
    assert record["effect_possible"] is False
    assert kinds["caddy-switch"] == kinds["restore-previous"] == "EFFECT_CONFIRMED"
    assert f.live.read_bytes() == CADDYFILE
    log = (tmp_path / "commands.log").read_text().split()
    assert log[-1] == "disconnect" and log.count("reload") == 2
    kept = f.g.read_private(directory / "previous-Caddyfile")
    assert kept == CADDYFILE


def test_host_main_nao_restaura_efeito_incerto_do_switch(tmp_path, monkeypatch):
    def fault(world, argv):
        if label(argv) == "reload":
            raise TimeoutError("synthetic lost response")

    f = real_host(tmp_path, monkeypatch, fault=fault)
    with pytest.raises(ValueError, match="unknown outcome"):
        execute_runner(f, monkeypatch, tmp_path)
    record, directory = final_record(f)
    kinds = {d["kind"]: d["state"] for d in record["dispatches"]}
    assert record["state"] == "RECOVERY_REQUIRED"
    assert record["effect_possible"] is True
    assert kinds["caddy-switch"] == "OUTCOME_UNKNOWN"
    assert "restore-previous" not in kinds
    log = (tmp_path / "commands.log").read_text().split()
    assert log.count("reload") == 1 and "disconnect" not in log
    assert f.live.read_bytes() == candidate_bytes(f.g)
    kept = f.g.read_private(directory / "previous-Caddyfile")
    assert kept == CADDYFILE
