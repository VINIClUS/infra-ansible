# container_runtime

Instala o runtime de containers do Debian somente quando a capability e
explicitamente habilitada. O role nao cria usuarios, nao altera SSH ou firewall
e nao configura registros de imagens, proxies ou workloads.

## Contrato

```yaml
container_runtime_enabled: true
container_runtime_technical_user: vagrant
```

Quando habilitado, o host precisa ser Debian e o usuario tecnico precisa ja
existir; o role nunca cria contas. O role instala `docker.io`, `docker-compose`, `docker-buildx`,
`python3-venv`, `git`, `curl`, `ca-certificates` e `rsync`, habilita
`docker.service` e adiciona apenas o usuario declarado ao grupo `docker`.

O default e desabilitado para que inventories reais nao recebam Docker por
acidente.
