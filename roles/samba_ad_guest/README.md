# samba_ad_guest

Lifecycle manual dedicado ao substrato Samba, independente de
`proxmox_lxc_guest`. Defaults `samba_ad_guest_enabled: false` e
`samba_ad_guest_apply: false`. Exige um request privado, `--limit` exato do nó
do template e somente `--tags samba_ad_guest`. Não entra no deploy de main.

A entrada `samba_ad_guest_request` segue o exemplo inerte
`contracts/samba_ad/s1-lab-example.yml`. Não carrega o manifesto S0 diretamente.
`apply: false` ou check mode faz somente leituras. Toda entrada vai por stdin;
a task tem `no_log` e não recebe segredos. Saída contém estado/contagem, e o
executável também retorna digest do guest para o operador privado.

O script stdlib `tools/samba_ad/guest.py` usa pvesh local no nó de origem e seu
proxy de cluster. Revalida quorum, nós, VMID/nome/MAC/IP (incluindo cloud-init),
capacidades conservadoras de RAM e storage em origem/destino (reserva >=2 GiB),
config/digest do template local, isolamento e ausência de devices/hooks extras
(incluindo passthrough/virtiofs). VMs fixam sockets=1 e balloon=0 para manter o
dimensionamento declarado.
Faz full clone local parado, remove features do clone LXC, configura endereço
estático e firewall, cresce somente o disco próprio e migra offline. Confere
identidade, storage e tamanho no destino antes do boot. Nunca altera templates.

A política por guest tem IN/OUT DROP, ipfilter-net0, macfilter e DHCP/NDP/RA
desativados. O primeiro boot mantém `link_down=1`; somente após readback das
cadeias/hook/drop/anti-spoof IPv4 e IPv6 do pve-firewall no nó destino conecta a
NIC. O backend legado PVE é exigido; outro backend falha fechado. Requer arping
no PVE, iptables-save/ip6tables-save e a confiança SSH estrita própria do cluster.
A role também exige cadeia restrita do roteador e hash da política persistente.

Reexecução requer `expected_digest` atual e configuração/firewall/power state
idênticos. `action: start` inicia explicitamente um clone próprio parado com digest
atual, revalida RAM/reserva no destino e mantém a NIC isolada até verificar firewall. Não adota recursos, não
reinicia guest e não corrige drift em silêncio.
Uma falha parcial fica isolada; consultar tarefas UPID e config antes de qualquer
recuperação. `action: absent` remove exclusivamente laboratório parado, com mesmo
marcador/hash, nome, VMID, tipo e digest atual, na origem ou destino declarados.
Não para guest automaticamente. Arquivos de firewall preexistentes bloqueiam criação.

Laboratório usa `scope: lab` e nomes sob `lab.ad.test`. `scope: production`
é recusado sem bundle operacional privado S2 completo, qualificado e vinculado
ao alvo, pin e auditoria de estado específicos; sem override booleano.
O consumidor é reutilizável; não há pin público preenchido ou escolha real.
VM Debian de laboratório usa o mesmo lifecycle para fallback; não cria outro LXC
quando a primeira prova protegida já falha. Consultar [runbook](../../docs/samba-ad-s1.md).

S2 acrescenta `action: stop`, exclusivamente lab, com identidade/digest atuais,
configuração própria conectada ou isolada, firewall próprio e pending vazio.
Shutdown limitado a 60 s sem forceStop; timeout não faz kill ou delete. Já parado
é no-op e check-mode só lê. `absent` confere firewall próprio e readback de VMID,
firewall e volumes; resíduos bloqueiam sucesso e nunca são apagados por glob.
Persistir laudo antes da limpeza. Ver [contrato S2](../../docs/samba-ad-s2.md).

## Readback após revisão S1 round 1

Antes de `start` e antes de conectar, a varredura repete nome/MAC/IP em config
ativa e desejada de todos os outros VMIDs, e ARP-DAD no segmento. Somente o próprio
VMID é excluído. DAD independe da ausência do arquivo firewall. `current=1`, pending
vazio e link efetivo no PVE são exigidos; pending não é sucesso nem motivo para
reiniciar guests. Uma falha deixa diagnóstico para recuperação por console.

O gate lê IPv4/IPv6, ipsets, bridge e hooks. Compara o caminho FORWARD/FWBR, a
ordem e todas as regras do guest com a matriz, os membros exatos dos dois ipsets,
MAC, accept-mark e netfilter da bridge. ACCEPT anterior, política antiga, set
amplo, hook divergente ou variante desconhecida falham fechados. Regras finais
DROP explícitas precedem helpers implícitos do PVE. Intervalos canônicos usam
hífen no contrato/nft e dois-pontos no PVE; o parser PVE instalado recusa erros
em regras e warnings de compile são fatais. Nenhuma liberação por fragmentos.

O roteador exige `samba_ad_guest_router_contract` (interface e matriz exata),
`samba_ad_guest_router_runtime_sha256` de artefato JSON carregado/revisado e o hash
persistente já existente. `router_guard.py --fingerprint` normaliza counters e
handles, mas não aprova o artefato. O gate compara runtime novo, matriz, hook inet
e jumps pela interface antes de LAN/ops; um hash correto de disco não o substitui.

## Revisão S1 round 2

O parent FWBR exige transferência por jump: goto para helper não é aceito sem
prova de terminação total, pois RETURN/fim poderia pular o binding próprio. Jump
para helper que só nega/loga/retorna permanece permitido. O parser conserva o
tipo de transferência e reconhece as formas nativas ICMP/multiport/mark e
assinaturas SHA1/base64 do PVE. Referências a chains não declaradas invalidam
a evidência, inclusive depois de DROP. Helpers alcançáveis continuam analisados;
a presença de ACCEPT neles não é ignorada por serem padrões do PVE.

As fixtures de teste são completas e sintéticas, com helpers e políticas de
host separados, e têm validação xtables em namespace local. Uma captura privada
readonly de baseline carregado comprova parsing, sem declarar probe pronto.
