# samba_ad_router_nic

Extensão QEMU dedicada, desabilitada por padrão (`enabled: false`, `apply: false`).
Exige `--limit` exato do nó PVE, tag única `samba_ad_router_nic`, request privado,
console Proxmox verificado ou canal independente PVE→QGA selecionado e comprovado,
e host SSH do roteador com chave/host key existentes.
O exemplo fictício está em `contracts/samba_ad/s1-router-nic-example.yml`.

Confere VMID/nó/nome/SMBIOS, digest, estado running, pending vazio e mapa completo
de NICs existentes. Somente adiciona o slot secundário declarado, MAC/bridge/MTU
exatos; não movimenta uplink ou altera outra NIC. A NIC do roteador tem firewall=0
porque o nftables do próprio roteador filtra tráfego roteado; não usar esta exceção
nos guests Samba. O programa recusa slot ocupado, MAC/bridge duplicados ou drift.

A rede persistente usa apenas `/etc/systemd/network/05-samba-ad-identity.network`,
com match por MAC e interface, endereço/MTU estáticos, sem gateway/DNS/DHCP/RA.
Exige systemd-networkd ativo e layout netplan existente. Não reescreve netplan,
cloud-init, arquivos de outras interfaces ou default routes. Recuperação técnica
preserva configs de rede em diretórios root-only fora do Git.

Antes da mudança arma timers independentes no PVE (`proxmox_change_guard`) e no
guest. Eles retiram somente a NIC/arquivo próprios com identidade/readback atual;
não restauram cegamente arquivos de outras interfaces. Timer pendente bloqueia
nova operação. Recovery cancela somente pending da NIC própria com valor exato;
pending alheio impede a reversão automática. Uma nova conexão SSH estrita, sem multiplexação, valida rota
padrão, MAC, IP e MTU; novo readback PVE valida NICs/pending antes de desarmar ambos. Falha mantém timers e instrução
do caminho de recuperação verificado; rescue tenta a mesma recuperação mínima.

Reexecução com NIC/arquivo idênticos verifica; estado parcial ou arquivo ocupado
falha fechado para recuperação. A política de zona é uma operação manual separada
pela role existente `network_router`, com `restricted: true`, preservando a política
completa das zonas antigas. SDN continua pela role `proxmox_sdn` existente.
Ver [runbook S1](../../docs/samba-ad-s1.md). Nada se aplica via main.

## Identidade prévia e reexecução

`router_state.py` captura interfaces, MACs, ifindices, devices/drivers, endereços e
rotas IPv4/IPv6 antes da alteração. Nome/MAC/endereço novos devem estar ausentes.
O snapshot original fica root-only em `/root/samba-ad-s1-network/before.json`,
sem substituição silenciosa. Baseline anterior bloqueia uma nova extensão até
revisão da recuperação; baseline ausente impede declarar uma reexecução verificada.

Após hotplug, a checagem precede `networkctl reconfigure`: MAC, PCI virtio e
ifindex novos, sem mudança de interfaces/endereço/rotas antigos. O executor repete
a checagem imediatamente antes do comando; dispositivo errado não é reconfigurado.
O mesmo `readback.yml` readonly por conexão nova serve add e verify e confere
IP/prefixo/MTU/MAC/link, rotas antigas e ausência de default route no novo device.
Drift falha sem reparo. Remoção PVE só termina com current=1 sem NIC, pending vazio
e ausência do tap efetivo no host; pending preserva falha/console, sem reboot.

Na round 2, toda reversão verifica novamente config ativa ausente, pending vazio
e tap ausente, mesmo se não houver delete nessa chamada. `changed` indica só a
mutação feita. Um tap residual ou erro de leitura continua falhando na repetição.
Verify exige também a rota conectada unicast kernel/link, na tabela main, para
o prefixo e device exatos. Rotas local/broadcast e endereço configurado não
substituem essa rota. Nenhum desses desvios é reparado silenciosamente.

## Recuperação de rede por PVE→QGA

`samba_ad_router_nic_qga_recovery: false` é uma opção separada, desabilitada por
padrão. Ela não define nem altera `samba_ad_router_nic_console_verified`. Selecionar
a opção exige inventário PVE com acesso de gerenciamento independente da rede
do guest e associação de host key já confiável. Antes de qualquer mutação, uma
conexão PVE nova, estrita e sem multiplexação executa `router_nic.py --plan
--qga-preflight`: revalida nó/VMID/nome/SMBIOS/digest/pending/running, exige o nó
local exato, faz `qm guest cmd VMID ping` e `qm guest exec VMID --timeout 10 --
/usr/bin/id -u`. A resposta deve ser concluída, íntegra, com exitcode=0 e uid=0.
Agente ausente, uid diferente, timeout ou identidade divergente interrompem antes
de arquivos/timers/hotplug. Não habilita agente, cria credenciais ou relaxa SSH.

Console verificado continua sendo alternativa. Se a opção QGA for selecionada,
a prova é exigida mesmo se console_verified também for true. O canal QGA depende
do PVE/QEMU e de kernel/userspace/agente vivos; não comprova console interativo,
bootloader ou recuperação de VM travada. Serve apenas à reversão técnica desta
mudança de rede. Os dois dead-man timers e todos os readbacks continuam obrigatórios.

Se a rede do guest impedir SSH, o operador pode, pelo mesmo PVE independente,
invocar o revert próprio já instalado pela role: `qm guest exec VMID --timeout 30
-- /bin/sh /root/samba-ad-s1-network/revert.sh`. Revalidar identidade e hashes antes;
o programa só remove arquivo/interface próprios. A reversão PVE usa o helper
com digest e deve provar NIC ativa/pending/tap ausentes. O rescue existente não
transforma falha SSH em sucesso automático. Reobservar endereços/rotas/política
antigos por QGA e provar SSH novo antes de desarmar proteção. Nenhuma destas
reversões foi executada pelos testes simulados.

A política completa `network_router` é uma etapa separada: além do nft, pode
alterar o override netplan, executar netplan generate/networkctl reload e conferir
ou alterar pacotes/sysctl/DNS/serviços. Revisar o footprint inteiro e a reversão
exata de cada delta; não autorizar apenas nft e executar a role inteira.
