# samba_ad_router_nic

Extensão QEMU dedicada, desabilitada por padrão (`enabled: false`, `apply: false`).
Exige `--limit` exato do nó PVE, tag única `samba_ad_router_nic`, request privado,
console Proxmox verificado e host SSH do roteador com chave/host key existentes.
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
de console; rescue tenta a mesma recuperação mínima.

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
