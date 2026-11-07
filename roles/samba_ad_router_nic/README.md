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
