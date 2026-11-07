# Samba AD — S1 manual, rede e substrato

Extensão code-only S2: `stop` lab explícito e cleanup/readbacks seguros; consumidor
de bundle privado auditado, sem pin público. [S2](samba-ad-s2.md) descreve a primeira
prova e os limites. Production segue recusado sem toda evidência específica;
este documento conserva abaixo o registro histórico de preparação S1.

S1 entrega código, exemplos inertes e testes simulados. Nesta sessão não foi
aplicada infraestrutura. S0 precisa ser alinhada com main antes de PRs/revisões
pela coordenação. Não há floresta, pacote Samba instalado ou DC final criado.
Backup é trabalho futuro separado após produção, sem recurso, reserva, fluxo,
segredo ou gate para homologação/produção nesta entrega.

## Interfaces e gates

- `playbooks/samba-ad-router-nic.yml` / tag `samba_ad_router_nic`: uma NIC QEMU e
  arquivo networkd próprio; defaults enabled/apply falsos e recuperação verificada
  por console ou PVE→QGA independente explicitamente selecionado.
- `playbooks/samba-ad-guest.yml` / tag `samba_ad_guest`: um clone por execução,
  operado do nó do template, em laboratório descartável. Defaults falsos.
- `tools/samba_ad/network_policy.py`: `expand(manifest, policy, collector)` devolve
  políticas por guest com IPs /32; `router_rules(manifest, policies, zones)` devolve
  somente pares que atravessam zonas. Mesmo-L2 é filtrado pelo PVE, não pelo roteador.
- `network_router_zones.<zone>.restricted: true`: jump antes das permissões amplas
  existentes, aceita somente forward_rules exatas e encerra com DROP; não serve DNS/DHCP.
- S0 continua `schema: 1`, `stage: S0`, inerte. São cinco identidades/cinco referências.
  Os requests S1 são arquivos separados fora de group_vars/host_vars. Nunca ativar
  manifesto S0 com extra-vars ou adicioná-lo ao deploy automático.

## Ordem de aplicação futura — ainda não executada

1. Coordenação alinha as bases com o merge S0 e a retirada de backup. CI e revisões
   novas devem avaliar o diff imutável antes da aplicação. Não aplicar este branch
   isolado enquanto S0/revisões estiverem pendentes.
2. Fazer readback vivo de versões/ajuda PVE (cluster heterogêneo), quorum, todos os
   configs/pending/tasks, templates e digests, firewall efetivo, storage e memória.
   Provar ausência de VMID/nome/MAC/IP, inclusive ipconfig/cloud-init, DHCP/vizinhos
   e ARP-DAD no segmento correto. Nenhum snapshot S0 vale como precondição atual.
3. Validar console ou o canal independente PVE→QGA de recuperação de rede e
   cópias técnicas root-only das configurações alteradas. QGA é opção separada
   `samba_ad_router_nic_qga_recovery: false`; quando selecionada, exige ping e
   exec uid=0 no VMID/nó exatos, por PVE autenticado com SSH estrito, antes de
   qualquer mutação. Não declara console interativo nem habilita agente.
   Revisar os comandos de recuperação antes da alteração; uma prova que exige
   escrita fica para a janela aprovada, sem fingir que foi executada no preflight.
   Nenhuma chave privada entra no Git.
4. Planejar a VNet de identidade e a rede descartável separada. Validar CIDR/tag/bridge
   e colisões ao vivo. Usar `proxmox_sdn` com mapa completo preservado, tag própria,
   limite exato, snapshot/dead-man/readback existentes. Não alterar a zona antiga,
   templates Packer ou redes de e-SUS/SIHA/outros projetos. Não alterar DHCP/DNS da LAN.
5. Com request privado de NIC e digest frescos, verificar com apply=false/check.
   Em execução explícita, adicionar só NIC/arquivo próprios do roteador, sob dois
   timers; readback por SSH nova antes de desarmar. `network_router` depois recebe
   todo o mapa antigo acrescido da zona identity restrita e regras /32. Revisar
   seu footprint completo: override netplan e handlers generate/reload, além de
   pacotes/sysctl/DNS/serviços; não executar a role inteira sob aprovação nft-only. Seu nft
   --check, timer e nova conexão continuam obrigatórios. Registrar hash persistente
   e readback efetivo da cadeia/jumps. Rede descartável começa sem uplink/serviços.
6. Preparar somente o primeiro probe LXC na rede descartável, com budget sequencial.
   Criar inicialmente parado (`boot: false`), full clone local, configuração estática,
   offline migrate e readback no destino. Capturar digest privado. Para iniciar, usar
   `action: start`, `boot: true` e o digest atual do clone parado; uma reexecução
   `present` não muda power state. A origem mantém piso vivo >=2 GiB sem alocar RAM do clone parado; o destino
   usa memória viva livre e máximos configurados dos running, desconta o request
   e mantém >=2 GiB. Stopped de terceiros não entram na soma, e dados desconhecidos
   falham fechados. O boot revalida a reserva de RAM no destino. Alternativamente declarar `boot: true` na criação após todos os gates;
   o primeiro boot será com link desconectado até verificar o firewall efetivo.
7. S2 executa a prova protegida via console/pct/agent na rede sem uplink. Se ACL/auditoria/
   isolamento falhar, registrar laudo e limpar somente probe próprio parado/digest
   exato; não criar segundo LXC. Usar template QEMU Debian para fallback descartável.
   Instalação de pacotes requer egress exato revisado de S2, sem regra Internet geral.
8. Testar permitidos/negados/counters no PVE e roteador, inclusive LAN/ops não admins,
   ambos sentidos e mesmo-L2; revalidar todas as zonas/interfaces/default routes antigas.
   Auditoria independente de estado pela coordenação. DCs finais permanecem recusados
   por S1; sua aceitação só será integrada após resultado S2 revisado.

Comandos de inspeção local (exemplos fictícios, sem aplicação):

```bash
python3 -m tools.samba_ad.contract contracts/samba_ad/example.yml
python3 -m pytest -q tests/test_samba_ad_contract.py tests/test_samba_ad_guest.py \
  tests/test_samba_ad_router.py tests/test_samba_ad_network_policy.py
ansible-playbook -i inventories/example/hosts.yml playbooks/samba-ad-guest.yml --syntax-check
ansible-playbook -i inventories/example/hosts.yml playbooks/samba-ad-router-nic.yml --syntax-check
```

No fluxo futuro o operador usará inventário privado, request privado por `-e @arquivo`
e flags de ativação explícitos, `--limit` de um nó e somente a tag do entrypoint.
Não colocar segredos em argumentos. O hash do request marca a propriedade; uma
mudança em recurso/template/política não pode adotar um clone anterior.

## Recuperação e limites

Clone/migração/config APIs não formam uma transação distribuída. Falha interrompe
sem retry de criação, shutdown ou resize de terceiros. Consultar UPID/pending/config
antes de recuperar; se necessário parar apenas o probe próprio, explicitamente,
por console e identidade verificada. `action: absent` exige laboratório parado,
marcador e digest atuais e alcança só origem/destino declarados. Falha depois do boot
mantém link_down quando o firewall não comprovou prontidão. Não destruir evidência S2.

O clone API não oferece digest atômico do template: há readback imediatamente antes
do clone e o template deve permanecer congelado durante a janela. Capacidade é
observação conservadora, não reserva transacional; readback por criação é obrigatório.
Backend nft PVE, Windows, outros devices/discos e produção são recusados neste escopo.
Testes locais não provam hotplug/firewall/migração em hosts reais; a aplicação e a
nova auditoria devem produzir essa evidência, com console verificado ou canal
PVE→QGA independente comprovado para reversão estreita da rede. QGA não recupera
VM/kernel/agente travados e não muda console_verified para true.

## Fontes

Context7 indisponível por cota mensal, conforme coordenação. Referências oficiais
consultadas nesta sessão, além dos contratos versionados e ajuda Ansible instalada:

- [API Proxmox VE](https://pve.proxmox.com/pve-docs/api-viewer/): clone full local,
  migrate online=0, digest em config/resize e pending/readback.
- [pct](https://pve.proxmox.com/pve-docs/pct.1.html) e
  [qm](https://pve.proxmox.com/pve-docs/qm.1.html).
- [Fonte oficial pve-firewall](https://github.com/proxmox/pve-firewall/blob/master/src/PVE/Firewall.pm):
  cadeias tap/veth, hooks FWBR, DROP e ipfilter/macfilter.
- [systemd.network](https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html):
  match por MAC, MTU, Address, DHCP/RA/link-local desabilitados.

## Gates corrigidos na revisão independente — round 1

A aplicação continua pendente. A preparação agora distingue config ativa
(`current=1`), desejada e pending; nenhum pending de link-up/delete produz sucesso.
Colisões e ARP-DAD são repetidos antes de start e link, excluindo só o VMID próprio.
O verificador PVE exige matriz, ordem/terminação, hooks FORWARD/FWBR, bridge e
ipsets exatos em IPv4/IPv6; formatos desconhecidos falham fechados. Intervalos
usam `:` apenas no PVE, com validação pelo parser instalado e warnings fatais.

Antes de executar o guest, revisar o artefato de `nft -j list ruleset` capturado
por conexão nova. O contrato do request inclui interface/matriz do roteador e
`samba_ad_guest_router_runtime_sha256`. Calcular o fingerprint localmente, sem
considerá-lo aprovação automática:

```bash
python3 tools/samba_ad/router_guard.py --fingerprint < /caminho/protegido/runtime-aprovado.json
```

Somente após revisão do artefato preencher o request inerte. O gate lê runtime
novo e exige fingerprint, matriz, hook e ambos os jumps pela interface antes das
permissões LAN/ops. Hash persistente em disco sozinho não prova regras carregadas.

A extensão do router inventaria e preserva o baseline original de interfaces,
endereços e rotas. MAC/PCI/ifindex são conferidos antes de reconfigure. Add e verify
compartilham a mesma checagem readonly por conexão nova; drift de IP, prefixo, MAC,
MTU, link e rotas falha sem reparo silencioso. O baseline protegido não é substituído.
A retirada efetiva do tap é conferida depois de delete, sem reboot para limpar pending.

Testes incluem snapshots adversos e o render nft em namespace local isolado, com
AST conferido. Isso não substitui prova nos hosts reais nem auditoria pós-apply.
