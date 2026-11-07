# Samba AD DC — contrato S0

Esta etapa entrega desenho, validação local e inventário privado inerte. Não
entrega provisionamento, floresta, PKI, firewall aplicado nem prontidão de
produção. O [plano aprovado](superpowers/plans/2026-11-07-samba-ad-production.md)
define as etapas consumidoras. Exemplos usam apenas nomes `.invalid`, nós
fictícios e endereços de documentação.

## Dados e execução

`contracts/samba_ad/defaults.yml` fixa `enabled: false`, `apply: false`, estágio
`S0` e execução manual. `example.yml` é um manifesto completo fictício, fora de
`group_vars`/`host_vars`; não é inventário Ansible nem é carregado automaticamente.
O manifesto real fica em `inventories/prod/contracts/samba-ad.yml` no repositório
privado, também fora dos caminhos carregados por Ansible. Não adicionar hosts
ou variáveis Samba aos grupos ativos nesta etapa.

Validação local, sem SSH, DNS, resolução de vault ou API:

```bash
python3 -m tools.samba_ad.contract contracts/samba_ad/example.yml
python3 -m tools.samba_ad.contract /caminho/privado/inventories/prod/contracts/samba-ad.yml
python3 -m pytest -q tests/test_samba_ad_contract.py
```

O validador exige os dois flags falsos e retorna somente contagens; erros da
CLI não reproduzem conteúdo de entrada. Rejeita chaves YAML duplicadas,
identidades repetidas, templates do tipo errado, sobreposição de redes,
origens administrativas amplas, DCs no mesmo nó e SANs diferentes da identidade
declarada. Ele valida declarações: não comprova ausência de colisão no cluster,
autorização operacional, capacidade livre, origem de pacote ou saúde de serviço.

| Bloco | Contrato entregue | Consumidor futuro |
| --- | --- | --- |
| `domain` | DNS, realm maiúsculo, NetBIOS, floresta nova confirmada, SID nulo | S4 registra SID observado; S5 exige o mesmo SID |
| `resources` | seis identidades candidatas, tipo, nó, MAC, IP, FQDN, template e tamanho | S1 revalida identidade/ausência e aplica proteção por digest |
| `network` | VNet exclusiva, CIDR sem sobreposição, MTU, gateway, DNS/tempo e administradores exatos | S1 implementa caminho de rede e controles efetivos |
| `secret_refs` | seis perfis independentes por arquivo vault e nome de variável | etapas que precisam dos segredos, com `no_log` |
| `certificate_profiles` | SAN exato por serviço/emissor, EKU e validade/rotação | S3/S7 implementam e comprovam emissão/rotação |
| `software` | versões requeridas, fonte candidata e verificação ainda pendente na instalação | S2/S4 verificam stack assinada e advisories atuais |
| `split_dns` | lista dos nomes públicos necessários ao piloto | S4/S6 verificam resolução interna e externa |

`state: candidate` significa reserva declarativa no Git privado, sem alocação no
Proxmox. Nenhum candidato pode substituir ou adotar automaticamente um recurso
existente. Antes de cada mutação futura, comparar VMID, tipo LXC/QEMU, nó,
nome/FQDN, MAC, IP, storage, tag de propriedade e digest atual. Falhar em conflito
ou identidade desconhecida. SID só é preenchido após observar a floresta real;
não há SID fabricado ou fixo no exemplo S0.

Cada fluxo mutante futuro exigirá opt-in explícito, `--limit` com uma identidade
exata, uma tag dedicada e readback das precondições. Os nomes reservados de tags
incluem `samba_ad_provision`, `samba_ad_pki`, `samba_ad_domain`,
`samba_ad_replica`, `samba_ad_pilot`, `samba_ad_observability` e
`samba_ad_backup`; ainda não existem entrypoints para executá-las. Não adicionar
Samba a `playbooks/site.yml`, ao workflow ou à allowlist `FIXED_RUNS` de
`tools/deploy/infra_ansible_deploy.py`. Merge de código não provisiona floresta.

## Plataforma e rede

Dois DCs em hosts físicos distintos: 2 vCPU, 4 GiB e 64 GiB cada. A CA
intermediária usa VM própria, 2 vCPU, 2 GiB e 20 GiB; receptor de backup em rede
de operações usa 1 GiB e 100 GiB. Windows e Linux piloto são clones novos,
sem ingresso de estações existentes. A edição, licença e suporte do Windows
serão verificados antes do piloto; o nome do template não é comprovação.

LXC é apenas candidato, não uma decisão de compatibilidade já aprovada. S2 deve
comprovar `security.NTACL`, ACL/xattr, SYSVOL, replicação, systemd, tempo e
auditoria em laboratório descartável. Exigir não privilegiado, AppArmor ativo e
sem nesting. Proibir `user.NTACL`, `CAP_SYS_TIME`, capacidades de auditoria do
host ou AppArmor unconfined como contorno. Falha implica VMs, sem novo pedido de
autorização. Templates originais de `packer-proxmox-templates` são preservados.
Storage local exige full clone desligado no nó de origem e migração offline
antes do primeiro boot; conferir identidade estática e isolamento no destino.
S1 revalida capacidade projetada e mantém pelo menos 2 GiB livres por host.
O laboratório LXC descartável precede os DCs definitivos: S1 pode preparar
lifecycle/rede e criar somente os recursos necessários à prova S2. Não exigir
coexistência de laboratório e DCs institucionais. Se a primeira prova de ACL
protegida/auditoria/isolamento falhar, adotar VMs sem criar um segundo LXC.
Não parar ou redimensionar guests de terceiros para obter capacidade.

A VNet exclusiva deve preservar as zonas/regras atuais. A role existente
`proxmox_guest_nic` atende LXC (`pct`/`/lxc`), não NICs QEMU. `network_router`
exige interfaces já endereçadas e com MTU correto. S1 precisa de extensão ou
role dedicada, com precondições e rollback, para NIC QEMU do roteador e
endereçamento persistente; essa capacidade não está implementada por S0.

`network-policy.yml` declara origens e destinos simbólicos; S1/S7/S8 expandem
cada grupo para IPs exatos do manifesto privado. Há controle no roteador e
`guest_default_drop`: tráfego na mesma VNet não passa pelo roteador. As atuais
permissões amplas de LAN e operações não comprovam isolamento dos novos guests;
as regras destes devem efetivamente recusar origens não aprovadas. Testar
conexões permitidas e negadas, inclusive de LAN/ops não administrativas, e
retorno `established/related`. Sem exposição de AD à Internet ou regras `any`.

`resource_groups` lista exatamente as chaves de recursos de cada grupo; não
corresponde a grupos Ansible existentes. `identity_guests` inclui os seis
guests deste projeto, inclusive backup em outra rede. `ssh_targets` exclui
Windows; `backup_senders` contém somente DC01, DC02 e CA, nunca pilotos.
Administradores vêm de `network.admin_sources`; DNS e tempo vêm das listas
exatas correspondentes. O coletor é um endpoint existente, a ser fixado por
identidade e porta em S7, sem ampliar o grupo dos seis guests do projeto.

| Origem → destino | TCP | UDP |
| --- | --- | --- |
| Pilotos/administradores exatos → DCs | 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 49152–65535 | 53, 88, 389, 464; 123 somente pilotos |
| DCs → DCs | mesmas portas TCP de AD | 53, 88, 389, 464 |
| DC01 → DC02 | 22 com chave de comando restrito para SYSVOL | — |
| Administradores exatos → `ssh_targets` | 22; Windows administrado por console inicialmente | — |
| Guests de identidade → CA | 443 com identidade TLS validada | — |
| DCs → forwarders exatos | 53 | 53 |
| Guests de identidade → fontes de tempo exatas | — | 123 |
| Emissores de telemetria → endpoint autenticado do coletor | 443 planejado, ainda sem listener comprovado | — |
| Emissores de backup → receptor independente do AD | 22 com credencial restrita | — |

NetBIOS 137/138/139, SMB1 e RDP não têm autorização nesta matriz. As portas
49152–65535 são o intervalo RPC padrão documentado, limitado aos pares
aprovados; não é regra geral para a LAN. Egress de pacotes/PKI ou coleta de
métricas adicional requer destinos e portas explícitos no contrato da etapa
consumidora, sem liberação genérica. A matriz de S0 não pretende permitir a
instalação antes de S1 detalhar o egress necessário.

## DNS, pacotes, certificados e segredos

O namespace institucional autorizado coincide com zona pública existente. A
autoridade pública permanece preservada. Ausência de SRV nos resolvedores
consultados corrobora a declaração do usuário de floresta inexistente, mas não
prova ausência em toda a rede. S4 deve rejeitar um host com domínio existente e
conferir colisões de NetBIOS/DNS novamente antes de criar a floresta.

Para o piloto, registrar somente os nomes públicos necessários, com A/AAAA,
CNAME e HTTPS esperados. Comparar respostas públicas e via cada DC e validar
SAN/cadeia do HTTPS. Como o AD é autoritativo pela zona interna, forwarder não
resolve sozinho nomes públicos da mesma zona: manter registros explícitos
necessários, inclusive a distinção entre apex público e registros do AD. Não
sobrescrever cegamente o apex ou replicar toda a zona municipal. DNS/DHCP da
LAN e migração municipal continuam fora desta entrega.

Requerer Samba 4.25.1, FFL/DFL 2016 e esquema 2019/v88 como conceitos distintos.
O candidato nativo da distribuição observado não atende à versão. A evidência
`source-provenance.json`, fornecida pela coordenação, registra assinatura e
hash dos metadados públicos do fornecedor em uma data específica. Isso não
comprova binários instalados nem ausência de advisories. Revalidar fingerprint,
InRelease, hashes dos pacotes e stack Samba/LDB/Python coerente antes de
instalar; sem source-build ou mistura de bibliotecas. Não executar elevação de
esquema repetida nem `dbcheck --fix` automático.

Certificados duram sete dias e rotacionam com novo par de chaves antes de dois
terços da validade; `0.66` é um limite conservador. LDAPS de cada DC e HTTPS da
CA usam SAN individual e EKU `serverAuth`; telemetria tem perfil `clientAuth`
individual por emissor, sem credencial ampla compartilhada. S3/S7 ainda precisam
validar cadeia, SAN, EKU, correspondência da chave e troca atômica. Raiz offline
com o operador, fora do Git e dos servidores; intermediária online separada.

O mecanismo aprovado é ansible-vault: valores somente em `vault.yml`
integralmente cifrado no inventário privado. Perfis de administrador inicial,
DSRM, provisioner da CA, SYSVOL, backup e telemetria são referências, não
credenciais já criadas. Chaves privadas, backups AD, bancos PKI, tickets e
material de recuperação não entram no Git, mesmo cifrados; variáveis com
sufixo `_ref` apontarão para material protegido fora do Git. Nunca fornecer
senhas por argumentos ou imprimir valores na validação.

## Observações e próximos contratos

A descoberta privada registra versões heterogêneas do cluster, memória/storage,
digests, fontes de tempo e templates. O coletor existente está ativo, mas a
porta de administração do Alloy é loopback e não é um endpoint de ingestão
remota. S7 deve entregar transporte autenticado com identidade exata e testes
de fila/falha/retomada, sem modificar retenção de outros projetos ou notificações.

S5 entregará SYSVOL unidirecional, com DC01 autor de GPO, preservação ACL/xattr/SID
e alertas de defasagem; não afirmar DFS-R nativo. S8 entregará backups locais
cifrados, monitorados e com credenciais independentes, antes do aceite de
produção. Não usar snapshot como único backup, copiar `sam.ldb` aberto ou
declarar restauração comprovada sem ensaio.

Recuperação externa, restauração integral e DR ficam em S10, pós-produção.
RTO/RPO continuam metas sem comprovação. Nem recuperação/custódia externa nem
inventário municipal completo são gates de prontidão. Não reativar Infisical,
MinIO descomissionado ou serviços de e-SUS PEC/SIHA para cumprir estes contratos.

## Fontes consultadas

- [Ansible: localização de variáveis de inventário](https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_inventory.html)
- [Ansible Vault: arquivos estruturados](https://docs.ansible.com/projects/ansible/latest/cli/ansible-vault.html)
- [Samba: smb.conf, RPC e transportes SMB](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html)
- [Samba 4.25.1](https://www.samba.org/samba/history/samba-4.25.1.html)

Ansible e Samba foram consultados via Context7 em S0. O retorno sobre firewall
também incluiu documentação antiga de NetBIOS/SWAT; ela não foi usada para
autorizar portas ou definir o baseline atual.
