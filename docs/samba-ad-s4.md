# Samba AD — S4 / DC01 e hardening

Fonte preparatória, desabilitada por padrão. Nenhuma floresta, SID, certificado
operacional, pacote ou guest foi criado por esta mudança. S1 aplicado/auditado,
qualificação real S2 em dois hosts e material S3 válido continuam necessários.
Não constitui aceite S4 ou prontidão de produção. Não integra site.yml, CI de
deploy, FIXED_RUNS ou configuração autocarregada do inventário.

## Entrada e execução manual

`playbooks/samba-ad-domain.yml` chama `samba_ad_domain`: `enabled: false` e
`apply: false`. A ativação exige um único `--limit` igual ao hostname de
inventário, somente `--tags samba_ad_domain`, SSH por usuário não-root e become.
O inventário privado precisa conter também o nó Proxmox exato do alvo.

```bash
ansible-playbook -i /privado/hosts.yml playbooks/samba-ad-domain.yml \
  -e @/privado/request-s4.yml --limit dc01-exemplo --tags samba_ad_domain --check
```

O request privado `samba-ad-domain/v1` é fechado. Desabilitado aceita somente
schema/enabled/apply falsos. Habilitado exige os blocos abaixo, sem senha,
PEM ou material privado embutido. Os nomes e caminhos operacionais reais ficam
no inventário privado revisado, fora de group_vars/host_vars autocarregados.

| Bloco | Vínculo |
| --- | --- |
| target | realm/NetBIOS do S0, FQDN exato DC01; SID nulo somente na criação |
| substrate | request S1 completo: production, enabled true, apply false, present, boot true, expected_digest atual; bundle S2 canônico completo/qualificado |
| pki | request S3 DC01 com adapter samba/636, identidade machine/boot/MAC/IP, spec_sha256 S1, trust público e provenance existentes |
| generation | identificador opaco de uma geração S3 já staged; não é certificado fictício |
| identity | boot_id, machine_id e SHA256 do smb.conf corrente antes da operação |
| source | diretório fixo /var/lib/samba-ad-source, pins InRelease/Packages/keyring/fingerprint, versões exatas por pacote, verified_utc e advisory_review_ref imutável |
| provenance | reviewed_config_revision e review_ref git imutáveis |

A revisão privada carregada é a raiz operacional de confiança: hashes verificam
coerência, não autenticam uma revisão humana. Não há pin ou request operacional
público. Os testes usam apenas fixtures sintéticas.

Antes do transporte ao DC, o controller valida S0/S2/S3 e delega ao nó PVE
`guest.reconcile(..., check=True)` com adapter que recusa mutate e firewall
apply. Só aceita state verified, changed false: VMID/tipo/nó, digest, ownership,
pending, sizing, fingerprint kernel/PVE e firewall efetivo S1 são rechecados.
Não cria, inicia, para ou adapta guests. Operações concorrentes devem permanecer
congeladas durante a janela manual, como em S1: o digest não é lock transacional
entre PVE e operações no guest. O helper DC-local é interno à role e não substitui
essa etapa ao ser invocado diretamente por root.

No alvo, confere identidade viva, config digest, pacote instalado/payload,
certificado e chave S3, SAN/cadeia/EKU/pins/validade, geração e firewall próprio.
A primeira execução rejeita DB parcial, secrets preexistentes, keytab, serviço
Samba/member ativo e geração previamente ativa. Consulta SRV da floresta nos
forwarders exatos novamente e recusa qualquer resposta positiva ou erro DNS.
A verificação de colisão NetBIOS fora desses resolvedores permanece uma prova
operacional privada antes de confirmar a floresta nova; não habilita NBNS.

## Pacotes e segredos

A role NÃO faz downloads nem resolução apt de dependências. Requer ferramentas
já instaladas, inclusive Python/PyYAML/cryptography, Samba, dig, nft, OpenSSH,
AIDE e auditd em QEMU. Samba/LDB e bindings Python são comparados com .debs verificados do
mesmo repositório, não com um booleano installed. `domain_source.install` permite
uma instalação offline explícita do conjunto staged completo: valida assinatura,
metadata e hashes antes de dpkg. Exige uma policy-rc.d root/executável já
existente com conteúdo exato `#!/bin/sh\nexit 101\n`, deny-all incondicional;
confere também retorno101 para start/stop/restart/reload/force-reload e variantes
try/reload-or-restart de samba, smbd, nmbd, winbind e samba-ad-dc. Uma policy
seletiva é recusada mesmo que bloqueie o primeiro start. Não cria, altera ou
substitui uma policy existente para forçar aprovação.
A aquisição e egress têm de ter sido revisados previamente em S1; não usa apt
para buscar dependências de outra origem nem faz source build.

O diretório protegido contém InRelease, Packages **descomprimido**, keyring.gpg
e packages/<basename.deb>. gpgv comprova assinatura pelo primary fixado ou por
sua subkey certificada; SHA256/size de Packages precisam constar no Release
assinado e cada arquivo precisa corresponder ao Packages. Conferir key pin e
primary atuais contra source-provenance.json e a revisão fresca do operador.

O conjunto de pins deve ser a closure exata de Depends/Pre-Depends do índice
assinado, partindo de samba-ad-dc e samba-ad-provision. Inclui samba-libs,
DSDB modules, common/common-bin, winbind, libwbclient, LDB, talloc/tdb/tevent e
bindings Python; resolve também Provides versionados do próprio fornecedor.
O índice candidato atual requer19 pacotes, incluindo duas bibliotecas ngtcp2
com versões próprias, sem sufixo4.25.1. Valida cada aresta de versão (inclusive
igualdade exata), presença e payload de todo o conjunto; omissões e versões
misturadas são recusadas. As restrições Debian externas ficam separadas e são
comparadas às versões instaladas, inclusive Python>=3.13~ e <3.14 e os pisos de
libc. Não exige versão4.25.1 em libc ou em bibliotecas de outro source package.

A verificação do payload cobre **todos os arquivos imutáveis**, incluindo
/usr/share/samba/setup, schema e LDIF, não somente binários e .so. Somente
/etc/samba/smb.conf é excluído explicitamente por ser configuração gerenciada
pela role e protegida pelo digest/readback próprio. A fixture pública de testes
projeta os19 registros de dependência do Packages autenticado fornecido pela
coordenação; não contém .debs ou recibo de instalação.

Date do Release é publicação, não expiração. Aceita publicação antiga quando
Valid-Until não existe; respeita Valid-Until quando presente e recusa publicação
no futuro além de cinco minutos. `verified_utc` registra a coleta/revalidação
operacional, com janela local de24h para execução e clock skew de5min; não é TTL
do fornecedor. O review de advisories precisa ser referenciado separadamente.
Ausência de Valid-Until limita a proteção criptográfica contra replay: a revisão
privada deve comparar o metadata com o repositório atual por canal autenticado.

O provisionamento chama a API Python oficial Samba4.25.1, sem subprocesso de
provisionamento e sem adminpass em argv. Lê exclusivamente
/run/samba-ad-domain-credentials/dc01/administrator, arquivo root protegido
preparado pelo resolver Vault confiável. Não recebe valores via Ansible,
set_fact, cache, diff ou log; logger/stdout/stderr Python da API são suprimidos.
O caminho fixo deve vir do perfil individual do administrador inicial. O helper
não lê outros cofres nem cria credenciais. Não fornece domainsid: o SID nasce
somente no provisionamento real. Parciais exigem inspeção direcionada, nunca
remoção/recriação automática. Antes de prepare_config ou da API, aplica o piso
de14 e `samba.check_password_quality` do Samba4.25.1 instalado/verificado em
memória. Rejeição ou erro nativo tem mensagem sanitizada e não troca config,
não altera unidades nem entra em provisionamento.

## Configuração, reexecução e aceitação

A API cria FFL/DFL2016 com base_schema2019/adprep2016; readback exige os níveis7
e objectVersion88. Nunca eleva repetidamente, executa dbcheck --fix, provisiona
DC02 ou substitui floresta existente. Reexecução exige SID privado já registrado,
mesmo realm/NetBIOS/FQDN e níveis/schema exatos; não lê a senha nem reprovisiona.

Antes da primeira mutação, verifica LoadState/UnitFileState/ActiveState,
FragmentPath e DropInPaths das unidades Samba, com identidade dos fragments
vendor já autenticada pelo payload. Só aceita masks reais /dev/null; recusa
unidades locais substitutas e drop-ins desconhecidos. Em DC novo/próprio/vazio,
a convergência inicial desabilita e mascara persistentemente samba/smbd/nmbd/
winbind, remove masks persistentes e runtime do DC pretendido e o habilita para
boot, ainda sem start. Faz readback completo antes de substituir smb.conf/criar
DB. O primeiro start ocorre depois da configuração. Readback final exige DC
active/running/enabled e membros inativos/mascarados. Reexecução somente verifica
esses estados: não inicia/para serviços nem corrige drift automaticamente.
Falha parcial na convergência inicial aborta antes da troca de config/API.
O SID observado e o config digest ficam em arquivo0600 próprio no guest, para
registro posterior no inventário privado. Não são fatos persistentes Ansible.

Política por SamDB:14 caracteres, complexidade, histórico30, minAge1dia,
maxAge0, reversible off, bloqueio10/15min/15min. SMB2_02 mínimo, signing
mandatory cliente/servidor, NTLMv2-only e DNS updates secure only. A preferência
Kerberos é AES256/AES128, mantendo RC4 como compatibilidade piloto; não força
AES-only ou remove NTLMv2 antes da etapa piloto.

LDAP strong auth=yes tem semântica CBT explícita na tag4.25.1: SASL sobre TLS
precisa binding correto, sem TLS precisa sign/seal; simple bind é permitido
somente sobre TLS. TLS exclui1.0/1.1. Após ativação, conexão LDAPS nova exige
cadeia/hostname/TLS>=1.2 e leaf exato da geração S3.

O primeiro handoff S3→S4 ativa somente geração staged válida sem active.conf
anterior, sob Store.lock, usando o fragmento nativo S3. Rotação subsequente é
S3-owned. Falha inicial conserva o estado parcial para inspeção; não declara
rotação/rollback bem-sucedido e não remove DB ou material possivelmente ativo.

Hardening usa arquivos próprios: SSH publickey/non-root com teste sshd -t e
readback sshd -T antes de reload, journald persistente, updates automáticos
bloqueados para manutenção controlada, AIDE com baseline próprio e timer,
auditoria DSDB/auth e regras auditd somente no kernel QEMU. LXC recusa
CAP_SYS_TIME e capacidades audit do host; não tenta habilitá-las. Tempo real é
qualificação S2 e verificação operacional, sem ajustar o relógio do host.

Firewall nft cria tabela dedicada inet samba_ad_s4, input/output drop, loopback,
established/related e somente peers/portas exatos S1. Recusa NetBIOS/RDP e
origens amplas. Não limpa regras/tabelas alheias; tabela preexistente sem recibo
próprio é recusada. Readback normalizado fica ligado ao spec/config; drift é
recusa. Serviço próprio persiste a tabela no boot, requerido antes de Samba.
O teste sintático nft do kernel-alvo ocorre antes de provisionar. Testes locais
de renderização não comprovam enforcement, retorno SSH novo ou persistência
no boot: esses readbacks nativos permanecem obrigatórios na aplicação.

Não há resultado efetivo CBT/SMB signing/SMB1/NTLMv1 negativo nesta fonte.
`native_protocol_acceptance: pending` é explícito mesmo após os readbacks locais.
É obrigatório provar binding válido, ausente e incorreto; LDAP sem assinatura;
TLS antigo; SMB sem signing; SMB1 e NTLMv1; NTLMv2 e AES piloto válidos antes de
aceite S4. Falta ainda o runner autenticado dessa bateria, vinculado aos clientes
piloto reais e à versão instalada; não substituir por assertions de configuração.
Backup/DR e migração municipal não fazem parte da entrega ou dos gates.

## Fontes e verificação

Context7 foi tentado nesta sessão e retornou Monthly quota exceeded. Fallback
registrado na tag oficial Samba4.25.1:

- https://github.com/samba-team/samba/blob/samba-4.25.1/python/samba/netcmd/domain/provision.py
- https://github.com/samba-team/samba/blob/samba-4.25.1/docs-xml/smbdotconf/ldap/ldapserverrequirestrongauth.xml
- https://github.com/samba-team/samba/blob/samba-4.25.1/docs-xml/smbdotconf/security/kerberosencryptiontypes.xml
- https://www.samba.org/samba/history/samba-4.25.1.html

Testes focados incluem recusas de identidade/SID/parcial/schema, política,
S1 read-only real sobre adapter simulado, segredo somente na API em memória,
entrada fechada, limites/tags/SSH da role real, loader comprimido, assinatura
GPGv real de fixture efêmera e recusa de arquivo alterado. Não executam Samba,
Proxmox, nft, AIDE ou PKI de produção. Lint/syntax não são qualificação nativa.
