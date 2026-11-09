# Samba AD — S5 / DC02 e SYSVOL

Implementação de fonte, manual e desabilitada por padrão. Não houve ingresso,
conexão SSH, criação de chave operacional ou alteração de pacote/serviço nesta
entrega. S1 aplicado/auditado, qualificação real S2, PKI S3 e DC01 S4 íntegro
continuam precondições de execução. Testes locais não constituem aceite S5.
Não depende dos PRs ainda não integrados de laboratório ou protocolos S4.

## Decisões de implementação

1. Reutilizar validação de pacote, identidade, PKI, hardening e máscaras S4;
   manter o entrypoint de provisionamento S4 restrito ao DC01.
2. Usar o contexto nativo `DCJoinContext` da tag Samba 4.25.1 para ingresso
   DRS na floresta existente; nunca usar provisionamento de floresta nova.
3. Validar fonte/identidade/SID/níveis/schema/PKI/ausência remota, registrar uma
   tentativa durável antes de mutação remota e preservar parciais para inspeção.
4. SYSVOL é **DC01 autor → DC02 consumidor**, por pull. Chave privada gerada
   somente no DC02; somente sua chave pública é transferida ao DC01.
5. Validar toda a árvore e seus IDs/ACLs antes e depois da cópia; recusar conflito
   de autoria em vez de sobrescrevê-lo. Publicar uma árvore completa por troca
   atômica de diretórios, com marcador persistente de operação parcial.
6. Exercitar recusas primeiro, verificar os adapters e transporte local com
   fixtures temporárias e manter os readbacks de produção explicitamente pendentes.

## Entrypoints e contrato

`playbooks/samba-ad-replica.yml`, tag `samba_ad_replica`, chama a role homônima.
`playbooks/samba-ad-sysvol.yml`, tag `samba_ad_sysvol`, prepara o transporte em
um host por execução. Ambos têm `enabled: false`, `apply: false`, exigem limite
exatamente igual a um hostname do inventário, usuário SSH não-root e become.
Não são chamados por `site.yml`, deploy de main ou configuração autocarregada.
Os loaders rejeitam campos desconhecidos e validam no controller antes de
qualquer transporte. Revalidam ambos os substratos S1 nos nós PVE com adapter
somente leitura, sem criar/iniciar/mover guests nem alterar firewall.

O request privado `samba-ad-replica/v1` habilitado contém:

| Campo | Contrato |
| --- | --- |
| `local` | Request S4 completo, mas com identidade e perfil PKI `dc02`; SID obrigatório e `apply: false` |
| `peer` | Request S4 DC01 completo, SID registrado e `apply: false` |
| `peer_leaf_sha256` | SHA256 DER do certificado público DC01 atualmente aprovado |
| `join_user` | Nome da conta de ingresso, sem senha |
| `site` | Site existente exato; nunca descoberta de outra floresta |
| `enabled`, `apply` | Booleanos reais; execução mutante exige ambos |

As ferramentas já precisam estar instaladas: Samba/bindings4.25.1 e stack S4,
rsync3.4.1, OpenSSH, sudo, useradd, AIDE e Python/PyYAML/cryptography. A role não
baixa nem instala pacotes. Os dois requests conservam pins de repositório/pacotes Samba 4.25.1, stack
LDB/Python coerente, qualificação S2, geração/trust/proveniência S3, identidade
machine/boot/MAC/IP e SHA de smb.conf. SID, realm e NetBIOS precisam coincidir.
O nome local é DC02 e o remoto DC01. Nenhuma fixture pública é um recibo privado.
O certificado remoto é validado por CA fixada, hostname, TLS ≥1.2 e leaf exato.
Rotação do peer exige atualizar o pin público revisado antes de nova execução.

O contrato simbólico de rede autoriza DC02 OUT TCP22 para DC01 e DC01 IN TCP22
exclusivamente do DC02. Os endpoints expandidos são `/32`. Como ambos pertencem
à zona identity, `router_rules` omite esse fluxo de mesma zona; PVE e firewall
local continuam obrigatórios. O S5 exige as regras existentes; não as amplia.

## Ordem manual de preparação

1. Preparar o consumidor no DC02 com `samba_ad_sysvol_role: consumer`, request
   completo, manifesto e `samba_ad_sysvol_host_key` contendo somente a chave
   pública Ed25519 SSH do DC01, obtida por canal autenticado. Não usa ssh-keyscan.
   O helper valida substrato/host/pacotes/PKI e ausência de ingresso. Gera
   `/var/lib/samba-ad-sysvol/pull_ed25519` em diretório0700 no próprio DC02.
   O resultado contém apenas a chave pública; nenhuma chave privada é lida
   para exibição, copiada, transferida ou colocada em facts/cache.
2. Preparar a origem no DC01 com `samba_ad_sysvol_role: source` e
   `samba_ad_sysvol_public_key` igual à chave pública retornada. Revalida DC01
   e AIDE antes de instalar a configuração; inclui essa adição revisada de SSH
   na baseline AIDE própria. Recusa adoção de usuário ou arquivo estranho.
3. Executar o ingresso S5 no DC02. Antes da primeira mutação remota, comprova
   autenticação SSH, host key, exportação, SID e manifesto da origem.
   Após ingresso/hardening, comprova DNS assinado e saúde DRS/GC/Kerberos,
   sincroniza SYSVOL pela primeira vez e habilita o timer.
4. Registrar o SID já existente e o novo digest de smb.conf no request privado.
   Reexecução íntegra é inspeção, sem ingresso, alterações de política/esquema,
   KCC, atualização DNS, reinício de serviço ou sincronização forçada.

Exemplo fictício/inertemente em check mode; os arquivos citados não são exemplos
operacionais e não existem neste repositório:

```bash
ansible-playbook -i /privado/hosts.yml playbooks/samba-ad-sysvol.yml \
  -e @/privado/s5-consumer.yml --limit dc02-exemplo --tags samba_ad_sysvol --check
ansible-playbook -i /privado/hosts.yml playbooks/samba-ad-replica.yml \
  -e @/privado/s5-replica.yml --limit dc02-exemplo --tags samba_ad_replica --check
```

## Ingresso, credenciais e falhas

A senha vem somente de `/run/samba-ad-domain-credentials/dc02/join`, arquivo
protegido preparado pelo resolver Vault. A API recebe Credentials em memória,
Kerberos obrigatório e sealing. Senha não entra em argv, Ansible, logs ou facts.
Streams Python e descritores stdout/stderr nativos são silenciados durante APIs
que podem emitir diagnósticos sensíveis. Erros externos são sanitizados.

O `do_join` upstream chama `cleanup_old_join`, inclusive após falha. Este backend
usa a sequência nativa equivalente para DC gravável e omite ambas as limpezas:
`build_nc_lists`, `join_add_objects`, `join_provision` em modo **FILL_DRS com SID
existente**, `join_replicate`, DNS e `join_finalise`. Nunca chama
`join_provision_own_domain`, elevação de schema ou `dbcheck --fix`. A ausência de
objetos DC02 é verificada também em outros sites/containers e nas partições DNS;
a ausência DNS é relida antes da fase que publica os registros. Não há retry
mutante. Alterações administrativas concorrentes devem ficar congeladas durante
a janela manual: LDAP/DNS e os guards PVE não formam uma transação distribuída.

`/var/lib/samba-ad-replica/attempt.json` é criado com O_EXCL/fsync antes de
qualquer alteração remota. DB local, secrets, keytab, árvore prévia, objeto remoto
ou tentativa sem `joined.json` íntegro bloqueiam nova execução. Nenhum parcial é
apagado/adotado. Máscaras persistentes de boot e serviços membros do S4 são
preservadas até as verificações locais de hardening. O serviço precisa estar
ativo para readbacks Kerberos/DRS e idmap; se aceitação inicial falhar após essa
ativação, o backend revalida as unidades próprias, para e mascara DC02 novamente.
Se a quarentena também falhar, informa explicitamente que não foi verificada.
Inspeção humana direcionada é necessária; não remover marcadores para tentar
novamente sem avaliar objetos remotos e locais.

Após a ativação inicial, KCC é solicitado nos dois DCs e a saúde é consultada
por até180s. A verificação exige as cinco partições, vizinho NTDS do outro DC,
resultado de replicação zero, nenhuma falha consecutiva e último sucesso ≤900s.
LDAPS SASL e GC/3269 usam Kerberos obrigatório; RootDSE deve informar sincronização
e GC prontos. Ambos os resolvedores precisam retornar LDAP/Kerberos/GC SRV de
ambos os DCs. `samba_dnsupdate --use-nsupdate` solicita atualizações GSS-TSIG na
primeira execução. Negativos de DNS não assinado e demais protocolos S4 ainda
pertencem à bateria nativa própria; configuração ou fixtures não os comprovam.

## SYSVOL e transporte restrito

A conta SSH `samba-sysvol` não é root, não tem senha utilizável, home ou key
compartilhada. `authorized_keys` é root-owned, com `restrict`, origem exata e
forced command. O gate aceita somente `manifest` ou `rsync --server --daemon .`.
Sudo permite somente duas invocações literais do helper root; não há wildcard,
shell root ou opção fornecida pelo cliente. O exporter roda rsync via stdio SSH,
sem listener TCP873, em módulo somente leitura/chroot, caminho fixo SYSVOL,
conexão única e timeout. Recusa links, devices, especiais e operações de escrita.
O Match SSH se aplica apenas à conta dedicada; readback `sshd -T -C` confirma
publickey, sem forwarding/TTY/password e mantém o contrato global não-root S4.

O consumidor usa host key fixa, `BatchMode`, `IdentitiesOnly`, timeout e chave
local protegida. `rsync -aAX --numeric-ids --fsync` preserva metadados; não usa
`user.NTACL` nem afrouxa o isolamento do guest. O manifesto inclui conteúdo,
modo, UID/GID, ACL POSIX e **security.NTACL**, GPT.INI e versões, rejeitando links
simbólicos/hardlinks, devices, mounts e escapes. UID/GID e IDs nomeados de ACL
precisam resolver para os mesmos SIDs em ambos os hosts; divergência exige
correção dirigida da configuração de idmap, nunca cópia automática de banco.
`sysvolcheck` nativo verifica a origem e o resultado contra o domínio real.

A origem é relida antes e depois da cópia; estágio e manifests precisam coincidir.
A árvore do DC02 deve coincidir com a baseline do último sucesso antes e depois
da transferência. Ambas as shares do DC02 são read-only; autoria legítima de
GPO acontece no DC01. Alteração local, ACL divergente, fonte instável ou cópia
parcial falham sem sobrepor a árvore corrente. A troca final usa Linux
`renameat2(RENAME_EXCHANGE)` no mesmo filesystem. Uma escrita local que corra com
a troca é detectada na árvore antiga; restaura-se essa árvore e conserva-se o
parcial. Interrupção durante publicação deixa `partial.json` e bloqueia retries.
Somente estágios próprios não publicados são removidos automaticamente.

## Estado observável e limites de prova

`/var/lib/samba-ad-sysvol/status.json` é0600 e registra `state` (`ok` ou
`failed_or_conflict`), `last_success`/`last_attempt` (epoch inteiro), `failures`,
`sid` e `baseline` (digest + entries). Falhas preservam o último sucesso.
`samba-ad-sysvol.service` tem limite300s; `samba-ad-sysvol.timer` roda a cada2min.
`--sysvol-inspect` exige timer enabled/active, idade ≤600s, ausência de parcial,
SID/identidade vivos, igualdade da árvore e sysvolcheck. Timer falho, estado,
idade e conflitos são entradas para S7; não há notificação externa. Não se
reivindica DFS-R nativo. Backup/DR e migração municipal continuam fora da entrega.

Testes usam árvores temporárias, xattrs `user.*` exclusivamente como fixture de
transporte rsync, adapters e metadados sintéticos. Exercitam transporte rsync
real via stdio local e recusa de escrita, mas **não** qualificam ACL protegida,
Samba real, dois DCs, Kerberos, SYSVOL operacional, SSH/sudo real ou timer remoto.
Esses readbacks são implementados e sua execução/auditoria continua pendente.
Não houve suite nativa completa nem testes de serviços não relacionados.

## Fontes consultadas

Context7 tentou resolver Samba e retornou `Monthly quota exceeded`. Fallback:

- [Samba4.25.1 join.py](https://github.com/samba-team/samba/blob/samba-4.25.1/python/samba/join.py)
- [CLI domain join](https://github.com/samba-team/samba/blob/samba-4.25.1/python/samba/netcmd/domain/join.py)
- [DRS readbacks](https://github.com/samba-team/samba/blob/samba-4.25.1/python/samba/netcmd/drs.py)
- [DNS update](https://github.com/samba-team/samba/blob/samba-4.25.1/source4/scripting/bin/samba_dnsupdate)
- [rsync3.4.1 manual](https://github.com/RsyncProject/rsync/blob/v3.4.1/rsync.1.md)
- [OpenSSH10 authorized_keys](https://github.com/openssh/openssh-portable/blob/V_10_0_P1/sshd.8)
