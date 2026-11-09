# S4 — medições nativas de protocolos

`python -m tools.samba_ad.protocol` é um entrypoint manual separado. O default
é inerte: `enabled: false`, `execute: false`; mesmo habilitado precisa também
da opção CLI `--execute`. Não é chamado pela role, deploy, inventário ou CI de
produção. Não instala dependências, cria contas, ingressa máquinas, altera
firewall, domínio ou serviços. Os testes da fonte não são aceite nativo.

## Raiz de confiança e entrada privada

O wire JSON em stdin é fechado: `schema: samba-ad-protocol-wire/v1`, `request`
e `manifest`. O manifest é o S0 privado já revisado. Desabilitado, o request
contém somente `schema: samba-ad-protocol/v1`, `enabled: false`, `execute: false`.
Habilitado, contém exatamente:

| Campo | Contrato |
| --- | --- |
| schema / enabled / execute | `samba-ad-protocol/v1`; booleanos explícitos |
| domain | request S4 completo e validado, `apply: false`, SID real registrado |
| client | `role: linux_pilot`, `machine_id`, `boot_id`, `interface`, `new_owned_review_ref` |
| server_audit_ref | `git:<SHA40>:<caminho>` da auditoria privada do DC instalado |
| leaf_sha256 | SHA256 DER da leaf exata da geração S3 ativa/auditada |
| username | conta dedicada `s4-probe...@REALM`, sem privilégios administrativos |
| timeout_seconds | inteiro de1 a30 por prova |

`new_owned_review_ref` também é `git:<SHA40>:<caminho>`. A revisão privada é a
raiz operacional: comprovar que o clone é novo/próprio e que os campos correspondem
ao inventário aprovado. O piloto deve ter o FQDN completo do manifest configurado
como hostname do kernel; o helper lê esse nome local por `gethostname()`, sem
NSS/DNS, sem completar nomes curtos ou aceitar aliases. O helper relê machine-id,
boot-id, FQDN, interface/MAC e
IPv4 do Linux piloto antes de qualquer rede ou credencial. O manifest S0 amarra
VMID, placement, owner, template e endereços; não descobre ou adota clientes.
Não executa testes Windows, ingresso ou GPO de S6.

A auditoria referenciada do servidor deve provar pacote/payload Samba4.25.1,
closure LDB/Python assinada, identidade DC01/SID, configuração e geração PKI
instalada. Esses fatos não são inferidos de um banner remoto ou da aceitação de
um bind. O request S4 e as referências imutáveis ligam o relatório a essa
auditoria; o helper não autentica sozinho a revisão humana. Falta de auditoria
ou mudanças no servidor/cliente/generation exigem nova revisão e nova bateria.

Depois da identidade local, uma conexão LDAPS nova valida CA, hostname e leaf
exata antes de ler o segredo. As conexões TCP usam somente o IPv4 numérico de
DC01 do request/manifest validado, portas389/636/445. Não há lista de alvos,
resolução DNS, SRV, redirects ou fallback de servidor. Kerberos usa apenas o
KDC exato DC01:88, por TCP, sem descoberta DNS nem canonicalização.

## Dependências, segredo e execução

Preparar previamente ambiente isolado e revisado com cryptography, PyYAML,
pyspnego0.12.4, gssapi1.11.1 e bibliotecas MIT GSS/Kerberos compatíveis. Pins e
hashes dos artefatos Python constam em
`tools/samba_ad/protocol-requirements.txt`; o arquivo não instala dependências
transitivas nem bibliotecas nativas. Não executá-lo cegamente em produção.
Versão errada/ausente ou API nativa indisponível é `operational_error`.

O resolver Vault confiável fornece um FD já aberto, contendo exclusivamente
JSON `username`/`password`, sem campo schema; nome igual ao request, senha
de14 a1024 caracteres, sem NUL/CR/LF. Não usar senha em argv, variável de
ambiente, request, log ou Git. O FD é limitado a8KiB, tem deadline e é fechado
após leitura. Exemplo somente com caminhos privados já preparados:

```bash
python -m tools.samba_ad.protocol --execute --credential-fd 3 \
  3</run/samba-ad-protocol-credentials/pilot.json \
  </privado/protocol-wire.json >/privado/protocol-report.json
```

O operador prepara diretórios/arquivos privados0600 e preserva a evidência
fora do Git. O runner não resolve cofre, cria ou modifica a credencial. A conta
deve estar íntegra/desbloqueada e ter acesso de leitura a NETLOGON. Não repetir
automaticamente esta bateria: os negativos autenticados podem contribuir para
bloqueio/alertas. Há no máximo cinco trocas SASL por sessão, sem retry de caso.

Cada prova executa num processo Linux separado, deadline rígido, output e logs
suprimidos, core dump desabilitado. O segredo e as chaves de sessão permanecem
em memória da API; não há keytab, kinit, pacote, serviço ou chave operacional
criada. Kerberos usa cache MEMORY e um diretório temporário privado em `/run`
com somente configuração pública do KDC; o contexto é destruído após medir.

## O que é medido

| Caso | Evidência aceita |
| --- | --- |
| LDAPS CBT válido | SASL GSS-SPNEGO/NTLMv2 realmente autenticado, TLS e leaf verificadas |
| CBT ausente/incorreto | novo bind, mesmo principal/senha, LDAP49 após transmitir NTLM Authenticate (Type3) com a variante; exige controle válido anterior |
| LDAP sem assinatura | tokens NTLM sem sign/seal sobre389, LDAP8; exige controle válido |
| TLS1.0 /1.1 | alerta **do peer** protocol_version; exige LDAPS moderno válido |
| NTLMv2 SMB assinado | SMB2.1, sessão autenticada sem guest/null, TREE_CONNECT NETLOGON e resposta com HMAC-SHA256 válida |
| SMB sem assinatura | TREE_CONNECT enviado sem flag/signature; erro ACCESS_DENIED/INVALID_SIGNATURE assinado e autenticado |
| SMB1 | negociação exclusiva NT LM0.12, resposta SMB1 NOT_SUPPORTED/nenhum dialect; exige SMB2 válido |
| NTLMv1 | NTLMv1 Authenticate (Type3) transmitido, SMB LOGON_FAILURE com corpo ERROR válido, após controle NTLMv2 válido |
| AES | bind GSS-SPNEGO Kerberos válido; API MIT exporta contexto lúcido com enctype17/18 observado |

pyspnego fornece os tokens/CBT/NTLM; não há implementação criptográfica NTLM
local. CBT usa `tls-server-end-point:` e digest da leaf desta conexão (RFC5929,
SHA256 no lugar de assinatura MD5/SHA1). O caso incorreto altera um byte. SMB2.1
é fixado para usar o algoritmo de assinatura definido pelo protocolo; nenhuma
escrita, leitura de arquivo ou alteração de ACL é enviada. O código só faz bind
e TREE_CONNECT de leitura, sem alteração de diretório/conta.

Rejeição genérica durante negociação (apenas Type1), antes de transmitir
Authenticate Type3, não mede CBT/NTLMv1 nem LDAP sem assinatura. O parser
inspeciona os bytes SPNEGO/NTLM efetivamente enviados; uma flag do adapter
não comprova a fase. Corpo ERROR SMB ausente, truncado ou inconsistente também
não prova rejeição.

Timeout, reset/EOF, parser inválido, falha de CA/hostname/leaf, cliente incapaz
de oferecer TLS antigo, GSS sem extensão nativa, erro genérico e assinatura de
resposta inválida não provam rejeição: são `operational_error`. Samba pode
encerrar conexão sem erro SMB assinado; esse caso precisa investigação/evidência
nativa adicional, continua pendente e não vira um `passed` por desconexão.

Cada caso é `not_run`, `passed`, `failed` ou `operational_error`. Um controle
positivo malsucedido impede seus negativos dependentes. O relatório contém
digests do request (`request_sha256`), manifest completo (`manifest_sha256`)
e código (`runner_sha256`), além de horários UTC, sem segredo, token ou topologia.
Request e manifest são digeridos separadamente após validação, usando JSON
canônico (`sort_keys=True`, separadores `,`/`:`), codificado em UTF-8. A auditoria
deve preservar privadamente ambos os objetos exatos do wire de execução e a
versão do runner para recalcular os três digests; a referência Git declarada
não substitui o digest do manifest efetivamente fornecido. Mesmo
se todos os casos forem `passed` (`state: measured`),
`native_protocol_acceptance: pending` permanece até auditoria independente do
relatório e do estado instalado. `domain.py` continua retornando pending; não há
importação automática de recibos nem booleano que libere o gate S4. Exit0 vale
para `not_run`/`measured`; falha operacional/controle retorna1 e input inválido2.

## Documentação verificada e limites da fonte

Context7 foi tentado para Samba/pyspnego/ldap3 e retornou quota mensal excedida.
Fallback oficial consultado em2026-11-08:

- [Samba4.25.1 GENSEC Python](https://github.com/samba-team/samba/blob/samba-4.25.1/source4/auth/gensec/pygensec.c): não expõe setter CBT; não presumir API inexistente.
- [pyspnego0.12.4 client](https://github.com/jborean93/pyspnego/blob/v0.12.4/src/spnego/auth.py), [CBT](https://github.com/jborean93/pyspnego/blob/v0.12.4/src/spnego/channel_bindings.py) e [NTLM](https://github.com/jborean93/pyspnego/blob/v0.12.4/src/spnego/_ntlm.py).
- [python-gssapi1.11.1 MIT extensions](https://github.com/pythongssapi/python-gssapi/blob/v1.11.1/gssapi/raw/ext_krb5.pyx) e [tipos exportados](https://github.com/pythongssapi/python-gssapi/blob/v1.11.1/gssapi/raw/named_tuples.py).
- [Python SSL](https://docs.python.org/3/library/ssl.html) e [RFC5929](https://www.rfc-editor.org/rfc/rfc5929).

Testes locais usam pares LDAP/SMB em memória com tokens NTLM reais, credencial
de fixture e chaves de sessão descartáveis; não chamam endpoints, DNS, DC ou KDC.
O ramo Kerberos real não foi executado neste ambiente sem gssapi/MIT: as provas
de enctypes são testes do limite da API, não um ticket AES real. A execução nos
pilotos, instalada/auditada, ainda é obrigatória. Backup/DR e migração municipal
continuam fora desta entrega e de seus gates.
