# samba_ad_pki

S3 manual e inerte por padrão. Defaults `samba_ad_pki_enabled: false`,
`samba_ad_pki_apply: false`, timers/boot policy falsos. Requer um `--limit`
igual à identidade exata, somente tag `samba_ad_pki` e contrato privado
imutável. Não é carregada por site.yml/FIXED_RUNS/deploy automático.

## Contrato e ordem

1. Raiz offline: executar o helper `tools/samba_ad/pki_root.py` **somente** no
   diretório LOCAL protegido de Vinicius, fora Git. Expected UID/hostname,
   algoritmo/tamanho/validade são explícitos. Passphrase por FD herdado,
   nunca argv. Esse módulo não é instalado em CA/DC.
2. CA QEMU própria: lifecycle S1 com bundle tipado `ca`, 2 vCPU/2048 MiB/20 GiB,
   template/placement/política/versões e estado S1/S2 auditados. Não inventar
   prova DC como qualificação CA ou ampliar gates DC. Sem recursos existentes
   ou provas reais, apenas código pode ser validado.
3. `ca_csr`: key intermediária cifrada e CSR gerados no destino qualificado.
   A raiz recebe somente CSR e devolve certificado público pathLen0. Chave
   intermediária nunca transita para o operador/controlador.
4. `trust`: validar criptograficamente raiz/intermediária **públicas** no
   controlador, devolver PEM normalizado e transferir somente esses bytes ao
   destino já identificado. Não instalar trust global ou copiar chave da raiz.
5. `identity`, action `auth_prepare`: seis JWKs independentes geradas nos
   próprios consumidores. Private JWK/JWE permanece no destino; somente
   `auth.public.json` é obtido pelo operador para registro. Não fornecer JWK
   privada/DB/ticket/token em Git, nem cifrado. Passphrase apropriada vem de
   vault/ref em arquivo host protegido previamente disponibilizado.
6. `ca_configure`: registrar seis públicas distintas, aplicar seis templates
   fixos e logger `common`; iniciar somente step-ca loopback. NGINX+njs fica
   configurado e **parado** até obter o leaf externo168h/serverAuth. Binários
   e módulo devem estar pré-instalados, fixados por hash/version/provenance.
   A role não baixa/instala pacotes ou executa curl | sh.
7. `identity`, profile `ca`, action `rotate`: primeiro sign pelo HTTPS nativo
   loopback, cadeia/ServerName validados; chave TLS nova no próprio host.
   Ativar NGINX apenas após validação real do candidato e readback do leaf
   externo. O TLS interno24h/dual EKU é somente detalhe loopback e não um
   perfil externo ou credencial compartilhada.
   O rotador prepara o ancestral runtime protegido antes de `nginx -t`, mesmo
   no primeiro start ou após limpeza de `/run`; só então solicita start/reload.
8. Outros perfis: sign novo por CSR/JWT, nunca renew com chave antiga ou
   rekey mTLS por header. `stage` não ativa/declara consumidor íntegro;
   adapters ausentes são integration_pending. Integração Samba/LDAPS é S4/S5,
   telemetria/coletor/alertas end-to-end são S7 e continuam gates explícitos.

Cada fluxo é invocação separada, sem bootstrap circular. Contratos completos
e exemplos de campos estão em [docs/samba-ad-s3.md](../../docs/samba-ad-s3.md)
e no exemplo inerte `contracts/samba_ad/s3-example.yml`. Configuração operacional
vai ao inventário privado revisado, fora de autoload; nunca neste exemplo.

Antes de qualquer SSH, o controlador valida o manifesto S0 completo e o contrato
fechado, selecionando somente os campos do fluxo pedido. Inputs CA não usados
não são enviados aos DCs. O adapter real fixa estado em `/var/lib/samba-ad-pki`,
trust público em `/etc/samba-ad-pki/{root,issuer}.pem`, material intermediário
em `/etc/samba-ad-ca` e DB em `/var/lib/samba-ad-ca`. Credenciais preexistentes
ficam em `/run/samba-ad-pki-credentials/<perfil>/passphrase`; a passphrase da
intermediária usa `/run/samba-ad-pki-credentials/ca/issuer-password`.
Esses arquivos protegidos são precondições, não criados pelo papel. Caminhos
redirecionados, ancestrais graváveis por terceiros e conta CA compartilhada
são recusados antes de chmod/copy/user. O preflight CA verifica a cadeia pública.

```bash
ansible-playbook -i /caminho/privado/hosts.yml playbooks/samba-ad-pki.yml \
  -e @/caminho/privado/request-s3.yml --limit ca-test --tags samba_ad_pki --check
```

Check/applyfalse faz somente leitura, sem upload de helpers, key/CSR/token,
trust, mkdir, pacote, timer, reload ou escrita persistente. Nenhuma chave ou
serviço operacional foi criado por testes/code-only. Defaults falsos encerram
a role antes de transporte/facts. Depois de boot/machine-id alterados, obter
nova evidência/contrato antes de retomar timer; não aceitar identidade por nome.

## Frontend e limites

NGINX+njs expõe somente POST `/1.0/sign`, JSON ASCII fechado csr/ott, rejeita
duplicados mesmo escapados, query/path alternativo e overrides temporais.
Limites de body/buffer/timeout/rate/conn; erro sanitizado, sem body/JWT em logs.
Upstream HTTPS verifica cadeia e ServerName, sem headers como identidade/mTLS.
Rotas administrativas/revoke/renew/rekey/SSH/ACME/SCEP não são expostas.

Templates fixam SAN/EKU/CA:false/keyUsage, RSA3072/4096 e claims temporais,
jti/audience/CSR-binding. Pedido de CA:true/EKU extra pode ser **coagido para
leaf restrito**, não necessariamente rejeitado por HTTP: aceite exige que
nenhuma identidade/uso proibido seja emitido/ativado, registrando a semântica real.

Revogar leaf não bloqueia novo sign por JWK ativa; retirar/rotacionar pública
comprometida e comprovar readback. JWK nativa pode autorizar revoke de serial
alheio; frontend bloqueia essa rota e backend fica inacessível pela rede.
Não prometer OCSP, CRL efetiva ou revogação instantânea. DB de replay é sensível
e persiste somente no guest, fora do Git. Nada de backup/DR/custódia externa,
retention ou inventário municipal completo nos gates desta entrega.

NGINX/njs/step-ca nativos ainda exigem prova na VM. Teste do módulo njs em Node
exercita o código/contrato HTTP, não prova o parser NGINX, ABI, templates Go,
handshake/reload ou tempo reais. Esses limites não podem virar skips silenciosos.
