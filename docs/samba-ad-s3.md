# Samba AD — S3 / PKI

Código de execução manual, sem pin operacional ou infraestrutura criada. A raiz
fica offline em diretório LOCAL protegido de Vinicius, fora do Git e dos DCs/CA.
Nenhuma chave privada, JWK privada, DB PKI ou ticket/token entra no Git, mesmo
cifrado. Passphrases apropriadas usam ansible-vault/referências protegidas;
nunca valores por argv, logs, facts persistentes ou diff.

## Fronteiras e contratos

O entrypoint é `playbooks/samba-ad-pki.yml`/role `samba_ad_pki`, com fluxo
explícito trust, ca_csr, ca_configure ou identity. Cada chamada exige limit/tag
exatos e uma única identidade. Defaults e exemplo público são inertes. Material
operacional fica no inventário privado revisado, sem autoload; propostas no SDD
ignorado não são inventário/aprovação. A role consome executáveis já instalados
e verificados; aquisição/proveniência/egress são precondições técnicas reais.

`samba-ad-ca-substrate-bundle/v1` aceita somente a CA QEMU 2 vCPU/2048 MiB/20 GiB
do manifesto privado, com evidência do mesmo template/nó/política e pareceres
S1/S2 reais. Reusa o lifecycle S1; não amplia consumer DC, sizing ou qualificação
de dois nós. A revisão privada imutável é a raiz operacional de confiança:
hashes verificam coerência, não autenticam um parecer por si.

O request `samba-ad-pki/v1` tem defaults `enabled: false`, `apply: false`.
Validação fecha os campos, vincula perfil/host ao snapshot S0 inerte, máquina,
boot, paths protegidos, trust público fixado, credencial individual e provenance.
Configuração ausente não ativa nada. Check/apply=false não geram chave, CSR,
JWT, arquivo, trust, download, timer ou reload; fazem somente preflight de leitura.

O controlador valida o S0 completo e seleciona somente o fluxo solicitado antes
de qualquer SSH. Contratos fechados recusam campos extras e material PEM bruto;
inputs CA não usados não seguem para os DCs. O adapter produtivo usa caminhos
fixos: `/var/lib/samba-ad-pki` para identidades, `/etc/samba-ad-pki/root.pem` e
`issuer.pem` para trust público, `/etc/samba-ad-ca/intermediate.key.pem` para
a intermediária cifrada e `/var/lib/samba-ad-ca` para seu DB. Não apontar esses
campos para diretórios de outros serviços. Referências de credenciais são
`/run/samba-ad-pki-credentials/<perfil>/passphrase` e
`/run/samba-ad-pki-credentials/ca/issuer-password`; os arquivos já devem existir
com proteção apropriada. Guardas de leitura recusam symlinks, ancestrais
graváveis por terceiros e conta `samba-ad-ca` preexistente com UID0, home/shell
ou grupo incompatíveis antes dos módulos de arquivo/usuário.

Seis perfis: dc01/dc02/ca têm SAN único e serverAuth; telemetry_dc01,
telemetry_dc02 e telemetry_ca têm SAN do emissor e somente clientAuth.
Certificados duram exatamente168h; tentativa inicia em0.60 da validade e deve
concluir antes de0.66, limite conservador anterior a dois terços. Não reutilizar
chave TLS; a JWK de autenticação é uma credencial distinta, gerada/mantida no
próprio consumidor, com somente a pública registrada no emissor.

O verificador criptográfico inicial aceita RSA3072/4096 com SHA256, cadeia
fechada raiz/intermediária/leaf, intermediária pathLen0 e EKU/SAN/keyUsage exatos.
Comprova assinaturas, pins públicos, tempo, CA:false, correspondência da chave
e SPKI diferente da geração anterior. Não implementa revogação online ou path
building arbitrário. Algoritmos/validades dos emissores e pins reais são entradas
privadas explícitas, nunca gerados pelo exemplo público.

## Rotador no destino

O módulo `pki_root` é exclusivamente local e não vai no pacote online. Usa
expected UID não-root/hostname explícitos, diretório0700 canônico fora do Git,
raiz cifrada e recusa de sobrescrita. `sign_intermediate` valida CSR sem
extensions arbitrárias e assina somente a pública com CA:true/pathLen0; a chave
do emissor não é recebida pelo operador. O helper `pki_material` no guest CA
gera essa chave cifrada e CSR após validar bundle específico e identidade viva.
O check não lê passphrase nem gera key/CSR; uma saída parcial exige inspeção
direcionada, nunca recriação cega. Não prova isolamento físico/offline por flag.

Passphrases apropriadas são resolvidas pelo caminho Vault aprovado e
disponibilizadas como arquivos protegidos no destino; a role recebe referências,
não valores. O módulo raiz recebe passphrase por FD herdado apenas no processo
local. A role só transfere PEMs **públicos normalizados/verificados**, sem slurp
ou fetch de chave privada. Exportação da pública JWK é etapa administrativa
direcionada; nenhuma privada do consumidor é registrada em `encryptedKey` na CA.

`python3 -m tools.samba_ad.pki_runtime` recebe JSON `{request,manifest}` por stdin;
sem `--execute` opera em check. `--request-file` aceita somente arquivo protegido.
Somente referências/caminhos são argumentos. Toolchain pré-instalado deve ter
hash/version/provenance aprovados; o helper não baixa/instala pacotes.

Emissão nova usa CSR assinado com chave local nova e JWT ES256 por perfil, com
audience canônica, TTL curto, jti e vínculo SHA256 ao CSR. O helper valida o JWT
retornado pelo signer local antes do HTTPS, sem imprimir claims/token. No CLI
candidato0.31.0, `crypto jwt sign --subtle` é necessário para claims completas
via stdin: desliga somente a exigência local de flags, não verificações do
emissor/TLS. O payload tem precedência sobre defaults; token/segredo/jti não
passam em argv. Essa interface depende da versão fixada/verificada do CLI.

Staging usa diretório0700, chave0600, lock exclusivo, arquivos exclusivos e
fsync. Um único `active.conf` aponta para fragmento imutável que contém ambos
os paths da mesma geração. Não há duas aberturas de cert/key através de um
ponteiro móvel. Troca, reload e conexão TLS nova precisam concordar com o leaf
validado. Falha restaura geração anterior válida e faz readback; erro na
reversão é estado degradado, nunca sucesso. Depois do sucesso, descarta apenas
a geração anterior da transação própria, sem política de backup/retention.

Como rename pode ocorrer antes de fsync falhar, qualquer exceção anterior ao
commit reconcilia o ponteiro efetivo sob lock antes de limpar a geração. Mesmo
que a reversão renomeie de volta, falha de durabilidade continua degradada;
quando possível, o serviço é recarregado e observado na geração anterior.
Material possivelmente ativo não é removido. O commit da ativação é fsync mais
readback TLS válido, anterior à publicação das métricas. Se essa publicação
falhar, a ativação comprovada permanece e o helper retorna erro de reporting
degradado. O último timestamp verdadeiro disponível é conservado também nos
sinais de falha; nenhum timestamp representa uma ativação revertida.

`expected_active` manual fixa o digest do fragmento anterior. Modo `managed`
para timer aceita somente ponteiro/fragmento canônico da geração própria,
verificada criptograficamente, e mantém lock/readback de drift; não adota
configuração arbitrária. Boot/machine-id mudados exigem revalidação privada.

`stage` retorna referência opaca de geração, sem ativar serviço. Adapter `pending`
não produz sucesso fictício; rotate devolve integration_pending antes de gerar
material. Samba precisa ser entregue/integrado por S4/S5 e já ter geração
gerenciada para o adapter real; não provisionar/iniciar Samba nesta etapa.
Telemetria depende do transporte/consumidor S7. Atualização efetiva desses
consumidores e alertas end-to-end permanecem gates explícitos posteriores.

Sinais locais incluem last_check, último sucesso real de rotação, prazo,
notAfter e falha de tentativa por perfil. Uma checagem sem rotação não avança
o timestamp de último sucesso. Arquivo de métricas/estado é privado no destino;
S7 entrega coleta autenticada, alertas e detecção de timer/coleta ausentes.

## Limites da versão candidata do emissor

step-ca0.30.2 gera nova chave para seu TLS nativo, mas lifetime24h com backdate1min
e EKUs server/client. Esse certificado fica **somente no backend loopback**;
não é o leaf externo168h/serverAuth nem credencial distribuída. `crt/key` da
configuração são da intermediária, não paths de leaf do listener.

O endpoint externo será NGINX+njs com sign por CSR/JWT; nenhum header representa
mTLS. `/rekey` exige peer TLS real e não resolve perfis serverAuth-only;
`/renew` conserva chave. Revogação passiva bloqueia renew/rekey do serial, mas
não novo sign com JWK ainda ativa. Credencial comprometida exige retirada/rotação
da JWK pública e readback. Não prometer OCSP, CRL efetiva ou revogação instantânea.

O logger JSON/text do step-ca inclui OTT bruto. Configurar `logger.format: common`,
cuja whitelist CLF exclui token/certificado/erro arbitrário, e verificar ausência
de vazamento no runtime. Frontend/helper não logam body/auth/query/PEM privado.
O NGINX descarta seu error log nativo em `/dev/null`: o formatter pode anexar
request-line/query em falhas anteriores ao njs, inclusive limite de body.
Seu access log contém apenas status, bytes e duração numéricos. Não basta
sanitizar o handler JS. A prova nativa futura deve inserir sentinelas em URI/query
e provocar body oversized com Content-Length/chunked, erros do parser de
request-line/headers, rejeições njs e falhas upstream, verificando ausência em
stdout/stderr/journal e presença dos sinais sanitizados. Essa prova não foi feita
por renderer/Node nem substituída por reduzir o nível de severidade do logger.
DB persistente armazena replay tokens e é material sensível fora do Git.

Backup/recovery/DR, custódia externa e inventário municipal completo estão fora
dos entregáveis e gates. Migração municipal/DNS/DHCP é trabalho separado;
somente clientes piloto novos nesta entrega.

Fontes: [step-ca0.30.2](https://github.com/smallstep/certificates/tree/6e8ec61405239cf3f37b2bbf260a587b7d2e4e31),
[step-cli0.31.0](https://github.com/smallstep/cli/tree/8301c0dfb1546ccddb808375b9f9311be03c2ba9),
[policies](https://smallstep.com/docs/step-ca/policies/),
[revogação](https://smallstep.com/docs/step-ca/revocation/).
