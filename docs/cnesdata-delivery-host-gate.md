# EXT3: boundary físico de entrega CnesData

Contrato: [infra-ansible#30](https://github.com/VINIClUS/infra-ansible/issues/30),
v6 ratificado em
[6731115454](https://github.com/VINIClUS/infra-ansible/issues/30#issuecomment-6731115454),
SHA-256 890c569eb4a5c9821c11b4ad63f75e5befa1df1603637f7891f7f3d19e7056c9.
O carrier privado foi nominalmente autorizado em
[6744949900](https://github.com/VINIClUS/infra-ansible/issues/30#issuecomment-6744949900).
Base: EXT2 d6c2fe101f5a5c2287aabc83ed73dd9f9b95f41f;
EXT1 P1/P2 97f8e7e086e3f107401b5eb35ff4017dde21ff34.

Código e testes locais não demonstram Ready nem Produção. Nenhum merge executa
deploy pessoal, apply, DNS, CA, emissão de credenciais ou migração de dados.
Os dados atuais dos dois protótipos são descartáveis; isso não dispensa recuperação
da infraestrutura, isolamento, proveniência, custos ou saúde real.

A composição R2a foi adotada em
[6746258958](https://github.com/VINIClUS/infra-ansible/issues/30#issuecomment-6746258958)
e o handoff público mínimo em
[6746617026](https://github.com/VINIClUS/infra-ansible/issues/30#issuecomment-6746617026).
Runner e host têm um verificador positivo de ClosedReady original; falta,
divergência ou prazo insuficiente recusam deploy/rollback antes de efeitos.
Nenhuma flag dispensa a evidência. #473 termina CLOSED; #474 continua dona de
C/reopen e do aceite global. O produtor real #472/#473 e seus pins integrados
ainda são dependências de Ready. validate não altera a aplicação.

## Interface pública e admissão

O reusable é exclusivamente workflow_call. O caller original deve ser manual,
VINIClUS/CnesData, refs/heads/develop, com run, attempt e source SHA exatos.
Os cinco inputs obrigatórios são strings:

| Input | Autoridade conferida |
|---|---|
| plan_evidence_id | identificador original da evidência de plataforma |
| plan_evidence_digest | SHA-256 original da evidência |
| plan_run_id | run original do plano |
| artifact_id | artifact CI original |
| artifact_digest | SHA-256 dos bytes ZIP publicados no GitHub |

Outputs escalares: status, host_evidence_version, host_evidence_sha256,
platform_evidence_version, platform_evidence_sha256. status pertence a
rejected/accepted/recovery_required; accepted é admissão. A conclusão depende
também do Proof/Receipt/Witness autenticado e da ausência de efeitos pendentes.
host_evidence_version identifica a revisão local; host_evidence_sha256 vincula
os bytes finais recebidos. platform_evidence_version continua sendo a versão
S3 original do produtor, sem upload do host.

O único secret explícito, host_governance, contém referências e pins originais
aprovados. Não contém sessões AWS, chaves SSH ou credenciais Cloudflare. O caller
futuro precisa fornecer a representação aprovada, sem secrets:inherit. A ausência
do secret ou uma divergência bloqueia antes de OIDC. Não se presume que o secret,
seus objetos privados ou o caller consumidor já existam.

A representação privada contém Binding fechado v6, envelope original, allowlists
de workflows/images, checks obrigatórios com app_id, source_files por SHA e hash,
archive_member exato, runtime_sha256, runtime_contract_sha256, plan_run_id e região.
O cost_handoff conserva os quatro objetos originais cost/stage/evidence/manifest
e é validado pelo mesmo contrato EXT1, incluindo somas gross, datas, FREE ACTIVE
e bindings. Nenhum literal pass substitui a medição. Os campos runner
identificam role ARN, objetos S3/version/hash/size, os três parâmetros SSM,
hostname/known_hosts e versão/checksum do cloudflared. O fragmento host fixa slot,
porta, hostname, bytes esperados de readiness e checkpoint Nginx. Esses valores
são configuração do owner; nenhum input público ou frame escolhe comandos,
paths, scripts, URLs de objetos, pins ou overrides.

O bootstrap lê a API do attempt atual, identifica o reusable efetivo em
referenced_workflows e baixa o runtime daquele commit. Não usa github.sha como
SHA do reusable. Antes de OIDC, o Python repete a autenticação, develop containment,
checks obrigatórios, arquivos de origem e attempt CI. A data de criação do
artifact precisa estar estritamente dentro do intervalo do attempt original.
O SHA do ZIP, os bytes do archive e todos os compromissos do envelope concordam.
Uma assinatura histórica não recebe TTL novo.

## ClosedReady original e handoff entre jobs

O job literal `closed-ready` do caller `.github/workflows/promote-production.yml`
executa os adapters #472, conserva seus bytes originais de close/drain e PhaseB,
e reobserva membership/permit após B. Publica o artifact único
`cnesdata-closed-ready-<run_id>-<run_attempt>`. Seus três membros exatos são
`close-drain.json`, `phase-b.json` e `closed-ready.json`; máximo ZIP2MiB,
descomprimido1MiB. Os schemas fechados completos estão na adoção R2a acima.

Ambos os verificadores descobrem esse artifact na API repo-scoped original.
Conferem source closure, run/attempt, job concluído com sucesso, criação dentro
do intervalo original, hashes ZIP/membros e todos os bindings. Artifact GitHub
não tem run_attempt próprio: nome derivado, endpoint de jobs do attempt,
intervalo e fonte aprovada são cumulativos. `source_files` deve incluir o caller
e `scripts/promotion/{environment_gate,phase_b,verify_routes,promote_api}.py`
no source SHA aprovado. Não se reescrevem config.json, manifest, archive CI ou A2.

O bundle prova CLOSED da mesma promotion/version, permit=null, membership
inteira sem pending/unknown, proofs originais de execução terminal/ausência
comprovada/send-disabled e checkpoint/rotas após B. A source closure do produto
mantém exclusão durante o host; canary, C e reopen dependem da resposta anterior.
GitHub concurrency ou um booleano do caller não provam esse boundary.

O produto não prevê generation/head do host. Após admissão, o host observa seu
CAS real e grava `closed-ready-binding.json`, ligando o hash original ao head,
geração e binding físicos. O watchdog confere esse vínculo a cada efeito/tick;
o process proof o compromete, e Proof/Receipt o vinculam pela cadeia existente.

O artifact `cnesdata-host-handoff-<run_id>-<run_attempt>` é **público**, com um
único `host-handoff.json` limitado32KiB e retenção1dia. Contém somente a whitelist
adotada: identidade pública do run/reusable, status, commitments de request/
ClosedReady/resposta/proof/receipt/witness, operação/binding/geração e decisão de
recovery original segura ou null. Resposta SSH e diagnóstico completos ficam
0600 no host/job e nunca entram no upload. `clock_boot_id` da decisão original é
um commitment com domínio separado; UUID físico, ARN, path, token, campo extra
ou decisão sensível recusam projeção, sem redigir e alterar seus bytes.

No recovery autenticado, o step gate escreve os cinco outputs existentes e
publica a projeção antes do step final falhar o job. Consumers #473/#474 devem
usar condição explícita pós-falha, autenticar job/steps/source/attempt/intervalo,
hashes e bindings, e importar a mesma decisão/D_rec. Ausência de resposta ou
handoff mantém unknown/CLOSED; nunca fabrica sucesso ou outro choice_at.

## Transporte, instalação e isolamento

Entrada SSH: três frames com prefixo uint64 big-endian de oito bytes, sem quarto
frame nem bytes após EOF. Limites: envelope 64 KiB, tar.gz 16 MiB comprimidos e
descomprimidos, token 16 KiB. O archive contém somente release-manifest.json,
compose.yml e config.json. Manifest embutida é idêntica aos bytes canônicos
externos. Duplicatas, traversal, links, devices, diretórios e extensões PAX/GNU
são recusados antes de staging.

O token GitHub entra por pipe, nunca por argv, ambiente do Python/SSH, logs ou
ledger. O host o mantém em memória e, quando necessário para GHCR, no Docker
config temporário 0700 em /run; ambos são limpos no exit tratado. Credenciais
Cloudflare usam o mecanismo de ambiente documentado do client access ssh,
somente no subprocesso isolado, nunca em argv ou logs. O host key é fixado por
known_hosts e comparado ao fingerprint original antes da conexão.

As quatro roles são disabled-by-default. O playbook exige enable explícito,
um --limit exatamente igual ao inventory_hostname, a tag
personal_platform_delivery, checkpoint do host e evidência de smoke LimnoPulse.
A instalação prepara o forced-command e os diretórios, valida sshd/nginx, mas
não recarrega SSH/Nginx nem inicia a aplicação. A conta não recebe Docker group,
forwarding ou sudo genérico. O único sudo é o interpretador e arquivo root-owned
com --host; as ações SSH são validate/deploy/rollback-previous.

O código novo físico fica em host_gate.py; a closure instalada inclui também
contract.py do EXT1 integrado, com bytes e hash verificados antes de executar seu
validador de custo. Ambos usam standard library, sem imports de checkout/cache.
O SDK boto3 fica exclusivamente no gate hospedado, com runtime-requirements.txt
fixado no mesmo producer e instalação --require-hashes. cloudflared exige versão
imutável e checksum original, sem latest. O helper físico requer Python, Docker
Compose, Nginx, OpenSSL e AWS CLI já governados pelo preflight.

Nginx altera somente o include CnesData. Os outros apps e suas rotas permanecem
fora de seu escopo. O origin fica em loopback; CF-Connecting-IP só é restaurado
do peer loopback do Tunnel e é descartado no upstream. CORS pertence ao FastAPI.
Firewall sem inbound 22/80/443, Tunnel, host key e smoke real são critérios
operacionais próprios, não inferidos da presença desses arquivos.

## Autoridade, lease e tempo

O ledger root-owned 0700 fica em /var/lib/personal-platform/deployments. Registros
imutáveis 0600 são fsync/readback antes do único rename da Authority, que contém
lease e head juntos. Não há bucket, tabela, uploader AWS ou store remoto novo.
CAS compara a snapshot inteira, preservando binding, nonce, generation, revision,
checkpoint anterior e pins. A expiração sozinha nunca permite takeover.

O lease é host-wide, 300s, para workflow/humano/systemd e todos os apps.
Só o readback efetivo de um CAS de renovação aumenta expires_at. O watchdog
verifica owner/CAS e tempo antes de cada efeito e a cada continuação. No pior
caso exige margem estritamente maior que 120+20+15+1 = 156s. Renovação falha
ou ambígua é latched, mesmo que o lease anterior ainda tenha validade.
Processos usam grupos próprios; cancelamento percorre INT/TERM/KILL e comprova
ausência do grupo em até 15s. Isso não comprova cancelamento remoto AWS/Docker.

A janela fixa é min(close confirmado+1800s, deadlines originais). Ela não inclui
o lease renovável no mínimo. Cada etapa tem deadline fixado ao iniciar; budgets
futuros nunca são recreditados durante a etapa. Recovery é uma escolha
irreversível com teto min(F, choice+420s), descontando tempo de parede real,
inclusive auditoria/requests. Reboot, regressão monotônica e descontinuidade
de relógio bloqueiam sucesso. Receipts não antecipam timestamps de eventos.

O conjunto de probes operacionais no host permanece exatamente unit/recovery/API.
São as sessões originais temporárias do owner, sem novo AssumeRole no host gate.
O helper confere o principal real e faz GET SigV4 da sonda fixa de objeto ausente:
NoSuchKey 404 é distinto de AccessDenied 403. Não há quarta role, RunTask,
PassRole de verifier, cross-assume ou escrita no semáforo.

## Efeitos, evidência e recuperação

SEND_PENDING é durável antes do envio. Timeout, falha de transporte ou resultado
incerto preservam membership e effect_possible; incrementar generation não os
apaga. Close mantém a lista antiga até reconciliação autenticada. CLOSED_READY
exige nenhum pending/unknown. Reopen confere as três revisões literais
unit/recovery/audit da mesma activation; somente o readback real preenche
reopen_verified_at. Resposta de open perdida significa recovery, sem afirmar
CLOSED e sem auto-close ou retry.

O produto continua dono de fence/permit/dispatch, plans e applies B/C, canaries e
retention. As operações kernel close/confirm_closed/closed_ready/reopen recebem
o boundary original autorizado do produto; elas não criam autoridade AWS no host.
Cada plan seguinte é produzido sobre o checkpoint real anterior e auditado antes
do apply do mesmo binário. Nenhum plan futuro fictício ou replan durante apply é
aceito como preparação. O wiring consumidor desses handoffs precisa ser conferido
no ensaio integrado; este repositório não modifica o consumer #473 nem o produto.
O CLI host não invoca esses callbacks nem inventa close a partir de seu relógio.
Importa close/F/expirations e deadline API do bundle autenticado. A admissão
original reserva180+840+420; transporte/OIDC/SSH gastam a mesma etapa. Cada efeito
e continuação conserva restante da etapa,840s posteriores,420s de recovery e
lease>156 simultaneamente. Clock Date/RTT/skew/quantização usa margem conservadora
que só encurta. Recovery importa D_rec e convergência<=choice+300, sem reset420.
Campos de fence não observado permanecem null no receipt físico. A conclusão
física da API precede C/reopen de #474; somente a conjunção das evidências
originais concede aceite global dentro dos1800s.

O host mantém os bytes originais para uma única consulta de diagnóstico. A
repetição autenticada consome AVAILABLE→CONSUMED via CAS/fsync antes da resposta.
Não renova lease, credencial, entrada ou artifact, nem renderiza/reenvia efeitos.
Perda após CONSUMED exige recovery revisada. E/W históricos retêm o nonce original
e não se tornam evidência aceita para a nova conexão.

A cadeia de evidência é:

1. Observação física de H/R e Proof sobre fatos concluídos.
2. Receipt E imutável com observed_at do H/R anterior; fsync e leitura exata.
3. Witness W posterior com início/fim reais da leitura de E.
4. Bytes finais da resposta congelados; índice I contém seu SHA-256.
5. Fsync/readbacks posteriores de W/I e envio no mesmo SSH autenticado.

O índice não entra no hash da própria resposta. Nenhum objeto contém timestamp
de seu próprio readback futuro. Guardas valem entre todas as etapas. Perda de
autoridade durante E/W/I não transforma um receipt já serializado em sucesso.
O gate verifica nonce, binding, hashes, tempos e chegada dentro do lease confirmado
e deadlines originais. Evidência copiada depois não altera o evento observado.

## IAM, custo e gates de Produção

host_gate=null preserva o seed e os dois outputs EXT1 existentes. Habilitado,
adiciona o leaf github.host_deploy_role_arn; o fragmento não é shared_outputs v2
completo. Trust usa customized sub de ref develop e job_workflow_ref por SHA.
Não copia o contexto environment:production exclusivo dos gates infra.

Permissões Allow são somente GetObjectVersion por objeto/version exatos,
GetParameter nos três leaves /cnesdata/deploy e Decrypt por chave/service/context
exatos. Há Deny de cross-assume, PassRole, RunTask, escrita/listagem S3,
mutação SSM e operações de cifra/assinatura KMS. Não há leitura de outro app.
EXT1 e EXT2 mantêm seus oito inputs/quatro outputs e ABI/purposes originais.

Ready exige handoffs originais autenticados e suas retenções/readbacks, claims
OIDC reais, contexto IAM efetivo, instalação com todos os modificadores sob o
mesmo lease, clock/CRL/CA e credenciais temporárias reais, recuperação e budgets
ensaiados, transporte e consumer integrados. Os arquivos de configuração, probes,
checkpoints e sessões reais não são fabricados por testes.

Produção exige EXT5/EXT6: LimnoPulse aceito primeiro e smoke antes/depois de
qualquer mudança compartilhada. Demonstrar isolamento/origem inacessível,
concorrência, stale recovery, refresh de cliente, cleanup, rollback exato e
Tunnel. Manter produto <=USD8, agregado <USD15, freeze ao atingir15,
Actions pagos USD0 e CloudFront FREE ACTIVE exato; não usar crédito ou fallback
pago como prova. Deploy-develop e Actions do personal-infra-live permanecem disabled.
