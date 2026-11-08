# Gates de infraestrutura CnesData

Este produtor fornece dois reusable workflows, somente `workflow_call`, e duas roles
OIDC separadas. O caller do CnesData continua manual (`workflow_dispatch` em `develop`).
Este código não executa apply no merge, não cria um provider OIDC, não cria buckets/CMKs,
não altera o host e não fornece o fragmento host_deploy_role_arn.

Autoridades imutáveis desta implementação:

- [Contrato técnico f880 e R1](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6715994616),
  documento SHA256 `f880c40365efeb5622e699cbcf3faa35371e7b22da50ef7cec8d375d002fca66`.
- [Outer A3 e exceção exclusiva R2](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6716076093).
- [Custo por etapa](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6716241666).
- [ACM/bootstrap inicial e outputs](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6716490764).
- [Closure de conteúdo e purposes](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6716699477).
- [Path actionlint](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6715872832).
- CnesData `7ebc0e3dc024617b33903577c87dac3ca6fba529`, arquivo
  `docs/superpowers/specs/2026-11-07-phase-a-contract-amendment.md` (A3).

#468 continua dono do único schema futuro `release/plan-apply-evidence.schema.json`.
Os validadores explícitos deste produtor verificam o contrato documental agora, sem
importar arquivo futuro nem ignorar validação se ele não existe. Compatibilidade do
schema e pin imutável serão conferidos antes de Produção. Não há schema rival.

## Workflow ABI e fronteiras

Ambos exigem oito strings: `request_descriptor`, `request_descriptor_sha256`,
`contract_repository`, `contract_source_sha`, `contract_path`, `contract_sha256`,
`expected_source_sha`, `purpose`. As saídas são `evidence_run_id`,
`evidence_artifact_id`, `evidence_artifact_digest`, `evidence_status`.
Purpose é somente `acm-certificate`, `bootstrap` ou `phase-a`.

O descriptor é um locator fechado, não uma prova autodeclarada. Ele contém
`schema_version`, `repository`, `source_sha`, `producer_pins`, `baseline_artifacts`,
`payload_artifact`. Dependências são a lista ordenada e única de
`{repository,source_sha,content_sha256}` governada. Referências de artifact contêm
exatamente repository/run_id/run_attempt/artifact_id/artifact_digest/workflow_path/
workflow_sha/source_sha; digest externo tem prefixo `sha256:`. Plan inicial não exige
o binário que ainda produzirá; deploy exige o artifact planned exato. Não há input de
URL, script, tfvars, backend, target, lock, parallelism ou destroy arbitrário.

`github` e checkout padrão pertencem ao caller. Antes de carregar helpers, o bootstrap
inline consulta o run autenticado e deriva o SHA real de `referenced_workflows` para o
path exato do reusable em SHA40. Busca somente a lista fixa de helpers naquele SHA.
Não faz checkout do produtor em github.sha, de input arbitrário, branch ou tag. O gate
compara esse pin à configuração governada e autentica novamente source/ref/workflow,
develop containment, checks e artifacts antes de solicitar OIDC. Reexecuta a admissão
no job privilegiado e imediatamente antes de assumir a role.

`producer.workflow_path/workflow_sha` no A3 identificam o workflow CALLER CnesData.
O reusable externo tem seu próprio pin separado na procedência/dependências. A exceção
R2 permite somente o workflow criador do candidato em revisão posterior ao source
histórico; seus metadados reais e os seis artifacts R1/dez checks continuam vinculados
e recompostos pelo produtor de promoção allowlisted. Ela não relaxa source de A3 ou
phase-input. R2 mantém seus bytes existentes, inclusive seu LF; A2 usa NUL e nenhum LF.

## Governança e capacidade real

A configuração `CNESDATA_DELIVERY_GOVERNANCE` vem do secret de DADOS revisados do environment
protegido `production`, nunca de workflow inputs ou de `validated:true` do caller.
Ausência de configuração ou de qualquer prova fecha o gate. Configuração não é aceite
de Produção: precisa de readback, revisão e handoffs reais dos owners.

Campos de configuração usados pelo executor: authority/activation_enabled, region,
account_id, roles.plan/deploy, gate_shas, dependencies, required_checks,
proof_producers, contract_sha256, baseline_artifacts, admission_reference;
state_bucket/state_kms_key_arn, evidence_bucket/evidence_kms_key_arn/evidence_prefix;
baseline com dependencies/toolchain/backend/cost_context/cost_evidence/cost_manifest;
product_inputs, cost, policy_sha256/policy_evaluator_sha256, readbacks e drift_matrix.
artifact_references/artifact_purposes fixam o conjunto exato governado: seis baselines
backend/policy/cost/drift/shared-outputs/toolchain, mais phase-inputs ou planned quando
aplicável; R2/promotion só por nome explicitamente allowlisted. Cada content_sha256
é o hash da lista canônica de TODOS os membros {name,size,sha256}, ordenada por name.
O ZIP tem digest externo separado; membro extra/omitido/alterado ou purpose trocado falha.
Phase A acrescenta release/phase_a_inputs, ecr_repository e os commitments privados
phase_input_objects (phase-inputs.json/candidate.json/promotion.json).
Esses dados não são credenciais nem um token para ler producers privados. Usar secret
de environment impede que o bloco env do runner publique ARNs/configuração privada;
nenhum secret/settings foi criado por este código. Credenciais STS geradas são
registradas no masker do runner antes de GITHUB_ENV. A configuração real não está neste repositório.

O executor usa SDK boto3/botocore com wheels e dependências hash-pinned, timeout sem
retry oculto, S3 ExpectedBucketOwner, SSE-KMS e writes condicionais. Código PR/local não
instala SDK nem acessa AWS. OIDC usa somente token efêmero do job e STS
AssumeRoleWithWebIdentity; não há chave estática/root ou cross-assume. Tokens/credenciais
não entram em argumentos, artifact ou log. Erros privados são reduzidos a um tipo seguro.
OpenTofu 1.13.2 e conftest 0.71.1 são instalados somente no runtime hospedado protegido
com archives SHA256 fixados. O lock/provider selecionado e bytes dos executáveis são
conferidos contra a governança. Não há provider upgrade/replan no apply.

O publisher executa o bundle imutável de upload-artifact em dist/upload/index.js com
Node24.11.1. Um passo actions/github-script v8 em SHA40 recebe ACTIONS_RUNTIME_URL,
ACTIONS_RUNTIME_TOKEN e ACTIONS_RESULTS_URL do NodeScriptActionHandler real do runner;
valida, mascara e exporta antes de qualquer credencial AWS. ScriptHandler de run não
fornece essas variáveis sozinho. A ausência fecha o gate antes de OIDC. O subprocesso
uploader recebe somente uma allowlist de metadados/runtime, sem governança, GITHUB_TOKEN
ou AWS; seus command files são privados e vazios, nunca o GITHUB_ENV que transporta STS.
RUNNER_TRACKING_ID permanece nos filhos para permitir cleanup do runner em cancelamento.

## A3, bytes e evidência

Outer fechado, ambos status:
`{schema_version,status,plan,apply,plan_binding_sha256}`. Planned exige apply=null;
applied preserva o mesmo plan e acrescenta receipt apply. Binding externo e dentro de
apply é SHA256 dos bytes canônicos de plan; o próprio outer não entra nesse hash.

Documentos A3: UTF-8, sort Unicode codepoint recursivo, compact comma/colon, ensure_ascii
false, um LF. Sem normalização Unicode, duplicatas, BOM, NaN/Infinity ou dados extras.
State integral usa Decimal sem perda, plain decimal sem expoente/zeros excedentes e
-0 vira 0. Entrada/saída <=128MiB, token/coefficient <=1024, abs exponent/expansão <=4096
antes de formatar. `1e999999999`, inclusive zero com esse expoente, falha sem expansão.
Vetores: `1.2300` → `1.23\n`, `1e-3` → `0.001\n`, `-0` → `0\n`;
`{}` → `{}\n`, SHA256 `ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356`.

Binário/plan.json/lock/archive/provider/policy e candidato R2 têm hashes dos bytes crus.
state_sha256 cobre TODO o JSON integral do backend incluindo secrets, nunca projeção;
seu plaintext nunca entra em artifact. outputs_sha256 cobre o mapa allowlisted completo.
Package lista arquivos de conteúdo (name/size/sha256), ordenada e única; aggregate é
hash dessa lista canônica, não do ZIP/envelope. São obrigatórios plan.bin, plan.json,
inputs.tfvars.json e redacted-plan.json. Máximos: 32 arquivos, binário32MiB, JSON128MiB, total192MiB;
envelope262144 bytes. Sem extras não declarados, links ou traversal.

Backend normalizado inclui workspace:"default", type:"s3", bucket, key, region,
encrypt:true/use_lockfile:true/kms_key_id. identity_sha256 inclui TODOS esses campos e
é conferido contra o backend/workspace efetivos. Produto usa
`cnesdata/prod/opentofu.tfstate`; produtor delivery usa
`shared/cnesdata-delivery/prod/opentofu.tfstate`. Não são intercambiáveis.

Envelope completo, binário/JSON/inputs e reports sensíveis ficam somente no S3 privado
governado de EXT2. GitHub recebe index.json sanitizado, redacted-plan.json e reports medidos com hashes e
compromissos, não ARNs/state/segredos/URLs assinadas. Index é transporte, não envelope
concorrente. Index inclui admission_proof inline; cada report seguro vem no mesmo
artifact e tem `{check_id,source_sha,measurement}` fechado, measurement não vazio,
hash observado = canonical(measurement). Expected/observed iguais não bastam sem repo,
run/attempt/workflow/code pin allowlisted autenticados e bytes reais dos reports.

A entrada admission usa proof.json + reports. A saída usa index.json + reports, e um
artifact posterior separado receipt.json. Nenhum objeto contém seu próprio artifact
ID/digest. A etapa privada pós-OIDC confere bytes/commitments e todas projeções do index
antes de mutação de produto. Não publica arquivos que contenham state/ARNs privados.
GITHUB_TOKEN não lê producers privados de outros repos: sem handoff público sanitizado
COMPLETO e autenticado do owner, Produção permanece fechada; hashes/locator não bastam.

## Projeções privadas e vista pública

A vista pública redacted-plan.json tem exatamente view_version=1, repository,
source_sha, purpose, plan_json_sha256 e changes. Cada mudança traz address_shape,
address_sha256, type e actions; read/no-op não entram. Todos os índices de endereço
viram [redacted]; o hash do endereço original usa UTF-8 cru sem LF. Ordenação é por
shape/hash. A vista é recomposta dos bytes privados, obrigatória no package e publicada
junto do index e reports, sem valores tfvars/plan/state.

ACM executa plan somente com target aws_acm_certificate.static_web. Seu output privado
tem exatamente acm_certificate_arn e acm_dns_validation_records, uma lista singleton
{domain,name,type,value} para cnesdata.com.br/CNAME. Não avalia outputs alheios do root;
ARN/registro são lidos do state e da API, conservando bytes, inclusive ponto terminal.
Bootstrap aceita somente a etapa inicial autenticada, mesmo certificado já ISSUED,
state anterior exclusivamente ACM e inputs runtime/canary nulos/desabilitados.
PENDING_VALIDATION no state anterior pode permanecer byte-idêntico enquanto a API
confirma ISSUED; o saved plan aprovado contém o snapshot refrescado correspondente.
State com runtime/canary ou bootstrap anterior falha, sem reset ou novo deploy.
Outputs privados bootstrap são exatamente cloudfront_distribution_id,
cloudfront_domain_name, free_subscription_binding_input={distribution_arn,web_acl_arn}
e bootstrap_invariants. A tupla é conferida diretamente em CloudFront/WAF/ACM;
invariantes exigem active_unit/state_machine/canary_release null, retained_units=[],
schedulers recovery/audit null e canary_storage=false.

## Custo por etapa

Objeto cost do A3 e do index é idêntico. Common8: verdict/evidence_sha256/
manifest_sha256/product_monthly_usd/aggregate_monthly_usd/paid_actions_limit_usd/
calculated_at/expires_at. Valores monetários são strings de centavos, produto<=8,
agregado<15 e paid Actions0. Não usa AWS account Free Tier.

PRE: scope pre-activation, cloudfront plan/status null, activation/dns/workloads blocked,
unbound_monthly_usd obrigatório. Só ACM/bootstrap inicial com checkpoint de etapa
governado/autenticado e guardrails medidos. Exposição bruta UNBOUND não recebe desconto
FREE ou créditos; se não couber8/<15, negar. Não pode regredir depois de ativação.
ACTIVE: scope active, cloudfront FREE/ACTIVE e subscription/distribution/waf binding
SHA256, observed_at/expires_at reais. Obrigatório Phase A e após #476 Produção2,
inclusive tentativas tardias chamadas bootstrap; outra distribuição/aplicação falha.

Check fixo cost-ledger-purpose-scope. O report tem measurement.cost SEM evidence_sha256;
o hash externo do report tipado completo liga cost.evidence_sha256. Manifesto financeiro
é outro documento, sem seu próprio hash: ledger bruto sem créditos, componentes e
somas; cifra/assinatura usam CMKs distintas e ambas são contadas, além de
S3/requests/versões/logs/CloudFront/WAF. Chave ENCRYPT_DECRYPT não assina. O código não
fabrica ACTIVE nem um producer EXT2 ainda inexistente.

## Lease, execução e R1

Objeto separado no state bucket:
`shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json`. Não é state nem
.tflock; tofu cria seu lock nativo. Sem -lock=false, precriação ou DeleteObject no lease.
Ausente adquire com If-None-Match; renovação/liberação confirmam dono e If-Match ETag.
TTL300, renovação60, reserva120. Expirar NUNCA permite takeover. Tombstone released
mantém checkpoint e exige run anterior success + receipt final autenticado antes de
outra aquisição automática; este executor conserva recuperação manual fechada quando
essa prova não está disponível. Não usa concurrency GitHub como CAS.

Watchdog controla grupo de processos, falhas/ambiguidade/cancelamento interrompem antes
da margem; SIGINT10s, SIGTERM5s, SIGKILL, provar grupo vazio. Sem alegar rollback.
Lease ambíguo fica retido. Não há cleanup always() que libere dono alheio.
Relógio monotônico usa Date autenticado/RTT<=20/skew<=30; reserva1+30s. TTL do plan<=3600,
admissão exige1980s em plan/insumos/credencial, tofu<=1800, término15/finalização45,
conclusão/publicação antes expires_at−120. Sem capacidade/margem, não começa operação.

Checkpoint exclui envelope/lease; CAS released grava checkpoint hash. Lease evidence
congela SOMENTE até esse CAS, sem index/envelope/final publication. Depois envelope
liga lease hash, é publicado/readback S3; index e receipt externo são publicados e
verificados por bytes/digest/API dentro da MESMA janela45 sob watchdog (R1). Metadata
do index/receipt pode ser do run atual in_progress. Só confirmação terminal success e
identidade externa posterior do receipt podem chegar depois; não estendem prazo nem
alteram completed_at. Ausência/falha mantém recovery_required. Não há hash circular.

Apply faz apenas `tofu apply <binário-exato>`; não executa nenhum plan refresh-only.
Antes, state/lineage/serial/hash devem coincidir exatamente e os valores funcionais
vêm do snapshot refrescado aprovado do plan original. Depois, state deve corresponder
a todos os valores conhecidos desse plan, resolvendo somente seus unknowns, com conjunto
exato de recursos/atributos e outputs. Readbacks diretos comparam valores, não apenas
hashes escolhidos de respostas inteiras. drift_matrix é privada, source/purpose-bound,
com matrix_version=1, source_sha, purpose, before e after; cada linha traz address,
attribute, readback (índice do report), path (componentes JSON) e encoding identity/json.
Toda propriedade de todo recurso managed existente na etapa exige uma projeção;
cobertura ausente, extra, duplicada, encoding desconhecido ou valor divergente falha.
Essa rigidez pode negar propriedades sem projeção observável: não existe matriz real
de produção neste PR, e sua construção/revisão é handoff bloqueante de Ready. A lista
não vazia de APIs/hashes, sozinha, nunca declara drift integral clean.
Phase A repete
readback ECR conta/us-east-2/repo exatos, IMMUTABLE, manifest/config/media/blob originais
sem recompressão e linux/amd64; todo digest deve coincidir com promoção #469/R2/A2/plan.

Antes da mutação há attempt.json privado write-once e readback com owner/session,
backend, state_before e plan binding; timeout parcial sem receipt exige recuperação
humana auditada. Retry de apply já concluído autentica receipt terminal-success,
envelope/index/lease anteriores e verifica state_after/outputs/readbacks atuais e
coordenação inalterada. Retorna IDs do artifact original; não cria applied fictício,
novo receipt, nova revisão ou filho ToFu. Expiração continua negada antes de OIDC.

## OIDC/IAM e validação

Provider compartilhado é data por ARN governado; readback URL/client IDs/thumbprint,
nenhum managed provider novo. O narrow amendment troca §4.1 SOMENTE para estes gates:
repo/context/job_workflow_ref com environment production, audience sts.amazonaws.com,
subject exato com SHA integrado/auditado/CI-verde. Trust tem prazo revisado e roles
distintas, deny cross-assume. Null github_delivery conserva default fechado e RA intacta.
Output github fornece somente infrastructure_plan_role_arn/infrastructure_deploy_role_arn.

Policies discriminam state/lock/lease/evidence/CMK/PassRole. Product writes são ações
finitas e ARNs revisados sem wildcard; unscopable creates ficam omitidos. CloudFront
CreateCachePolicy/CreateOriginAccessControl/CreateResponseHeadersPolicy não suportam
escopo por instância/condition produto: nenhuma exceção global está concedida aqui.
Isso, capacidades de criação, boundary/SCP efetivos, bucket/CMK grants e provas reais
continuam gates operacionais antes de Produção, sem interpretar ARN como permissão.

CI existente pipeline.yml:46 chama native_bootstrap e:55 pytest. Somente o bootstrap
ganhou actionlint1.7.7, archive SHA256
023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757; teste executa ambos
workflows, falta/versão incorreta falha sem skip. Casos nativos usam source exato,
provider cached e mocks em user+network namespace; sem AWS e sem apply.
Handoff pós-merge registra workflow refs SHA40, root/lock/contrato/dependency digests,
BASE/HEAD e CI auditado. Não fechar #28 Produção apenas com Código.
