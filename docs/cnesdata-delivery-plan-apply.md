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
- [Closure de conteúdo e purposes](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6716699477),
- [Resolver de fontes do bootstrap](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6718141241),
- [Capacidade e pin das session policies](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6718506538).
- [Deploy legado somente manual](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6720657218).
- [Path actionlint](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6715872832).
- CnesData `7ebc0e3dc024617b33903577c87dac3ca6fba529`, arquivo
  `docs/superpowers/specs/2026-11-07-phase-a-contract-amendment.md` (A3).

#468 continua dono do único schema futuro `release/plan-apply-evidence.schema.json`.
Os validadores explícitos deste produtor verificam o contrato documental agora, sem
importar arquivo futuro nem ignorar validação se ele não existe. Compatibilidade do
schema e pin imutável serão conferidos antes de Produção. Não há schema rival.

## Deploy legado do repositório infra-ansible

O workflow `.github/workflows/pipeline.yml` mantém Validate hospedado em PR,
push em `main` e chamada manual. Merge/push em `main` somente valida: o job
`Deploy production` exige `workflow_dispatch`, ref `refs/heads/main`, repositório
`VINIClUS/infra-ansible` e o booleano `inputs.deploy_production == true`.
O input é opcional e tem default `false`; uma chamada manual sem opt-in apenas valida.
PRs, inclusive de forks, nunca habilitam o runner self-hosted desse job.

Para uma execução de Produção autorizada separadamente, abrir Actions →
Validate and deploy → Run workflow, selecionar a branch `main` e marcar
`deploy_production`. Validate precisa concluir com sucesso nessa mesma execução
antes do deploy. A capacidade manual conserva o manifest validado e sua conferência
contra `GITHUB_SHA`, environment `production`, concurrency `ansible-production`
sem cancelamento e o comando restrito `sudo /usr/local/sbin/infra-ansible-deploy`.
O booleano usa o contexto `inputs`, que preserva o tipo, conforme a
[documentação oficial do GitHub](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onworkflow_dispatchinputs).

O aceite de Código verifica essa fronteira no YAML real: PR/fork, push/merge,
manual sem opt-in ou com `false`, branch/tag ou repositório incorreto são negados;
somente manual/main/repositório esperado/`true` habilita o job após Validate.
Aceite de Código e merge não autorizam uma chamada de Produção. O aceite de
Produção continua dependente das decisões dos owners, auditoria do SHA exato,
checks obrigatórios e handoffs existentes; este patch não modifica settings do
environment nem comprova apply. O caller CnesData em `develop` e os reusable
workflows continuam com suas próprias fronteiras, independentes desse deploy legado.

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

A criação do artifact deve estar estritamente entre `run_started_at` e `updated_at`
da tentativa autenticada: `run_started_at < created_at < updated_at`. Igualdade com
qualquer borda é recusada antes de baixar o ZIP, inclusive em R2. Os timestamps
aceitos têm precisão de segundos; run ID, SHA e digest não distinguem tentativas
que compartilhem um segundo. Não há garantia documentada de separação mínima de
um segundo entre tentativas, nem se afirma uma colisão observada em produção.
Esta regra conservadora também pode recusar um artifact legítimo criado no mesmo
segundo de uma borda; uma janela sem segundo estritamente interior não admite
artifacts. O produtor deve republicar com metadados autenticados inequivocamente
internos à tentativa, sem ajustar timestamps ou inventar precisão/campos de API.

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

### Correções do round de auditoria de a2da20a

O resolver IAM independente usa blobs Git do checkout de produto SHA40 autenticado.
Rejeita fontes alteradas, untracked, symlinks e paths fora dos módulos fechados;
confere todos os inputs gerados compartilhados com plan.variables e a conta governada.
Um único orçamento cobre precheck, bind e verificação integral das sete policies
Phase A ou das nove instâncias bootstrap. ACM não admite policy IAM alterada.
Escopo each/count e nomes vêm das fontes. Apenas identidades de producers podem
resolver ARNs desconhecidos; policies e fingerprints de state/API não autorizam grants.
Depois do apply, o documento integral, nome e role de cada policy têm de coincidir
com fonte, state e GetRolePolicy, com inventário completo de readbacks.

O kernel próprio deriva de CnesData a06f84fb82a90705f6f2df371609ff687dbbaead e recebe
o delta imutável 80e6451a2c995905183a30a0775f98a68b1f6c10: sort/setunion até 128,
deduplicação antes do limite; concat/for/splat continuam 64. A extensão bootstrap
admite somente os formatos/funções ratificados. try está restrito ao parser observado
da API role e captura apenas erros dinâmicos de null/index. Descrição heredoc estática
é metadata lexical ignorada, sem admitir heredoc como expressão. Os 30 arquivos HCL
de fixture mantêm os hashes de CnesData 00370142815870a90ea3e7790c7a9465fb3e7aaa;
oracles fixos verificam os 16 documentos integrais e suas mutações.

A prova histórica de plan usa o inventário independente de seus seis baselines e,
para Phase A, phase-inputs; nunca exige o futuro artifact planned do deploy.
O deploy mantém seu próprio inventário com planned e verifica a ligação à prova original.
O retorno ECR fresco é retido e readback antes do processo de produto, e novamente
ligado ao drift aplicado, aos readbacks posteriores e ao checkpoint. O drift original
do plan é preservado; ambos os digests de apply.drift comprometem os bytes retidos.

Este round exige nova CI hosted no SHA final e auditoria independente antes de merge.
Positivos nativos da nova session policy continuam pendentes até essa execução;
os testes puros com identidades sintéticas não constituem evidência de Produção.

### Session policy gerenciada e prova original do owner

A extensão S3 cria uma managed policy por role na própria raiz delivery, com ARN
determinístico e uso exclusivo como session policy. Não há attachment de identidade
ou uso como permissions boundary. Os paths novos estão enumerados no
[complemento de caminhos](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6719681668),
sem novo A3, workflow input, shared_outputs, reader role ou transporte.

A autorização efetiva é identity intersectada com a união de managed e inline;
qualquer Deny aplicável prevalece. A managed exclui dados S3/List/multipart e todo
KMS de seu NotAction geral, restaura state/.tflock/coordination e metadados de produto
em seus escopos finitos e preserva os Denys. A inline contém somente current/history
de evidência: Get/Decrypt para os escopos admitidos, Put/Encrypt/GenerateDataKey para
o current, com Deny explícito de Put nos históricos. Os testes cobrem buckets e CMKs
iguais/distintos, sem negar buckets/CMKs inteiros que também atendem state/produto.

O pin privado `session_policy_pins` contém conta/role/ARN próprios, root source SHA,
DefaultVersionId esperado, documento integral/hash, observação/expiração, freeze do
epoch e producer owner. Não é autoridade sozinho: o mesmo admission_reference e
os reports tipados existentes têm de carregar as medições ORIGINAIS do owner,
autenticadas novamente por API/bytes/proof. Report de consumidor, fatos ausentes,
datas estendidas, binding de outro plan ou versões/documentos misturados fecham antes
do pedido OIDC. A medição pública transporta commitments; o documento fica privado.

Após STS, a própria sessão retornada faz GetPolicy/GetPolicyVersion/GetPolicy antes
do export: ARN/default/version/documento exatos e AttachmentCount e
PermissionsBoundaryUsageCount zero. A verificação se repete antes do lease e do
processo privilegiado. Owner deve serializar/fixar default e conteúdo durante todo
o epoch; não há alegação de binding atômico entre STS e versão IAM. As roles delivery
não podem administrar versões/attachments das policies de sessão.

Policy e todos os PolicyArn enviados somam no máximo 2048 caracteres ASCII, com no
máximo dez managed policies; capacidade packed/utilization inválida nega antes do
export. O builder mediu 1934/1936 caracteres nos casos sintéticos plan/deploy com
input-run autenticado agrupado e receipt anterior. Isso é medição de documento,
não prova AWS. Se o grouping não for demonstrado, preserva as três chaves exatas e
pode negar por capacidade; não reduz ARN nem amplia namespace para caber.

Grouping exige exatamente phase-inputs.json/candidate.json/promotion.json sob o
prefixo dedicado phase-inputs/source40/run/attempt já governado, o payload completo
autenticado, purpose correto e a reserva medida pelo owner no report original.
Só essas três chaves e seus hashes são consumidos. A leitura de outros membros
desse único prefixo não os transforma em inputs. Não há VersionId map/carrier novo.

A [ratificação multipart r2 do owner](https://github.com/VINIClUS/infra-ansible/issues/28#issuecomment-6721134447)
exige Deny explícito de s3:AbortMultipartUpload e s3:ListMultipartUploadParts nos
objetos evidence aplicáveis, e de s3:ListBucketMultipartUploads no bucket evidence.
O helper Python governado usa somente put_object condicional, Body em bytes e
BucketKeyEnabled=False, sem transfer manager ou chamadas multipart.
CreateMultipartUpload, UploadPart/UploadPartCopy e CompleteMultipartUpload
compartilham a autorização s3:PutObject: as credenciais ainda permitem essas APIs
no escopo PutObject. Os três Denys e a seleção single-put do helper não comprovam
proibição IAM universal nem o comportamento de outros clientes, inclusive
backend/provider OpenTofu; esse limite deve constar da evidência operacional.
A ratificação não concede aceite de Código, Ready, merge ou aceite operacional:
continuam obrigatórios auditoria independente e CI nativa verde no HEAD final,
além de readbacks e evidências reais do owner para os aceites de Produção.


### Preflight de Schedulers e checkpoint de versão do state (P1/P2)

Sob o lease, antes de `apply` do binário salvo, os valores resolvidos de
`plan.json.variables.scheduler_recovery_task_definition_arn` e
`scheduler_audit_task_definition_arn` devem coincidir literalmente com recovery/audit
em `processor_task_definition_arns` do state **anterior**, com mapa unit/recovery/audit
completo e revisões válidas. Defaults vêm do JSON autenticado do binário; tfvars do
caller e outputs candidatos não substituem esse check. Saída parcial/desconhecida ou
divergência fecha antes do child. Ausência, null ou mapa vazio só admitem estágio
inicial demonstrado sem revisões ECS/Schedulers prévios e ambos inputs null, incluindo
a primeira Phase A depois do bootstrap. Phase A conserva as rotas anteriores; este
controle não implementa nem autoriza futuros propósitos B/C.

A leitura específica da única key de state produto conserva, no mesmo GetObject,
bytes e metadata real: o campo privado `state_object_before` do `attempt.json` e
`state_object` do `checkpoint.json` têm exatamente `status`, `version_id` e
`etag_sha256`. Objeto existente exige status `present`, VersionId opaco não vazio,
diferente de `null`, e SHA-256 do ETag UTF-8; ausência real (NoSuchKey/404) usa
`{status: absent, version_id: null, etag_sha256: null}` e só permite o estágio inicial
acima. A identidade A3 lineage/serial/hash permanece como definida no contrato;
VersionId/ETag não são publicados no A3, index, ABI ou redacted-plan.

Antes de um novo apply, autentica-se o receipt original do run planned, seu index,
envelope/package/binário, checkpoint e lease; o state atual deve ter a mesma versão
observada nesse checkpoint além de lineage/serial/hash. Nova leitura imediatamente
antes do child detecta alterações durante init/preflight. Mesmo bytes/hash/ETag com
VersionId diferente são divergência. Planejamento também recusa troca de identidade
ou versão durante sua própria operação. O attempt é escrito e relido antes do child;
uma falha parcial preserva a versão anterior e o checkpoint planned original, sem
publicar checkpoint terminal de sucesso. Retry concluído compara o checkpoint
aplicado original, inclusive a versão, e só devolve o receipt original após readbacks;
não adquire lease, executa produto nem grava/publica novo resultado.

Em divergência/falha ambígua, conservar os checkpoints privados e a coordenação e
pedir recovery revisado ao owner do backend. Restore de uma versão identificada é
operação manual separada: exige permissões, retenção e readback reais do owner;
o gate não faz restore, import, replan ou liberação automática. Não se adicionam
GetObjectVersion/ListBucketVersions às roles delivery e não se leem outros states.
Versões do state compartilhado continuam responsabilidade dos respectivos owners.
A dispensa de migração/preservação dos dados de aplicação dos protótipos não dispensa
este controle de state/plan de infraestrutura, identidade e proveniência.
