# Spec de integracao do application (P02): decisoes DD-1 a DD-7

> **Estado:** proposta para ratificacao. Esta spec recomenda e nao ratifica: toda recomendacao abaixo e "proposta, aguarda ratificacao" da coordenadora em infra-ansible#55, exceto as decisoes do dono marcadas (O19-O22, O24; DD-1, DD-6 e a parte do O22 no DD-7). Nenhum codigo, teste, workflow ou doc de contrato muda neste PR. Registro de decisao: infra-ansible#55 comentarios 7024515854 e 7038419407 (ordem unica de PRs, IDs P01a..P33, em 7038419407 §3).

**Pins lidos:**
- IA = infra-ansible `b9760be354d86d1f0faab025fdec15a09638d75b` (`main`; o codigo e identico ao de `be2f6b52`, pois o PR #83 so adicionou a spec dos produtores). Prefixo `tools/cnesdata_delivery/` salvo indicacao.
- CD = CnesData `258e55c58ea9109c4c4a35fc519ab9292027a4b0`.

Convencoes: `AG`=`application_gate.py`, `LC`=`lifecycle_contract.py`, `LR`=`lifecycle_runtime.py`, `HG`=`host_gate.py`, `ct`=`contract.py`, `rt`=`runtime.py`, `so`=`session_owner.py`, `DOC`=`docs/cnesdata-delivery-application-lifecycle.md`. `REU-plan`, `REU-deploy`, `REU-app` e `REU-host` sao `.github/workflows/reusable-cnesdata-infra-plan-gate.yml`, `...-infra-deploy-gate.yml`, `...-application-gate.yml` e `...-host-deploy-gate.yml`. `CD:` marca citacao do CnesData. Toda citacao `arquivo:linha` foi lida no pin; onde a linha vem de um doc ja mergeado, ele e nomeado. Perguntas ao dono: O18 em diante (O17 ja existe em `docs/cnesdata-delivery-producers.md` §8, item 17).

## 0. Resumo

Fatos que ancoram tudo (leitura do codigo, nao opiniao):
- Cada chamada de plan ou de deploy e um reusable com dois jobs, `validate` e `execute`, ambos com `environment: production` (`REU-plan:60-62,128-130`; `REU-deploy` nas mesmas linhas). O environment `production` do CnesData tem um revisor obrigatorio e nenhum `wait_timer` (medido, §6.2). Logo cada chamada custa **2 pausas de reviewer**.
- Cada etapa do lifecycle e plan + audit independente + deploy: o deploy recusa sem `approval.json` do job de audit (`LR:1348-1354`; `DOC:48`). A estimativa anterior contava 6 pausas para a preparacao; o minimo pelo codigo e 8 pausas nas quatro chamadas de plan/deploy (`observer-bootstrap` e `operational`, plan e deploy cada) e mais as do audit (DD-5), 10 no desenho atual.
- Cada comando tofu so e admitido se o seu proprio `timeout` couber antes do deadline: `LifecycleWatchdog.run` chama `phase_capacity(operation_seconds=timeout)` (`LR:898-902`), e `phase_capacity` exige `now + operation_seconds + 157 < preparation_deadline` antes do fence (`LC:1550-1552`). Um `tofu apply` (timeout 120, `LR:1372`) so pode **comecar** ate 623 s depois do acquire. Na cadeia de DD-1, o ultimo `apply` e precedido por 11 operacoes tofu (4 `init`, 2 `plan`, 4 `show`, 1 `apply`), cujos tetos somam 620 s (`LR:1331,1340,1341,1366,1372`).

| DD | Recomendacao (proposta, aguarda ratificacao, exceto as decisoes do dono marcadas: O19-O22, O24) | PRs afetados |
|---|---|---|
| DD-1 | Preparacao em tres tempos, `observer-bootstrap`, `inventory`, `operational`, com o mode-canary co-aplicado na etapa `operational` (1C); a alternativa sem mode-canary na janela (1A) so se o primeiro `execute` nao precisar de `accepted-open` (O19) | P14, P16, P19, P25, P27, P28 |
| DD-2 | Job `closed-ready` do caller vira sonda que espera; o keeper publica o artefato `cnesdata-closed-ready-*` no proprio job; host gate e trust inalterados | P13, P14, P27 |
| DD-3 | Gatilho externo so onde um job do caller publica (host, phase-c-*); interno onde o journal do keeper ja tem a observacao (static, unit); uma emenda por transicao | P14, P15, P16, P17 |
| DD-4 | A regra de aceite vive no handler do adapter (reaproveita `_unit_checks`, `accept_mode_canary`, `freeze_proof`); o keeper valida forma, compromissos e `accepted is True` | P13, P16, P17 |
| DD-5 | Audit como reusable proprio de job unico, com role e trust proprios (nao um terceiro job no plan/deploy) | P11, P12, P19, P22, P28 |
| DD-6 | A estimativa e **negativa** para o desenho atual; o dono decidiu (O20, O21, O24) manter um revisor por job, a janela de 900 s e 60 s por pausa: replanejar para o desenho C (`validate` dobrado no `execute`, 6 pausas) | P10-P17, P25-P30 |
| DD-7 | `finish` e `publish_terminal` no processo do keeper; `lifecycle_terminal_job` = o proprio job do application; a conclusao do run depende de O22 | P17, P27-P30 |

Resultado do S unico (§8): **um S unico serve a Phase A e ao application**, imposto pelo produto e pelo host gate; o caminho critico de 10 nos nao encurta.

Respostas do dono em 2026-11-20 (§9): O19 `accepted-open` no primeiro `execute` (DD-1 1C decidida); O20 e O24 um revisor por job, `validate` dobrado, 60 s por pausa; O21 janela de 900 s mantida; O22 terminal `failed-*` fica vermelho. O18 segue aberta.

## 1. DD-1: ordem e conteudo da preparacao em 900 s

**Questao.** O que roda entre o acquire e o `prepared`, em que ordem, e o mode-canary entra ou nao?

**Evidencia.**
- O keeper fixa `preparation_deadline = clock + 900` (`AG:2119`), exige `clock + 158 < deadline` no acquire (`AG:1559`) e limita o contexto de modo de promotion a 900 s (`LC:972`). O que sobra para o close-drain e a reserva de 157 s (`LC:1552`; `AG:1975-1980`).
- O evento `prepared` e a conclusao do job `application-prepare-operational / execute` do reusable de **deploy** (`LC:440-441`, `AG:1258-1261`), com os oito arquivos de `FENCE_PREPARE_FILES` (`LC:453-455`). O handler `prepared` tambem exige a publicacao do **plan** `operational` do mesmo run (`AG:1949-1972`) e roda o close-drain (`AG:1993-2022`).
- Os modos de prepare admitidos pelo oraculo sao `observer-bootstrap` (cria `static_observer`) e `operational` (cria `static_normal` e `static_recovery`) (`LC:1342-1349`). O `inventory` so e admitido em `application-prepare` (`LC:203-207`), usa a sessao `sp-i-*` do observador e o nome da sessao nao depende do plano (`DOC:808-812`).
- Sessoes estaticas e de modo sao por run: o binding inclui `run_id`, `run_attempt` e `generation` (`LC:213`, `LC:1200-1221`). Os roles nao podem ser aplicados antes do run. O trust do role `static_normal` depende de `static_plan_sha256`, que vem do `inventory` (`LC:213-243`; `CD:scripts/promotion/_api_static_records.py:101`): o `inputs.json` do plan `operational` precisa do resultado do `inventory`.
- O mode-canary: o runtime o recusa hoje (`LR:1358`); o portao estrutural e de oito enderecos (`LC:1288-1323`); promotion tem oito sessoes `mc-*` (`LC:173-181`). `accepted-open` exige `unit`, `recovery` e `audit` (`AG:78-84`), logo exige modos.

**Opcoes.**

| Opcao | Chamadas plan/deploy | O que muda |
|---|---|---|
| 1A: `observer-bootstrap`, `inventory`, `operational`; sem mode-canary na janela | 4 (+ 2 audits) | Gate: nada novo no oraculo. O primeiro `execute` nao alcanca `accepted-open` (faltam unit, recovery, audit), so os terminais `failed-*`. |
| 1B: 1A + mode-canary como terceira etapa (plan, audit, deploy) | 6 (+ 3 audits) | Gate: remove `LR:1358` com oraculo completo (P16). Pausas e maquina somam 50 por cento (§6.3): nao cabe em nenhum cenario medido. |
| 1C: 1A com os oito enderecos de modo co-aplicados no plan/deploy `operational` | 4 (+ 2 audits) | Gate: `validate_delta` da etapa `operational` passa a admitir tambem os oito enderecos (`LC:1326-1405`, `LC:1288-1323`); o conjunto fechado de modos (`LC:1343`) ganha uma forma. Reusables: nenhum novo. CnesData: um `inputs.json` carrega `static_promotion` e `mode_canary` (`CD:infra/opentofu/env/prod/variables.tf:1-41`). Risco: dois oraculos num plano so. |

**Decidido pelo dono (O19, 2026-11-20): 1C**; o primeiro `execute` deve alcancar `accepted-open`. Recomendacao original (proposta): **1C**, na ordem `observer-bootstrap` (plan, audit, deploy), `inventory` (adapter), `operational` com modos (plan, audit, deploy). 1B e inviavel pela conta do §6. 1A e a escolha se o dono aceitar que o primeiro `execute` termine sem `accepted-open` (O19). O `inventory` precisa de um gatilho dentro do `application-prepare` (hoje `STAGE_TRIGGERS` so liga `prepared` e `phase-b`, `LC:1230`): o evento e o job `observer-bootstrap / execute` do deploy concluido com sucesso, mesmo padrao de `stage_event_source` (`AG:1265-1282`). O resultado do `inventory` chega ao job que monta o `inputs.json` do plan `operational` pelo mesmo canal do DD-2.

**Nao determinado pelo codigo.** Quem produz o `inputs.json` privado do plan `operational`: os testes usam `input_jobs: {}` nesse passo (`tests/test_cnesdata_delivery_lifecycle.py:511,523`) e o catalogo ainda nao modela um job de entrada. P19 e P25 fecham.

**PRs afetados.** P14 (handler e gatilho do `inventory` no keeper), P16 (oraculo com modos), P19 (catalogo `lifecycle_steps` e montagem), P25 (gerador de `inputs.json`), P27 e P28 (cadeia de jobs do caller).

## 2. DD-2: canal keeper para caller (closed-ready, host-gate, host-outcome)

**Questao.** Quem publica `cnesdata-closed-ready-<run>-<attempt>`, quem libera o `host-gate`, e como o `host-outcome` obtem `closed_ready_sha256`.

**Evidencia.**
- O verificador do host exige, no run original do caller, **um unico job de nome literal `closed-ready`**, `completed`/`success` (`HG:4894-4904`), e o artefato `cnesdata-closed-ready-<run_id>-<run_attempt>` com `job.started_at < artifact.created_at < job.completed_at` (`HG:4906`, `HG:4934-4936`), tres membros exatos `close-drain.json`, `phase-b.json`, `closed-ready.json` (`HG:4940-4955`). A amarra entre artefato e job e so o nome e esse intervalo.
- Hoje o job `closed-ready` do CD e um placeholder que sai com erro (`CD:.github/workflows/promote-production.yml:67-79`); `host-gate` e `host-outcome` dependem dele (`:82`, `:99`) e `host-outcome` le `needs.closed-ready.outputs.closed_ready_sha256` (`:128`).
- O keeper roda o run inteiro: o job do application so conclui no terminal (`AG:2046-2063`, `DOC:544-546`: nenhuma saida de reusable). Ele ja consome o artefato publico do host (`HOST_JOB`, `AG:1756-1765`; `authenticate_host_handoff`, `AG:1826`) e ja publica artefatos (`publish_terminal`, `AG:351`; o `REU-app:142-150` traz o SDK de artefatos).
- O `host-gate` nao tem pausa de reviewer (`REU-host:49-99` nao declara environment) e roda dentro da janela API de 180 s (`LC:1225-1227`).

**Opcoes.**

| Opcao | O que muda |
|---|---|
| 2a: o job do application e o `closed-ready` | Impossivel sem reescrever o host gate: o job precisa estar `completed` (`HG:4903-4904`) e o keeper continua rodando durante o host. Exigiria trocar o nome literal e o conceito de job concluido no `HG`, no trust e nos inputs do `host-outcome`. |
| 2b: sonda + artefato do keeper | O keeper sobe o artefato de tres membros no proprio job. O job `closed-ready` do caller vira sonda: comeca junto com o application, espera o artefato aparecer, confere os tres membros e conclui, expondo `closed_ready_sha256`. Host gate, `HG` e trust do host: inalterados. Gate: o keeper ganha a publicacao (P14), com o limite de 2 MiB e 1 MiB (`HG:4940-4955`). A latencia da sonda (intervalo de poll mais conclusao do job e fila do `host-gate`, ~8 s por analogia com poll de 5 s e fila de 2 s mais setup de 1 s) consome parte dos 180 s da janela API (`LC:1225-1227`); o intervalo de poll e escolha de P27. CnesData: o placeholder (`:67-79`) vira a sonda (P27). |
| 2c: dispatch ou saida de reusable | Fora da regra fechada do DOC (`DOC:544-546`); exige emenda e muda o trust. |

**Propriedade de confianca da 2b.** O artefato passa no verificador porque nasce dentro do intervalo do job sonda (`HG:4934-4936`). A sonda nao cria nem assina bytes: os tres membros carregam os compromissos do keeper (`HG:4628-4668`), e o caller que contem a sonda e medido pela source closure (`HG:4857-4864`). Falha segura: se a sonda iniciar depois do upload, o intervalo falha e o host recusa. O keeper deve conferir, pelo inventario de jobs do run, que o job `closed-ready` esta em andamento antes de subir (padrao `_same_run_job`, `AG:1217`).

**Recomendacao (proposta, aguarda ratificacao): 2b.** O `host-gate` segue `needs: [preamble, closed-ready]`, entao a sonda concluida libera o host sem sinal extra; `host-outcome` mantem a fonte do hash.

**PRs afetados.** P13 (adapter produz os tres membros), P14 (publicacao pelo keeper), P27 (sonda e `needs`). Dependencia aberta: o `referenced_workflows` com varias chamadas (DR3, `LR:42`, `LR:837-840`) vale tambem para a sonda.

## 3. DD-3: estagios depois do API

**Questao.** Gatilho e fonte de cada transicao depois do API, um por transicao (`DOC:893-898`).

**Evidencia.**
- `STAGES` tem sete estagios (`LC:1225-1228`) e `STAGE_TRIGGERS` so liga `application-prepare -> prepared` e `phase-b -> phase-b` (`LC:1230`); depois do `phase-b` a janela vira `api` e o proximo evento recusa `stage trigger not connected stage=api` (`AG:1273`; teste `tests/test_cnesdata_stage_events.py:876`). O comentario em `LC:1228-1229` exige uma emenda por transicao.
- O padrao de evento externo: job do mesmo run com nome do catalogo, `completed`/`success`, artefato `lifecycle-<step>` criado dentro do intervalo (`AG:1265-1282`).
- Ja existem no keeper o consumidor do host handoff (`AG:1826`), `run_closed_ready` (`AG:1911`) e `publish_static_closed_ready` (`AG:1732`). `publish-static` roda no estagio `static` e `retire-static` em nenhum (`LC:203-207`).
- O R16 (retirar versoes dentro de 60 s) nao cabe (`DOC:881-891`).

**Opcoes e recomendacao (proposta, aguarda ratificacao).** A regra: gatilho externo so onde um job do caller publica; interno onde o journal do keeper ja contem a observacao.

| Transicao | Gatilho recomendado | Fonte |
|---|---|---|
| prepare, apos o `observer-bootstrap` | externo | deploy `observer-bootstrap / execute` com sucesso (DD-1) |
| prepare para close, close para B, B para api | existentes | `LC:1230`, close CAS |
| api para static | externo | `host-gate / execute` com sucesso mais o host handoff autenticado (`AG:1759`, `AG:1826`) |
| static para unit | interno | observacao `publish-static` liquidada no journal e `publish_static_closed_ready` (`AG:1732`) |
| unit para phase-c-recovery | interno e externo | aceite do `unit` (DD-4), depois o deploy `phase-c-recovery / execute` |
| phase-c-recovery para phase-c-audit | externo | deploy `phase-c-recovery` mais aceite do modo `recovery` (DD-4) |
| phase-c-audit para final | externo | deploy `phase-c-audit` mais aceite do modo `audit` (DD-4); o `final` e interno (DD-7) |

R16: o remedio (teto por run, `DeleteObjects` em lote ou uma execucao `static-maintenance` posterior) segue em aberto como decisao da coordenadora na ratificacao (D-C1). Ate la o estagio `static` nao retira versoes.

**PRs afetados.** P14 (api), P15 (static, R16), P16 (unit, C-recovery, C-audit), P17 (final). Cada PR reescreve o teste que fixa o stop (`T-SE:876`) e o conjunto fechado de call sites (`tests/test_cnesdata_application_gate.py:5445-5490`).

## 4. DD-4: regras de aceite de unit, recovery, audit e restoration

**Questao.** Quando um modo esta aceito e o que prova `restoration` (`DOC:652-668`).

**Evidencia.**
- `finish()` recusa os tres terminais porque o registro nao tem validadores de `unit`, `recovery`, `audit`, `restoration` (`AG:78-92`, `AG:1876-1883`; `tests/test_cnesdata_application_gate.py:7235`). O registro `mode-canary v2` nao tem campo de veredito (`DOC:652-657`).
- A regra de aceite ja existe no produto: `_unit_checks` aceita o `unit` quando a execucao e `SUCCEEDED` na maquina da rota, todas as tasks `STOPPED` na revisao da rota com exit 0 e ha saida (`CD:scripts/promotion/mode_canary.py:286-299`); `accept_mode_canary` aceita `recovery` e `audit` (`CD:scripts/promotion/phase_c_recovery.py:414`); o `audit` ainda exige `freeze_proof_sha256` (`CD:scripts/promotion/phase_c_audit.py:27`).
- `rollback-api-static` cobre so o canal estatico (`CD:scripts/promotion/rollback_api_static.py:116-160`); `unit`, `recovery`, `audit`, `api` e `first_static_absent` nao decorrem dele (`DOC:658-663`).
- Os formatos de `routing` e `terminal-readback` sao SINTETICOS (`AG:100-102`); o produto nao tem handler (`CD:scripts/promotion/promote_api.py:107-109,189-192`).

**Opcoes.**
- (a) O handler do adapter roda a regra do produto e emite uma observacao fechada `{accepted, checks, compromissos}`; o validador do keeper confere forma, hashes dos originais e `accepted is True`. Justificativa: o handler e as funcoes de aceite sao codigo do produto autenticado em S pelo manifesto de fonte (`AG:14-58`; P09/P10, D6), e a observacao compromete os hashes dos originais; risco residual declarado: o produto julga o proprio aceite. Isso difere do DD-5, onde o audit tem de ser independente de quem faz o deploy; aqui o produto ja e a fonte de varias observacoes dos validadores existentes (`AG:97-98`; as de host e de decisao de recuperacao tem outra origem).
- (b) O keeper reimplementa as regras. Gate: mais codigo num `application_gate.py` (hoje 137 954 B, cerca de 53 por cento do teto de 256 KiB por arquivo do closure, `LC:616`; sobram ~124 KB).
- (c) Acrescentar um campo de veredito ao `mode-canary v2`: muda o contrato do produto e os vetores.

**Recomendacao (proposta, aguarda ratificacao): (a).** `restoration` exige, alem da observacao do `rollback`, os handlers `reopen` e `terminal-readback` e uma prova de API e primeira publicacao estatica ausente: definir o formato fechado em P13/P17 com as regras acima. O que significa "operational-pending" (`DOC:261`) continua indeterminavel pelo codigo e sai do aceite.

**PRs afetados.** P13 (handlers e observacoes), P16 (validadores `unit`, `recovery`, `audit`), P17 (`restoration`, remocao do rotulo SINTETICO).

## 5. DD-5: veiculo do audit independente (`approval.json`)

**Questao.** O deploy recusa sem `approval.json` de um job de audit independente; nao ha produtor nem veiculo.

**Evidencia.**
- O plan so publica `plan.bin`, `plan.json`, `inputs.json`, `checkpoint.json` (`LR:1342-1345`); o deploy le `approval.json` do payload e o amarra a plano, inputs e checkpoint (`LR:1348-1356`). `main(role)` so aceita `plan` e `deploy` (`LR:1493`). Nao ha reusable de audit; nenhum codigo do CD produz `approval.json`.
- O approval carrega `delta`, `drift_matrix` e `readbacks` before/after (`LR:1348`), entao o job precisa de leitura AWS e de escrita privada no namespace do step.
- A identidade AWS vem de `sub` e `job_workflow_ref` (`LR:1437-1478`, `opentofu/cnesdata-delivery/oidc.tf:79`): dois jobs do **mesmo** reusable tem o mesmo `sub` e o mesmo `job_workflow_ref`, entao o trust AWS nao distingue o job de audit do job `execute` do plan.
- `validate` nao tem `id-token` nem AWS (`REU-plan:66-70`): nao serve como audit.

**Opcoes (com o custo no orcamento do DD-6).**

| Opcao | Trust e gate | Custo na janela |
|---|---|---|
| 5a: reusable proprio `reusable-cnesdata-infra-audit-gate.yml`, job unico | role `audit` com trust no seu `job_workflow_ref` (quinto valor de X* no apply unico da raiz de entrega, N7); novo arquivo na superficie pinada e nas listas de arquivos; `main` aceita `audit` | 1 job (~19 s de maquina medida por analogia) e 1 pausa por etapa |
| 5b: terceiro job `audit` dentro do reusable de plan | independencia so por job, sem separacao no trust AWS | igual a 5a, sem arquivo novo |
| 5c: audit dentro do `validate` do deploy | `validate` nao tem AWS nem escrita privada | 0 pausas extras, inviavel sem mudar permissoes e quebra a independencia |
| 5d: audit como job do CD | logica fora de X*: o produto auditaria a si mesmo | descartada |

**Recomendacao (proposta, aguarda ratificacao): 5a**, com um unico job (sem `validate` separado) para custar uma pausa. A independencia e uma propriedade de trust, e so um `job_workflow_ref` proprio a entrega.

**PRs afetados.** P11 (produtor do `approval.json`; passa a incluir o reusable), P12 (catalogo que o audit le), P19 (montagem), P22 (role e trust do audit), P28 (jobs do caller). Cada etapa do catalogo ganha um `producer_job` (`LR:95-98`).

## 6. DD-6: tamanho da governanca e orcamento de pausas dentro dos 900 s

### 6.1 Questao e evidencia

A preparacao de 900 s comporta as chamadas de DD-1 com as pausas de reviewer? E a governanca do application cabe no secret?

Evidencia de codigo: pausas `REU-plan:62,130`, `REU-deploy:62,130`; timeouts de tofu `init` 45 s, `plan` 120 s, `show` 20 s, `apply` 120 s (`LR:1331,1340,1372`, `LR:1341`); admissao por timeout (`LR:898-902`, `LC:1550-1552`); poll do keeper de ate 5 s (`AG:2046`).

### 6.2 Medicao

**O que existe.** Nenhum run do `infra-plan`, `infra-apply`, `promote-production` ou `phase-a-prepare` do CnesData que chame os reusables existe, e os reusables do infra-ansible nunca rodaram (lista de runs por workflow vazia, lida em 2026-11-20 com GET `actions/workflows/<id>/runs`). Nao ha ensaio de Phase A no GitHub Actions. **Nao existe nenhum tempo real de `tofu plan` ou `tofu apply` contra o backend de producao, nem dos passos de admissao.** O que foi medido sao os insumos por analogia (so GET: `gh run list`, `gh api .../runs/<id>/attempts/<n>/jobs`, `.../environments/production`, `.../runs/<id>/approvals`).

**Tempo de maquina por analogia (todos attempt 1, 2026-11-19 e 2026-11-20, runners hospedados pelo GitHub).** Runs: verify-production 44731095061, 44590506495, 44578894407, 44560903317, 44556856773, 44554344685, 44546218704; infra-native 44733570027, 44731095039, 44590506409, 44578894563, 44560902802, 44560606275, 44556856772; python-quality 44755144780, 44731094760, 44578894718, 44560903269, 44556856782, 44554397026, 44548944753, 44541298657; production-runtime-acceptance 44733570084, 44731095006, 44590506435, 44578894771, 44560902789, 44560606288, 44556856774, 44554396939.

| Insumo | n | p50 (s) | p90 (s) | Uso |
|---|---|---|---|---|
| fila de job que depende de outro (`needs`) | 14 | 2 | 14 | fila de `execute` e de audit |
| fila de job raiz | 36 | 2 | 73 | so referencia; cauda de matrizes paralelas |
| `Set up job` | 153 | 1 | 2 | |
| `actions/checkout` | 141 | 3 | 6 | duas por `execute` (produto e SDK) |
| `setup-node` ou `setup-bun` | 22 | 3 | 5 | uma por `execute` |
| `uv sync --locked` | 47 | 5 | 6 | analogo do `pip install --require-hashes` do reusable (nao medido) |
| `upload-artifact` | 40 | 2 | 3 | |
| `tofu init -backend=false -lockfile=readonly` na raiz de producao | 7 | 9 | 10 | piso do `init` do gate (o gate ainda configura o backend S3) |

Resultado por job: `validate` >= ~3 s (fila 2 e setup 1; faltam os dois passos de carga do produtor e de prova de admissao, `REU-plan:71,126`); `execute` >= ~26 s ate o primeiro comando mutante (soma dos p50 da tabela: fila 2, setup 1, dois checkouts 6, node 3, instalacao 5, `init` 9) e ~28 s com o upload, sem contar carga do produtor, admissao, bridge e a repeticao do gate, que nao estao medidos; audit de job unico ~19 s (analogia; as leituras AWS nao estao medidas).

**Espera do reviewer.** O environment `production` do CnesData tem um revisor obrigatorio, `prevent_self_review` falso, nenhum `wait_timer` e politica de branch custom. Fonte: 15 runs do `Deploy main` (`workflow_dispatch`, 2026-09-18 a 2026-10-11): 38108059903, 38101178340, 36279073204, 36135957764, 36015859448, 35905048806, 35800360776, 35799259545, 35782304011, 35746153331, 35539182577, 35416290819, 35350504778, 35348386961, 35345051252. Regra de inclusao unica: so aprovacoes com estado `approved` no endpoint `approvals` do run, attempt 1; a espera e `deploy.started_at` menos o maior `completed_at` dos jobs de que ele depende. Ficam fora o run com aprovacao rejeitada (35799259545), o com aprovacao pulada (35345051252) e o attempt 2 de 38108059903 (duplica o 1 e nao tem registro de aprovacao). Amostra: 12 aprovacoes, esperas em segundos 13, 19, 24, 30, 32, 34, 45, 113, 123, 183, 352, 424. **Mediana 40 s, p75 123 s, p90 352 s, media 116 s.** Vieses: o job de deploy roda num runner proprio, entao a espera inclui a captura do runner; e as aprovacoes nao foram avisadas, enquanto o R22 supoe revisores avisados e presentes. Nao ha como separar, nesses dados, a latencia humana da do runner. O `Deploy esusdata` do infra-ansible nao entra: o environment dele resolve no infra-ansible e nao pausa.

**Referencia do desenho anterior.** O orcamento da Phase A em `docs/cnesdata-delivery-producers.md` §6.1 assume 4 min no `validate` e 3 min no setup do `execute`; os insumos medidos aqui sao so pisos (~3 s e ~28 s, sem os passos de admissao) e nao permitem concluir que essa premissa e conservadora. Tambem nao dizem nada sobre o `tofu plan` e o `apply`, que seguem sem medida.

### 6.3 Estimativa

Premissas: a cadeia ate o `prepared` e a de DD-1 com o mode-canary co-aplicado (1C): `observer-bootstrap` (plan, audit, deploy), `operational` (plan, audit, deploy). O teto util e o inicio do ultimo `apply` ate 623 s depois do acquire (900 menos 277, `LR:1372`, `LC:1552`); depois dele ainda cabem o proprio `apply`, a publicacao, o poll, o handler `prepared` e o close-drain, que tambem precisa de `now + op + 157 < deadline`. A conta abaixo e a soma de pausas e maquina medida ate esse inicio; a folga cobre ainda a duracao real das 11 operacoes tofu que precedem o ultimo `apply`, as admissoes de cada job, o `inventory` e a passagem entre jobs, tudo sem medida.

| Cenario | Maquina (s) | Pausas | Espera a 40 s | Inicio do ultimo apply | Folga | Espera a 123 s | Folga |
|---|---|---|---|---|---|---|---|
| A: desenho atual (validate e execute com environment, audit com pausa) | 160 | 10 | 400 | 560 | 63 | 1230 | -767 |
| B: A, com a primeira `validate` aprovada antes do acquire | 157 | 9 | 360 | 517 | 106 | 1107 | -641 |
| C: `validate` dobrado no `execute`, audit com pausa | 148 | 6 | 240 | 388 | 235 | 738 | -263 |
| D: C sem pausa dentro da janela (O20) | 148 | 0 | 0 | 148 | 475 | 0 | 475 |

Nos tetos do codigo, um ciclo de plan soma 45+120+20 = 185 s e um de deploy 45+20+120 = 185 s (o deploy tambem roda `tofu show`, `LR:1366`); duas de cada somam 740 s contra 742 s de janela util (900 menos a reserva de 158). Antes do ultimo `apply` comecar sao 4 `init` (180), 2 `plan` (240), 4 `show` (80) e o primeiro `apply` (120) = 620 s contra o limite de 623 s: 3 s de folga com zero pausa e zero maquina. Essa soma e pior caso, nao regra de admissao (`phase_capacity` confere so o timeout de cada comando contra o deadline), entao nao sustenta sozinha o veredito. **Veredito: negativo**, com base nas linhas de pausa media (116 s, §6.2) e p75 (123 s), que estouram A, B e C por centenas de segundos (tabela acima). Nos tipicos a conta e indeterminada, porque nenhum plan ou apply real foi medido; no desenho atual (A) a mediana de espera deixa 63 s para as 11 operacoes tofu, todas as admissoes e o `inventory`. Nao ha leitura positiva demonstravel do desenho atual, e a regra acordada em 7038419407 diz o que fazer: **P10-P17 sao replanejados antes de comecar.** Sem 1C (mode-canary em chamadas proprias, 1B) a conta piora de 4 para 6 chamadas de plan/deploy e 3 audits, e nao fecha em nenhum cenario.

#### 6.3.1 Desenho C no alvo de 60 s por pausa (decisao do dono)

Cenario C (maquina 148 s, 6 pausas, limite de 623 s para o inicio do ultimo `apply`):

| Espera por pausa | Espera total | Inicio do ultimo apply | Folga |
|---|---|---|---|
| 60 s (alvo do dono, O24) | 360 s | 508 s | +115 s |
| 123 s (p75 medido, sem aviso) | 738 s | 886 s | -263 s |

No alvo a janela e **positiva, mas fina e nao demonstrada**: 115 s cobrem a duracao real das 11 operacoes tofu, as admissoes de cada job, o `inventory` e a passagem entre jobs, nenhuma medida; nos tetos do codigo a soma e 620 s contra 623 s e nao cabe (pior caso, nao regra de admissao). Com os revisores avisados e presentes (R22) a espera de 60 s e meta, nao medida: os dados medidos (mediana 40 s, p75 123 s) vieram de aprovacoes sem aviso. Se os revisores perderem o alvo, o ciclo falha fechado: o `phase_capacity` recusa o comando seguinte, o lease fica preso e a recuperacao e a do runbook do P32 (e o run fica vermelho, O22). O pior caso do teto continua valendo como nota: a folga so se confirma na primeira execucao gated.

O mesmo calculo vale para as janelas ratificadas de B (360 s) e C (240 s cada), `LC:1225-1227`, cada uma com plan, audit e deploy: maquina ~81 s e 5 pausas (200 s a 40 s) deixam 79 s em B e -41 s em C com o desenho atual, **sem tofu** (so pausas e maquina; nos tetos, plan mais deploy somam 370 s, acima dos 360 s de B); com `validate` dobrado, 3 pausas deixam 165 s em B e 45 s em C; sem pausas, 285 s e 165 s. Estimativa pela mesma base, sem tofu e sem a regra de capacidade pos-fence conferida: o minimo e levar a pergunta ao dono (O20, O21).

### 6.4 Opcoes e recomendacao

| Opcao | O que muda | Custodia |
|---|---|---|
| (i) dobrar `validate` no `execute` | os dois reusables de plan e de deploy; ele ja repete o passo de admissao antes do OIDC (`REU-plan:126,201,254`), entao o `validate` e conveniencia de UX. Muda a superficie pinada (antes de X*). | neutra: o job continua com o environment |
| (ii) tirar o `environment` do `validate` | o job deixa de receber o secret de environment: a sonda O2 mediu que o job sem o environment recebeu 0 B (`docs/cnesdata-delivery-producers.md` §8, item 2) | exige a governanca em secret de repositorio, mais fraca; so vale se o DR2 (R24) provar o caminho; decisao do dono |
| (iii) segundo environment sem revisores para os jobs dentro das janelas, mantendo a aprovacao humana unica no job do application | trust AWS (`sub` dos roles de plan, deploy e audit), secret duplicado no novo environment, branch so `main` | mudanca de modelo de seguranca; decisao do dono (O20) |
| (iv) ampliar a janela de preparacao | emenda de `AG:2119` e `LC:972`, e revisao de `DOC:753-767` (a sessao de 900 s) | nenhuma; decisao do dono (O21). Antes do fence a preparacao nao fecha o API (`LC:1550-1552`), o risco e o tempo de lease preso. |
| (v) fusao do mode-canary (DD-1, 1C) | menos chamadas | neutra |

**Decisao do dono (2026-11-20): (i) mais (v), sem (iii) nem (iv).** Mantem um revisor por job, a janela de 900 s e o doc de autoridade do lifecycle sem mudanca. Replanejar P10-P17 "para o desenho C" significa: os reusables de plan e deploy perdem o job `validate` separado (a admissao ja repetida no `execute` passa a ser a unica) e o mode-canary e fundido na etapa `operational` (DD-1 1C). A coordenadora atribui os PRs na ratificacao; esta spec nao os atribui. Recalculo no §6.3.1. **Efeito no caminho critico:** o replanejamento pode alongar a cadeia de REL. P19 depende de P10, P11 e P12 (folga de 1 no, pois P18 e mais profundo); P30 tem folga de ~2 a 3 sobre P16 e P17; P28 depende de P11; a opcao (i) edita os reusables de plan e deploy, onde P07, que esta no caminho critico, tambem trabalha. A cadeia tem de ser recalculada com o script de profundidades depois do replanejamento, como a ordem unica exige; nenhuma profundidade nova foi calculada aqui.

Medida que falta: o tempo de `tofu plan` e `apply` e das admissoes so aparece na primeira execucao gated da Phase A, que depende de X*; ate la a estimativa fica sem um ponto tipico.

### 6.5 Tamanho da governanca

Teto vinculante da CLI: 43 856 B (4 096 B abaixo do teto do GitHub de 47 952 B, sonda O2), decisao do P21; a constante muda no P38. Historico v2, antes do P21: teto da CLI de 40 960 B, documento 1 de ~32 900 B esperado e ~36 400 B na cota, margens de 8 060 B e 4 560 B sob 40 960 B; o `source_closure` do lifecycle (6 824 B) so o excedia na cota se viesse somado ao documento 1 inteiro.

As medicoes do documento 1 (29 728 B), do documento de lifecycle e do documento do application (35 802 B medido no P37; ~40 399 B com o audit) estao na tabela de medicoes do P21 em `docs/cnesdata-delivery-producers.md` (§2.4). O fragmento, o catalogo e os documentos dos pins (cada um aceita ate 65 536 B no codigo, `so:273`) entram nessa tabela.

Opcoes: (a) hidratar `source_closure` e o catalogo de um membro de artefato autenticado, o mesmo mecanismo de D6/P10, com o sha256 na governanca; (b) um secret por etapa: o caller mapeia o valor por job (`CD:.github/workflows/infra-plan.yml:100`, `infra-apply.yml:109`), mas o gate compromete governanca entre jobs (o catalogo e lido ao autenticar a cadeia, `LR:247`; o hash de `source_closure` entra em `fence-origins.json`, `LR:688`), entao o ganho e parcial; (c) um unico documento mais enxuto. **Recomendacao (proposta, aguarda ratificacao): (a)**, estendendo P10, e o P21 mediu antes do P20 (ver acima).

### 6.6 Custodia

A troca de custodia so vale se o R24 provar que o secret de ambiente chega ao reusable por nome. Os callers existentes passam `${{ secrets.CNESDATA_DELIVERY_GOVERNANCE }}` num job `uses:` sem environment (`CD:.github/workflows/infra-plan.yml:100`, `infra-apply.yml:109`) e o reusable declara o secret "passed by name from the caller environment" (`REU-plan:33`); esse caminho e exatamente o que o DR2 tem que provar. Se o GitHub nao repassar o secret de environment, qualquer opcao que dependa dele exige secret de repositorio, custodia mais fraca. **Nao decido: decisao do dono (O18).**

**PRs afetados.** P10-P17 (replanejados), P19, P20, P21, P25-P30.

## 7. DD-7: job e CLI de terminal

**Questao.** Onde roda `finish`, quem publica `publish_terminal`, e como o run termina `success`.

**Evidencia.**
- `Keeper.finish` valida originais e so entao libera o lease (`AG:1664-1672`); `publish_terminal` publica so bytes originais do keeper (`AG:351-360`). Os validadores sao em processo, sobre as observacoes do journal do keeper, "nunca JSON do caller" (`AG:93-96`).
- O proximo acquire exige o run anterior `completed`/`success` e um unico reusable do application (`AG:382-398`, `LR:832-838`); o artefato `lifecycle-terminal` precisa ter sido criado dentro do job `governance["lifecycle_terminal_job"]` (`AG:401-405`, `LR:839`). Sem isso: "reviewed recovery required".
- `execute` nunca chama `finish` e `keeper_loop` nao retorna (`AG:2046-2063`).

**Opcoes.**
- 7a: `finish` e `publish_terminal` no processo do keeper, no fim do `execute`; `lifecycle_terminal_job` = o nome do job do application (`<job do caller> / execute`, como `HOST_JOB`, `AG:1759`). O artefato nasce dentro do intervalo do proprio job.
- 7b: job de terminal separado no caller. Os validadores precisam do journal em memoria do keeper (`AG:93-96`), entao o job teria de rodar dentro do processo do keeper: nao serve.

**Recomendacao (proposta, aguarda ratificacao): 7a.** `execute` passa a retornar apos `finish` e `publish_terminal`; a CLI de terminal e uma operacao do mesmo entrypoint, nao um job novo. Como o run termina `success` depende do terminal: para `accepted-open` o job sai com 0 e, se todos os jobs do caller forem `success`, o run conclui `success`. Para `failed-closed-quiescent` e `failed-prepare-quiescent` a promocao falhou, mas o lease foi liberado e o terminal publicado; para o proximo acquire aceitar esse run, o run tem de concluir `success` (`AG:382-398`). Isso pediria jobs do caller com `continue-on-error`. **Decidido pelo dono (O22, 2026-11-20): o run que termina limpo em `failed-*` fica vermelho e exige recuperacao revisada** (runbook de recuperacao do lease, P32); o proximo acquire recusa esse run (`AG:382-398`) e os jobs do caller nao usam `continue-on-error`.

**PRs afetados.** P17 (`finish`, `publish_terminal`, retorno de `execute`), P13 (`reopen`, `terminal-readback`), P27 a P30 (nome do job, `needs` e `continue-on-error` conforme O22).

## 8. S unico: a Phase A e o application usam o mesmo S?

**Questao.** `AG:1567-1570` exige release igual. Isso obriga um S unico para a Phase A e para os callers do application?

**Evidencia.**
- O gate nao obriga por si: o application admite fonte atual diferente da historica, desde que a historica seja ancestral (`LR:312-335`; "fence current and historical sources distinguished", `LC:724`). O que `AG:1567-1570` amarra e a **release**: `sha256(canonical(release do plan da Phase A)) == release_sha256` do application.
- A release da Phase A e o candidate: `release.source_sha == expected_source` e `candidate["source_sha"] == source` (`ct:652-655`, `rt:610-613`, `LC:119`, `LR:321`). Release igual implica candidate igual (`candidate_sha256`) e portanto `candidate.source_sha` igual ao S da Phase A.
- O produto exige o contrario: `_candidate` recusa se `candidate.source_sha != request.source_sha` e se o `release_id` nao comeca por `candidate-<request.source_sha>-`, e e chamado por `inventory` e `publish-static` (`CD:scripts/promotion/promote_api.py:129-148,220-229`). O `request.source_sha` e o `source_sha` do dono (`AG:1940-1941`), igual ao `github.sha` do `promote-production` (`LC:14-19`, `LR:36-38`). O host gate amarra a release do closed-ready (`HG:4642-4657`) e exige `job.head_sha == caller.source_sha` (`HG:4901`).

**Resposta: sim.** O S unico e imposto pelo produto (handlers de `inventory` e `publish-static`, `promote_api.py:222-229`) e pelo host gate (`HG:4642-4657`, `HG:4901`), nao pelo gate de application. Relaxar exigiria quebrar a igualdade de release (mudanca [X] no gate e novo X*) ou afrouxar `promote_api.py:222-229` (perder o binding candidate-fonte). Nenhuma das duas e recomendada.

**Consequencia (proposta, aguarda ratificacao).** S tem de conter os callers da Phase A, os callers do application (P27 a P30) e os pins (P31); a Phase A gated nao pode rodar antes de P30 e da release por tree (REL). A cadeia critica de 10 nos nao encurta (P01a-P05-P06-P07-P18-P19-P28-P29-P30-REL, ordem unica em 7038419407 §3), P27-P30 ficam no caminho, e o atalho "S' anterior" da ordem unica nao se abre. Nenhuma profundidade nova foi calculada: o resultado confirma a existente.

## 9. Perguntas ao dono (O18 em diante)

A O18 aguarda o dono; a O19-O22 e a O24 tem resposta do dono registrada; a O23 foi retirada. Esta spec nao decide nenhuma. O17 ja existe na spec dos produtores (§8, item 17), por isso a numeracao aqui comeca em O18.

18. **O18, custodia do DD-6.** Aceita a governanca (e, se for o caso, a `report_hmac_key`) em secret de repositorio, custodia mais fraca, se o DR2/R24 mostrar que o secret de environment nao chega ao reusable por nome, ou se a opcao (ii) do DD-6 for escolhida? Depende do resultado do drill R24.
    - **Resposta do dono (2026-11-20):** ainda aberta; depende do drill R24/DR2.
19. **O19, alvo do primeiro `execute`.** O primeiro `execute` de producao precisa alcancar `accepted-open` (mode-canary na janela, DD-1 1C) ou pode terminar num terminal `failed-*` controlado (DD-1 1A)?
    - **Resposta do dono (2026-11-20):** o primeiro `execute` deve alcancar `accepted-open` (DD-1 1C); o mode-canary e co-aplicado no plan/deploy `operational`.
20. **O20, pausas dentro das janelas.** Aceita um segundo environment sem revisores para os jobs de plan, audit e deploy dentro das janelas (aprovacao humana unica no job do application), com a mudanca de trust e a duplicacao do secret que isso exige, ou mantem um revisor por job e aceita as janelas so com revisores presentes (R22)?
    - **Resposta do dono (2026-11-20):** um revisor por job; `validate` dobrado no `execute` (6 pausas); revisores presentes e avisados antes da janela (R22).
21. **O21, janela de preparacao de 900 s.** Aceita emendar o valor de 900 s (DD-6 opcao iv), ou mantem a janela e o desenho do DD-6 (i) mais (v)?
    - **Resposta do dono (2026-11-20):** mantem a janela de 900 s: DD-6 (i) mais (v), sem mudar o doc de autoridade do lifecycle.
22. **O22, conclusao do run em terminal `failed-*`.** O run de uma promocao que falhou e terminou limpa (lease liberado, terminal publicado) deve concluir `success` para que o proximo acquire passe, ou fica vermelho e exige recuperacao revisada (DD-7)?
    - **Resposta do dono (2026-11-20):** o run que termina limpo em `failed-*` fica vermelho e exige recuperacao revisada (runbook de recuperacao do lease, P32).
23. **O23, retirada.** O remedio do R16 deixou de ser pergunta ao dono: ver D-C1 abaixo.
24. **O24, tempo-alvo por pausa.** Se as pausas ficarem, qual espera por pausa o dono assume e os revisores confirmam? Medido: mediana 40 s, p75 123 s, sem aviso previo (§6.2). Cobre tambem o R22: os revisores estao presentes e avisados antes da janela.
    - **Resposta do dono (2026-11-20):** cada aprovacao em ate 60 s, com revisores presentes e avisados (R22).

Decisoes da coordenadora na ratificacao (a delegacao de emendas e dela, nao do dono):

- **D-C1, remedio do R16** (`DOC:893-898`). Proposta: execucao `static-maintenance` posterior, que nao muda o estagio `static`, mas exige estagio, gatilho e entrada de IAM proprios (hoje ausentes de `STAGES`, `LC:1225-1227`, e vazia em `iam_source.py:100`); os outros dois remedios (teto por run, `DeleteObjects` em lote como nova operacao ABI) mudam o gate. Custo a confirmar; aguarda ratificacao.

## 10. Lacunas desta spec

- Nao existe tempo real de `tofu plan`, `tofu apply`, admissao, leituras do audit nem de `inventory`; a estimativa do §6.3 e por analogia e e negativa nos tetos do codigo e indeterminada nos tipicos.
- O documento de governanca do application nao esta medido (§6.5); P21 mede.
- O produtor privado do `inputs.json` do plan `operational` nao e determinavel pelo codigo (DD-1).
- O comportamento de `referenced_workflows` com varias chamadas do mesmo reusable (`LR:42`) depende do DR3; ele limita o numero de chamadas de plan e de deploy por run.
- A capacidade pos-fence das janelas B e C nao foi conferida contra `phase_capacity` (§6.3).
