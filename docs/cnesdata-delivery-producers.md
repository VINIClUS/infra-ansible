# Spec dos produtores de entrega (B3), G3 (B9) e G4 (B10) para a Phase A pelos gates (v3)

> **Revisao (v3):** v1 e v2 passaram por revisores de contexto limpo. As mudancas do v3 (resolucao do `K`, regra restrita do novo X*, congelamento do `main` em `K`, P33, textos da O15/O16, N3a decidido: so o caminho de CI) ainda nao foram revisadas e sao revisadas na auditoria do P01a.

**Estado (v2):** design, sem escrita em nenhum repositorio. Registro de decisao: infra-ansible#55 comentario 7024515854 (§2.4). v2 responde ao review independente (17 achados); secoes alteradas levam "(v2)". **v3 aplica as decisoes do coordenador sobre o re-review**; secoes alteradas levam "(v3)". Decisoes D1-D6 e respostas O15/O16 do dono: infra-ansible#55 comentario 7038419407 (§1, §2). Ordem unica de PRs (IDs P01a..P33): mesmo comentario, §3, ate o P02 levar o plano para o repositorio.

**Pins lidos:**
- IA = infra-ansible `be2f6b527766511f2e734b0d5271d9118d1d62cd` (inclui PR #82, G1/G2), prefixo `tools/cnesdata_delivery/` salvo indicação.
- CD = CnesData `258e55c58ea9109c4c4a35fc519ab9292027a4b0`.
- Tamanhos: state privado do ciclo p2 da Phase A (só contagens e nomes de atributo; nenhum valor, ARN ou ID foi copiado).

Convenções: `111122223333` é a conta, `<arn>`, `<bucket>`, `<sha>` são placeholders. `rt` = `runtime.py`, `ct` = `contract.py`, `pv` = `provenance.py`, `so` = `session_owner.py`, `sp` = `session_policy.py`. Placeholders de forma (`<arn>`, `<sha>`) so aparecem em exemplos de formato; nenhum valor sintetico entra em artefato ou relatorio reais. `LC`=`lifecycle_contract.py`, `LR`=`lifecycle_runtime.py`, `AG`=`application_gate.py`.

## 0. Resumo e achados (v2)

Decisoes (justificativas nas secoes; alternativas e decisoes: infra-ansible#55 comentario 7038419407):
- **G3 (v2):** a matriz e as especificacoes de readback saem do secret e viajam em `drift-handoff.json`, membro do artefato baseline `drift` (ja exigido e autenticado). Governanca guarda so o sha256 do membro; hidratacao em `admission()` antes de qualquer credencial (§2). **A hidratacao de `baseline.cost_manifest` foi retirada:** o `cost-manifest.json` do CD nao e o objeto que o gate valida; o manifesto do gate e derivado (D3, §4.2) e e pequeno.
- **G4:** readbacks por estagio sem `expected_sha256`; comparador `drift_coverage`; `verify_api` de IAM intacto (§3). **(v2)** a especificacao de readback nao carrega parametros: o gate os deriva do atributo de identidade do proprio endereco (liga linha a leitura, e tira nomes do arquivo publico).
- **G5 (v2, O1 decidida = envelope minimo):** envelope por purpose, com regra de completude, ligacao linha-leitura, prova de ausencia para delete no lifecycle (D4) e catalogo dos tipos alterados. O caminho de cobertura integral (47 tipos, ~16 servicos, ~600 entradas; nao re-medidas) esta descartado.
- **G6 (v2):** a conta nao e hasheada nem publicada; todo `*_sha256` publico derivado de ARN/conta/bucket vira HMAC com chave de ciclo, custodiada em quatro lugares (D5, §3.6).
- **Produtores:** P-A (infra-ansible, montador de proof + observador, via reusable em sha), P-B (CnesData, baselines), P-C (CnesData, upload privado), P-D (infra-ansible + CLI do dono) (§4). **(v2)** o derivador do manifesto de custo do gate e parte do P-A (§4.2).
- **Pin unico X* (v2):** a governanca tem um `gate_shas` por papel e ele autentica o historico e admite a corrida corrente; a Phase A e o application compartilham X* (§7.1). **(v3)** X* e tambem o valor de `host_gate.workflow_sha`, `ext2.workflow_sha` e `X_R`; `K` e um descendente de X*, nao igual a ele (§7.2). Decisao D1 no comentario 7038419407.

**Achados B11, S48, conta, pin e listas de arquivos (v2):**
- **B11, cobertura inviavel.** `ct:136-186` exige uma linha por atributo de todo recurso `managed`, inclusive `no-op`. `_readbacks` so aceita 6 servicos e 12 operacoes (`rt:147-150`); `drift_coverage` so aceita `identity` e `json` (`ct:181`). Contagens do v1 (47 tipos, 1773 pares, 753 pares tipo-atributo) **nao foram re-medidas**: o state do p2 nao foi localizado na revisao; so a ordem de grandeza importa e P21 recontar.
- **B11 bloqueia o primeiro execute do application:** o lifecycle chama o mesmo `drift_coverage` com allowlist mais estreita (`LR:906-909`, chamadas `LR:1364`, `LR:1380`). O mecanismo do envelope do lifecycle entra em P06; as entradas de catalogo dos seus tipos tem PR proprio (P12).
- **S48, teto do secret.** Codigo aceita 65 536 B (`rt:25`; 262 144 em `LR:86`); teto medido na sonda O2 (2026-11-20, repositorio descartavel, secret de environment, valores aleatorios, sem AWS): 47 952 B de texto claro (48 000 B cifrados, com 48 B de overhead do sealed box); 47 953 B recusado com HTTP 422. O teto efetivo e o do GitHub, nao o do codigo. Medido: o manifesto de custo do CD tem 17 972 B mas nao e carregado na governanca; o derivado do gate tem um componente por linha do CD (34 linhas x ~110 B + ~250 B = ~3,8 KB; cota dura 64 componentes = ~7,3 KB). Documento do plan sem matriz: ~33 KB esperado, ~36 KB na cota (§2.4). O `source_closure` do lifecycle soma 6 824 B medidos (59 arquivos, `LR:688,1282`).
- **Conta e hashes de baixa entropia (G6).** `so:291-304` publica `account_id` em claro; `role_arn_sha256`, `policy_arn_sha256`, `document_sha256`, `repository_sha256` (`aws_boundary.py:181` inclui `registryId`) e `bucket_sha256` sao enumeraveis (so a conta e desconhecida).
- **Fixacao do `job_workflow_ref`.** So e pinado a sha quando o job roda num reusable chamado por `uses: ...@<sha>` (`oidc.tf:79`). Workflow top-level carrega o ref git.
- **Listas de arquivos (v2).** Todo modulo novo de `tools/cnesdata_delivery` que o gate importe entra em pelo menos cinco lugares: `files` dos reusables plan (`reusable-cnesdata-infra-plan-gate.yml:114-118`, `:189-193`) e deploy (idem), o reusable do application, e `APPLICATION_PYBOOT` (`LC:599-603`; closure `LC:604-618`). Guarda existente so compara o reusable do application com `APPLICATION_PYBOOT` (`tests/test_cnesdata_application_closure.py:60-63`); as listas plan/deploy nao tem guarda (RED novo em P07). O reusable de signing tem tres listas proprias de modulos (`reusable-cnesdata-signing-gate.yml:126`, `:261`, `:417`), que so cobrem os modulos do signing.
- **Pins do CD (v2).** Nao sao "cinco": 3 workflows (`infra-plan.yml:89`, `infra-apply.yml:98`, `promote-production.yml:88`), 2 constantes Python (`scripts/promotion/verify_plan_artifact.py:27`, `_api_static_handoff.py:28`), `docs/runbooks/infrastructure-plan.md:68`, 3 testes (`tests/production/delivery/test_trilha_em_main.py:15` e `:29-30`, `_plan_apply_fixtures.py:15`, `test_plan_apply_workflows.py:184`) e `tests/fixtures/static-promotion-cross-repo/render.json` (5 ocorrencias; seu campo `command` manda regenerar contra IA em X*, nao trocar texto). Dono unico: P31 (comentario 7038419407, §3).

## 1. Inventário dos insumos fornecidos por produtor

Legenda de visibilidade: P = artefato público, V = privado (secret ou S3). `exp` = expiração.

| Insumo | Contrato (path:line) | Produtor | Validade | Vis. |
|---|---|---|---|---|
| Chaves da governança | `rt:22-40` (autoridade, região, roles, backend); lista em prosa `docs/cnesdata-delivery-plan-apply.md:105-117`; forma sintética `tests/fixtures/cnesdata_delivery_chain.py:42-65` | P-D (CLI do dono) monta; dono escreve | 3 documentos por ciclo | V |
| Descriptor | fechado em `pv:312-320`; cópia no caller `scripts/promotion/verify_plan_artifact.py:180-216` (CD) | CLI do dono (P-D) a partir das referências | por dispatch | P (input do workflow) |
| Baseline backend | `rt:30-33`, `ct:596-616` (identity_sha256 = sha da configuration) | P-D (compromissos, §4.4) | 30 d (retenção) | P, só hashes |
| Baseline toolchain | `ct:617-627`, `rt:510-513` (hash do binário, lock) | P-B (CD `verify-production.yml`) | 30 d | P |
| Baseline policy | `rt:683-684` (`policy_sha256`, hash do conftest) | P-B | 30 d | P |
| Baseline cost | `ct:332-381`; `rt:70-74` (relatorio == `baseline.cost_evidence`) | P-B (manifesto-fonte do CD) + P-A (derivacao do manifesto do gate e relatorio, §4.2) + dono (CloudFront) | `cost.expires_at` >= expiracao do plano | P |
| Baseline shared-outputs | schema `infra/opentofu/env/prod/shared-outputs.schema.json` (CD); valor real vai em `product_inputs` | P-D (compromisso) + CLI do dono (valor) | 30 d | P só hash; valor V |
| Baseline drift | opaco hoje (`pv:264-266`); passa a conter `drift-handoff.json` (§2) | P-A (observador) | 30 d; matriz amarrada ao state | P |
| Admission proof | `pv:270-308`; checks `pv:19-21`, `:282-284` | P-A (montador) | 3 h (§4.1, §6) | P |
| 13 check_ids | formas em §5.2 | P-A (+ dados de P-B/P-C/P-D) | cada `expires_at` >= `proof.expires_at` (`pv:294`) | P |
| `session_policy_pins` | `so:251-288`; fatos `so:291-304` | P-A (leitura IAM) -> dono copia o `document` | `frozen_until` >= now+3600 em cada admissão (`so:395-402`) | V (contém ARNs) |
| `cost` / `cost_manifest` | `ct:332-381` | P-A (deriva do manifesto-fonte autenticado, D3) + dono (CloudFront Free ACTIVE, #476 P2) | `calculated_at <= now < expires_at`; rederivado na escrita 3 (`LR:1320`) | cost P; manifesto P (so precos) |
| `drift_matrix` | `rt:35-39`, `ct:136-186` | P-A (gerador, §2) | amarrada a source, purpose, state | P (sanitizada) |
| `readbacks` (especificacoes) | `rt:141-183`; por estagio no lifecycle `LR:1363,1379` | P-A | idem | P (servico, operacao, endereco; sem parametros). Respostas (reports) sao privadas |
| `caller_allowlist` | `pv:328-330` | CLI do dono | por source | V (secret) |
| `required_checks` | `pv:332-336` | CLI do dono | estático | V |
| `proof_producers` | `pv:277`; `so:283-287` | CLI do dono | estático por produtor | V |
| `dependencies` / `producer_pins` | `pv:320`; CD `_descriptor` `:197-209` | P-D (CLI) | por `X*` | V / P |
| `phase_input_objects` | `rt:354-358`, `rt:561-572`; chaves `session_grouping.py:29-44` | P-C (upload) + CLI do dono (hashes) | 30 d no bucket; leitura exata | V (S3) |
| `phase_a_graph` | `ct:522-590`, uso `rt:525-531`, `:690` | derivador P-A local (§5.3) | por plano | V (secret) |
| `release`, `phase_a_inputs`, `ecr_repository` | `ct:651-659`; `rt:561-573` | P-C (inputs) + CLI | por release | V |

Observações de contrato que o implementador não pode perder:
- Toda referência de artefato exige run concluído com sucesso e `head_sha == reference.source_sha == reference.workflow_sha` (`pv:199-208`; réplica no caller CD `verify_plan_artifact.py:105`). O `repository` da referência pode ser outro repositório `VINIClUS/*` (`ct`/`pv:210-236`, CD `:97`). Portanto baselines podem vir do infra-ansible, mas o sha do run é o do próprio produtor.
- `source_sha` do produtor não precisa ser o `S` do produto; só os relatórios do proof e o payload (phase-inputs, planned) são amarrados a `S` (`pv:304-305`, `rt:80`, `:563`).
- `unzip` aceita no máximo 32 membros, nomes `[A-Za-z0-9_.-]{1,128}` (`pv:239-253`).

## 2. G3: transporte da matriz e dos readbacks (B9)

### 2.1 Aritmética

Linha fechada `{address, attribute, readback, path, encoding}` compacta: 165 a 206 B (auditoria PR #82; amostra 168 B).

| Cenário | Linhas por estágio | Dois estágios | Cabe em 47 952 B? |
|---|---|---|---|
| Todos os atributos (1773 pares) | 1773 | 3546 x ~180 B = ~640 KB | não (13x) |
| Sem a classe 4 (122 pares só-state) | 1651 | ~594 KB | não |
| G5 (IAM role, IAM policy, ECS task def: 32 instâncias) sem classe 4 | 315 | 630 x 170 B = ~107 KB | não (2,2x) |

Readbacks por estagio no cenario G5: 13 `get_role` + 16 `get_role_policy` + 3 `describe_task_definition` = 32 especificacoes (v2: ~60 B cada sem `parameters`, ~2 KB). O teto de 4096 linhas por estagio (`ct:163`) deixa de ser o limite; o limite e o byte do secret. Contagens deste bloco: nao re-medidas (v2). Conclusao: nenhum cenario cabe inline; o transporte tem de sair do secret.

### 2.2 Escolha: membro do baseline `drift`, hash pinado na governança

O artefato baseline `drift` já é obrigatório (`pv:259`, `:316`), já é autenticado em `admission()` (`rt:76-77`, hoje com o retorno descartado), tem o conteúdo amarrado no proof (`pv:264-266`) e a retenção conferida (`:267`). Basta que ele passe a carregar um membro com semântica.

Alternativas rejeitadas, com evidência:
- **Objeto S3 privado** (precedente `phase_input_objects`): exige um escritor AWS para o observador (deixa de ser só leitura) e exige que `_session_reads` (`rt:348-373`) e `sp._reads` (`sp:308-332`) admitam a chave. A política inline de sessão + a gerenciada têm teto de 2048 caracteres (`sp:335-346`). Estimativa: `own` ~130 caracteres, wildcard de phase-inputs ~136, wildcard do run anterior ~130; a lista `read` (que já contém `own`) aparece duas vezes (S3 e condição KMS) e `own` mais duas (PutObject e KMS). O total já fica perto de 2000 com as chaves atuais; qualquer chave exata a mais arrisca o erro "exceeds 2048 characters; reviewed recovery required".
- **Carga no artefato do proof (`admission_reference`)**: o proof é por role e por plano, mas a matriz `before` precisa existir antes do plano e a `drift` é reutilizada entre plan e deploy (`historical_plan_governance`, `pv:123-138`, exige as mesmas referências); um membro no `drift` mantém uma única referência imutável nos dois ciclos.

### 2.3 Forma do `drift-handoff.json` (v2; canonico, no maximo 2 MiB)

```json
{
  "handoff_version": 1,
  "source_sha": "<sha40>",
  "purpose": "phase-a",
  "catalog_sha256": "<sha64>",
  "matrix": {"matrix_version": 2, "source_sha": "<sha40>", "purpose": "phase-a",
             "before": [{"address": "...", "attribute": "...", "readback": 0, "path": ["Role", "Path"], "encoding": "identity"}],
             "after": [], "absent": []},
  "readbacks": {"before": [{"service": "iam", "operation": "get_role", "address": "..."}],
                "after": []}
}
```

Regras de sanitizacao (o observador falha fechado, e o gate repete `c.public_safe`):
- nenhuma string com prefixo de ARN da AWS, `://`, 12 digitos, nome de bucket de governanca ou ID de ec2. **(v3)** O `public_safe` real (`ct:414-424`) so recusa prefixo de ARN da AWS, `://`, chaves privadas, `AKIA`/`ASIA` e ids de vpc/subnet/sg/eni/instancia: nao recusa 12 digitos nem nome de bucket. P07 o estende para recusar qualquer sequencia de 12 digitos e os nomes dos buckets de governanca (mudanca na superficie pinada em X*, pois `public_safe` vive em `contract.py`). RED: handoff ou relatorio com o id da conta de governanca ou uma string de 12 digitos e recusado;
- **(v2) a especificacao nao tem `parameters`:** nomes de role, policy, family, tabela e **bucket** nao entram no arquivo publico. O gate deriva os parametros do atributo de identidade do proprio endereco (§3.2);
- `address` so casa com lista fechada de regex derivada do catalogo (tipos COVERED e SUPPORTED do envelope, §3.5). As chaves de instancia sao nomes de modo (`unit`, `recovery`, `audit`) ou `[0]`. Os `index_key` do state sao varridos pelo observador; se algum aparecer num endereco coberto e casar ARN/ID, a geracao falha (O4: enderecos publicos, nomes nao).

### 2.4 Seams do gate (todos pre-credencial)

1. `rt:35-39` (`configuration`): troca `drift_matrix`/`readbacks` inline por `drift_handoff` fechado `{member, sha256}`; valida so a forma e o prazo. Ausencia das chaves inline e exigida (sem caminho duplo).
2. `rt:76-77` (`admission`): guarda o retorno de `api.artifact` do baseline `drift`; o novo modulo `drift_handoff.load(files, governance, proof, files_of_proof)`:
   - `sha(files["drift-handoff.json"]) == governance["drift_handoff"]["sha256"]`;
   - o mesmo hash aparece como `handoff_sha256` na medicao do relatorio `drift-baseline` (checagem dupla);
   - fechado, canonico, `source_sha`/`purpose` iguais a `EXPECTED_SOURCE_SHA`/`PURPOSE`, `catalog_sha256 == drift_catalog.CATALOG_SHA256` (**depende do P06; ordem G4, G5, G3**, achado de ordem do review; **(v3)** `CATALOG_SHA256` e computado nas fixtures a partir do catalogo, nao congelado, de modo que o P12 (entradas do lifecycle) nao reescreve os vetores do P07), `public_safe`;
   - hidrata `governance | {"drift_matrix": ..., "readbacks": ...}` em memoria.
3. Modulos novos (`drift_handoff.py`, `drift_catalog.py`) entram nas cinco listas do §0 (guarda nova para plan/deploy). A closure muda; `content_sha256` de `producer_pins` (§5.1) e recalculado em X*.
4. O handoff nao carrega a identidade do state (so conferivel apos o acquire, `rt:589-590`).
5. **(v2) Sem hidratacao de `baseline.cost_manifest`.** O objeto que o gate valida e `{source_sha, calculated_at, expires_at, credits_usd, gross, components[<=64]}` (`ct:347-368`; fixture `tests/fixtures/cnesdata_cost.py:14-19`), nao o `cost-manifest.json` do CD (`schema_version, as_of, region, currency, limits, lines[33]`). Fica inline na governanca (~3,8 KB esperado: um componente por linha do CD; <= ~7,3 KB por cota). Seam removido do P07. O fixture `tests/fixtures/cnesdata_delivery_chain.py:30-54` muda de forma (matriz/readbacks) no P05/P07.

**Tamanho da governanca (documento 1, role plan), sem matriz (v2; estimativas salvo indicacao):**

| Componente | Bytes | Base |
|---|---|---|
| `baseline.cost_manifest` (derivado, §4.2) | ~3 800 (cota 7 300) | 34 linhas do CD (33 + `kms_signing`) x ~110 B + ~250 B; re-medir no P21 com o derivador real |
| `session_policy_pins[plan,deploy].document` | ~7 000 | ~3,5 KB cada, de `session-policies.tf` |
| `phase_a_graph` (forma do p2) | ~4 500 | ~20 `source_files` x 130 B + 3 testemunhas |
| `artifact_references` + `baseline_artifacts` (8 + 6) | ~5 600 | 350 B por referencia, duplicadas |
| `cost`, `baseline.cost_evidence`, `cost_context` | ~2 500 | |
| `product_inputs` + `phase_a_inputs` | ~3 300 | `inputs.tfvars.json` do p2 2 157 B (nao re-medido) + 1 KB |
| `toolchain` + `backend` + `dependencies` | ~2 000 | |
| `release`, `phase_input_objects`, `roles`, `gate_shas`, `proof_producers`, `caller_allowlist`, `required_checks`, `admission_reference`, `drift_handoff`, `report_hmac_key`, chaves fixas | ~4 200 | |
| **Total** | **~32 900 esperado; ~36 400 na cota** (soma das linhas acima) | cabe sob 47 952 B, com ~11,6 KB de margem na cota (47 952 - 36 400 = 11 552 B); contra o teto da CLI (decisao do P21: 43 856 B, o que vincula; historico v2: 40 960 B, margem na cota 4 560 B) a margem na cota e 7 456 B (43 856 - 36 400); no esperado, 10 956 B |

Decisao (v2): **G3 nao hidrata `cost_manifest`**. `phase_a_graph` e pins ficam inline.

**Documentos do lifecycle e documento 3 (application), nao medidos no v1 (v2):** o lifecycle le `source_closure` (arvore `infra/opentofu`, `LR:688,1117,1282`: 59 arquivos, 6 767 B canonicos em CD `86ce51e8`), mas desde o P37 a governanca nao o carrega: guarda so `source_closure_sha256` (~91 B) e o gate o hidrata do membro `product-source-manifest.json` autenticado. O catalogo `lifecycle_steps` tambem sai: a governanca guarda `lifecycle_steps_sha256` (~92 B) e o gate le `.github/delivery/lifecycle-steps.json` no sha do manifesto. O recibo EXT2 do plan operacional nao cabe no catalogo (so existe depois da assinatura): vai na chave `activation_receipts`, por passo, e a hidratacao o compoe no passo. O documento 3 soma ainda `application_fragment`, `application_configuration`, `lifecycle_predecessor`, o pin do role `application` e a referencia do manifesto de produto (D6, ~350 B; o manifesto de ~304 KB sai da governanca). O teto de codigo 262 144 nao vale sob 47 952 B.

**Aceite do PR P01a (esta spec, so texto):** sonda O2 feita em 2026-11-20 (teto 47 952 B; ver S48). **(v3)** As medicoes saem do P01a e vao para o **P21**, porque precisam do `cost_ledger`, do derivador de `phase_a_graph` e dos documentos de sessao renderizados, entregas do P18 (P01 precede P18). Aceite do P21: (b) tamanho do documento 1 medido com o manifesto derivado real, o `phase_a_graph` do `plan.json` do p2 (§5.3) e os documentos de sessao renderizados; (c) tamanho do documento de plan/deploy do lifecycle e do documento 3 medidos (inclui `source_closure`); (d) "G3b adicional sim/nao" registrado. P20 depende de P21: fechado **antes** de X*, porque um G3b tardio forca novo X*.

**Medicoes do P21 (2026-11-23, so leitura, local; CnesData `develop` 3976303d, infra-ansible `main` c33912de, documentos do application no head do P37 83a4056):**

| Documento | Bytes | Margem sob 43 856 B (teto da CLI, P21) | Margem sob 40 960 B (historico) | Margem sob 47 952 B | Base |
|---|---|---|---|---|---|
| 1, role plan | 29 728 | 14 128 | 11 232 | 18 224 | custo derivado real 3 069; pins plan e deploy 7 341 (as policies reais pesam 2 956 e 3 109; o resto, 1 276, sao os campos dos pins); `phase_a_graph` real 1 902 (2 testemunhas); `inputs.tfvars.json` real 2 116 mais ~1 000 de envelope; restante pelas estimativas da tabela acima (5 600, 2 500, 2 000, 4 200) |
| lifecycle plan/deploy | ~ igual ao documento 1 | ~14 000 | ~11 000 | ~18 000 | `source_closure` e `lifecycle_steps` saem do documento (P37): so os dois sha256 (~160) |
| 3, application, medido no P37 | 35 802 | 8 054 | 5 158 | 12 150 | `render` com campos do P36 e um recibo EXT2 |
| 3, application, com o audit (estimativa montada com partes medidas) | ~40 399 | ~3 457 | ~561 | ~7 553 | 35 802 + pin audit 3 257 (policy 2 617 + 640 de campos) + `roles.audit` ~80 (estimado) + `session_owner_references` 1 260 (4 x 315 B de referencia: plan, deploy, audit e application); ficam sem medir as chaves e separadores dessas referencias (< ~100 B) |

Campos de janelas governadas (P36): 152 B (`stage_windows` mais `fixed_deadline_seconds`), ja dentro do documento 3 e do documento do host. Recibo EXT2 (`activation_receipts`): 487 B por recibo. O handoff de drift (artefato, nao governanca) mede 81 122 B (233 linhas por estagio, 32 leituras por estagio).

**G3b adicional: sim.** O documento 3 com o audit deixa ~561 B sob o teto historico de 40 960 B, abaixo da meta de 4 096 B; o documento 1 fecha com folga. **Decisao (i), adotada:** `CLI_CEILING` passa a 43 856 B (4 096 B sob 47 952 B), margem ~3 457 B no documento 3; a constante, o runbook de recuperacao e os testes mudam no P38, nao no P21. Daqui em diante o teto normativo da CLI e 43 856 B; 40 960 B fica so como historico das medicoes. Nenhum consumidor liga um digest de governanca entre roles (o `caller_binding_sha256` liga so o documento do application; `governance_sha256` do host liga so o documento do host), mas o documento do application precisa dos pins e das referencias dos outros roles para autenticar as sessoes que pede, entao dividir por role nao o reduz. Hidratar os pins reduziria ~12 KB, mas muda a ancora de confianca e e um PR proprio.

**Calibracao R-X3 (forma real do plano).** Contra o state real (serial 21, ultimo apply do ciclo p2) e o `develop` atual, com os inputs do fim do p2 o plano tem 1 criacao (state machine do processador) e 1 policy alterada (`runtime_iam.api[0]`); o canary nao muda e `aws_s3_bucket_versioning` nao muda (fora de SUPPORTED, como decidido em #55 §4). Com um digest novo e `processor_active_unit_task_definition_arn` nulo: 3 task definitions substituidas (`unit`, `recovery`, `audit`) e 2 policies alteradas (`processing.canary_verifier_run_task[0]`, `processing.step_functions_ecs[0]`); a forma "3 policies" do p2 so aparece com a revisao ativa preenchida, caso em que `runtime_iam.api[0]` e a state machine entram no plano e o resolvedor IAM recusa `iam=policy_scope` (`api[0]` fora do escopo da Phase A). Desconhecidos do provider 6.54 na task definition substituida: `arn`, `arn_without_revision`, `enable_fault_injection`, `id`, `requires_compatibilities`, `revision`, `runtime_platform`, `volume`. O derivador fecha (8 arquivos de fonte, 2 testemunhas, 1 902 B) e `validate_graph` recusa a mutacao de um byte de fonte, da configuration e do produtor. A auto-checagem viva `drift_coverage` do estagio `before` e recusada (`drift response field`) em 9 de 233 linhas: `describe_task_definition` omite `enableFaultInjection`, `ipcMode` e `pidMode` quando padrao e `OMITTED` nao tem entrada para `aws_ecs_task_definition`. Defeito na superficie pinada, fora do P21. **Revisao ativa hoje:** nula. O state real nao tem `aws_sfn_state_machine` e o `processor_active_unit_task_definition_arn` entra no plano como mudanca (criacao da state machine e alteracao de `runtime_iam.api[0]`) quando preenchido; a evidencia do p2 registra `active_before` nulo. Por isso o primeiro plano da Phase A e a forma "digest novo, revisao ativa nula": 3 task definitions substituidas e 2 policies alteradas. **Achado pos-primeira-aceitacao (registrado, nao corrigido):** qualquer ciclo depois da primeira aceitacao tem a revisao ativa preenchida, o plano traz `api[0]` e a state machine, e o gate recusa (`iam=policy_scope` e tipo fora de SUPPORTED).

**Inventario (§3.5).** O catalogo e o inventario do provider 6.54 coincidem nos dois sentidos (`test_catalogo_igual_ao_inventario`, ja no main) e os nomes de atributo do state e do plano reais igualam o inventario nos 10 tipos com evidencia local. Contagem por tipo (observavel / isento): `aws_iam_role` 11/5, `aws_iam_role_policy` 3/2, `aws_ecs_task_definition` 14/11, `aws_dynamodb_table` 12/22, `aws_s3_bucket_policy` 1/3, `aws_s3_bucket_object_lock_configuration` 1/6.

### 2.5 Testes RED (novo arquivo `tests/test_cnesdata_delivery_drift_handoff.py`, fixtures em `tests/fixtures/cnesdata_delivery_chain.py`)

Todos falham no base pelo motivo indicado:
- `test_governanca_com_matriz_inline_e_recusada`: base aceita; novo exige `drift_handoff`.
- `test_hidrata_matriz_do_artefato_drift_e_passa_plan_gate`: base nao conhece a chave (`closed object fields`).
- `test_recusa_hash_do_membro_diferente_da_governanca`, `test_recusa_hash_diferente_da_medicao_drift_baseline`.
- `test_recusa_handoff_de_outro_source_ou_purpose`, `test_recusa_handoff_nao_canonico`, `test_recusa_handoff_com_arn_ou_conta`, `test_recusa_handoff_com_parameters_ou_bucket` (v2).
- `test_falha_de_handoff_ocorre_antes_do_acquire_do_lease` (o lease fake nunca recebe `acquire`).
- `test_governanca_acima_de_40kb_e_recusada_pelo_montador` (CLI P-D).
- `test_listas_dos_reusables_cobrem_os_modulos_do_pyboot` (v2): plan x2, deploy x2, application e `APPLICATION_PYBOOT` iguais para todo modulo importado.
- Aritmetica: `test_matriz_g5_de_32_instancias_excede_o_teto_inline` com o gerador do §4.1.

## 3. G4: expectativas por estágio (B10) e G5, G6

### 3.1 Diagnóstico confirmado no código

- `_readbacks` é chamado antes (`rt:602`) e depois (`rt:721`; `_reuse_completed` `rt:447`) sobre a mesma lista, e toda especificação, exceto o `get_role_policy` rastreado pelo resolver, exige `expected_sha256` fixo (`rt:174`, `:179`). Recursos que o apply cria ou muda leem diferente depois: novas revisões de task definition, tags `ReleaseId`, trust do fence. O hash do `before` quebra no `after`.
- Mesmo antes do apply o hash da resposta inteira é frágil por campos voláteis. Evidência dos arquivos de readback do run p2: `ddb-table.json` contém `Table.ItemCount` e `Table.TableSizeBytes`; o `describe_task_definition` carrega `registeredAt`; `get_role` carrega `RoleLastUsed` quando o role foi usado. No p2 o check manual de ECS já precisou normalizar `compatibilities` (`order_differs: true`, `same_set: true`) e `container_definitions` ("normalized: env/secrets sorted, ECS defaults dropped").
- O caminho do lifecycle já resolve isso: especificações por estágio sem hash fixo, com `drift_coverage` como comparador (`lifecycle_runtime.py:905-934`, `:1363`, `:1379`). O G4 alinha o caminho legado a esse precedente.

### 3.2 Desenho (v2)

- `governance["readbacks"]` (hidratado do handoff) vira `{"before": [spec...], "after": [spec...]}`. Spec fechada `{service, operation, address}`: **`expected_sha256` e `parameters` removidos**.
- **Ligacao linha-leitura:** o gate deriva os parametros da chamada de `drift_catalog.parameters(tipo, atributos)`, com `atributos` = os mesmos que `drift_coverage` usa como expectativa do endereco no estagio (`change.before`, `ct:149`; state aplicado, `ct:150-160`). Mapa fechado por tipo (role: `name`; role policy: `role`+`name`; task definition: `family`, sem revisao; tabela: `name`; s3: `bucket`). Toda linha da matriz exige `specs[row.readback].address == row.address` e `(tipo, atributo)` no catalogo com operacao igual a da spec. Todo tipo do catalogo declara seu mapa e a linha de identidade correspondente.
- **(v3) Dono do mapa.** `drift_catalog.py` nasce no **P05** como modulo minimo: para cada tipo de recurso, o atributo de identidade e o nome do parametro, sem linhas de atributo; e a `parameters(tipo, atributos)` acima. O **P06** estende o mesmo modulo com o catalogo (operacao, path, codificacao) e `NOT_OBSERVABLE`. P05 e P06 continuam PRs separados; os RED `test_parametros_da_leitura_vem_do_atributo_de_identidade` e `test_recusa_linha_cuja_spec_pertence_a_outro_endereco` ficam no P05, e a checagem "`(tipo, atributo)` no catalogo com operacao igual" e do P06.
- **(v3) Identidade nao tautologica.** Os atributos de identidade tem de ser conhecidos no plano (fora de `after_unknown`); fora de create/delete, `before` e `after` tem de ser iguais neles; para ausencia, o nome tem de ser igual a identidade de `before` do plano. Assim um valor alterado so pode apontar a leitura para o objeto que o plano nomeia. RED no P05 (`test_recusa_identidade_desconhecida_ou_divergente_entre_before_e_after`, `test_ausencia_exige_nome_igual_ao_before`). **(P05, decisao da coordenadora)** A regra acima vale para todo endereco que nao e criacao. Para endereco com acao `create` (qualquer spec de `after` cuja acao no plano e create), antes do acquire basta que cada atributo de identidade esteja em `change.after` ou em `change.after_unknown` (atributo ausente de ambos e recusado); depois do apply os valores vem do state aplicado (ja ligado ao plano por `drift_coverage("after")`) e valor vazio e recusado. **(P05, rodada 3)** A checagem pre-acquire e por estagio: spec de `after` em endereco sem `after` (delete) e recusada; spec de `before` em endereco sem `before` (criacao pura) e recusada, e a identidade de uma spec de `before` tem de estar em `before`; todo valor de identidade aceito no pre-acquire (plano ou `before`) e `str` nao vazia, a mesma regra de `parameters()`. Motivo: na criacao a identidade e computada (ACM `arn`; `role` de policy apontando para role criado no mesmo plano; `bucket` de sub-recurso S3 de bucket criado no mesmo plano).
- **(P05, decisao da coordenadora)** Alem do mapa acima (role `name`, role policy `role`+`name`, task definition `family`, table `name`, s3 `bucket`), o mapa minimo do P05 inclui: `aws_ecs_cluster` `name` (parametro `clusters`, lista); `aws_s3_bucket_policy`, `aws_s3_bucket_versioning` e `aws_s3_bucket_object_lock_configuration` `bucket`; `aws_scheduler_schedule` `name`+`group_name`; `aws_acm_certificate` `arn`. Tipo fora do mapa e recusado antes do acquire, tambem para specs de `after`.
- `matrix.before[*].readback` indexa `readbacks.before`; `matrix.after[*].readback` indexa `readbacks.after`. Hoje os dois estagios indexam a mesma lista (`ct:170-173`).
- Disponibilidade pre-acquire: plan.json em `rt:538-545`; state via `aws.get_state()` (precedente `rt:439`). `_readbacks` (`rt:141`) passa a receber plano e state (assinatura muda; limite de 4 parametros: agrupar em um objeto de estagio).
- Regras novas do gate, antes do acquire no deploy:
  - toda especificacao e referenciada por pelo menos uma linha do seu estagio (sem leitura orfa);
  - a lista `after` contem cada `get_role_policy` rastreado pelo resolver exatamente uma vez (`rt:181-182`);
  - `get_role` e `get_role_policy` do fence aparecem uma unica vez nos relatorios `after` (`LR:446-456`, `LC:789-797`);
  - validacao estrutural da matriz `after` contra o plano: atributos previstos de cada recurso coberto = `keys(change.after) | keys(change.after_unknown)` menos `NOT_OBSERVABLE` (**(v3)** simbolo novo do P06; nao existe no pin. O precedente do conjunto de atributos e a regra `set(actual) == set(expected) | set(mask)` de `ct:97`).
- Forma de relatorio intacta: `{service, operation, sha256, observed}` (`rt:180`, `:272-274`).

### 3.3 Cobertura por caso

- **Criação (ausente antes):** não existe linha `before` (`change.before` é nulo, `ct:149`); a especificação só existe em `after`. Os parâmetros precisam ser nomes conhecidos no plano (`after` conhecido, não `after_unknown`). O gerador recusa criação cujo nome é desconhecido. **(P05, decisão da coordenadora)** Emenda: na criação o atributo de identidade pode estar em `after_unknown` (só é recusado se faltar também em `after`); o valor vem do state aplicado depois do apply e vazio é recusado (§3.2).
- **Substituição retida de ECS (3 task definitions no p2):** o `describe_task_definition` usa só o `family`, sem revisão, e devolve a revisão ativa mais recente: `:3` antes, `:4` depois. A linha `arn`/`revision` compara com o plano antes e com o state depois. As revisões anteriores seguem ACTIVE (skip_destroy), então "mais recente" é determinístico. `skip_destroy`/`track_latest` são só-state (classe 4).
- **Update de tag/trust (5 roles e 3 policies no p2):** `get_role` antes e depois com a codificação `tags-kv` (lista de `{Key,Value}` para mapa) e `json` para `assume_role_policy`.
- **IAM `verify_api`:** inalterado (`rt:170-177`, `iam_boundary.py:198-209`). Os policies rastreados (so os alterados, `iam_boundary.py:161-162`) seguem exigindo a leitura da API no `after` (`rt:721`).
- **Delete (v2, D4):** Phase A ja recusa delete exceto o replace retido de ECS (`ct:467-468`; o endereco segue no state, entao tem linha). RED fixa a recusa. No lifecycle o delete e admitido so em converge, sobre endereco criado pelo proprio passo (`LC:1373-1377`; tipos de `scheduler_closure` `LC:1251-1260` e `STATE_MACHINE` no inverso de B). Envelope exige linha de ausencia (§3.5).

### 3.4 Interação com `drift_coverage`

- **Antes** (`rt:604`, `rt:673`): o plan role só consegue cobrir depois do `tofu plan` (precisa do `plan.json`, `rt:672-674`). O deploy pode antecipar. Seam: no deploy, mover para antes do `lease.acquire()` (`rt:581`) cópias fail-fast de `scheduler_preflight` (`rt:597`; usa `aws.get_state()`, como `_reuse_completed` já faz pré-acquire em `rt:439`), das leituras `before` e de `drift_coverage("before")`, usando o guard somente leitura de `rt:436-437` como precedente. As chamadas pós-acquire existentes ficam (elas vinculam o instante imediatamente anterior ao apply). Resultado: erro de matriz ou de preflight no deploy não prende o lease (B7).
- **Depois** (`rt:721-724`): `drift_coverage("after", state)` exige que o conjunto de pares seja exatamente o do state aplicado. Hoje uma matriz incompleta aqui falha depois do apply, com o lease preso. A validação estrutural pré-acquire (§3.2) elimina esse modo de falha; só divergência de valor continua pós-apply.
- `_reuse_completed` (`rt:447-448`) passa a usar `readbacks["after"]`.
- **Chamada do plan role em `rt:721`:** no plan role ela re-lê o estágio `before` depois do `tofu plan` (`rt:721-724`, estágio `"after" if deploy else "before"`); portanto usa `readbacks["before"]` e o estágio `before`. Só o deploy usa `readbacks["after"]`.
- **Perda explícita do hash:** com `expected_sha256` removido, caem os dois ramos de `_readbacks` que comparavam o hash da resposta inteira: o `get_role_policy` não rastreado (`rt:173-174`) e o ramo genérico (`rt:178-179`). O `get_role_policy` rastreado continua só com `verify_api` (`rt:172`, `:175-177`). O que se perde é o pin de campos não gerenciados da resposta; o que fica é a comparação de todo atributo coberto contra o plano e o state, mais forte e estável (`RoleLastUsed`, `ItemCount`, `registeredAt` deixam de importar).
- **Plan role (v2):** `drift_coverage` do plan role so ocorre apos o `tofu plan` (`rt:673`, `:722`), isto e, depois do acquire. Falha ali prende o lease (B7). A matriz do plan role tem de vir de um plano de ensaio com a forma do plano real (P21); mudanca de forma do plano real entre ensaio e janela e recusada antes do dispatch (§5.3). So o deploy ganha checagem pre-acquire.

### 3.5 G5: envelope de cobertura (v2, O1 decidida: envelope minimo)

Classificacao heuristica dos pares tipo-atributo do state p2 (47 tipos; **nao re-medida**, serve so para dimensionar): 1) projetavel hoje (`identity`/`json`): 82 pares tipo-atributo; 2) exige API nova: 588; 3) exige encoding novo: 41; 4) so-state: 42. Total 753. Descartado (O1): cobertura integral, servicos de leitura extras no observador, encodings alem de `identity`, `json`, `tags-kv`, `json-set`, `ecs-container-definitions`.

`drift_coverage(..., envelope=)` recebe um envelope por purpose (mecanismo em P06, entradas do lifecycle em P12):
- **`PHASE_A_ENVELOPE`.** COVERED = todas as instancias no state de `aws_iam_role`, `aws_iam_role_policy`, `aws_ecs_task_definition` (32 no p2) mais todo endereco com acao diferente de `no-op`. SUPPORTED = COVERED + `aws_dynamodb_table` (`describe_table`) + `aws_s3_bucket_policy`, `aws_s3_bucket_versioning`, `aws_s3_bucket_object_lock_configuration` (`rt:147-150`). Endereco alterado de tipo fora de SUPPORTED e recusado (`unsupported changed type`).
- **Limitacao declarada:** `validate_delta` admite tambem `aws_s3_bucket`, `_public_access_block`, `_ownership_controls`, `_server_side_encryption_configuration` e `_lifecycle_configuration` em `.canary[0]` (`ct:476`). Nenhum e SUPPORTED, entao qualquer mudanca neles na Phase A e recusada (falha fechada). Listado em O11.
- **Completude:** `required(endereco, estagio) = atributos(endereco, estagio) - NOT_OBSERVABLE[tipo]`; todo atributo exigido tem de ter linha **e** entrada de catalogo, senao `unclassified attribute` (novo atributo de provider ou atributo class-2/3 nao listado nao passa em silencio). RED: `test_catalogo_igual_ao_inventario` nos dois sentidos (catalogo => inventario do state/plano; inventario => catalogo ou `NOT_OBSERVABLE`).
- **Isencao:** `NOT_OBSERVABLE` vive em codigo (`drift_catalog`), no pyboot e na closure; atributo isento nao pode ter linha. Atributos class-4 alterados tem so prova de state (declarado).
- **Catalogo:** fixa por (tipo, atributo) operacao, path, codificacao e o mapa de parametros (§3.2). O gate recusa linha divergente. ~46 atributos para os 3 tipos COVERED **mais** as entradas dos tipos alterados (dynamodb canary, 3 de s3); contagem final fixada pelo inventario no P21.
- **Ausencia (D4):** `matrix_version: 2` com `absent: [{address, readback}]` (so no estagio `after`); conjunto exigido = enderecos com acao delete no plano; a spec e derivada de `change.before`; a prova aceita esta em §3.5.2. `matrix_version: 1` continua para chamadas sem envelope.
- **`LIFECYCLE_ENVELOPE`** (chamado em `LR:1364`, `:1380`): COVERED = alterados + instancias de `aws_iam_role`/`aws_iam_role_policy` (`LR:906-909`); SUPPORTED = tipos que a allowlist do lifecycle le: state machine, scheduler schedule/group, event rule, metric alarm, role/policy IAM, s3 lifecycle configuration, cloudfront response headers policy (`LC:1236-1250`, `:1364-1365`). O mecanismo e a tabela de isencoes entram no P06; as entradas de catalogo desses tipos sao do **P12** (depende de P06). `describe_alarms` nao levanta erro para ausente: P12 ajusta `readbacks()` (`LR:925-928`) para tratar lista vazia como ausencia.
- **Admissao do plano real (v3, N3a).** Na admissao, o gate exige que o conjunto de enderecos nao-`no-op` do plano **real** seja subconjunto do conjunto COVERED observado; senao recusa e o ciclo e refeito. A seguranca nao depende do `plan.json` de ensaio (§5.4); a completude de D4 continua valendo. RED (P18 e P07): plano real com endereco fora do COVERED e recusado; relatorio sem o `plan_sha256` do ensaio e recusado. O `plan.json` nunca vai a artefato publico.
- `drift_coverage` sem envelope (bootstrap/acm) continua estrito.
- **Atestacao dos nao cobertos (v2):** recursos fora do envelope e `no-op` ficam atestados pelo refresh do proprio `tofu plan` (leitura ao vivo) e por `applied_state`, que e consistencia entre plano salvo e state lido do S3 (`ct:121-127`), nao leitura independente. A janela plano->apply (<= ~27 min, `coordination_lease.py:149-151`) nao e observada para esses recursos; aceitavel porque o apply do plano salvo nao os toca.

Encodings (funcoes puras em `ct`, testes RED proprios): `identity`, `json`, `tags-kv`, `json-set`, `ecs-container-definitions`.

#### 3.5.1 Spec de readback do lifecycle (v3, N3b)

- Forma: `{service, operation, address, absent}`, mais `members` para o `list_schedules` agrupado (`LR:905-934`). **`parameters` sai** e e derivado dos atributos de identidade, igual ao caminho legado (§3.2). Hoje a spec e `{service operation parameters absent [members]}` e vem do `approval.json` do audit job (`LR:1349-1352`).
- `drift_coverage` ganha o argumento `specs` (hoje recebe so `reports`, `ct:136`); os dois chamadores, `LR:1363-1364` e `LR:1379-1380`, o passam, e a ligacao `specs[row.readback].address == row.address` vale tambem no lifecycle.
- Dono: **P06** a funcao de ligacao; **P11** e **P12** os chamadores do lifecycle e suas fixtures; o produtor de `approval.json` do audit job segue a nova forma (P11).

#### 3.5.2 Prova de ausencia (v3)

A leitura roda logo apos o `tofu apply` (`LR:1371-1380`) e os servicos apagam de forma assincrona. Uma leitura com `absent: true` passa quando:
- a chamada falha com codigo NotFound, de um conjunto tirado dos modelos de servico do botocore instalado (offline), exatamente para os tipos apagaveis: state machine, schedule, schedule group, rule e alarm (hoje `LR:912-925` aceita so `ResourceNotFoundException`, `StateMachineDoesNotExist` e `ResourceNotFound`); ou
- o recurso reporta status/estado `DELETING`, que e irreversivel; `observed` e entao projetado para `{absent: true}`.

`ACTIVE` ou qualquer outro estado e recusado. Sem poll. O alarme usa lista vazia (`describe_alarms` nao levanta erro). RED (P12): NotFound passa, `DELETING` passa, `ACTIVE` e recusado, codigo de erro desconhecido e recusado.

Limitacao declarada: o envelope cobre a Phase A "posterior" (state do p2, sem criar recurso fora de SUPPORTED). Premissa **nao verificada** (O11): P21 mostra, em modo local somente leitura, que o conjunto de enderecos e a identidade do state real tem a forma do p2 antes de congelar X*. Phase A sobre bootstrap limpo cria recursos de S3 fora do envelope e seria recusada.

### 3.6 G6 (v2): nada derivado de conta/ARN/bucket e publico em hash simples

- Hoje: `so:291-304` publica `account_id` em claro e `role_arn_sha256`, `policy_arn_sha256`, `document_sha256`; `authenticate` exige igualdade canonica (`so:383-388`; `authenticate_lifecycle` `so:51`). Tambem `repository_sha256` (`aws_boundary.py:181`) e `bucket_sha256` (P-D). Todos enumeraveis: a unica incognita e a conta de 12 digitos.
- Mudanca (D5 A): `account_id` sai do relatorio (nao e hasheado; o gate ja compara `pin["account_id"] == governance["account_id"]`, `so:260-266`). Os demais campos viram HMAC-SHA256 com `report_hmac_key`; `_facts(pin, key)` recomputa e compara, logo o gate precisa da chave (`so:383-388` compara por igualdade canonica com `_facts` de `so:291-304`). `validate_proof` recusa relatorio cuja serializacao contenha a conta da governanca ou um sha256 simples de ARN/documento conhecidos.
- **(v3) Custodia (O14 emendada, substitui a D5 "nunca em governanca").** A `report_hmac_key` (32 bytes aleatorios por ciclo, gerada pelo CLI do dono) vive em exatamente quatro lugares, porque o gate precisa recomputar `_facts` para verificar:
  1. o Secret Service local do dono (geracao e rotacao);
  2. o secret de governanca, que fica so no environment `production` (o gate verifica com ele);
  3. um secret do environment `cnesdata-observer` (o observador produz com ele). Esse environment recebe a mesma regra de branch de deploy do `production`, so `main`. Criar essa regra e escrita de configuracao do GitHub e exige aprovacao do dono na janela;
  4. o store privado de evidencia.
  A chave nunca aparece em logs de workflow, artefatos, recibos, argv nem evidencia publica; chega ao workflow so por stdin ou por secret de ambiente. Rotacao: chave nova a cada ciclo; a antiga nunca e reutilizada. A alternativa (retirar os valores derivados de ARN) foi rejeitada: remove a ligacao entre a observacao e o role pinado.
- RED: `test_relatorio_policy_evaluation_nao_publica_conta`, `test_relatorio_publico_nao_tem_sha256_simples_de_arn_ou_documento`, `test_validate_proof_recusa_relatorio_com_conta_em_claro`.
- Ids numericos do GitHub: lidos como ids de conta/org/usuario/repositorio/instalacao (nenhum aparece nas medicoes); `run_id`, `run_attempt`, `artifact_id`, `job_id` sao identidade de protocolo publica (O15).

### 3.7 Testes RED do G4/G5 (reuso e extensão do replay do PR #82)

O stub "dual-view" do DynamoDB (`tests/fixtures/cnesdata_phase_a_replay.py:218-237`, `:266`) devolve um documento sintético que satisfaz um único `expected_sha256` nos dois estágios; por isso B9 e B10 nunca podiam ficar RED. Substituir por respondedores por recurso, escritos a partir da forma real das APIs (lista KV de tags, revisão `:3` para `:4`, `RoleLastUsed` presente), e gerar a matriz com o gerador real do §4.1, não do mesmo dict que ela valida.

- `test_apos_apply_get_role_com_tags_novas_passa_com_readbacks_por_estagio` (base: `live drift/readback mismatch`).
- `test_substituicao_retida_de_ecs_le_revisao_3_antes_e_4_depois`.
- `test_criacao_ausente_antes_so_tem_leitura_no_estagio_after`.
- `test_recusa_leitura_orfa_e_policy_rastreado_duplicado_no_after`.
- `test_application_recusa_checkpoint_sem_get_role_e_get_role_policy_do_fence`.
- `test_get_role_policy_rastreado_continua_isento_de_hash` (regressao de `verify_api`).
- `test_matriz_after_incompleta_falha_antes_do_acquire_no_deploy` e `test_matriz_after_incompleta_falha_depois_do_apply_no_base`.
- `test_scheduler_preflight_falha_antes_do_acquire_no_deploy`.
- G5 (v2): `test_recusa_tipo_alterado_fora_do_envelope`, `test_recusa_linha_que_diverge_do_catalogo`, `test_recusa_linha_para_atributo_so_state`, `test_recusa_atributo_do_recurso_coberto_fora_do_catalogo_e_de_not_observable`, `test_recusa_linha_cuja_spec_pertence_a_outro_endereco`, `test_parametros_da_leitura_vem_do_atributo_de_identidade_do_endereco`, `test_delete_no_lifecycle_exige_linha_de_ausencia_e_recusa_sem_ela`, `test_phase_a_continua_recusando_delete` (fixa `ct:467-468`), `test_recusa_mudanca_em_s3_canary_fora_do_supported`, `test_lifecycle_usa_envelope_proprio_e_recusa_tipo_alterado_fora_dele`, `test_chamada_sem_envelope_continua_estrita`.
- Mutantes que o auditor deve matar: remover a regra de leitura orfa; aceitar `expected_sha256` ou `parameters` residuais; aceitar tipo fora de SUPPORTED; trocar `before`/`after` no indice; aceitar linha de atributo isento; aceitar spec de endereco diferente da linha; dispensar a linha de ausencia.

## 4. Jobs produtores

### 4.1 P-A: montador do proof e observador (infra-ansible)

**Confirmação de que fica no infra-ansible, com argumento de código:**
- `pv:277-281` exige `run.head_sha == workflow_sha` do produtor. Num repositório de produto, o sha do run é o `S` mutável do produto e o proof auto-mediria o próprio candidato.
- `so:283-287` proíbe que o `owner_producer` seja um workflow consumidor (`CONSUMER_WORKFLOWS`, `so:12-20`) e exige que ele esteja em `proof_producers`. O montador é o dono independente dessas medições.
- O argumento "reescrever `proof_producers` a cada `S`" é fraco, porque a governança é reescrita três vezes por ciclo de qualquer forma. O argumento forte é independência e estabilidade do trust entre releases do produto.

**Repositório e identidade:**
- Reusable `reusable-cnesdata-observer.yml` no infra-ansible (nome fora de `CONSUMER_WORKFLOWS`), chamado por `cnesdata-producers.yml` (caller, `workflow_dispatch`). O caller declara `environment: cnesdata-observer` (sem revisores; deployment branch so `main`, nenhuma tag; v3: o `main` do infra-ansible fica congelado em `K` na janela, O8 decidida). O job do reusable pede `id-token: write`.
- Trust do role de leitura (novo, `opentofu/cnesdata-delivery/oidc-observer.tf`): `aud` = audience padrao de STS (o host `sts` no dominio publico da AWS); `sub = repo:VINIClUS/infra-ansible:environment:cnesdata-observer` (formato default, nunca renomear o repositório, regra de imutabilidade do `sub`); `job_workflow_ref = VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-observer.yml@<X_R>` (sha literal do reusable); `DateLessThan aws:CurrentTime = enabled_until`. Mesmo desenho de `oidc.tf:65-84`.
- `proof_producers` e `session_policy_pins[*].owner_producer` usam o **caller**: `{repository: VINIClUS/infra-ansible, workflow_path: .github/workflows/cnesdata-producers.yml, workflow_sha: K}`, porque o run que cria o artefato é o do caller e `provenance` confere `run.path` e `run.head_sha` (`pv:279-281`). **(v3; `K` resolvido pela coordenadora)** `X_R` vale X* (o reusable do observador esta no commit X*). `K` e o commit do caller (merge do P33, com o `main` congelado em `K`, O8), descendente de X*, e nunca igual a X*: um commit nao contem o proprio sha. O caller cita `uses: VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-observer.yml@<X*>`; `uses: ./` fica recusado porque o `job_workflow_ref` passaria a carregar o ref e nao o sha. O reusable do observador busca `tools/cnesdata_delivery/producers/**` no proprio sha `X_R`, resolvido de `run.referenced_workflows` e exigido igual a `path@sha` exato, com sha de 40 hex igual ao X* que o caller em `K` passa como input literal (precedente de leitura: `.github/workflows/reusable-cnesdata-host-deploy-gate.yml:71-80`, busca em `refs[0].sha`; aqui a comparacao e com o input, porque o ambiente do observador nao tem governanca; o input e um literal do arquivo do caller em `K`, nao um input de dispatch, e a comparacao e so de consistencia, nao controle de seguranca: as ancoras sao o trust AWS em X*, o `uses:` conferido pela CLI e o `main` congelado), nunca no `github.sha` do caller (que e `K`). O reusable busca em `X_R` todo modulo de `tools/cnesdata_delivery/` que executa: `producers/**` e os modulos de gate que importa (`contract` para `public_safe`, `aws_boundary` para `_facts`). A trust do role do observador (`job_workflow_ref` = `.../reusable-cnesdata-observer.yml@X*`) impoe o mesmo pin do lado AWS, e o job observe precisa de `actions: read` para `getWorkflowRunAttempt`. O proprio caller em `K` roda com o environment `cnesdata-observer` e fica fora da superficie pinada em X*: a confianca nele vem de `proof_producers.workflow_sha` = `K`, do `main` congelado e do environment so do `main`. Antes da escrita 1, a CLI do P18 exige que X* seja ancestral de K (`git merge-base --is-ancestor X* K`), que o pin `uses:` do caller seja igual a X*, e recusa se `git diff --name-only X*..K` tocar a superficie pinada em X* (RED no P18). "Superficie pinada em X*" e todo `tools/cnesdata_delivery/**` (inclui `host_gate.py`, `ext2_inventory.py`, `producers/**` e `tools/cnesdata_delivery/runtime-requirements.txt`; as listas de arquivos do §0 sao um subconjunto) mais `.github/workflows/reusable-cnesdata-*.yml`; nao se confunde com `APPLICATION_CLOSURE_PATHS` (§5.1). A superficie cobre so codigo do infra-ansible; o que os gates leem do CnesData em S (arvore do produto e workflows do caller, `provenance.py:76`; `source_closure`, `lifecycle_runtime.py:338-350`) e ancorado por S e pelas baselines, nao por X*. Um commit posterior a K no `main` torna `head_sha != K` e a admissao falha fechada.
- `head_sha == workflow_sha == K` exige despachar sobre ref imutável. Duas opções:
  - congelar o `main` do infra-ansible em `K` durante a janela (como o `main` do CnesData);
  - despachar `--ref refs/tags/cnesdata-producers-<K8>` (criada pelo dono). `run.path` vira `...@refs/tags/...` e `pv:280` divide em `@`; `head_sha` é o commit da tag.
  **Decidido (v3, coordenadora): congelar o `main` do infra-ansible em `K`** desde a escrita 1 ate o primeiro `execute` do application. A opcao da tag fica recusada: o environment `cnesdata-observer` aceita so `main`, e uma tag exigiria regra extra de protecao. `K` e o merge do P33, o ultimo PR do infra-ansible antes da janela.

**Entradas e saídas** (dispatch com `purpose`, `role`, `source_sha`, referências públicas; **nenhum ARN ou ID nas entradas**, pois inputs de workflow são públicos):
- Job `observe` (OIDC, leitura AWS): lê o state (hash e conjunto de instâncias), lê os pins das políticas gerenciadas de sessão (`iam:GetPolicy`, `iam:GetPolicyVersion`), executa as especificações `before` (o gerador as monta, §5.4), lista e lê o prefixo `phase-inputs` do bucket de evidência, lê o ECR. Emite só arquivos sanitizados.
- Job `assemble` (sem AWS, sem `id-token`): monta relatórios, `proof.json` e o artefato final; espera 3 s após o upload (o artefato precisa ser estritamente interior ao run, `pv:229-232`). O `assemble` **não autentica o artefato `drift` do próprio run** por `pv.GitHub.artifact`, porque `pv:206` exige run concluído; ele lê o conteúdo que o `observe` acabou de gerar (artefato de job a job) e só calcula o `content_sha256` pela lista de membros; a autenticação pública acontece depois, no gate. No ciclo do deploy o `drift` já existe e é autenticável normalmente.
- Artefatos (retenção 30 dias, `retention-days: 30`):
  - `delivery-drift-<source8>-<run>-<attempt>` (membro `drift-handoff.json`): é o baseline `drift` (só no ciclo do plan; no deploy reutiliza-se a mesma referência);
  - `delivery-admission-<role>-<run>-<attempt>`: `proof.json` + relatórios (é o `admission_reference`).
- Execução em dois modos, mesmo código: CI (OIDC) e local (credenciais do dono), esse último para o ensaio da fase IV (§6.0).

**AWS (role observador, exato):** só leitura, deny explícito de `sts:AssumeRole*` e de qualquer escrita (como `oidc.tf:100`).
- IAM: `iam:GetPolicy`, `iam:GetPolicyVersion` nos três ARNs de política de sessão (`local.delivery_session_policy_arns`); `iam:GetRole`, `iam:GetRolePolicy` em `role/cnesdata-prod-*`.
- ECS: `ecs:DescribeTaskDefinition` (recurso `*`, exigência do serviço); `ecs:DescribeClusters` no cluster.
- ECR (check OCI): `ecr:DescribeRepositories`, `DescribeImages`, `BatchGetImage`, `GetDownloadUrlForLayer` no repositório.
- S3/KMS: `s3:GetObject` em `cnesdata/prod/opentofu.tfstate` (+ `kms:Decrypt` na chave de state, `kms:ViaService` e `kms:EncryptionContext:aws:s3:arn` igual à chave do objeto ou ao ARN do bucket do state, por causa da S3 Bucket Key); `s3:GetObject` em `<evidence_prefix>phase-inputs/*`; `s3:ListBucket` com `s3:prefix = <evidence_prefix>phase-inputs/*`; `kms:Decrypt` na chave de evidência com a mesma condição de contexto. Nada de `Put*`.
- As ações IAM/ECS/ECR repetem as listas já aprovadas em `delivery_product_reads` (`oidc.tf:19-34`); o teste do role compara por subconjunto para não divergir.
- **(v3)** Autoconferencia do §5.4 passo 4 le tipos SUPPORTED (`rt:147-150`): a politica do observador ganha `dynamodb:DescribeTable` e as leituras S3 `GetBucketPolicy`, `GetBucketVersioning` e `GetBucketObjectLockConfiguration`, cada uma com escopo nos recursos nomeados (precedente de escopo: `oidc.tf:57`; `dynamodb:DescribeTable` aparece em `oidc.tf:25`). Entregue no P22.
- **(v3, N3a; P21b)** O observador gera o plano de ensaio no proprio job: `tofu init -lockfile=readonly` e `tofu plan -refresh=false -lock=false` sobre `infra/opentofu/env/prod` do produto em `S` (OpenTofu v1.13.2 com sha256 conferido), com os insumos de `phase-inputs.json` mais `shared_outputs` da configuracao privada do observador, e o state lido pelo role de leitura. O JSON do plano fica so na memoria do job: nunca vai a S3, artefato ou log. `rehearsal_plan_sha256` do relatorio `drift-baseline` e o sha256 desse JSON e serve so de identidade; o gate confere apenas o formato. Antes do `init` o observador liga a toolchain ao valor governado da configuracao privada (`toolchain`: `lock_sha256` e `providers`, iguais ao `baseline.toolchain` da governanca): confere o sha256 do `.terraform.lock.hcl`, grava o CLI config com `provider_installation { direct { include = <providers> } }` no temp do job e, depois do `init`, le de volta o workspace e o backend efetivos. Um `shared_outputs` divergente do da governanca falha fechado no gate (a cobertura e re-derivada do `plan.json` do gate). Falha de `init`, leitura de volta, `plan` ou `show` para o observador antes de qualquer medicao; os timeouts somam 670 s dentro da sessao de 900 s.
- **(v3) `report_hmac_key`.** A `report_hmac_key` (32 bytes aleatorios por ciclo, gerada pelo CLI do dono) vive em exatamente quatro lugares, porque o gate precisa recomputar `_facts` para verificar:
  1. o Secret Service local do dono (geracao e rotacao);
  2. o secret de governanca, que fica so no environment `production` (o gate verifica com ele);
  3. um secret do environment `cnesdata-observer` (o observador produz com ele). Esse environment recebe a mesma regra de branch de deploy do `production`, so `main`. Criar essa regra e escrita de configuracao do GitHub e exige aprovacao do dono na janela;
  4. o store privado de evidencia.
  A chave nunca aparece em logs de workflow, artefatos, recibos, argv nem evidencia publica; chega ao workflow so por stdin ou por secret de ambiente. Rotacao: chave nova a cada ciclo; a antiga nunca e reutilizada. A alternativa (retirar os valores derivados de ARN) foi rejeitada: remove a ligacao entre a observacao e o role pinado.
- Sem servicos de leitura alem dos listados (O1 decidida).

**Cadeia de expiração até as admissões** (T = observação do plan):

| Elemento | Valor | Por quê |
|---|---|---|
| `proof.expires_at` | T + 3 h | exige >= now+3600 em credentials e execute de plan e deploy (`so:397-401`); índice do plan <= expiração do proof histórico (`rt:105-107`) |
| `check.expires_at` | = `proof.expires_at` ou maior | `pv:294` |
| `pin.observed_at`, `pin.expires_at` | igual a `check.observed_at`/`check.expires_at` do `policy-evaluation` | `so:389-392` |
| `pin.expires_at` | >= `proof.expires_at` | `so:397-399` |
| `pin.frozen_until` | T + 4 h | >= now+3600 no último admit (`so:395-401`); o dono não aplica a raiz de entrega nesse intervalo |
| `artifacts[i].expires_at` | >= `proof.expires_at`, <= retenção real | `pv:262`, `:267` |
| `cost.expires_at` | >= expiração do plano (min de `rt:555-558`) | índice `<=` custo (CD `verify_plan_artifact.py:325`) |
| CloudFront `expires_at` | >= `cost.expires_at` | `ct:379` |

**P-A no deploy** é só montagem, sem AWS: reutiliza os fatos observados no ciclo do plan (inclusive o pin do deploy, observado no plan), anexa `plan_binding_sha256` do índice público e os dois checks do deploy (§5.2). Isso mantém o P-A do deploy em ~3 min, dentro do orçamento (§6).

### 4.2 P-B: baselines no CnesData (`verify-production.yml`)

- Repositório e gatilho: job novo `delivery-baselines` em `.github/workflows/verify-production.yml`, `needs: opentofu-policy-cost`, em push no `main` (o run em `S` já é exigido; as referências têm `head_sha == S`). O job já tem tofu 1.13.2 (`:234-237`) e conftest 0.71.1 com hash (`:242-257`).
- Saídas, três artefatos distintos (retenção 30 dias, nome estável):
  - `delivery-baseline-toolchain`: `toolchain.json` `{opentofu{version, binary_sha256}, providers[{source, version, package_sha256}], lock_sha256}`. `binary_sha256` é o hash do binário extraído (`rt:512`); `lock_sha256` do `.terraform.lock.hcl` (`:283`); `package_sha256` é o hash `zh:` do pacote linux_amd64 da versão do lock, conferido contra o conjunto `zh:` do lock.
  - `delivery-baseline-policy`: `policy.json` `{policy_sha256 (policies/cnesdata.rego), conftest_version, conftest_sha256}`.
  - `delivery-baseline-cost`: `cost-manifest-source.json` (o `cost-manifest.json` do CD, **verbatim**, validado por `schemas/cost-manifest.schema.json`; e a fonte, nao o objeto do gate) e `cost-context.json` `{stage, checkpoint_sha256, target_sha256, source_sha, unbound_required, cloudfront}`.
- Identidade: nenhuma AWS. Pinning: o run é do próprio `S`.
- Observação: o artefato atual `production-config` (`:279-296`) continua existindo; ele não tem hashes de tofu/providers.
- **Derivador do manifesto do gate (v2, D3; v3):** `producers/cost_ledger.py` (infra-ansible, no P-A e no CLI do dono, mesma funcao, fora do X*), entrada = manifesto-fonte autenticado + tabela de mapeamento revisada + `S` + datas do ciclo (`calculated_at` = T, `expires_at` >= expiracao do plano e do CloudFront, `ct:349-351`, `:379`). Regras:
  - `scope shared` -> `aggregate-only`; `monthly_usd` = max(quantidade-franquia) x preco, **arredondado para cima** a 2 casas; `credits_usd "0.00"`, `gross true`, `unbound false` no estagio `active`.
  - **(v3)** Um componente por linha do CD (34 linhas com `kms_signing`, ~3,8 KB). A categoria de cada linha vem da tabela de mapeamento revisada (`kms-encryption` <- `kms_envelope`; `kms-signing` <- `kms_signing`; `s3-requests-versions-logs`, `cloudfront-waf` por lista revisada; as demais linhas, Fargate, Lambda, DynamoDB etc., recebem categoria propria); linha sem categoria e recusada. O gate aceita categorias extras (`ct:366` usa `<=`), entao nada exige as quatro categorias como particao.
  - **(v3, N4a) Preco.** Linha com preco toma o preco da lista publica de precos da AWS para us-east-2; URL da fonte e data de recuperacao ficam registradas em cada linha.
  - **(v3, N4b) Credito nao verificado.** Linha de franquia ou credito nao verificado (`cognito_allowance`, `unit_price_usd: null`) e excluida das somas e listada em `excluded` com o motivo "credit not applied". Excluir um credito so pode subir o limite. RED: excluir a linha nunca reduz `max`.
  - **(v3, N4c) `other_projects_spend`.** O manifesto do CD declara a linha (scope `shared`); ela nao e removida. A linha e precificada por valor medido e datado que o dono fornece: **pergunta O16**; o P04 espera por ela, e por isso a O16 esta no caminho critico (P04, P18, P19, ...).
  - **(v3, N4d) `kms_signing`.** Scope `shared` (so agregado), porque o product ja esta em ~7,99 de 8 (`ct:329`); preco da lista publica de KMS; a chave ext2 e real (`signing.tf:29`). A fixture de `kms-signing` como product (`tests/fixtures/cnesdata_cost.py:17`) nao serve de modelo. P04 tambem atualiza `PRODUCT_IDS` e `CAP_IDS` em `tests/production/infra/test_cost_manifest.py:48,58`.
  - **(v3) Ligacao com a fonte.** A evidencia de custo ganha `source_manifest_sha256` (sha do manifesto-fonte autenticado do CD), ligando o manifesto derivado a fonte: hoje `ct:341-348` le so `cost`, `checkpoint` e `manifest_sha256`, e o dono poderia escrever qualquer manifesto que passe `validate_cost`. Mudanca de closure no P08, com RED.
  - Totais recomputados `product <= 8`, `aggregate < 15` (`ct:329`); soma max atual ~7,90 product, por componente ~7,99 (folga ~0,01: qualquer linha product nova estoura). RED por regra, mais `test_manifesto_derivado_passa_validate_cost`.
- O dono entrega os tres digests do CloudFront Free ACTIVE (O6).

### 4.3 P-C: `phase-a-prepare.yml` (CnesData)

Mudanças no job `prepare` (`phase-a-prepare.yml:34-112`):
1. Após `promote-ecr` e `phase-inputs` (`:96-104`), copiar byte a byte o `candidate.json` do artefato R2 já autenticado (`reference` de entrada; bytes R2 canônicos com LF, `ct:314-320`).
2. Trocar para o role de escrita da **raiz de entrega** `cnesdata-prod-phase-inputs-writer` (OIDC do mesmo job, segundo `AssumeRoleWithWebIdentity`) e gravar com SSE-KMS e `If-None-Match: *`:
   - `<evidence_prefix>phase-inputs/<S>/<run_id>/<run_attempt>/phase-inputs.json`;
   - `.../candidate.json`;
   - `.../promotion.json`.
   Chaves exatas de `session_grouping.py:29-33`.
3. O artefato público `phase-a-prepare-<run>-<attempt>` passa a conter só `phase-a-public.json` `{objects: [{name, sha256, size}], source_sha, run_id, run_attempt}`. Hoje ele publica `promotion.json` e `phase-inputs.json` com ARNs (`:105-112`). Nenhum consumidor lê esse conteúdo. CnesData: nenhuma ocorrência em `scripts`, `release`, `.github`, `docs/runbooks`; o caller só autentica a referência (`verify_plan_artifact.py:367-380`). infra-ansible no pin: `git grep` de `phase-inputs`/`promotion.json`/`candidate.json` em `tools` e `.github` só acha leituras do objeto **privado** no S3 (`rt:565-570`, `rt:607-608`, `rt:450`, `session_grouping.py:29-44`) e a autenticação da referência com retorno descartado (`rt:564`); o lifecycle não lê membros do payload de phase-inputs (os originais da Phase A vêm de `envelope.json`, `lease.json`, `checkpoint.json`, `drift.json`, `ecr-before.json`, `session_policy.py:127-144`).
4. Retenção 30 dias.
5. **(v3, N3a; P21b)** Nao ha upload do plano de ensaio: o observador (CI) o gera no proprio job (§4.3, observador) e o JSON fica so na memoria, nunca em S3, artefato ou log. O relatorio leva so o sha256 (`rehearsal_plan_sha256`, identidade). Nao existe chave de ensaio nem prefixo `phase-inputs/` de ensaio; o namespace `<S>/<run_id>/<run_attempt>/` mantem os tres objetos.

Role de escrita (raiz de entrega, ver §7): `s3:PutObject` em `<evidence_prefix>phase-inputs/*` com `s3:if-none-match` e `kms:GenerateDataKey`/`Encrypt` na chave de evidência com contexto `<evidence_prefix>phase-inputs/*`. Trust: `sub = repo:VINIClUS/CnesData:environment:production` e `job_workflow_ref = VINIClUS/CnesData/.github/workflows/phase-a-prepare.yml@refs/heads/main`. Isso não é sha-pinado (workflow top-level), mas é o mesmo padrão do role `ecr-promotion` (`modules/runtime-iam/ecr-promotion.tf:13-17`), e o environment `production` tem revisores. A alternativa sha-pinada exigiria mover o upload para um reusable que recebesse os arquivos privados por artefato, o que vazaria os ARNs (O9).

A atestação do namespace **não** sai do P-C: `phase_input_namespace.payload_reference_sha256` hasheia a referência completa do artefato, que inclui `artifact_id` e `digest` (`session_grouping.py:29-44`), e o run não conhece o próprio artifact id. O P-A calcula depois: lista o prefixo, exige exatamente 3 objetos com hash igual aos de `phase-a-public.json`, e escreve `{purpose: "phase-inputs", dedicated: true, payload_reference_sha256, prefix_sha256}` na medição de `policy-evaluation` (`so:379-404`).

Os três checks da Phase A são medidos no P-A (a autoridade única das medições), não no P-C. Divergência declarada do registro de decisão: os relatórios precisam estar no artefato do run do `owner_producer` (`so:322-340`), então o P-C só entrega os dados.

### 4.4 P-D: compromissos e CLI do dono

Dois pedaços, ambos no infra-ansible:
- **Workflow `cnesdata-baseline-commitments.yml`** (público, sem AWS): recebe como inputs apenas hashes e fatos públicos e emite dois artefatos:
  - `delivery-baseline-backend`: `{identity_sha256, key, workspace, region, encrypt, use_lockfile, bucket_hmac, kms_key_id_sha256}` (D5: `bucket_hmac` no lugar de `bucket_sha256`; `identity_sha256` e `kms_key_id_sha256` hasheiam config/ARN com UUID de chave KMS, alta entropia);
  - `delivery-baseline-shared-outputs`: `{schema_version: 2, schema_sha256 (do schema CD), shared_outputs_sha256}`.
  Limitação declarada: é atestação do dono (os valores reais vêm do catálogo privado de inventário, que nenhum run público lê). O valor real viaja em `product_inputs.shared_outputs` na governança e o CLI confere `sha(valor) == shared_outputs_sha256`.
- **CLI `tools/cnesdata_delivery/producers/governance_assembly.py`** (roda na sessão de produção do dono, fora do CI): monta cada documento a partir das referências públicas e dos valores privados, valida o fechamento de chaves, tamanho (<= 43 856 B, 4 096 B abaixo do teto de 47 952 B do GitHub; este e o limite que vincula; era 40 960 B ate o P21), cruzamento de hashes e prazos, e emite por stdout para `gh secret set --env production` (escrita por stdin). Reduz erro de transcrição, que é modo de falha pós-acquire.
- **(v3)** O CLI gera a `report_hmac_key` por ciclo (32 bytes aleatorios), grava no Secret Service local do dono e a entrega por stdin aos secrets da governanca (environment `production`) e do environment `cnesdata-observer`; nunca por argv, log ou artefato. Rotacao: chave nova a cada ciclo, a antiga nunca e reutilizada (§3.6). Runbook de custodia: P32.

## 5. As quatro lacunas

### 5.1 O que `content_sha256` de `producer_pins` hasheia

`pv:320` só confere igualdade entre `descriptor.producer_pins` e `governance.dependencies`; `ct:578` não impõe semântica; o caller só confere a forma (`_descriptor`, CD `:197-209`). Definição proposta: para o pin do infra-ansible em `X*`,

`content_sha256 = sha256(canonical({"files": {path: sha256(bytes@X*)}}))` sobre `APPLICATION_CLOSURE_PATHS`, isto é, o mesmo valor de `application_gate.closure(X*)` (`lifecycle_contract.py:604-618`; a auditoria do PR #82 reproduziu a closure da base e da cabeça com `git cat-file`, valores `<closure-base>` e `<closure-head>`).

Justificativa: a closure já é a definição de "código executado" dos gates do application (módulos do pyboot e o reusable; a superfície pinada em X* é mais ampla, §4.1); reaproveitá-la dá um número único e verificável. O check `dependency-pins` recomputa a partir de `git cat-file` em `X*` (§5.2) e compara com a governança. O pin vira inválido quando o gate muda, o que é o comportamento desejado. O pin do CnesData não existe (a descriptor só exige o do infra-ansible, CD `:205-208`).

### 5.2 Formato da medição por check_id

Todos são `{check_id, source_sha, measurement}`, canônicos, `public_safe` e <= 256 KiB (`pv:300-306`). `observed_sha256 = sha(canonical(measurement))`. Onde um hash substitui um ARN, vira `*_sha256`. O gate só impõe a forma de dois deles; a semântica abaixo é contrato do produtor e é testada no P-A.

| check_id | Medição | Fonte |
|---|---|---|
| `source-develop-checks` | `{branch: "main", compare_status, required: [{name, conclusion: "success", head_sha}]}` para `governance.required_checks` e os 10 de `REQUIRED_CHECKS` (CD `release/build_candidate.py:24-27`) | API de check-runs e `compare/<S>...main` (espelha `pv:332-336`) |
| `artifact-origin-attempt-expiry` | por propósito: `{purpose, reference_sha256, artifact_digest, run_id, run_attempt, run_started_at, created_at, updated_at, expires_at, interior: true}` | API de runs/artifacts |
| `dependency-pins` | `{pins: governance.dependencies, closure_recomputed_sha256}` com a closure de `X*` recalculada via `git cat-file` | repositório em `X*` |
| `toolchain-lock-selections` | o baseline `toolchain` completo + `lock_providers_equal: true` (providers do lock == providers da medição) | artefato P-B |
| `backend-identity-workspace` | `{identity_sha256, workspace: "default", key, region, encrypt, use_lockfile, bucket_hmac, kms_key_id_sha256}` (D5) | artefato P-D |
| `policy-evaluation` | `{managed_session_policy: _facts(pin, key), phase_input_namespace? (so phase-a), policy_sha256, conftest_sha256}`; `_facts` sem `account_id` e com HMAC (G6, §3.6) | AWS IAM + P-B |
| `cost-ledger-purpose-scope` | o relatorio inteiro tem de ser igual a `baseline.cost_evidence` (`rt:71-72`): `measurement.cost` = governanca `cost` sem `evidence_sha256`, `measurement.checkpoint` = `cost_context`, `measurement.manifest_sha256` = sha do manifesto **derivado** (`ct:342-348`), `measurement.source_manifest_sha256` = sha do manifesto-fonte autenticado do CD (v3) e `measurement.excluded` (linhas excluidas com motivo, v3) | P-A (derivador) + P-B (fonte) + dono (CloudFront) |
| `drift-baseline` | `{handoff_sha256, rehearsal_plan_sha256 (v3, N3a), catalog_sha256, matrix_version: 2, source_sha, purpose, state_identity, rows_before, rows_after, absent_rows, readbacks_before, readbacks_after}` (o gate confere `handoff_sha256`, §2.4) | gerador do P-A |
| `promotion469-origin` | `{promotion_sha256, producer: {repository, workflow_path, workflow_sha, run_id, run_attempt}, artifact_digest}` do run `phase-a-prepare` | P-C + API |
| `r2-candidate-a2-binding` | `{candidate_sha256, release_id, canary_id, binding_sha256, creator_workflow_sha}` recalculados com `canary_binding` (`ct:306-311`) sobre os bytes R2 do objeto `candidate.json` | S3 (observador) |
| `oci-promotion-byte-integrity` | `{repository_hmac, image_digest, config_digest, manifest_sha256, blob_digests_sha256, platform: "linux/amd64"}`; `repository_sha256` de `aws_boundary.py:181` inclui `registryId` e so existe na forma privada de `ecr-before.json` (`rt:616-618`, `rt:286-296`) | ECR (observador) |
| `exact-saved-plan-package` (deploy) | `{plan_binding_sha256, envelope_sha256, package_aggregate_sha256, index_artifact_digest}` do índice público | artefato do plan (sem AWS) |
| `planned-source-input-binding` (deploy) | `{source_sha, purpose, phase_inputs_reference_sha256, planned_reference_sha256, release_candidate_sha256}` | índice público + governança |

Os campos do proof `candidate_sha256` e `promotion_evidence_sha256` (`pv:271`) são o `release.candidate_sha256` e o `sha256` do `promotion.json` (= `phase_input_objects["promotion.json"].sha256`). O gate só confere que, na Phase A, são hashes iguais entre o proof histórico e o atual (`rt:108-113`).

### 5.3 Derivação de `baseline.phase_a_graph`

Forma fechada: `{source_files: [{path, sha256}] (<= 32), configuration_sha256, unknown_policies: [{address, references, producers, before_policy_sha256}], known_policies: {address: sha}}` (`ct:522-590`). `rt:525-531` lê os arquivos do checkout em `S`; `validate_graph` (`rt:690`, `ct:526`) recalcula o hash da `configuration` do plano. Dependências de um plano real: a derivação não pode vir só do código.

Derivador `producers/phase_a_graph.py`, inverso de `validate_graph`, rodado sobre o `plan.json` do ensaio da fase IV (e de novo no passo 3 da janela, com os inputs reais) e sobre os arquivos de `S`:
- `configuration_sha256 = sha(canonical(plan["configuration"]))` (`ct:526`);
- `source_files`: o conjunto de caminhos que o `SourceResolver` realmente leu durante `precheck` dos endereços alterados, medido com um `dict` instrumentado nos `sources` (`iam_source.py:72-83`). `authenticate_sources` seleciona até 64 arquivos `.tf` em 9 diretórios (`iam_boundary.py:9-10`, `:135-157`); são 41 no `S` atual (5 + 3+4+4+5+3+10+4+3), logo o corte a <= 32 vem do que o resolver toca;
- `unknown_policies`: para cada `aws_iam_role_policy` alterado com `after_unknown.policy` ou `role`, `references = sorted(set(configuration[local]["expressions"]["policy"]["references"]))`, `producers = resolver.precheck(address)` (criações realmente necessárias), `before_policy_sha256 = sha(canonical(change.before.policy))` ou nulo (`ct:546-585`);
- `known_policies`: `{address: sha(canonical(policy depois))}` para os alterados com documento conhecido (`ct:586-588`).

Aceite: `validate_graph(plan, derive(plan, sources), sources, resolver)` fecha para a forma do p2 (3 policies alteradas, 3 task definitions substituídas); mutar um byte de fonte, o `configuration` ou um produtor faz falhar. O derivador roda localmente (o `plan.json` é privado e nunca sobe); o resultado (endereços e hashes) entra na governança. Dependência de calibração: o `plan.json` da janela tem de ter a mesma forma do ensaio (conferido no passo 3 da janela); divergência é recusada antes de qualquer dispatch.

### 5.4 Geração e revisão da matriz de produção

Gerador `producers/drift_handoff.py` (modo CI e modo local):
1. Entradas: state (identidade e instancias) lido pelo observador, `drift_catalog` (G5), plano de ensaio gerado pelo observador no job (P21b) para o conjunto COVERED e os alterados. **(v3, N3a; P21b)** O plano de ensaio nao e enviado: o observador de CI o gera no job e grava so o sha256 no relatorio (§4.3 item 5). O baseline `drift` e artefato de CI autenticado antes do `tofu plan` real (`pv:199-208`); um handoff gerado so localmente nao serve. A seguranca nao depende do ensaio: o gate recusa plano real com endereco nao-`no-op` fora do COVERED observado (§3.5).
2. Para cada instancia coberta, expande o catalogo: uma especificacao por endereco (`{service, operation, address}`; **sem parametros**, o gate os deriva) e uma linha por atributo exigido (`path`/`encoding` do catalogo). Endereco deletado (lifecycle): linha em `absent`. **(v3, N3b)** No lifecycle a spec e `{service, operation, address, absent}` (+ `members`), sem parametros (§3.5.1).
3. `after` = o mesmo conjunto de enderecos (a Phase A posterior so substitui in-place), com a lista `after` propria; criacoes: identidade vinda de valores conhecidos do plano; falha se `after_unknown` na identidade.
4. Auto-conferência antes de publicar: executa o `drift_coverage` real sobre as leituras ao vivo (`before`) e a validação estrutural do `after` contra a previsão do plano; falha fechado.

Revisão:
- o dono e o revisor leem o **catalogo** (3 tipos COVERED mais os tipos alterados, ~46 modelos + entradas dos alterados) e as contagens (linhas por estagio, especificacoes, enderecos), nao as 630 linhas;
- o PR do catalogo traz inventario publico de nomes de atributo por tipo (extraido do state, sem valores) e o teste catalogo = inventario nos dois sentidos (§3.5);
- na fase IV, o ensaio compara o conjunto de endereços de `after` com o do plano de ensaio e com o plano real do passo 3 da janela.

## 6. Run-book da janela (lado produtor)

**Tempo:** T0 = início do `execute` do plan (`rt:555`). O deploy exige 1980 s de vida em `min(prazo do plano, credencial)` em todo passo mutável (`coordination_lease.py:149-151`), então o `tofu apply` precisa começar até T0 + 27 min. Alvo: 25 min.

### 6.0 Antes da janela (fase IV, sem dispatch de gate)
1. `S` e `K` congelados (e `X*`, `X_R` fixados): `main` do CnesData em `S` e `main` do infra-ansible em `K`.
2. P-B: run `verify-production` verde em `S`. Candidato cortado. P-C: `phase-a-prepare` aprovado (1 revisor), três objetos privados gravados.
3. P-D: compromissos publicados. Dono entrega os três digests do CloudFront (O6).
4. Ensaio do P-A com a release sintética e o plano de ensaio (o observador gera o plano de ensaio no job e nada e enviado, §4.3 item 5): gera `drift-handoff`, `phase_a_graph`, roda os validadores do gate (`validate_delta`, `scheduler_preflight`, `drift_coverage`, resolver IAM).
5. Leitura do objeto do lease (ausente ou liberado com recibo que ainda autentica) e runbook de recuperação do lease aprovado. **(v3, P32)** O runbook, a custodia e rotacao da `report_hmac_key` com o CLI do dono (§3.6) e o checklist de drills (DR1 R21, DR2 R24, DR3, presenca dos revisores R22, ordem de `predecessor_read` e escrita 3 na janela de ~24 h) sao entregaveis do **P32** (IA, docs, fora da superficie pinada em X*, depende de P18; mergeado antes da janela, nao antes de X*).

### 6.1 Sequência com orçamento

| Passo | Quem | Duração alvo | Acumulado desde T0 |
|---|---|---|---|
| P-A(plan): `observe` + `assemble` | CI, sem revisor | 6 min (antes de T0) | n/a |
| Escrita 1 (plan) | dono, por stdin | 2 min (antes de T0) | n/a |
| `infra-plan.yml` (admit, validate, execute) | 2 revisores | até o início do execute (T0) | 0 |
| plan executa `tofu plan`, conftest, publica | CI | 5 min | 5 |
| P-A(deploy) só montagem | CI | 3 min | 8 |
| Escrita 2 (deploy) | dono | 2 min | 10 |
| `infra-apply.yml`: admit | CI | 2 min | 12 |
| apply `validate` (job + revisor) | CI + revisor | 4 min + espera Y1 | 16 + Y1 |
| apply `execute` (setup + revisor) | CI + revisor | 3 min + espera Y2 | 19 + Y1 + Y2 |
| `watchdog.admit()` no `tofu apply` | gate | exige acumulado <= 27 | folga = 8 min - (Y1 + Y2) |

Y1 + Y2 precisam somar no máximo 8 min. Os revisores devem estar presentes e avisados (R22). As duas esperas de reviewer são o item mais arriscado; o resto é determinístico.

### 6.2 Escritas do secret e gates dentro da janela
1. Escrita 1: governança do plan (`roles` plan/deploy, `drift_handoff`, `admission_reference` do P-A(plan), `phase_input_objects`, `phase_a_graph`, `session_policy_pins` plan e deploy). Dono aprova por escrito na sessão de produção.
2. `infra-plan.yml` `phase-a` (um acquire do lease).
3. P-A(deploy), escrita 2: governança com `planned` nas `artifact_purposes`/`artifact_references` e `admission_reference` novo com `plan_binding_sha256` (`rt:61-63`, `pv:123-138`). Reutiliza `drift_handoff` e baselines.
4. `infra-apply.yml` `phase-a` (novo acquire; sai o predecessor `applied`).
5. Em até 1 dia (`rt:214`), sem nenhum run de gate no meio (`application_gate.py:433-455`): apply do `predecessor_read` na raiz de entrega (fora do escopo desta spec), escrita 3 (application) e o `execute` do application. Os produtores do application são P-A com o role `application` (pin do `session_owner_references`) e P-B/P-D de novo; o `approval.json` do lifecycle (matriz por estágio no próprio payload, `lifecycle_runtime.py:1349-1380`) usa o mesmo gerador, mas sua construção é parte do plano B8, não desta spec.

Falha pós-acquire: lease preso, runbook da fase IV. Reduções desta spec: tudo que dá para falhar no deploy fica antes do acquire (§3.4); P-A(plan) só publica depois do auto-teste (§5.4); o CLI de montagem barra tamanho e prazos. **(v2)** O plan role nao ganha checagem pre-acquire da matriz (§3.4): ela e provada no ensaio do P21 (modo local, so leitura, e deploy-rehearsal no CI) com a forma do plano real. O manifesto de custo e rederivado na escrita 3, porque o lifecycle revalida custo a cada passo (`LR:1320`) e o `execute` do application vem ate ~24 h depois da Phase A (`rt:214`).

## 7. Divisao em PRs e pins (v2)

A ordem unica dos dois documentos (IDs P01a..P33, dependencias, dono de cada bump de pin, PRs que mudam a superficie pinada em X* ou fixtures) esta em **comentario 7038419407 §3**. Mapa deste documento: PR1 -> P01a (so texto; sonda O2 ja feita; medicao de tamanho em P21); PR2 (G4) -> P05; PR4 (G5) -> **P06, antes do G3** (o handoff valida `catalog_sha256`; achado de ordem do review); PR3 (G3) -> P07; PR5 (G6) -> P08; PR6 (produtores + derivador de custo) -> P18; PR7 (calibracao) -> P21; PR8 (raiz de entrega) -> P22; PR9 (P-B) -> P23; PR10 (P-C) -> P24; PR11 (pins) -> P31 (dono unico, junto de B PR-C5). Novos: P03 (desrastrear `spike_fb_driver`, D2), P04 (linha `kms_signing` e linhas nulas do manifesto de custo do CD, D3), P12 (catalogo do lifecycle), P32 (runbooks e checklist de drills, docs).

### 7.1 Pin X* e caminho critico (v2)

- `gate_shas.{plan,deploy}` autentica o historico de toda corrida seguinte (`coordination_lease.py:45`, `rt:376`, `rt:315`) e admite a corrente (`pv:82`, `pv:331`, `LR:41`). A Phase A e o application compartilham X*; qualquer mudanca de X entre duas corridas gated invalida o predecessor.
- Recibos de Phase A tem retencao de 1 dia (`rt:214`) e o predecessor do application e rejeitado se expirado (`LR:856`): uma Phase A antecipada nao serve de predecessor. Logo a primeira Phase A gated roda em X* e ate ~24 h antes do `execute` do application.
- X* = merge de P20 (doc final, `contract_sha256`), depois de todos os [X] do B (P10, P11, P12, P14-P17), dos [X] desta spec (P05-P08) e de P21 (calibracao e medicao de tamanho). **A primeira Phase A gated fica bloqueada por esse conjunto**, nao so pelo PR2-5 daqui. Alternativas (Phase A antecipada em X1; pin por papel) estao no comentario 7038419407 (D1).
- **Mudanca na superficie pinada em X* (todo `tools/cnesdata_delivery/**` mais `.github/workflows/reusable-cnesdata-*.yml`, definida no §4.1) depois do primeiro apply da raiz de entrega gera novo X* e novo apply.** Dois documentos ficam fora dessa superficie e nao mudam X* por si: (a) o documento de contrato da Phase A mora em `VINIClUS/CnesData` no `CONTRACT_SHA` imutavel (`contract.py:13-15`, lido em `runtime.py:48-54`); trocar o pin exige editar `contract.py`, que esta na superficie pinada, logo novo X*; (b) o documento de autoridade do lifecycle `docs/cnesdata-delivery-application-lifecycle.md` e lido no `lifecycle_contract.source_sha` pinado na governanca e conferido por sha256 (`lifecycle_runtime.py:117-124`); o caller do CnesData passa os mesmos valores como inputs (`reusable-cnesdata-application-gate.yml:50-53`); editar o documento muda `lifecycle_contract` na governanca e os inputs do caller (P31 ou a escrita de governanca da janela), nao X*. Os demais docs nao entram. Commits so de caller, de outros docs ou de tofu (P22, P32, `K`) nao mudam X*.
- Cada X* exige apply da raiz de entrega (`oidc.tf:13-16,79`; `application_promotion.workflow_sha` e `source_closure_sha256` reais, sem sentinela, `variables.tf:24`, `tests/test_cnesdata_delivery_oidc.py:657-658`) e reescrita da governanca (`gate_shas`, `dependencies`/`content_sha256` do §5.1).

### 7.2 Pin unico X* para todo reusable (v3)

X* e o sha dos quatro valores de trust abaixo, fixados por um unico apply da raiz de entrega. `K` e o commit do caller, descendente de X* (§4.1), fixado pela escrita de governanca da janela.

| Valor | Onde | Dono |
|---|---|---|
| `delivery` (plan/deploy/application) | `oidc.tf:79` | P22 (variaveis); apply do dono apos P20 |
| `host_gate.workflow_sha` | `host-gate.tf:19`, `variables.tf:291,300` | P22 (variavel); P31 (constante `HOST_GATE_SHA`) |
| `ext2.workflow_sha` | `signing.tf:15`, `variables.tf:245,273` | P22 (variavel); P31 (caller de signing, P26) |
| `X_R` (reusable do observador) | `oidc-observer.tf` (novo) | P22 |
| `K` = `proof_producers.workflow_sha` (commit do caller, != X*) | governanca | escrita de governanca da janela; CLI do P18 confere X* ancestral de K, o `uses:` do caller igual a X* e o diff `X*..K` sem tocar a superficie pinada |

A igualdade `HOST_GATE_SHA == PRODUCER` de `tests/production/delivery/test_trilha_em_main.py:29-30` permanece. Os pins do CD (§0) sao do P31.

## 8. Perguntas ao dono (v2)

Decididas pelo codigo: o infra-ansible hospeda P-A (§4.1); o carrier e o `drift` (§2.2); a closure e o `content_sha256` (§5.1); o observador so le; os tres checks da Phase A sao medidos no P-A. **Decididas pelo dono (instrucao fixa):** O1 = envelope minimo (§3.5); nenhum hash simples de baixa entropia nem nome de bucket em evidencia publica.

1. ~~O1~~ decidida.
2. **O2, teto do secret (feita, 2026-11-20).** Sonda em repositorio descartavel, secret de environment: 47 000 B aceito; 48 000 B e 48 001 B recusados (HTTP 422); busca binaria: maior aceito 47 952 B, menor recusado 47 953 B (47 952 + 48 B de overhead = 48 000 B cifrados). Entrega a 47 952 B: o job com o environment recebeu 47 952 B com sha256 igual; o job sem o environment recebeu 0. Codigo aceita 65 536 B (262 144 no lifecycle); o teto efetivo e 47 952 B.
3. ~~O3~~ removida: a conta nao e publicada (G6).
4. **O4, nomes e enderecos.** Aceitar enderecos de modulo no artefato `drift` (nomes de recurso e bucket nao entram, §2.3).
5. **O5, environment `cnesdata-observer`** (regra de branch so `main`, escrita de configuracao do GitHub que exige aprovacao do dono na janela, e o secret `report_hmac_key`, O14).
6. **O6, CloudFront Free ACTIVE (#476 P2).** Tres digests e datas.
7. **O7, esperas dos revisores.** Confirmar Y1 + Y2 <= 8 min (R22) ou aceitar duas passadas.
8. **O8, ref imutavel (decidida em v3).** Congelar o `main` do infra-ansible em `K` (merge do P33) da escrita 1 ao primeiro `execute`; sem tag.
9. **O9, trust do escritor de phase-inputs** por `job_workflow_ref` em ref `main` (padrao `ecr-promotion`).
10. **O10, aplicacao dos roles** observador e escritor e das raizes por X*: fase III com aprovacao escrita.
11. **O11, limite do G5.** Confirmar Phase A "posterior" (premissa nao verificada, P21 evidencia) e que mudanca nos cinco tipos de S3 canary fora de SUPPORTED e recusada.
12. **O12, shared-outputs como atestacao.**
13. **O13 (emendada, v3), custo.** Precos da lista publica da AWS para us-east-2, com URL e data por linha; `kms_signing` com scope `shared`; `cognito_allowance` excluida das somas e listada em `excluded` ("credit not applied"); `other_projects_spend` fica e depende de O16 (§4.2).
14. **O14 (emendada, v3), custodia de `report_hmac_key`:** quatro lugares, listados em §3.6 e §4.1.
15. **O15 (respondida pelo dono em 2026-11-20).** `run_id`, `run_attempt`, `job_id` e `artifact_id` ficam publicos onde o gate ja os publica (nomes de artefato, recibos, descritores). Ids de conta, org, usuario, repositorio e instalacao viram sempre `<id>`, tambem na evidencia postada a mao.
16. **O16 (novo, v3), gasto mensal de outros projetos na mesma conta AWS**, para a linha `other_projects_spend`. Fonte recomendada: o dono le o total da conta do ultimo mes fechado no console de Billing, menos CnesData, e informa o valor com a data. O P04 espera por esta resposta. **Respondida em 2026-11-20:** o dono le o Billing e fornece o valor em USD com o mes; o valor ainda nao chegou, e o P04 espera por ele.
17. **O17 (renumerada; era O16 no v2), D1 (pin unico X*), D2 (desrastrear `spike_fb_driver`), D6 (manifesto de produto por artefato)** no comentario 7038419407 (§1).
