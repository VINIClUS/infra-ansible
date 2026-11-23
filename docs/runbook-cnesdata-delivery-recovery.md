# Runbook: entrega CnesData, recuperacao do lease, custodia da `report_hmac_key` e drills

Runbook do dono para a entrega de producao do CnesData (EPIC #465, infra-ansible#55). Entregavel do P32
(docs, fora da superficie pinada em X*). Nao e gate: nenhum teste depende dele alem das frases pinadas
das outras docs. Contratos: `docs/cnesdata-delivery-producers.md` (§3.6, §4.4),
`docs/cnesdata-delivery-application-integration.md` (DD-7, O22). Sem ARN, conta, bucket, caminho local
nem valor de segredo neste arquivo; o que e privado fica no store privado de evidencia.

## 1. Recuperacao do lease depois de um terminal `failed-*`

### 1.1 Quando se aplica

Decisao O22 (2026-11-20): o run de uma promocao que falha e termina limpa (lease liberado, terminal
publicado) fica vermelho e exige recuperacao revisada. Os terminais de falha sao
`failed-closed-quiescent` e `failed-prepare-quiescent` (`terminal_result` em `lifecycle_contract.py`,
que devolve `failed`; `accepted-open` devolve `accepted`). Os jobs do caller nao usam `continue-on-error`.
Tambem se aplica a lease preso em `held` com `recovery_required` (comando privado falhou, deadline,
descendente vivo, leitura de readback divergente): TTL nunca e takeover (`coordination_lease.py`).

### 1.2 O que o proximo acquire aceita (confirmado no codigo)

`Lease.acquire` (`coordination_lease.py`) passa so se o objeto do lease esta ausente (`value is None`)
ou se esta `released` e `previous_success(value)` e verdadeiro. Para lifecycle v1 isso chama
`previous_terminal` (`application_gate.py`), que autentica o terminal publicado e exige
`promotion_status == "accepted"`; um terminal `failed` recusa com "failed terminal requires exact
reviewed recovery acceptance" dentro de `previous_terminal`; como `previous_success` engole a excecao
(`runtime.py`), o acquire em si falha com "held/recovery_required". Para o fluxo legado, `previous_success` (`runtime.py`) autentica recibo,
envelope, evidencia do lease e checkpoint do run anterior, e qualquer excecao devolve falso ("retain
coordinator and demand reviewed recovery").

O modelo F1 `formal/cnesdata_delivery/LeaseTerminal.tla` define o estado alvo: `Admissible(record)` =
`released` com `result` aceito **ou** `recovered`; a acao `ReviewedRecovery` marca `recovered` num lease
`held` com `coord = recovery_required` ou `released` com `result = failed`, e a propriedade
`RefuseFailedUntilReview` diz que nenhum acquire parte de um predecessor `failed` sem essa revisao.

**Lacuna declarada (para a coordenadora decidir antes da janela):** o marcador `recovered` do modelo nao
existe no codigo. Nenhum caminho de codigo aceita um lease `released` de terminal `failed`, e nao ha
comando de recuperacao no CLI do dono. Este runbook nao inventa um. Hoje o unico estado que o acquire
aceita sem um terminal `accepted` e o objeto do lease ausente, e esse reset tem custos (secao 1.4).

### 1.3 Passo 1: reter toda a evidencia antes de qualquer escrita

Nada do que segue e feito antes de o item abaixo estar completo e conferido por leitura.

1. Anotar run id e attempt do run vermelho (ids numericos do GitHub sao identidade de protocolo publica).
2. Baixar e arquivar, no store privado de evidencia, os artefatos do run, o `lifecycle-terminal`, o
   indice publicado e todo objeto privado sob o prefixo do run (envelope, checkpoint, drift, `lease.json`,
   observacoes do keeper), conferindo sha256 de cada um contra o recibo ou indice.
3. Copiar o objeto do lease atual com a versao e o etag, e o historico de versoes se o bucket tem
   versionamento (o observador le `GetBucketVersioning`; confirmar antes que esta ativo).
4. Registrar o estado observado da fence e das rotas (`routes_match`, `state_clean`, `quiescent`,
   `pending`, `unknown` do terminal). Em `failed-closed-quiescent` a restauracao original deve estar
   completa e a fence `CLOSED`; em `failed-prepare-quiescent` nada foi promovido.
5. Nunca fabricar, editar ou re-hashear recibo, terminal, checkpoint ou indice. Um recibo novo so existe
   se um run autenticado o produzir.

### 1.4 Passo 2: revisao e reset

1. Revisao pelo dono, por escrito (data, run, causa, evidencia retida, decisao), antes de mexer no lease.
   Se o estado e `held`/`recovery_required` ou ha duvida sobre o estado da fence ou das rotas, a
   recuperacao do ambiente (host, rotas, restauracao) vem antes e fora deste runbook.
2. Reset a um estado que o acquire aceita: apenas **objeto do lease ausente**. Nao ha caminho de
   remocao no codigo: o mecanismo e a identidade que o executa ficam para a aprovacao do dono. Condicoes:
   precondicao no etag lido no passo 1 quando o mecanismo a suportar, uma escrita, aprovada pelo dono,
   sem nenhum run em andamento, e leitura de volta confirmando a ausencia. Efeito colateral a decidir na revisao: o acquire
   seguinte com objeto ausente parte da geracao 1 (`previous_generation = 0`), e o lifecycle
   (`generation` do predecessor, `predecessor_read`) pode exigir que o proximo run se encadeie ao
   predecessor original; confirmar na governanca antes do reset.
3. Proximo acquire so por um novo run gated (Phase A ou promocao). Nao dispare em cima do run vermelho e
   nao use rerun do mesmo run id.
4. Registrar o reset (data, quem, etag antes, ausencia confirmada) junto da evidencia retida.

### 1.5 Verificacao

Leitura do objeto do lease mostra ausencia (ou, no futuro, o marcador revisado); o proximo acquire passa
e escreve geracao e `acquired_at`; a evidencia retida no passo 1 continua legivel e com os mesmos
sha256.

## 2. Custodia e rotacao da `report_hmac_key`

### 2.1 Onde a chave vive

Quatro lugares (§3.6 do spec de produtores, O14 emendada), todos com a mesma chave de 32 bytes em 64 hex:

1. Secret Service local do dono (`secret-tool`, servico `cnesdata-delivery`, tipo `report_hmac_key`):
   geracao e rotacao.
2. Secret do environment `production` (o gate verifica com ele) e o campo `report_hmac_key` do
   documento de governanca (`contract.report_key`, 64 hex minusculos).
3. Secret do environment `cnesdata-observer` (o observador produz com ele). A regra de branch desse
   environment (so `main`) e escrita de configuracao do GitHub e precisa de aprovacao do dono na janela.
4. Store privado de evidencia.

A chave nunca aparece em argv, log de workflow, artefato, recibo nem evidencia publica. O CLI
(`producers/hmac_key.py`, `governance_assembly.py`) a passa so por stdin (`input=` do subprocess).

### 2.2 Rotacao, por ciclo

A chave e nova a cada ciclo e a antiga nunca e reutilizada (`rotate` recusa `fresh == previous`).

1. Primeira chave de um ciclo: `key generate --repo <repo> --environment production`: gera, grava no
   Secret Service e entrega ao secret do environment por `gh secret set` com stdin.
2. Troca de chave: `key rotate --repo <repo> --environment production`: le a anterior do Secret Service,
   gera a nova, grava local e entrega ao environment dado.
3. **O CLI entrega a um environment por chamada e `rotate` gera uma chave nova a cada chamada.** Nao
   repita `rotate` para o `cnesdata-observer`: os dois environments teriam chaves diferentes e o gate
   recusaria o relatorio do observador. Entregue a mesma chave ao observador pelo pipe, sem argv:
   `secret-tool lookup service cnesdata-delivery kind report_hmac_key | tr -d '\n' | gh secret set
   REPORT_HMAC_KEY --repo <repo> --env cnesdata-observer` (o CLI grava a chave sem quebra de linha;
   o `tr` remove qualquer uma que o `secret-tool` acrescente, e o valor entregue tem 64 caracteres). Uma melhoria do CLI (entregar a chave local a um segundo
   environment) fica como item aberto, nao como requisito.
4. Quarto lugar: gravar a mesma chave no store privado de evidencia por stdin (por exemplo
   `secret-tool lookup ... | tr -d '\n' | <upload do dono lendo stdin>`), com criptografia do store; a quarta copia nao
   tem comando no CLI.
5. Governanca: renderizar de novo o documento com `report_hmac_key` igual a chave nova (`render` roda
   `crosscheck`, recusa chave fora de 64 hex e teto acima de 40 960 B; o teto de escrita do GitHub e
   47 952 B) e fazer a escrita de governanca da janela. Tudo derivado por HMAC muda: `baseline-inputs`
   (que le a chave do Secret Service e falha com "report hmac key absent from custody" se ela falta), os
   `_facts` das session pins e os `*_hmac` do relatorio. Observacoes e baselines do ciclo anterior deixam
   de verificar; refazer a observacao do ciclo.

### 2.3 Verificacao (sem expor a chave)

- Presenca: `secret-tool lookup service cnesdata-delivery kind report_hmac_key | tr -d '\n' | wc -c`
  (esperado: 64) e `gh secret list --repo <repo> --env <environment>` mostram `REPORT_HMAC_KEY` com data
  de atualizacao nova nos dois environments. Nunca imprima o valor.
- Igualdade entre os quatro lugares: comparar sha256 de cada copia obtida por stdin, nunca o valor.
- Relatorio: o gate recomputa `_facts` e aceita o relatorio do observador; um relatorio produzido com a
  chave antiga e recusado.
- Higiene: grep dos logs do run e dos artefatos por 64 hex derivado da chave e por `report_hmac_key` com
  valor; zero ocorrencias.

### 2.4 Notas do ambiente do dono

- O venv do dono precisa de PyYAML: `release_guard` importa `yaml` no nivel do modulo, inclusive para
  `render` e `key`.
- Pins em modo CI exigem uma execucao local do observador pelo dono, com a mesma versao de policy padrao.
- Para o job assemble so "Re-run all jobs" pode ter sucesso.

## 3. Registro dos drills (registro, nao gate)

| Item | Estado | Observacao |
|---|---|---|
| DR1 (R21): dois tokens OIDC no mesmo job | rodou | resultado registrado so no registro privado do dono; nao verificavel por este arquivo |
| DR2 (R24): secret de environment ate o reusable por nome | rodou | a O18 (custodia do DD-6) continua aberta ate o dono registrar a resposta |
| DR3: `referenced_workflows` com varias chamadas do mesmo reusable | rodou | dependencia declarada: o numero de chamadas de plan e deploy por run depende do DR3 (spec de integracao do application); o resultado medido nao e reproduzido aqui |
| Sonda O2: teto do secret | rodou (2026-11-20) | maior aceito 47 952 B (HTTP 422 em 47 953 B); job sem environment recebeu 0 B |
| DR4: leituras cross-repo com `github.token` no job assemble do infra-ansible (runs e attempts do CnesData, artefatos, zip, compare, check-runs) | pendente, nao rodou | a lista das leituras e a do proprio item; auditoria do P18 no #98 |
| Presenca dos revisores (R22) | pendente, na janela | avisar os revisores; o caller inicia o job do application primeiro |

Aprovacoes de environment (decisao do dono, 2026-11-21): a coordenadora as faz por `gh api` com o token do
dono e para se houver recusa; nao se tenta outro caminho.

Ordem na janela de ~24 h contada a partir da Phase A: (1) apply do `predecessor_read` na raiz de entrega;
(2) escrita 3 da governanca (o documento carrega `predecessor_read`, entao depende do apply); (3) `execute`
do application, sem nenhum run de gate no meio. Todo o conjunto cabe dentro das ~24 h da Phase A; se
estourar, o predecessor deixa de ser aceito e a Phase A se refaz. Depois do reset da secao 1.4, uma nova
Phase A reinicia o relogio de ~24 h. Se os revisores perderem o alvo, o ciclo falha fechado, o lease fica preso e
a recuperacao e a da secao 1.
