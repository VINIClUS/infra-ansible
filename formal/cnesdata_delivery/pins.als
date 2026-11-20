sig Blob {
  pino: lone Commit
}

abstract sig Arquivo {}
sig Superficie extends Arquivo {}
one sig CallerProdutores extends Arquivo {}
sig ForaDaSuperficie extends Arquivo {}

sig Commit {
  pais: set Commit,
  conteudo: Arquivo -> lone Blob,
  tocados: set Arquivo
}

fact historico_sem_ciclo {
  no c: Commit | c in c.^pais
}

fact tocados_vem_do_conteudo {
  all c: Commit | c.tocados = { f: Arquivo |
    (no c.pais and some c.conteudo[f]) or (some p: c.pais | c.conteudo[f] != p.conteudo[f]) }
}

abstract sig TrustPin {
  aceita: one Commit
}
abstract sig delivery extends TrustPin {}
one sig github_delivery_plan_workflow_sha, github_delivery_deploy_workflow_sha,
  application_promotion_workflow_sha extends delivery {}
one sig host_gate_workflow_sha, ext2_workflow_sha, observer_workflow_sha extends TrustPin {}

abstract sig Papel {}
one sig Plan, Deploy, Application extends Papel {}

one sig Governanca {
  gate_shas: Papel -> one Commit,
  proof_producers: one Commit
}

one sig CnesData {
  PRODUCER: one Commit,
  PRODUCER_SHA: one Commit,
  HOST_GATE_SHA: one Commit,
  uses: Papel -> one Commit
}

one sig Janela {
  x: one Commit,
  k: one Commit
}

fun pino_do_caller[c: Commit]: lone Commit {
  c.conteudo[CallerProdutores].pino
}

fun faixa[base, topo: Commit]: set Commit {
  topo.*pais - base.*pais
}

fun executados: set Commit {
  TrustPin.aceita + pino_do_caller[Janela.k] + Janela.k + Governanca.gate_shas[Papel]
    + CnesData.uses[Papel] + CnesData.PRODUCER + CnesData.PRODUCER_SHA + CnesData.HOST_GATE_SHA
}

pred cli_x_ancestral_de_k {
  Janela.x in Janela.k.*pais
}

pred cli_k_diferente_de_x {
  Janela.k != Janela.x
}

pred cli_uses_do_caller_igual_a_x {
  pino_do_caller[Janela.k] = Janela.x
}

pred cli_faixa_nao_toca_superficie {
  no faixa[Janela.x, Janela.k].tocados & Superficie
}

pred cli_escreve_governanca {
  Governanca.gate_shas[Papel] = Janela.x
  Governanca.proof_producers = Janela.k
}

pred cli_diff_de_arvore_sem_superficie {
  all f: Superficie | Janela.k.conteudo[f] = Janela.x.conteudo[f]
}

pred gate_admite_sha_da_governanca {
  all p: Papel | CnesData.uses[p] = Governanca.gate_shas[p]
}

pred cnesdata_pins_iguais {
  CnesData.PRODUCER_SHA = CnesData.PRODUCER
  CnesData.HOST_GATE_SHA = CnesData.PRODUCER
  CnesData.uses[Papel] = CnesData.PRODUCER
}

pred trusts_em_x_exceto[livres: set TrustPin] {
  all t: TrustPin - livres | t.aceita = Janela.x
}

pred apply_unico_da_raiz {
  trusts_em_x_exceto[none]
}

pred base {
  gate_admite_sha_da_governanca
  cnesdata_pins_iguais
  cli_escreve_governanca
}

pred verificacoes {
  base
  apply_unico_da_raiz
  cli_x_ancestral_de_k
  cli_k_diferente_de_x
  cli_uses_do_caller_igual_a_x
  cli_faixa_nao_toca_superficie
}

pred superficie_executada_igual_a_x {
  all c: executados, f: Superficie | c.conteudo[f] = Janela.x.conteudo[f]
}

pred pinos_iguais_a_x {
  TrustPin.aceita = Janela.x
  pino_do_caller[Janela.k] = Janela.x
  CnesData.HOST_GATE_SHA = Janela.x
  CnesData.PRODUCER = Janela.x
  Governanca.gate_shas[Papel] = Janela.x
}

pred caller_em_k_cita_commit_que_ja_existia {
  pino_do_caller[Janela.k] not in Janela.k.*~pais
}

assert gate_em_k_executa_bytes_de_x {
  verificacoes implies superficie_executada_igual_a_x
}

assert trusts_e_pinos_aceitam_so_x {
  verificacoes implies pinos_iguais_a_x
}

assert caller_em_k_e_realizavel {
  verificacoes implies caller_em_k_cita_commit_que_ja_existia
}

assert diff_de_arvore_preserva_os_asserts {
  (base and apply_unico_da_raiz and cli_x_ancestral_de_k and cli_k_diferente_de_x
    and cli_uses_do_caller_igual_a_x and cli_diff_de_arvore_sem_superficie)
    implies (superficie_executada_igual_a_x and pinos_iguais_a_x
      and caller_em_k_cita_commit_que_ja_existia)
}

assert diff_de_arvore_dispensa_ancestralidade_nos_bytes {
  (base and apply_unico_da_raiz and cli_k_diferente_de_x and cli_uses_do_caller_igual_a_x
    and cli_diff_de_arvore_sem_superficie and caller_em_k_cita_commit_que_ja_existia)
    implies superficie_executada_igual_a_x
}

check gate_em_k_executa_bytes_de_x for 6 but 7 Commit
check trusts_e_pinos_aceitam_so_x for 6 but 7 Commit
check caller_em_k_e_realizavel for 6 but 7 Commit
check diff_de_arvore_preserva_os_asserts for 6 but 7 Commit
check diff_de_arvore_dispensa_ancestralidade_nos_bytes for 6 but 7 Commit

check mutant_sem_ancestralidade {
  (base and apply_unico_da_raiz and cli_k_diferente_de_x and cli_uses_do_caller_igual_a_x
    and cli_faixa_nao_toca_superficie and caller_em_k_cita_commit_que_ja_existia)
    implies superficie_executada_igual_a_x
} for 6

check mutant_k_igual_x {
  (base and apply_unico_da_raiz and cli_x_ancestral_de_k and cli_uses_do_caller_igual_a_x
    and cli_faixa_nao_toca_superficie) implies caller_em_k_cita_commit_que_ja_existia
} for 6

check mutant_diff_toca_superficie {
  (base and apply_unico_da_raiz and cli_x_ancestral_de_k and cli_k_diferente_de_x
    and cli_uses_do_caller_igual_a_x and caller_em_k_cita_commit_que_ja_existia)
    implies superficie_executada_igual_a_x
} for 6

check mutant_um_trust_divergente {
  (base and (some t: TrustPin | trusts_em_x_exceto[t]) and cli_x_ancestral_de_k
    and cli_k_diferente_de_x and cli_uses_do_caller_igual_a_x and cli_faixa_nao_toca_superficie
    and caller_em_k_cita_commit_que_ja_existia) implies superficie_executada_igual_a_x
} for 6

run sat_verificacoes {
  verificacoes
} for 6

run sat_faixa_com_tofu_docs_e_caller {
  verificacoes
  some disj t, d: faixa[Janela.x, Janela.k] - Janela.k |
    some t.tocados and t.tocados in ForaDaSuperficie
    and some d.tocados and d.tocados in ForaDaSuperficie
  Janela.k.tocados = CallerProdutores
} for 6

run sat_superficie_difere_fora_da_janela {
  verificacoes
  some Janela.x.pais and some Janela.x.tocados & Superficie
  some c: Commit - executados, f: Superficie | c.conteudo[f] != Janela.x.conteudo[f]
} for 6

run sat_merge_na_faixa {
  verificacoes
  some c: faixa[Janela.x, Janela.k] | #c.pais > 1
} for 6
