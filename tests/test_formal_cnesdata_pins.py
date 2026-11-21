"""Conformidade do modelo Alloy de pins e trusts com a raiz tofu de entrega."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODELO = ROOT / "formal/cnesdata_delivery/pins.als"
RAIZ_TOFU = ROOT / "opentofu/cnesdata-delivery"
RAIZ_DO_TRUST = "TrustPin"
SO_NO_MODELO = {"observer_workflow_sha": "X_R, trust do reusable do observador, entra no P22"}
MUTANTES_EXIGIDOS = {
    "mutant_sem_ancestralidade",
    "mutant_k_igual_x",
    "mutant_diff_toca_superficie",
    "mutant_um_trust_divergente",
}
JOB_WORKFLOW_REF = re.compile(r'"token\.actions\.githubusercontent\.com:job_workflow_ref"\s*=\s*"([^"]*)"')
INTERPOLACAO = re.compile(r"\$\{([^}]*)\}")
VARIAVEL = re.compile(r"var(?:\.\w+)+")
EACH_VALUE = re.compile(r"each\.value\.(\w+)")
FOR_EACH_LOCAL = re.compile(r"for_each\s*=\s*local\.(\w+)")
SIG = re.compile(r"\b(abstract\s+)?(?:one\s+|lone\s+|some\s+)?sig\s+([\w\s,]+?)\s+extends\s+(\w+)")


def _trusts_do_modelo(texto):
    pais, abstratas = {}, set()
    for abstrata, nomes, pai in SIG.findall(texto):
        for nome in (parte.strip() for parte in nomes.split(",")):
            pais[nome] = pai
            if abstrata:
                abstratas.add(nome)

    def descende(nome):
        while nome in pais:
            nome = pais[nome]
            if nome == RAIZ_DO_TRUST:
                return True
        return False

    return {nome for nome in pais if descende(nome) and nome not in abstratas}


def _bloco_local(textos, nome):
    definicao = re.compile(rf"^(\s*){nome}\s*=.*$", re.MULTILINE)
    for texto in textos:
        achado = definicao.search(texto)
        if achado is None:
            continue
        recuo, linhas = len(achado.group(1)), [achado.group(0)]
        for linha in texto[achado.end() + 1:].splitlines():
            if linha.strip() and len(linha) - len(linha.lstrip()) <= recuo:
                break
            linhas.append(linha)
        return "\n".join(linhas)
    raise AssertionError(f"local ausente: {nome}")


def _resolver(expressao, texto, posicao, textos):
    if VARIAVEL.fullmatch(expressao):
        return {expressao}
    campo = EACH_VALUE.fullmatch(expressao)
    if campo is None:
        raise AssertionError(f"interpolacao de trust nao resolvida: {expressao}")
    inicio = texto.rfind('resource "', 0, posicao)
    for_each = FOR_EACH_LOCAL.search(texto, max(inicio, 0), posicao)
    if inicio < 0 or for_each is None:
        raise AssertionError(f"each.value sem for_each em local: {expressao}")
    bloco = _bloco_local(textos, for_each.group(1))
    valores = set(re.findall(rf"\b{campo.group(1)}\s*=\s*(var(?:\.\w+)+)", bloco))
    if not valores:
        raise AssertionError(f"local sem variavel para {expressao}")
    return valores


def _variaveis_de_trust(textos):
    variaveis = set()
    for texto in textos:
        for ref in JOB_WORKFLOW_REF.finditer(texto):
            pin = ref.group(1).rpartition("@")[2]
            expressoes = INTERPOLACAO.findall(pin)
            if len(expressoes) != 1 or pin != f"${{{expressoes[0]}}}":
                raise AssertionError(f"job_workflow_ref sem pin unico: {ref.group(1)}")
            variaveis |= _resolver(expressoes[0], texto, ref.start(), textos)
    return variaveis


def _nome_no_modelo(variavel):
    return variavel.removeprefix("var.").replace(".", "_")


def _trusts_da_raiz_tofu():
    textos = [arquivo.read_text(encoding="utf-8") for arquivo in sorted(RAIZ_TOFU.glob("*.tf"))]
    return {_nome_no_modelo(variavel) for variavel in _variaveis_de_trust(textos)}


def _modelo():
    return MODELO.read_text(encoding="utf-8")


def test_toda_variavel_de_trust_da_raiz_tofu_esta_no_modelo():
    assert _trusts_da_raiz_tofu() - _trusts_do_modelo(_modelo()) == set()


def test_modelo_so_tem_a_mais_a_lista_de_diferencas_esperadas():
    assert _trusts_do_modelo(_modelo()) - _trusts_da_raiz_tofu() == set(SO_NO_MODELO)


def test_diferenca_esperada_some_quando_a_raiz_tofu_ganha_o_trust():
    assert set(SO_NO_MODELO) & _trusts_da_raiz_tofu() == set()


def test_modelo_declara_os_mutantes_exigidos_e_runs_sat():
    texto = _modelo()
    assert MUTANTES_EXIGIDOS <= set(re.findall(r"^check\s+(mutant_\w+)", texto, re.MULTILINE))
    assert re.findall(r"^run\s+(sat_\w+)", texto, re.MULTILINE)


def test_resolve_each_value_pelo_local_do_for_each():
    texto = (
        "locals {\n  papeis = {\n    a = { sha = var.x.a_sha }\n    b = { sha = var.x.b_sha }\n  }\n"
        "  outro = { sha = var.y.sha }\n}\n"
        'resource "r" "t" {\n  for_each = local.papeis\n'
        '  "token.actions.githubusercontent.com:job_workflow_ref" = "o/r/w-${each.key}.yml@${each.value.sha}"\n}\n'
    )
    assert _variaveis_de_trust([texto]) == {"var.x.a_sha", "var.x.b_sha"}


@pytest.mark.parametrize("pin", ["${local.sha}", "${each.key}", "literal", "${var.a.sha}${var.b.sha}", "x${var.a.sha}"])
def test_recusa_pin_de_trust_que_nao_resolve_para_variavel(pin):
    texto = f'resource "r" "t" {{\n  "token.actions.githubusercontent.com:job_workflow_ref" = "o/r/w.yml@{pin}"\n}}\n'
    with pytest.raises(AssertionError):
        _variaveis_de_trust([texto])


def test_modelo_particiona_arquivos_como_a_superficie_pinada_do_cli():
    from tools.cnesdata_delivery.producers.pins import PINNED_SURFACE, on_surface

    texto = _modelo()
    assert re.search(r"^sig Superficie extends Arquivo", texto, re.MULTILINE)
    assert re.search(r"^one sig CallerProdutores extends Arquivo", texto, re.MULTILINE)
    assert re.search(r"^sig ForaDaSuperficie extends Arquivo", texto, re.MULTILINE)
    assert on_surface("tools/cnesdata_delivery/producers/pins.py")
    assert on_surface(".github/workflows/reusable-cnesdata-observer.yml")
    assert not on_surface(".github/workflows/cnesdata-producers.yml")
    assert len(PINNED_SURFACE) == 2
