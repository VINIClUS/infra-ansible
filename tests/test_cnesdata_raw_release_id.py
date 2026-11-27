"""P45: the raw candidate release id, up to 128 chars, crosses the fence package, the mode context and the mode session."""
import pytest
from test_cnesdata_application_gate import REAL_RELEASE_ID, _fence_contract_case, _mode_semantic_context

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc


def identifier(length):
    return "c" + "a" * (length - 1)


def fence(release_id=REAL_RELEASE_ID, mutate=None):
    payloads, _, kwargs, encode = _fence_contract_case(release_id=release_id)
    if mutate:
        mutate(payloads["fence-origins.json"]["phase_a"])
    files, originals = encode()
    return lc.validate_fence_prepared_package(files, originals=originals, **kwargs)


def mode_context(release_id):
    manifest, originals, owner, encode = _mode_semantic_context("promotion")
    originals["release_id"] = manifest["release_id"] = release_id
    return lc.validate_mode_context(encode(manifest), owner=owner, application_purpose="promotion", originals=originals)


def session_binding(release_id):
    return {"schema_version": 2, "context_kind": "promotion", "operation": "unit-seed", "phase": "unit",
            "repository": c.REPOSITORY, "product_source_sha": "1" * 40, "product_source_closure_sha256": "2" * 64,
            "shared_source_sha": "3" * 40, "shared_source_closure_sha256": "4" * 64, "release_id": release_id,
            "activation_sha256": "5" * 64, "run_id": 19876543210, "run_attempt": 1, "generation": 1,
            "owner_sha256": "6" * 64, "context_manifest_sha256": "7" * 64}


def test_id_real_do_candidato_tem_64_caracteres_no_formato_do_build():
    assert len(REAL_RELEASE_ID) == 64
    assert REAL_RELEASE_ID.startswith("candidate-" + "9" * 40 + "-")


@pytest.mark.parametrize("release_id", [REAL_RELEASE_ID, identifier(128)])
def test_pacote_do_fence_aceita_o_id_bruto_do_candidato_ate_128(release_id):
    assert fence(release_id)["outcome"] == "observed"


def test_pacote_do_fence_recusa_release_id_de_129():
    def longer(phase_a):
        phase_a["release_id"] = identifier(129)
    with pytest.raises(ValueError, match="^fence original release identity$"):
        fence(mutate=longer)


def test_canary_id_do_fence_continua_limitado_a_32():
    def longer(phase_a):
        phase_a["canary_id"] = identifier(33)
    with pytest.raises(ValueError, match="^fence original release identity$"):
        fence(mutate=longer)


@pytest.mark.parametrize("release_id", [REAL_RELEASE_ID, identifier(128)])
def test_contexto_de_modo_aceita_o_id_bruto_do_candidato_ate_128(release_id):
    assert mode_context(release_id)["manifest"]["release_id"] == release_id


def test_contexto_de_modo_recusa_release_id_de_129():
    with pytest.raises(ValueError, match="^mode context release id$"):
        mode_context(identifier(129))


@pytest.mark.parametrize("release_id", [REAL_RELEASE_ID, identifier(128)])
def test_sessao_de_modo_aceita_o_id_bruto_e_o_nome_sts_nao_cresce(release_id):
    session = lc.mode_session(session_binding(release_id), "promotion")
    assert len(session["session_name"]) == len("mc-us-") + 40


def test_sessao_de_modo_recusa_release_id_de_129():
    with pytest.raises(ValueError, match="^mode session release id$"):
        lc.mode_session(session_binding(identifier(129)), "promotion")
