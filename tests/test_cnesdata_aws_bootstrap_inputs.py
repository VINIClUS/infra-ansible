"""REDs nativos para o contrato de entradas dos dois roots."""

import pytest
from fixtures.cnesdata_aws_bootstrap_native import native as native_fixture

native = native_fixture
EXPECTED_INPUTS = {"account_id", "region", "roots", "identities", "tags"}


def _assert_exact_interface(plan, inputs):
    root = plan["configuration"]["root_module"]
    assert set(root["variables"]) == EXPECTED_INPUTS, "declared_input_interface"
    assert set(plan["variables"]) == EXPECTED_INPUTS, "effective_input_interface"
    for name in EXPECTED_INPUTS:
        assert plan["variables"][name]["value"] == inputs[name], (
            f"effective_input_value: {name}"
        )


def test_foundation_atual_exige_exatamente_cinco_inputs_e_mostra_red(native):
    result = native.plan("a", "foundation-inputs-only", "target")
    _assert_exact_interface(result["plan"], result["inputs"])
    witness = native.plan("a", "foundation-inputs-only", "witness")
    _assert_exact_interface(witness["plan"], witness["inputs"])
    for mutation in ("foundation_backend_kms_defaults", "foundation_extra_variable"):
        mutant = native.mutated_witness_plan(mutation, root="foundation-inputs-only")
        with pytest.raises(AssertionError, match="declared_input_interface"):
            _assert_exact_interface(mutant["plan"], mutant["inputs"])


@pytest.mark.parametrize(
    ("case_id", "root", "diagnostic"),
    [
        (
            "foundation-source-sink",
            "foundation-inputs-only",
            r"(?i)(bucket.*(differ|different|difer)|source.*sink|backend.*logging)",
        ),
        ("foundation-foreign-prefix", "foundation-inputs-only", r"(?i)prefix.*access/"),
        (
            "budget-source-sink",
            "budget-backend",
            r"(?i)(bucket.*(differ|different|difer)|source.*sink|backend.*logging)",
        ),
        ("budget-foreign-prefix", "budget-backend", r"(?i)prefix.*access/"),
    ],
)
def test_roots_rejeitam_source_sink_e_prefixo_com_diagnostico_nativo(
    native, case_id, root, diagnostic
):
    with pytest.raises(AssertionError, match=diagnostic) as error:
        native.plan(case_id, root, "target")
    assert "target_input_contract_incompatible" in str(error.value)
