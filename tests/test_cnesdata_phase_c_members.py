"""P16b ruling 6 item 2: the C deploy publication carries apply-output.bin; every other purpose keeps checkpoint and approval."""
import ast
import inspect
import textwrap

import pytest

from test_cnesdata_mode_stages import C_STEPS
from test_cnesdata_stage_events import GOVERNANCE, IDENTITY, OWNER, RUN, _GitHub, _Guard
from tools.cnesdata_delivery import application_gate as ag
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_runtime as lr

CHECKPOINT, APPROVAL, APPLY = b'{"checkpoint":1}\n', b'{"approval":1}\n', b"Apply complete! Resources: 0 added.\n"
C_PURPOSES = ["phase-c-recovery", "phase-c-audit"]


@pytest.mark.parametrize("purpose", C_PURPOSES)
def test_deploy_c_publica_a_saida_do_apply_como_membro_proprio(purpose):
    assert lr.deploy_result_files(purpose, CHECKPOINT, APPROVAL, APPLY) == {
        "checkpoint.json": CHECKPOINT, "approval.json": APPROVAL, "apply-output.bin": APPLY}


@pytest.mark.parametrize("purpose", ["phase-b", "static-maintenance", "application-prepare"])
def test_outros_propositos_publicam_so_checkpoint_e_approval(purpose):
    assert lr.deploy_result_files(purpose, CHECKPOINT, APPROVAL, APPLY) == {
        "checkpoint.json": CHECKPOINT, "approval.json": APPROVAL}


def test_corpo_do_deploy_publica_pelo_helper_com_a_saida_do_apply():
    tree = ast.parse(textwrap.dedent(inspect.getsource(lr.execute)))
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "deploy_result_files"]
    assert [ast.unparse(node) for node in calls] == [
        "deploy_result_files(step['purpose'], c.canonical(checkpoint), payload['approval.json'], "
        "(temp / 'apply.log').read_bytes())"]


def _publication(purpose, served=None):
    files = {"checkpoint.json": CHECKPOINT, "approval.json": APPROVAL, "apply-output.bin": APPLY, "plan.json": b"{}\n"}
    step = purpose + "-deploy"
    index = {"version": 1, "source_sha": "b" * 40, "run_id": 4242, "run_attempt": 1, "step": step,
             "owner_sha256": OWNER["owner_sha256"], "generation": OWNER["generation"], **IDENTITY,
             "files": [{"name": name, "size": len(raw), "sha256": c.sha(raw)} for name, raw in sorted(files.items())]}
    governance = GOVERNANCE | {"evidence_prefix": "cnesdata/prod/evidence/", "evidence_bucket": "evidence",
                               "context_kind": "promotion",
                               "lifecycle_steps": dict(GOVERNANCE["lifecycle_steps"]) | C_STEPS}
    request = {"source_sha": "b" * 40, "step": "closed-ready", "application_purpose": "promotion",
               "caller_binding_sha256": "c" * 64}
    prefix = lr.namespace(governance, request, RUN, step)
    reads = []

    class Store:
        def get(self, bucket, key, maximum=None):
            reads.append(key.removeprefix(prefix))
            return (served or files)[key.removeprefix(prefix)], None
    api = _GitHub(C_STEPS[step]["job_name"], step, index=index)
    result = ag._deploy_publication(api, Store(), governance, request, dict(RUN), dict(OWNER), _Guard(), 1300, purpose)
    return result, reads


@pytest.mark.parametrize("purpose", C_PURPOSES)
def test_keeper_le_a_saida_do_apply_so_nos_propositos_c_pelo_indice_autenticado(purpose):
    (files, moments), reads = _publication(purpose)
    assert files == {"checkpoint.json": CHECKPOINT, "approval.json": APPROVAL, "apply-output.bin": APPLY}
    assert sorted(reads) == ["apply-output.bin", "approval.json", "checkpoint.json"]
    assert moments == {"artifact_created_at": c.utc(1200), "job_completed_at": c.utc(1250)}


@pytest.mark.parametrize("purpose", C_PURPOSES)
def test_saida_do_apply_fora_do_indice_recusa(purpose):
    served = {"checkpoint.json": CHECKPOINT, "approval.json": APPROVAL, "apply-output.bin": APPLY.replace(b"0", b"9")}
    with pytest.raises(ValueError, match="^private original bytes$"):
        _publication(purpose, served)
