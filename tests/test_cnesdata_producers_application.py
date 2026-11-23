"""Produtores da governanca do application: predecessor, configuracao, fragmento, release, catalogo e caller (P19)."""
import copy
import importlib
import json
import re
import time
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery import session_owner
from tools.cnesdata_delivery.session_policy import managed_arn, predecessor_keys

PREDECESSOR_JOB = {"id": 91, "name": "apply / execute"}
TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
         "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"}}]}
POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::synthetic-evidence/cnesdata/prod/evidence/lifecycle/*"}]}
KEEPER = {"job_name": "promote / keeper", "producer_job": "keeper",
          "admission_steps": ["Authenticate original caller", "Issue credentials"]}


def producer():
    return importlib.import_module("tools.cnesdata_delivery.producers.application")


def digest_of(value):
    return session_owner._terraform_document_digest(value)


class JobAPI:
    """GitHub answers 404 for a job id that does not exist; the provenance reader raises then."""
    def __init__(self, inner):
        self.inner = inner

    def read(self, path, **kwargs):
        if "/actions/jobs/" in path and not path.endswith("/jobs/91"):
            raise ValueError("GitHub HTTP failure")
        return self.inner.read(path, **kwargs)

    def artifact(self, *args, **kwargs):
        return self.inner.artifact(*args, **kwargs)


def originals(aws, governance, selector):
    return {key.rsplit("/", 1)[1]: aws.get(governance["evidence_bucket"], key)[0]
            for key in predecessor_keys(governance, selector)}


@pytest.fixture
def history(monkeypatch, tmp_path):
    from test_cnesdata_application_gate import _legacy_history_fixture
    chain, aws, api, store, previous, reference = _legacy_history_fixture(monkeypatch, tmp_path)
    selector = chain.gov.pop("predecessor_read")
    chain.gov.pop("lifecycle_predecessor")
    api = JobAPI(api)
    produced = producer().predecessor(api, chain.gov, selector, lease=previous, job=PREDECESSOR_JOB,
                                      objects=originals(aws, chain.gov, selector))
    return SimpleNamespace(gov=chain.gov, aws=aws, api=api, previous=previous, reference=reference,
                           selector=selector, produced=produced)


def test_predecessor_produzido_e_o_mesmo_que_o_gate_autentica_no_fixture_legado(history):
    assert history.produced == {"predecessor_read": history.selector, "lifecycle_predecessor": history.reference}


def changed_entry(name):
    def mutate(reference):
        entry = next(item for item in reference["objects"] if item["name"] == name)
        entry["sha256"] = "3" * 64
    return mutate


PREDECESSOR_FIELDS = {
    "predecessor_version": lambda r: r.update(predecessor_version=2),
    "protocol": lambda r: r.update(protocol="lifecycle"),
    "repository": lambda r: r.update(repository="VINIClUS/infra-ansible"),
    "source_sha": lambda r: r.update(source_sha="8" * 40),
    "run_id": lambda r: r.update(run_id=r["run_id"] + 1),
    "run_attempt": lambda r: r.update(run_attempt=r["run_attempt"] + 1),
    "owner_sha256": lambda r: r.update(owner_sha256="7" * 64),
    "generation": lambda r: r.update(generation=5),
    "session_sha256": lambda r: r.update(session_sha256="6" * 64),
    "checkpoint_sha256": lambda r: r.update(checkpoint_sha256="5" * 64),
    "artifact_id": lambda r: r.update(artifact_id=r["artifact_id"] + 1),
    "artifact_digest": lambda r: r.update(artifact_digest="sha256:" + "4" * 64),
    "producer_job_id": lambda r: r.update(producer_job_id=r["producer_job_id"] + 1),
    "producer_name": lambda r: r.update(producer_name="apply / other"),
    **{f"objects[{name}]": changed_entry(name)
       for name in ("checkpoint.json", "drift.json", "ecr-before.json", "envelope.json", "lease.json")},
}


PREDECESSOR_REASONS = {
    "predecessor_version": "original predecessor selection",
    "protocol": "original predecessor selection",
    "repository": "original predecessor selection",
    "source_sha": "original predecessor selection",
    "run_id": "original predecessor selection",
    "run_attempt": "original predecessor selection",
    "owner_sha256": "original released predecessor selection",
    "generation": "original released predecessor selection",
    "session_sha256": "original released predecessor selection",
    "checkpoint_sha256": "original historical checkpoint commitment",
    "artifact_id": "original legacy predecessor receipt",
    "artifact_digest": "original legacy predecessor receipt",
    "producer_job_id": "GitHub HTTP failure",
    "producer_name": "original historical producer job",
    "objects[checkpoint.json]": "original historical checkpoint commitment",
    "objects[drift.json]": "original selected historical bytes",
    "objects[ecr-before.json]": "original selected historical bytes",
    "objects[envelope.json]": "original selected historical bytes",
    "objects[lease.json]": "original selected historical bytes",
}


def test_campos_do_predecessor_cobrem_o_validador_fechado_do_consumidor():
    from tools.cnesdata_delivery.lifecycle_runtime import validate_predecessor_reference
    constants = validate_predecessor_reference.__code__.co_consts
    closed = next(value for value in constants if type(value) is str and value.startswith("predecessor_version protocol"))
    assert {name.split("[")[0] for name in PREDECESSOR_FIELDS} == set(closed.split())


@pytest.mark.parametrize("field", [None, *PREDECESSOR_FIELDS])
def test_consumidor_recusa_predecessor_produzido_com_um_campo_mudado(history, field):
    from tools.cnesdata_delivery.application_gate import authenticated_previous
    value = copy.deepcopy(history.produced)
    if field is None:
        result = authenticated_previous(history.aws, history.api, history.gov | value, history.previous)
        assert result["predecessor_reference"] == value["lifecycle_predecessor"]
        return
    PREDECESSOR_FIELDS[field](value["lifecycle_predecessor"])
    with pytest.raises(ValueError, match=re.escape(PREDECESSOR_REASONS[field])):
        authenticated_previous(history.aws, history.api, history.gov | value, history.previous)


@pytest.mark.parametrize("change", ["object-missing", "checkpoint-lease", "lease-held", "publication-legacy"])
def test_produtor_do_predecessor_recusa_entrada_incoerente(history, change):
    objects = originals(history.aws, history.gov, history.selector)
    lease, publication = copy.deepcopy(history.previous), None
    if change == "object-missing":
        objects.pop("drift.json")
    if change == "checkpoint-lease":
        lease["checkpoint_sha256"] = "5" * 64
    if change == "lease-held":
        lease["status"] = "held"
    if change == "publication-legacy":
        publication = {"artifact_id": 1, "artifact_digest": "sha256:" + "1" * 64}
    with pytest.raises(ValueError):
        producer().predecessor(history.api, history.gov, history.selector, lease=lease, job=PREDECESSOR_JOB,
                               objects=objects, publication=publication)


@pytest.fixture
def entry(monkeypatch, tmp_path):
    from test_cnesdata_application_gate import _application_entry_case
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    gov, request, run, job, configure, store, reads = _application_entry_case(monkeypatch, tmp_path)
    gov["application_fragment"].update(trust_sha256=digest_of(TRUST), policy_sha256=digest_of(POLICY))
    configuration, fragment = gov.pop("application_configuration"), gov.pop("application_fragment")
    for key in ("application_delegations", "application_coordination_policy"):
        gov.pop(key, None)
    now = time.time()
    section = producer().application_section(gov, configuration=configuration, fragment=fragment,
                                             coordination_policy=json.dumps(POLICY), now=now)
    return SimpleNamespace(gov=gov, request=request, run=run, configure=configure, store=store, reads=reads,
                           section=section, now=now, api=lr.GitHub())


def test_secao_do_application_copia_a_saida_do_tofu_e_deriva_as_delegacoes(entry):
    section = entry.section
    assert set(section) == {"application_configuration", "application_fragment", "application_delegations",
                            "application_coordination_policy"}
    assert section["application_delegations"] == section["application_fragment"]["delegations"]
    assert section["application_configuration"]["predecessor_read"] == entry.gov["predecessor_read"]


CONFIGURATION_FIELDS = {
    "role_name": lambda v: v.update(role_name="cnesdata-other-application"),
    "workflow_sha": lambda v: v.update(workflow_sha="c" * 40),
    "source_closure_sha256": lambda v: v.update(source_closure_sha256="e" * 64),
    "enabled_until": lambda v: v.update(enabled_until=c.utc(c.instant(v["enabled_until"]) + 1)),
    "delegations": lambda v: v["delegations"].update(normal=v["delegations"]["recovery"],
                                                      recovery=v["delegations"]["normal"]),
    "predecessor_read": lambda v: v["predecessor_read"].update(run_id=v["predecessor_read"]["run_id"] + 1),
}


CONFIGURATION_REASONS = {
    "role_name": "private original raw configuration",
    "workflow_sha": "private original raw configuration",
    "source_closure_sha256": "private original raw configuration",
    "enabled_until": "private original raw configuration",
    "delegations": "private original ten delegations",
    "predecessor_read": "protected predecessor selector/configuration",
}


def test_campos_da_configuracao_cobrem_o_validador_fechado_do_consumidor(entry):
    assert set(CONFIGURATION_FIELDS) == set(entry.section["application_configuration"])


@pytest.mark.parametrize("field", [None, *CONFIGURATION_FIELDS])
def test_consumidor_recusa_configuracao_produzida_com_um_campo_mudado(entry, field):
    governance = entry.gov | copy.deepcopy(entry.section)
    if field is None:
        assert session_owner.application_fragment(governance, entry.now) == entry.section["application_fragment"]
        return
    CONFIGURATION_FIELDS[field](governance["application_configuration"])
    with pytest.raises(ValueError, match=re.escape(CONFIGURATION_REASONS[field])):
        session_owner.application_fragment(governance, entry.now)


def other_account(value):
    return str(int(value) + 1)


FRAGMENT_FIELDS = {
    "fragment_version": lambda v: v.update(fragment_version=3),
    "account_id": lambda v: v.update(account_id=other_account(v["account_id"])),
    "region": lambda v: v.update(region="us-east-1"),
    "application_role_arn": lambda v: v.update(
        application_role_arn=v["application_role_arn"].rsplit("/", 1)[0] + "/cnesdata-other-application"),
    "application_role_name": lambda v: v.update(application_role_name="cnesdata-other-application"),
    "producer": lambda v: v["producer"].update(workflow_sha="c" * 40),
    "caller_by_purpose": lambda v: v["caller_by_purpose"]["promotion"].update(ref="refs/heads/develop"),
    "provider_arn": lambda v: v.update(provider_arn=v["provider_arn"].rsplit("/", 1)[0] + "/other.example.invalid"),
    "lease": lambda v: v["lease"].update(key=v["lease"]["key"] + ".other"),
    "evidence": lambda v: v["evidence"].update(prefix=v["evidence"]["prefix"] + "other/"),
    "delegations": lambda v: v["delegations"].update(normal=v["delegations"]["recovery"],
                                                      recovery=v["delegations"]["normal"]),
    "enabled_until": lambda v: v.update(enabled_until=c.utc(c.instant(v["enabled_until"]) + 1)),
    "predecessor_reads": lambda v: v["predecessor_reads"].update(run_id=v["predecessor_reads"]["run_id"] + 1),
}


FRAGMENT_REASONS = {
    "fragment_version": "private fragment version/account/region",
    "account_id": "private fragment version/account/region",
    "region": "private fragment version/account/region",
    "application_role_arn": "private application role identity",
    "application_role_name": "private application role identity",
    "producer": "private immutable producer closure",
    "caller_by_purpose": "private exact purpose callers",
    "provider_arn": "private original provider",
    "lease": "private original coordination locus",
    "evidence": "private original evidence locus",
    "delegations": "private original ten delegations",
    "enabled_until": "private original raw configuration",
    "predecessor_reads": "private exact predecessor inventory",
}


def test_campos_do_fragmento_cobrem_o_validador_fechado_do_consumidor(entry):
    assert set(FRAGMENT_FIELDS) | {"trust_sha256", "policy_sha256"} == set(entry.section["application_fragment"])


@pytest.mark.parametrize("field", [None, *FRAGMENT_FIELDS])
def test_consumidor_recusa_fragmento_produzido_com_um_campo_mudado(entry, field):
    governance = entry.gov | copy.deepcopy(entry.section)
    if field is None:
        session_owner.application_fragment(governance, entry.now)
        return
    FRAGMENT_FIELDS[field](governance["application_fragment"])
    with pytest.raises(ValueError, match=re.escape(FRAGMENT_REASONS[field])):
        session_owner.application_fragment(governance, entry.now)


@pytest.mark.parametrize("changed", [False, True])
def test_consumidor_recusa_fragmento_com_policy_sha256_mudado(entry, changed):
    governance = entry.gov | copy.deepcopy(entry.section)
    fragment = governance["application_fragment"]
    if not changed:
        assert session_owner.application_identity_document(governance, fragment)["Statement"][0] == POLICY["Statement"][0]
        return
    fragment["policy_sha256"] = "9" * 64
    with pytest.raises(ValueError, match="application coordination policy commitment"):
        session_owner.application_identity_document(governance, fragment)


class IAM:
    def __init__(self, pin, fragment, governance):
        self.pin, self.fragment, self.governance = pin, fragment, governance

    def call(self, service, operation, **parameters):
        assert service == "iam"
        name = self.pin["policy_arn"].rsplit("/", 1)[1]
        if operation == "get_policy":
            return {"Policy": {"Arn": self.pin["policy_arn"], "PolicyName": name, "AttachmentCount": 0,
                               "PermissionsBoundaryUsageCount": 0, "DefaultVersionId": self.pin["default_version_id"]}}
        if operation == "get_policy_version":
            return {"PolicyVersion": {"VersionId": self.pin["default_version_id"], "IsDefaultVersion": True,
                                      "Document": self.pin["document"]}}
        if operation == "get_role":
            return {"Role": {"RoleName": self.fragment["application_role_name"], "RoleId": "AROAORIGINAL",
                             "Arn": self.fragment["application_role_arn"], "MaxSessionDuration": 3600,
                             "AssumeRolePolicyDocument": quote(json.dumps(TRUST))}}
        if operation == "list_role_policies":
            return {"IsTruncated": False, "PolicyNames": ["cnesdata-application-coordination",
                                                          "cnesdata-application-predecessor-read"]}
        if operation == "list_attached_role_policies":
            return {"IsTruncated": False, "AttachedPolicies": []}
        assert operation == "get_role_policy"
        from tools.cnesdata_delivery.session_policy import predecessor_policy
        document = POLICY if parameters["PolicyName"].endswith("coordination") else predecessor_policy(
            self.governance, self.governance["predecessor_read"])
        return {"RoleName": parameters["RoleName"], "PolicyName": parameters["PolicyName"],
                "PolicyDocument": quote(json.dumps(document))}


class Guard:
    def check(self, seconds=1):
        return seconds


@pytest.mark.parametrize("changed", [False, True])
def test_consumidor_recusa_fragmento_com_trust_sha256_mudado_na_leitura_do_iam(entry, changed):
    governance = entry.gov | copy.deepcopy(entry.section)
    fragment = governance["application_fragment"]
    document = {"Version": "2012-10-17", "Statement": []}
    pin = {"policy_arn": managed_arn(governance, "application"), "default_version_id": "v1", "document": document,
           "document_sha256": c.sha(c.canonical(document)), "frozen_until": c.utc(entry.now + 7200),
           "role_arn": fragment["application_role_arn"]}
    if changed:
        fragment["trust_sha256"] = "9" * 64
    authority = SimpleNamespace(pin=pin, expires_at=entry.now + 7200, application_fragment=fragment)
    def verify():
        return session_owner.verify_application(IAM(pin, fragment, governance), authority, entry.now + 3600, Guard(),
                                                clock=lambda: entry.now)
    if not changed:
        assert verify()["trust_sha256"] == digest_of(TRUST)
        return
    with pytest.raises(ValueError, match="original application trust readback"):
        verify()


@pytest.mark.parametrize("change", ["policy-text", "configuration-extra", "fragment-account"])
def test_secao_do_application_recusa_saida_que_o_consumidor_recusa(entry, change):
    configuration = copy.deepcopy(entry.section["application_configuration"])
    fragment = copy.deepcopy(entry.section["application_fragment"])
    policy = json.dumps(POLICY)
    if change == "policy-text":
        policy = json.dumps({"Version": "2012-10-17", "Statement": []})
    if change == "configuration-extra":
        configuration["caller"] = "unreviewed"
    if change == "fragment-account":
        fragment["account_id"] = other_account(fragment["account_id"])
    with pytest.raises(ValueError):
        producer().application_section(entry.gov, configuration=configuration, fragment=fragment,
                                       coordination_policy=policy, now=entry.now)


def candidate_bytes(source="b" * 40, release_id=None):
    value = {"repository": c.REPOSITORY, "source_sha": source, "release_id": release_id or f"candidate-{source}-7-1",
             "created_at": "2026-11-20T12:00:00Z"}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


IMAGE = "sha256:" + "3" * 64


def produced_release():
    return producer().release(candidate_bytes(), IMAGE)


def test_release_deriva_os_seis_campos_do_candidate_e_passa_na_ligacao_a2_do_gate():
    raw = candidate_bytes()
    value = producer().release(raw, IMAGE)
    expected = c.canary_binding({"repository": c.REPOSITORY, "release_id": value["release_id"], "source_sha": "b" * 40},
                                value["candidate_sha256"])
    assert set(value) == set("release_id source_sha candidate_sha256 canary_id binding_sha256 image_digest".split())
    assert value["candidate_sha256"] == c.sha(raw) and value["image_digest"] == IMAGE
    assert all(value[key] == expected[key] for key in ("source_sha", "candidate_sha256", "binding_sha256", "canary_id"))


@pytest.mark.parametrize("change", ["image-digest", "noncanonical", "repository"])
def test_release_recusa_candidate_ou_imagem_fora_da_forma(change):
    raw, image = candidate_bytes(), IMAGE
    if change == "image-digest":
        image = "3" * 64
    if change == "noncanonical":
        raw = raw.replace(b",", b", ", 1)
    if change == "repository":
        raw = raw.replace(c.REPOSITORY.encode(), b"VINIClUS/other")
    with pytest.raises(ValueError):
        producer().release(raw, image)


def test_release_do_application_e_a_do_plan_da_phase_a_no_acquire():
    from tools.cnesdata_delivery.application_gate import application_release_sha256
    value = producer().release(candidate_bytes(), IMAGE)
    envelope = c.canonical({"plan": {"release": value}})
    assert producer().application_release(value, envelope) == value
    assert c.sha(c.canonical(c.loads(envelope)["plan"]["release"])) == application_release_sha256({"release": value})
    other = producer().release(candidate_bytes(release_id="candidate-" + "b" * 40 + "-8-1"), IMAGE)
    with pytest.raises(ValueError, match="phase a plan release"):
        producer().application_release(other, envelope)


@pytest.mark.parametrize("vector", [v for v in __import__("fixtures.cnesdata_delivery_lifecycle",
                                                           fromlist=["CALLER_VECTORS"]).CALLER_VECTORS if v["valid_pair"]],
                         ids=lambda v: v["name"])
def test_caller_binding_produzido_e_o_vetor_canonico(vector):
    data = vector["input"]
    governance = {"application_purpose": data["application_purpose"],
                  "gate_shas": {"application": data["producer_workflow_sha"]},
                  "application_source_closure_sha256": data["producer_source_closure_sha256"]}
    run = {"head_sha": data["source_sha"], "id": data["run_id"], "run_attempt": data["run_attempt"]}
    binding, binding_sha256 = producer().caller_binding(governance, run)
    assert c.canonical(binding).decode() == vector["caller_binding_canonical_utf8"]
    assert binding_sha256 == vector["caller_binding_sha256"]


def test_descriptor_e_canonico_fechado_e_o_sha_vai_junto():
    raw, digest = producer().descriptor("c" * 64, source_sha="b" * 40, step="keeper", payloads={},
                                        purpose="promotion")
    assert c.loads(raw, canonical=True) == {"schema_version": 1, "repository": c.REPOSITORY, "source_sha": "b" * 40,
                                            "step": "keeper", "payloads": {}, "application_purpose": "promotion",
                                            "caller_binding_sha256": "c" * 64}
    assert digest == c.sha(raw)


@pytest.mark.parametrize("change", ["step", "payload-extra", "purpose", "binding"])
def test_descriptor_recusa_campo_fora_da_forma_que_o_consumidor_admite(change):
    kwargs = {"source_sha": "b" * 40, "step": "operational-deploy", "purpose": "promotion",
              "payloads": {"plan": {"artifact_id": 1, "artifact_digest": "sha256:" + "1" * 64, "job_id": 2}}}
    binding = "c" * 64
    if change == "step":
        kwargs["step"] = "Operational"
    if change == "payload-extra":
        kwargs["payloads"]["plan"]["name"] = "x"
    if change == "purpose":
        kwargs["purpose"] = "other"
    if change == "binding":
        binding = "C" * 64
    with pytest.raises(ValueError):
        producer().descriptor(binding, **kwargs)


def keeper_step():
    return producer().step("application", "application-prepare", **KEEPER)


def infra(role, purpose, job_name, **extra):
    fields = {"job_name": job_name, "producer_job": "execute", "admission_steps": ["Repeat source gate"],
              "mode": extra.pop("mode", "initial"), "direction": extra.pop("direction", "advance")}
    return producer().step(role, purpose, **fields, **extra)


def full_catalog():
    fence = lc.FENCE_PREPARE_PRODUCER
    return {"keeper": keeper_step(),
            "operational-audit": infra("audit", "application-prepare", "application-prepare-operational-audit / audit",
                                       mode="operational"),
            fence["step"]: infra("deploy", "application-prepare", fence["job_name"], mode="operational",
                                 input_jobs={"approval": {"name": "application-prepare-operational-audit / audit",
                                                          "step": "operational-audit"}}),
            "phase-b-deploy": infra("deploy", "phase-b", "phase-b / execute")}


def test_catalogo_aceita_steps_tipados_com_entradas_que_apontam_para_steps_do_proprio_catalogo():
    catalog = producer().catalog(full_catalog())
    assert catalog["keeper"] == {"role": "application", "purpose": "application-prepare", "input_jobs": {}, **KEEPER}
    assert catalog[lc.FENCE_PREPARE_PRODUCER["step"]]["job_name"] == lc.FENCE_PREPARE_PRODUCER["job_name"]


def without_phase_b(steps):
    steps.pop("phase-b-deploy")


@pytest.mark.parametrize("mutate", [
    lambda s: s["keeper"].update(extra=True),
    lambda s: s[lc.FENCE_PREPARE_PRODUCER["step"]]["input_jobs"]["approval"].update(step="missing"),
    lambda s: s[lc.FENCE_PREPARE_PRODUCER["step"]]["input_jobs"]["approval"].update(name="other / audit"),
    lambda s: s["phase-b-deploy"].update(job_name="promote / keeper"),
    lambda s: s.update({"phase-b-other": copy.deepcopy(s["phase-b-deploy"]) | {"job_name": "phase-b-2 / execute"}}),
    without_phase_b,
    lambda s: s.update({"Bad Name": s.pop("keeper")}),
    lambda s: s["keeper"].update(admission_steps=["a", "b", "c", "d", "e"]),
    lambda s: s["phase-b-deploy"].update(direction="sideways"),
    lambda s: s["phase-b-deploy"].update(purpose="unknown"),
    lambda s: s.update({"fence-renamed": s.pop(lc.FENCE_PREPARE_PRODUCER["step"])}),
], ids=["chave-extra", "entrada-sem-step", "entrada-com-outro-job", "job-repetido", "dois-phase-b",
        "sem-phase-b", "nome-de-step", "admission-demais", "direction", "purpose", "fence-renomeado"])
def test_catalogo_recusa_step_que_o_consumidor_nao_admitiria(mutate):
    steps = full_catalog()
    mutate(steps)
    with pytest.raises(ValueError):
        producer().catalog(steps)


def test_governanca_montada_pelos_produtores_passa_na_admissao_real_do_application(entry):
    from tools.cnesdata_delivery import application_gate as ag
    from tools.cnesdata_delivery.producers import governance_assembly
    previous, _ = entry.store.get()
    selector = entry.gov.pop("predecessor_read")
    entry.gov.pop("lifecycle_predecessor")
    entry.gov.pop("lifecycle_steps")
    objects = originals(entry.store.aws, entry.gov, selector)
    predecessor = producer().predecessor(entry.api, entry.gov, selector, lease=previous, job=PREDECESSOR_JOB,
                                         objects=objects)
    pieces = predecessor | entry.section | {"lifecycle_steps": producer().catalog(full_catalog()),
                                            "release": produced_release()}
    document = producer().document(entry.gov, pieces)
    binding, binding_sha256 = producer().caller_binding(document, entry.run)
    raw, _ = producer().descriptor(binding_sha256, source_sha=entry.run["head_sha"], step="keeper", payloads={},
                                   purpose=document["application_purpose"])
    entry.request.clear()
    entry.request.update(c.loads(raw, canonical=True))
    entry.gov.clear()
    entry.gov.update(document)
    entry.configure()
    admitted = ag.main(["preflight"])
    assert admitted[1]["caller_binding_sha256"] == binding_sha256
    assert admitted[0]["authenticated_application_caller"] == binding
    assert admitted[0]["lifecycle_predecessor"] == predecessor["lifecycle_predecessor"]
    assert len(governance_assembly.render(document, ceiling=governance_assembly.SECRET_CEILING)) > 0


def document_inputs(entry):
    base = copy.deepcopy(entry.gov)
    pieces = copy.deepcopy(entry.section) | {"lifecycle_steps": producer().catalog(full_catalog()),
                                             "release": produced_release()}
    return base, pieces | {key: base.pop(key) for key in ("predecessor_read", "lifecycle_predecessor")}


@pytest.mark.parametrize("change", [None, "missing-piece", "inline-manifest", "unknown-key", "context", "release",
                                    "predecessor"])
def test_montagem_do_documento_do_application_recusa_pecas_incompletas_ou_fora_do_conjunto(entry, change):
    base, pieces = document_inputs(entry)
    if change is None:
        assert producer().document(base, pieces) == base | pieces
        return
    if change == "missing-piece":
        pieces.pop("application_fragment")
    if change == "inline-manifest":
        pieces["application_product_source_manifest"] = {"version": 1}
    if change == "unknown-key":
        pieces["surprise"] = 1
    if change == "context":
        base["context_kind"] = "readiness"
    if change == "release":
        pieces["release"]["extra"] = 1
    if change == "predecessor":
        pieces["lifecycle_predecessor"]["run_id"] += 1
    with pytest.raises(ValueError):
        producer().document(base, pieces)


def test_novas_chaves_do_conjunto_fechado_entram_na_montagem_sem_mudar_o_produtor(entry, monkeypatch):
    from tools.cnesdata_delivery.producers import governance_assembly
    base, pieces = document_inputs(entry)
    pieces["stage_windows_probe"] = {"b": 360}
    with pytest.raises(ValueError, match="governance key=stage_windows_probe"):
        producer().document(base, pieces)
    monkeypatch.setattr(governance_assembly, "GOVERNANCE_KEYS", governance_assembly.GOVERNANCE_KEYS | {"stage_windows_probe"})
    assert producer().document(base, pieces)["stage_windows_probe"] == {"b": 360}
