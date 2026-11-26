"""P16b ruling 9: the prepared session bound min(enabled_until, preparation_deadline + fixed_deadline_seconds) and the
minted deadline d = min(stage, credential limit, bound), built by the same builder and checked against the prepared bytes
before STS."""
import copy
import json

import pytest

import test_cnesdata_mode_session_sts as sts
from tools.cnesdata_delivery import contract as c
from tools.cnesdata_delivery import lifecycle_contract as lc
from tools.cnesdata_delivery.iam_boundary import effective_iam


def _ib():
    from tools.cnesdata_delivery import iam_boundary
    return iam_boundary


def _sp():
    from tools.cnesdata_delivery import session_policy
    return session_policy


def _scope_inputs(monkeypatch, shift):
    from test_cnesdata_application_gate import _fence_prepare_package_case
    kwargs, _, _ = _fence_prepare_package_case(monkeypatch)
    mode = c.loads(kwargs["mode_input_raw"], canonical=True)["mode_canary"]
    window = copy.deepcopy(kwargs["guard"].window)
    fixed = lc.governed_windows(window["windows"])["fixed_deadline_seconds"]
    enabled = int(c.instant(mode["enabled_until"]))
    window["preparation_deadline"] = enabled - fixed + shift
    admitted = {"delegation_sessions": mode["delegation_sessions"], "enabled_until": mode["enabled_until"]}
    return kwargs, admitted, window, enabled, fixed


@pytest.mark.parametrize("shift", [-100, 100], ids=["preparacao-antes", "enabled-until-antes"])
def test_limite_preparado_e_o_menor_entre_enabled_until_e_preparacao_mais_janela_fixa(monkeypatch, shift):
    kwargs, admitted, window, enabled, fixed = _scope_inputs(monkeypatch, shift)
    scope = _ib().mode_prepared_scope(kwargs["mode_input_raw"], admitted, owner=kwargs["owner"],
                                      governance=kwargs["governance"], window=window)
    assert scope["deadline"] == min(enabled, window["preparation_deadline"] + fixed)
    assert scope["deadline"] == (window["preparation_deadline"] + fixed if shift < 0 else enabled)


def test_documentos_preparados_de_sessao_usam_o_limite_preparado(monkeypatch):
    from tools.cnesdata_delivery import lifecycle_runtime as lr
    kwargs, _, _, _, _ = _scope_inputs(monkeypatch, 0)
    files = lr.fence_prepare_package(**kwargs)
    evaluation = c.loads(files["mode-evaluation.json"], canonical=True)
    mode = c.loads(kwargs["mode_input_raw"], canonical=True)["mode_canary"]
    window = kwargs["guard"].window
    bound = min(int(c.instant(mode["enabled_until"])),
                window["preparation_deadline"] + lc.governed_windows(window["windows"])["fixed_deadline_seconds"])
    expired = [case for case in evaluation["cases"] if case["case_id"].endswith("-expired")]
    assert expired and all(case["context"]["aws:CurrentTime"] == c.utc(bound) for case in expired)


def _minted(monkeypatch, which):
    args, calls, _ = sts._case(monkeypatch, "recovery-start")
    stage = args["journal"]._request["stage"]
    if which == "preparado":
        args["authority"] = sts._authority(args["governance"], args["journal"]._request["owner"],
                                           deadline=stage["deadline"] - 10)
    session = _mb().assume_mode_session(**args)
    return args, calls, session, stage


def _mb():
    from tools.cnesdata_delivery import mode_broker
    return mode_broker


@pytest.mark.parametrize("which", ["janela", "preparado"])
def test_politica_cunhada_e_o_construtor_com_o_prazo_d_e_o_mesmo_tamanho(monkeypatch, which):
    args, calls, session, stage = _minted(monkeypatch, which)
    bound = args["authority"].scope["deadline"]
    d = min(stage["deadline"], args["credential_limit"], bound)
    minted = _sp().mode_session_policy("recovery-start", resources=sts.RESOURCES, owner_sha256=sts.OWNER, deadline=d)
    prepared = args["authority"].documents["session.rx"]
    assert calls[0][2]["Policy"] == c.canonical(minted).decode().strip() and session.deadline == d
    assert len(calls[0][2]["Policy"]) == len(c.canonical(prepared).decode().strip())
    assert (d < bound) is (which == "janela")


def test_pedido_a_partir_de_d_e_negado_pela_politica_cunhada_e_permitido_pela_preparada(monkeypatch):
    args, calls, _, stage = _minted(monkeypatch, "janela")
    d, bound = stage["deadline"], args["authority"].scope["deadline"]
    assert d < bound
    minted, prepared = json.loads(calls[0][2]["Policy"]), args["authority"].documents["session.rx"]
    role = args["authority"].documents["role.mode_dispatch"]
    allowed = [case for case in args["authority"].evaluation["cases"]
               if case["case_id"].startswith("rx-") and case["expected"] is True]
    assert allowed
    for case in allowed:
        def decide(document, at, case=case):
            return effective_iam(role, [document], case["action"], case["resource"],
                                 case["context"] | {"aws:CurrentTime": c.utc(at)})
        assert decide(minted, d - 1) and decide(prepared, d - 1), case["case_id"]
        assert not decide(minted, d) and decide(prepared, d), case["case_id"]


SCOPE = {"resources": sts.RESOURCES, "owner_sha256": sts.OWNER, "deadline": sts.DEADLINE}


def _prepared():
    return _sp().mode_session_policy("recovery-start", resources=sts.RESOURCES, owner_sha256=sts.OWNER,
                                     deadline=sts.DEADLINE)


@pytest.mark.parametrize("which, stage, credential, expected", [
    ("janela", sts.DEADLINE - 600, sts.DEADLINE - 100, sts.DEADLINE - 600),
    ("credencial", sts.DEADLINE - 100, sts.DEADLINE - 300, sts.DEADLINE - 300),
    ("preparado", sts.DEADLINE + 100, sts.DEADLINE + 200, sts.DEADLINE)])
def test_prazo_cunhado_e_o_menor_entre_janela_credencial_e_limite_preparado(which, stage, credential, expected):
    deadline, minted = _ib().mode_minted_session("rx", "recovery-start", SCOPE, prepared=_prepared(),
                                                 stage_deadline=stage, credential_limit=credential, now=sts.START)
    assert deadline == expected
    assert minted == _sp().mode_session_policy("recovery-start", resources=sts.RESOURCES, owner_sha256=sts.OWNER,
                                               deadline=expected)


@pytest.mark.parametrize("now", [sts.DEADLINE - 600, sts.DEADLINE - 599], ids=["d-igual-agora", "d-antes-de-agora"])
def test_prazo_cunhado_que_nao_esta_no_futuro_recusa(now):
    with pytest.raises(ValueError, match="^mode_session_deadline=window$"):
        _ib().mode_minted_session("rx", "recovery-start", SCOPE, prepared=_prepared(), stage_deadline=sts.DEADLINE - 600,
                                  credential_limit=sts.DEADLINE, now=now)


def _expiry(document):
    return document["Statement"][0]["Condition"]["DateLessThan"]["aws:CurrentTime"]


def _date(document, value):
    for statement in document["Statement"]:
        statement["Condition"]["DateLessThan"]["aws:CurrentTime"] = value
    return document


def _deny(document):
    document["Statement"][0]["Effect"] = "Deny"
    return document


def _byte(document):
    action = document["Statement"][0]["Action"][0]
    document["Statement"][0]["Action"][0] = action[:-1] + ("X" if action[-1] != "X" else "Y")
    return document


def _longer(document):
    document["Statement"][0]["Action"] = document["Statement"][0]["Action"] + ["ecs:StopTask"]
    return document


def _other_date(document):
    document["Statement"][1]["Condition"]["DateLessThan"]["aws:CurrentTime"] = c.utc(sts.DEADLINE - 500)
    return document


@pytest.mark.parametrize("change, message", [
    (lambda document: document, None),
    (lambda document: _date(document, c.utc(sts.DEADLINE)), "^mode_session_deadline=statement$"),
    (_deny, "^mode_session_deadline=statement$"),
    (_byte, "^mode_session_deadline=reverse$"),
    (_longer, "^mode_session_deadline=format$"),
    (_other_date, "^mode_session_deadline=statement$"),
    (lambda document: _date(document, c.utc(sts.DEADLINE - 600).replace("Z", "+00:00")), "^mode_session_deadline=statement$"),
    (lambda document: _date(document, "2026-12-01T00:00Z"), "^mode_session_deadline=statement$"),
], ids=["igual", "com-o-limite-preparado", "em-deny", "outro-byte", "byte-a-mais", "outra-data", "formato", "tamanho"])
def test_substituicao_reversa_recusa_cunhagem_fora_do_documento_preparado(change, message):
    d = sts.DEADLINE - 600
    minted = change(_sp().mode_session_policy("recovery-start", resources=sts.RESOURCES, owner_sha256=sts.OWNER,
                                              deadline=d))
    if message is None:
        assert _ib().mode_deadline_reverse(minted, _prepared(), deadline=d, bound=sts.DEADLINE) is None
        assert _expiry(minted) == c.utc(d)
        return
    with pytest.raises(ValueError, match=message):
        _ib().mode_deadline_reverse(minted, _prepared(), deadline=d, bound=sts.DEADLINE)


def test_formato_do_prazo_do_construtor_mudado_recusa(monkeypatch):
    real = _sp()._mode_expiring

    def iso(statements, deadline):
        document = real(statements, deadline)
        return _date(document, c.utc(deadline).replace("Z", "+00:00"))
    prepared = _prepared()
    monkeypatch.setattr(_sp(), "_mode_expiring", iso)
    with pytest.raises(ValueError, match="^mode_session_deadline=statement$"):
        _ib().mode_minted_session("rx", "recovery-start", SCOPE, prepared=prepared, stage_deadline=sts.DEADLINE - 600,
                                  credential_limit=sts.DEADLINE, now=sts.START)


def test_cunhagem_com_byte_alterado_recusa_antes_do_sts(monkeypatch):
    args, calls, _ = sts._case(monkeypatch, "recovery-start")
    real = _ib().mode_session_document

    def altered(code, operation, scope):
        document = real(code, operation, scope)
        return _byte(document) if scope["deadline"] != args["authority"].scope["deadline"] else document
    monkeypatch.setattr(_ib(), "mode_session_document", altered)
    with pytest.raises(ValueError, match="^mode_session_deadline=reverse$"):
        _mb().assume_mode_session(**args)
    assert calls == []
