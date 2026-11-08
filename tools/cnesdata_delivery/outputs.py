"""Private normative projections (#28/6716490764), never raw Terraform outputs."""
import re
import time

from tools.cnesdata_delivery import contract as c

DOMAIN = "cnesdata.com.br"
INVARIANTS = {"active_unit": None, "retained_units": [], "state_machine": None,
              "schedulers": {"recovery": None, "audit": None}, "canary_release": None, "canary_storage": False}


def ascii_value(value, maximum):
    c.require(type(value) is str and 0 < len(value) <= maximum and value.isascii()
              and all(32 < ord(char) < 127 for char in value), "bounded ASCII identifier")
    return value


def dns(value, *, terminal=True, underscore=True, maximum=254):
    ascii_value(value, maximum)
    c.require(terminal or not value.endswith("."), "hostname terminal dot")
    labels = value[:-1].split(".") if value.endswith(".") else value.split(".")
    alphabet = r"[A-Za-z0-9_-]+" if underscore else r"[A-Za-z0-9-]+"
    c.require(len(labels) >= 2 and all(0 < len(label) <= 63 and re.fullmatch(alphabet, label)
              and not label.startswith("-") and not label.endswith("-") for label in labels), "DNS labels")
    return labels


def resource(state, address):
    found = []
    for item in state.get("resources", []):
        prefix = (item.get("module", "") + ".").lstrip(".") + item["type"] + "." + item["name"]
        if item.get("mode") == "managed" and prefix == address:
            found.extend(instance["attributes"] for instance in item["instances"])
    c.require(len(found) == 1, "exact resource state singleton")
    return found[0]


def record(value):
    c.closed(value, "domain name type value")
    c.require(value["domain"] == DOMAIN and value["type"] == "CNAME", "ACM domain/type")
    labels = dns(value["name"])
    c.require(len(labels) > 3 and [label.lower() for label in labels[-3:]] == DOMAIN.split("."), "ACM validation name suffix")
    dns(value["value"])
    return value


def validate(value, purpose, account):
    if purpose == "acm-certificate":
        c.closed(value, "acm_certificate_arn acm_dns_validation_records")
        arn = ascii_value(value["acm_certificate_arn"], 2048)
        c.require(arn.startswith(f"arn:aws:acm:us-east-1:{account}:certificate/") and arn.rsplit("/", 1)[-1], "certificate governed ARN")
        c.require(type(value["acm_dns_validation_records"]) is list and len(value["acm_dns_validation_records"]) == 1, "one governed domain")
        record(value["acm_dns_validation_records"][0])
    elif purpose == "bootstrap":
        c.closed(value, "cloudfront_distribution_id cloudfront_domain_name free_subscription_binding_input bootstrap_invariants")
        identifier = ascii_value(value["cloudfront_distribution_id"], 128)
        c.require(re.fullmatch(r"[A-Za-z0-9_-]+", identifier), "distribution ID")
        dns(value["cloudfront_domain_name"], terminal=False, underscore=False, maximum=253)
        binding = c.closed(value["free_subscription_binding_input"], "distribution_arn web_acl_arn")
        c.require(ascii_value(binding["distribution_arn"], 2048) == f"arn:aws:cloudfront::{account}:distribution/{identifier}", "distribution ARN binding")
        waf = ascii_value(binding["web_acl_arn"], 2048)
        c.require(waf.startswith(f"arn:aws:wafv2:us-east-1:{account}:global/webacl/cnesdata-prod-static-web/")
                  and waf.rsplit("/", 1)[-1], "WAF governed ARN")
        c.require(value["bootstrap_invariants"] == INVARIANTS, "closed bootstrap invariants")
    else:
        raise ValueError("private projection purpose")
    return value


def certificate(state, api, account, *, issued=False):
    item = resource(state, "aws_acm_certificate.static_web")
    arn = ascii_value(item["arn"], 2048)
    c.require(arn.startswith(f"arn:aws:acm:us-east-1:{account}:certificate/") and arn.rsplit("/", 1)[-1], "certificate account/region")
    observed = api.call("acm", "describe_certificate", region="us-east-1", CertificateArn=arn)["Certificate"]
    c.require(observed["CertificateArn"] == arn and observed["DomainName"] == item["domain_name"] == DOMAIN
              and all(name == DOMAIN for name in observed.get("SubjectAlternativeNames", []))
              and all(name == DOMAIN for name in item["subject_alternative_names"]), "certificate exact source domain/SAN")
    c.require(observed["Status"] in ({"ISSUED"} if issued else {"PENDING_VALIDATION", "ISSUED"}), "certificate status")
    options = observed["DomainValidationOptions"]
    c.require(len(options) == 1 and options[0]["DomainName"] == DOMAIN, "certificate DVO singleton")
    rr = options[0]["ResourceRecord"]
    projected = record({"domain": DOMAIN, "name": rr["Name"], "type": rr["Type"], "value": rr["Value"]})
    state_options = item["domain_validation_options"]
    c.require(len(state_options) == 1 and {"domain": state_options[0]["domain_name"],
        "name": state_options[0]["resource_record_name"], "type": state_options[0]["resource_record_type"],
        "value": state_options[0]["resource_record_value"]} == projected, "state/API record literal equality")
    root = state.get("outputs", {}).get("acm_dns_validation_records")
    if root is not None:
        c.require(root["value"] == {DOMAIN: {key: projected[key] for key in ("name", "type", "value")}}, "root/state/API record equality")
    return arn, projected


def acm(state, api, account):
    arn, option = certificate(state, api, account)
    return validate({"acm_certificate_arn": arn, "acm_dns_validation_records": [option]}, "acm-certificate", account)


def no_runtime(state):
    for item in state.get("resources", []):
        if item.get("mode") != "managed" or not item.get("instances"):
            continue
        c.require(item["type"] not in {"aws_ecs_task_definition", "aws_sfn_state_machine", "aws_scheduler_schedule"}
                  and "canary" not in item["name"], "bootstrap cannot reset runtime/canary")


def initial_stage(before, checkpoint, source_sha, api, account, now):
    c.require(type(checkpoint) is dict and checkpoint.get("stage") == "bootstrap-initial"
              and checkpoint.get("source_sha") == source_sha and c.instant(checkpoint["expires_at"]) > now,
              "authenticated initial stage/ISSUED checkpoint")
    c.require(before is not None and c.state_identity(before)["state_sha256"] == checkpoint["state_before_sha256"], "initial state checkpoint")
    state = c.loads(before, state=True)
    no_runtime(state)
    for item in state.get("resources", []):
        if item.get("mode") == "managed" and item.get("instances"):
            c.require(item["type"] == "aws_acm_certificate" and item["name"] == "static_web" and not item.get("module"), "already bootstrapped/residual; recover or consume receipt")
    arn, _ = certificate(state, api, account, issued=True)
    c.require(arn == checkpoint["certificate_arn"], "same phase1 ISSUED certificate")


def initial_admission(plan_json, inputs, before, checkpoint, source_sha, api, account, now):
    initial_stage(before, checkpoint, source_sha, api, account, now)
    expected = {"image_digest": None, "processor_active_unit_task_definition_arn": None,
                "processor_retained_unit_task_definition_arns": [], "canary_release_id": None,
                "canary_trusted_principal_arn": None, "canary_storage_enabled": False}
    for name, value in expected.items():
        actual = plan_json["variables"][name]["value"]
        c.require(actual == value and type(actual) is type(value), "bootstrap resolved input invariant")
        if name in inputs:
            c.require(inputs[name] == value and type(inputs[name]) is type(value), "bootstrap generated input invariant")
    for item in plan_json.get("resource_changes", []):
        if item["change"]["actions"] not in (["no-op"], ["read"]):
            c.require(item["type"] not in {"aws_ecs_task_definition", "aws_sfn_state_machine", "aws_scheduler_schedule"}
                      and "canary" not in item["name"], "bootstrap planned runtime mutation")


def bootstrap(state, api, account):
    no_runtime(state)
    cert, _ = certificate(state, api, account, issued=True)
    cf = resource(state, "module.static_web.aws_cloudfront_distribution.this")
    waf = resource(state, "module.static_web.aws_wafv2_web_acl.this")
    observed = api.call("cloudfront", "get_distribution", region="us-east-1", Id=cf["id"])["Distribution"]
    direct_waf = api.call("wafv2", "get_web_acl", region="us-east-1", Name="cnesdata-prod-static-web",
                          Scope="CLOUDFRONT", Id=waf["id"])["WebACL"]
    config = observed["DistributionConfig"]
    c.require(observed["Id"] == cf["id"] and observed["ARN"] == cf["arn"] and observed["DomainName"] == cf["domain_name"]
              and observed["Status"] == "Deployed" and direct_waf["ARN"] == waf["arn"] == cf["web_acl_id"] == config["WebACLId"]
              and direct_waf["Name"] == waf["name"] == "cnesdata-prod-static-web" and direct_waf["Id"] == waf["id"]
              and config["ViewerCertificate"]["ACMCertificateArn"] == cert
              and config["Aliases"] == {"Quantity": 1, "Items": [DOMAIN]}, "distribution/certificate/WAF actual tuple")
    root = state["outputs"]
    c.require(root["cloudfront_distribution_id"]["value"] == cf["id"] and root["cloudfront_domain_name"]["value"] == cf["domain_name"], "root distribution identity")
    # Null/false constants are emitted ONLY after source/inputs/plan/stage admission
    # and actual complete state absence plus direct readbacks above have agreed.
    return validate({"cloudfront_distribution_id": cf["id"], "cloudfront_domain_name": cf["domain_name"],
                     "free_subscription_binding_input": {"distribution_arn": cf["arn"], "web_acl_arn": waf["arn"]},
                     "bootstrap_invariants": INVARIANTS}, "bootstrap", account)
