"""Synthetic direct AWS readbacks and complete state; not live Ready evidence."""
from fixtures.cnesdata_cost import encoded

ACCOUNT = "111122223333"
CERT = f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/not-a-uuid-assumption"
DIST = f"arn:aws:cloudfront::{ACCOUNT}:distribution/Synthetic_Dist"
WAF = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:global/webacl/cnesdata-prod-static-web/not-a-fixed-id"


def fixture(bootstrap=False):
    record = {"domain": "cnesdata.com.br", "name": "_validation.cnesdata.com.br.", "type": "CNAME", "value": "_token.acm-validations.aws."}
    certificate = {"CertificateArn": CERT, "DomainName": "cnesdata.com.br", "SubjectAlternativeNames": ["cnesdata.com.br"],
                   "Status": "ISSUED" if bootstrap else "PENDING_VALIDATION",
                   "DomainValidationOptions": [{"DomainName": "cnesdata.com.br", "ResourceRecord": {"Name": record["name"], "Type": "CNAME", "Value": record["value"]}}]}
    attributes = {"arn": CERT, "domain_name": "cnesdata.com.br", "subject_alternative_names": [],
                  "domain_validation_options": [{"domain_name": record["domain"], "resource_record_name": record["name"],
                                                 "resource_record_type": record["type"], "resource_record_value": record["value"]}]}
    state = {"lineage": "synthetic", "serial": 1, "outputs": {}, "resources": [
        {"mode": "managed", "type": "aws_acm_certificate", "name": "static_web", "instances": [{"attributes": attributes}]}]}
    distribution = {"Id": "Synthetic_Dist", "ARN": DIST, "DomainName": "synthetic.cloudfront.net", "Status": "Deployed",
                    "DistributionConfig": {"WebACLId": WAF, "Aliases": {"Quantity": 1, "Items": ["cnesdata.com.br"]},
                                           "ViewerCertificate": {"ACMCertificateArn": CERT}}}
    waf = {"Name": "cnesdata-prod-static-web", "Id": "not-a-fixed-id", "ARN": WAF}
    if bootstrap:
        state["resources"] += [
            {"mode": "managed", "module": "module.static_web", "type": "aws_cloudfront_distribution", "name": "this",
             "instances": [{"attributes": {"id": distribution["Id"], "arn": DIST, "domain_name": distribution["DomainName"], "web_acl_id": WAF}}]},
            {"mode": "managed", "module": "module.static_web", "type": "aws_wafv2_web_acl", "name": "this",
             "instances": [{"attributes": {"arn": WAF, "id": waf["Id"], "name": waf["Name"]}}]}]
        state["outputs"] = {"cloudfront_distribution_id": {"value": distribution["Id"]}, "cloudfront_domain_name": {"value": distribution["DomainName"]}}
    class API:
        def call(self, service, operation, **kwargs):
            assert kwargs.get("region") == "us-east-1"
            if service == "acm":
                assert operation == "describe_certificate" and kwargs["CertificateArn"] == CERT
                return {"Certificate": certificate}
            if service == "cloudfront":
                assert operation == "get_distribution" and kwargs["Id"] == distribution["Id"]
                return {"Distribution": distribution}
            assert service == "wafv2" and operation == "get_web_acl" and kwargs["Scope"] == "CLOUDFRONT"
            return {"WebACL": waf}
    return state, API(), certificate, distribution, record
