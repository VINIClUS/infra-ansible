"""Mutações sintéticas usadas para testar os oráculos nativos."""

import json

MUTATIONS = (
    "executor_boundary_deny_all",
    "executor_policy_deny_all",
    "readback_policy_deny_all",
    "executor_conditions_wrong_account",
    "readback_action_resource_crosswired",
    "kms_condition_prevents_recovery",
    "state_bucket_policy_deny_all",
    "logging_deny_delivery",
    "executor_boundary_points_elsewhere",
    "executor_inline_policy_attached_to_readback",
    "assume_policy_attached_to_other_user",
    "bucket_controls_attach_to_foreign_bucket",
    "state_bucket_policy_allows_delete_state",
    "readback_role_name_does_not_match_mock_arn",
    "logging_lifecycle_expires_state",
    "logging_lifecycle_wrong_prefix_and_glacier",
    "logging_owner_foreign_and_object_lock",
)
CONTROLS = (
    "control_trust_missing_mfa",
    "control_kms_rotation_disabled",
    "control_executor_deletes_state",
    "control_logging_sourceaccount_absent",
)
EXTRA_MUTATIONS = (
    "logging_glacier_only",
    "logging_owner_only",
    "logging_object_lock_only",
    "logging_sourcearn_absent",
    "logging_wildcard_resource",
    "logging_sse_kms",
    "logging_cycle_to_source",
    "logging_wrong_source",
    "logging_removed",
    "logging_expiration_31",
    "logging_prefix_only",
    "login_attached_other_user",
)
INTERFACE_MUTATIONS = (
    "foundation_backend_kms_defaults",
    "foundation_extra_variable",
)


def _change_policy(config, kind, label, change):
    resources = config["resource"]
    document = json.loads(resources[kind][label]["policy"])
    change(document["Statement"])
    resources[kind][label]["policy"] = json.dumps(document)


def _deny_all(config, kind, label):
    _change_policy(
        config,
        kind,
        label,
        lambda statements: statements.append({"Effect": "Deny", "Action": "*", "Resource": "*"}),
    )


def _wrong_conditions(config):
    def update(statements):
        for statement in statements:
            statement["Condition"] = {"StringEquals": {"aws:PrincipalAccount": "999999999999"}}

    for kind, label in (
        ("aws_iam_policy", "executor_boundary"),
        ("aws_iam_role_policy", "bootstrap_executor"),
    ):
        _change_policy(config, kind, label, update)


def _crosswire_readback(config):
    _change_policy(
        config,
        "aws_iam_role_policy",
        "bootstrap_readback",
        lambda statements: statements[0].update(Resource="${aws_kms_key.foundation.arn}"),
    )


def _wrong_kms_condition(config):
    _change_policy(
        config,
        "aws_kms_key",
        "foundation",
        lambda statements: [
            statement.update(Condition={"StringEquals": {"aws:PrincipalAccount": "999999999999"}})
            for statement in statements
        ],
    )


def _deny_bucket(config, label):
    _change_policy(
        config,
        "aws_s3_bucket_policy",
        label,
        lambda statements: statements.append(
            {"Effect": "Deny", "Action": "*", "Resource": "*", "Principal": "*"}
        ),
    )


def _foreign_bucket_controls(config):
    for kind, values in config["resource"].items():
        if kind.startswith("aws_s3_bucket_"):
            for attrs in values.values():
                attrs["bucket"] = "example-foreign-bucket"


def _allow_state_delete(config):
    _change_policy(
        config,
        "aws_s3_bucket_policy",
        "state",
        lambda statements: statements.append(
            {
                "Effect": "Allow",
                "Action": "s3:DeleteObject",
                "Resource": "arn:aws:s3:::${var.roots.foundation.backend.bucket}/*",
                "Principal": {
                    "AWS": "arn:aws:iam::${var.account_id}:role"
                    "${var.identities.executor.path}"
                    "${var.identities.executor.name}"
                },
            }
        ),
    )


def _wrong_lifecycle(config):
    config["resource"]["aws_s3_bucket_lifecycle_configuration"]["logging"]["bucket"] = (
        "${aws_s3_bucket.state.id}"
    )


def _wrong_lifecycle_prefix(config):
    rule = config["resource"]["aws_s3_bucket_lifecycle_configuration"]["logging"]["rule"][0]
    rule["filter"] = [{"prefix": "foreign/"}]
    rule["transition"] = [{"days": 1, "storage_class": "GLACIER"}]


def _remove_condition(config, operator):
    _change_policy(
        config,
        "aws_s3_bucket_policy",
        "logging",
        lambda statements: statements[1]["Condition"].pop(operator),
    )


def _simple(config, name):
    resources = config["resource"]
    if name == "executor_boundary_points_elsewhere":
        resources["aws_iam_role"]["bootstrap_executor"]["permissions_boundary"] = (
            "arn:aws:iam::${var.account_id}:policy/unreviewed"
        )
    elif name == "executor_inline_policy_attached_to_readback":
        resources["aws_iam_role_policy"]["bootstrap_executor"]["role"] = (
            "${aws_iam_role.bootstrap_readback.name}"
        )
    elif name == "assume_policy_attached_to_other_user":
        resources["aws_iam_user_policy"]["local_assume"]["user"] = "foreign-user"
    elif name == "readback_role_name_does_not_match_mock_arn":
        resources["aws_iam_role"]["bootstrap_readback"]["name"] = "foreign-reader-name"
    elif name == "logging_lifecycle_expires_state":
        _wrong_lifecycle(config)
    elif name == "logging_lifecycle_wrong_prefix_and_glacier":
        _wrong_lifecycle_prefix(config)
    elif name == "logging_owner_foreign_and_object_lock":
        resources["aws_s3_bucket"]["logging"].update(
            tags={"Owner": "foreign-owner"}, object_lock_enabled=True
        )


def _controls(config, name):
    resources = config["resource"]
    if name == "control_trust_missing_mfa":
        for attrs in resources["aws_iam_role"].values():
            trust = json.loads(attrs["assume_role_policy"])
            trust["Statement"][0].pop("Condition")
            attrs["assume_role_policy"] = json.dumps(trust)
    elif name == "control_kms_rotation_disabled":
        resources["aws_kms_key"]["foundation"]["enable_key_rotation"] = False
    elif name == "control_executor_deletes_state":
        _change_policy(
            config,
            "aws_iam_role_policy",
            "bootstrap_executor",
            lambda statements: statements[1].update(Resource=statements[0]["Resource"]),
        )
    else:
        _remove_condition(config, "StringEquals")


def _extras(config, name):
    resources = config["resource"]
    actions = {
        "logging_glacier_only": lambda: resources["aws_s3_bucket_lifecycle_configuration"][
            "logging"]["rule"][0].update(
            transition=[{"days": 1, "storage_class": "GLACIER"}]),
        "logging_owner_only": lambda: resources["aws_s3_bucket"]["logging"].update(
            tags={"Owner": "foreign-owner"}),
        "logging_object_lock_only": lambda: resources["aws_s3_bucket"]["logging"].update(
            object_lock_enabled=True),
        "logging_sourcearn_absent": lambda: _remove_condition(config, "ArnLike"),
        "logging_wildcard_resource": lambda: _change_policy(
            config, "aws_s3_bucket_policy", "logging",
            lambda statements: statements[0].update(Resource="*")),
        "logging_sse_kms": lambda: resources["aws_s3_bucket_server_side_encryption_configuration"][
            "logging"]["rule"][0]["apply_server_side_encryption_by_default"][0].update(
                sse_algorithm="aws:kms"),
        "logging_cycle_to_source": lambda: resources["aws_s3_bucket_logging"]["state"].update(
            target_bucket="${aws_s3_bucket.state.id}"),
        "logging_wrong_source": lambda: resources["aws_s3_bucket_logging"]["state"].update(
            bucket="${aws_s3_bucket.logging.id}"),
        "logging_removed": lambda: resources.pop("aws_s3_bucket_logging"),
        "logging_expiration_31": lambda: resources["aws_s3_bucket_lifecycle_configuration"][
            "logging"]["rule"][0].update(expiration=[{"days": 31}]),
        "logging_prefix_only": lambda: resources["aws_s3_bucket_logging"]["state"].update(
            target_prefix="foreign/"),
        "login_attached_other_user": lambda: resources["aws_iam_user_policy_attachment"][
            "local_login"].update(user="foreign-user"),
    }
    action = actions.get(name)
    assert action, f"unknown mutation: {name}"
    action()


def _interface(config, name):
    variables = config["variable"]
    if name == "foundation_backend_kms_defaults":
        variables["backend"] = {"type": "any", "default": {}}
        variables["kms_key_arn"] = {"type": "string", "default": "unused"}
    else:
        variables["unexpected"] = {"type": "string", "default": "unexpected"}


def _deny_mutation(config, name):
    labels = {"executor_boundary_deny_all": ("aws_iam_policy", "executor_boundary"),
              "executor_policy_deny_all": ("aws_iam_role_policy", "bootstrap_executor"),
              "readback_policy_deny_all": ("aws_iam_role_policy", "bootstrap_readback")}
    if name in labels:
        _deny_all(config, *labels[name])
    elif name == "state_bucket_policy_deny_all":
        _deny_bucket(config, "state")
    else:
        _deny_bucket(config, "logging")


def _policy_mutation(config, name):
    if name == "executor_conditions_wrong_account":
        _wrong_conditions(config)
    elif name == "readback_action_resource_crosswired":
        _crosswire_readback(config)
    else:
        _wrong_kms_condition(config)


def _special_mutation(config, name):
    if name == "bucket_controls_attach_to_foreign_bucket":
        _foreign_bucket_controls(config)
    else:
        _allow_state_delete(config)


def _mutation_groups():
    return (
        ({"executor_boundary_deny_all", "executor_policy_deny_all", "readback_policy_deny_all",
          "state_bucket_policy_deny_all", "logging_deny_delivery"}, _deny_mutation),
        ({"executor_conditions_wrong_account", "readback_action_resource_crosswired",
          "kms_condition_prevents_recovery"}, _policy_mutation),
        ({"executor_boundary_points_elsewhere", "executor_inline_policy_attached_to_readback",
          "assume_policy_attached_to_other_user", "readback_role_name_does_not_match_mock_arn",
          "logging_lifecycle_expires_state", "logging_lifecycle_wrong_prefix_and_glacier",
          "logging_owner_foreign_and_object_lock"}, _simple),
        ({"bucket_controls_attach_to_foreign_bucket", "state_bucket_policy_allows_delete_state"},
         _special_mutation),
        (set(CONTROLS), _controls),
        (set(EXTRA_MUTATIONS), _extras),
        (set(INTERFACE_MUTATIONS), _interface),
    )


def mutate(config, name):
    """Aplica uma mutação controlada ao witness."""
    for names, handler in _mutation_groups():
        if name in names:
            handler(config, name)
            return
    raise AssertionError(f"unknown mutation: {name}")
