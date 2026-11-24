"""Synthetic B/C sources with the product addresses and types; mock-provider plans only."""
import json
import shutil

MACHINE = {"enabled": False, "definition": json.dumps({"StartAt": "A", "States": {"A": {"Type": "Pass", "End": True}}})}
POLICY = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
REVISION = "arn:aws:ecs:us-east-2:111122223333:task-definition/cnesdata-prod-{mode}:{revision}"

ROOT_TF = '''terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "6.54.0" }
  }
}
provider "aws" { region = "us-east-2" }
variable "machine" { type = object({ enabled = bool, definition = string }) }
variable "api_policy" { type = string }
variable "schedules" { type = map(object({ enabled = bool, revision = string, policy = string })) }
module "processing" {
  source  = "./modules/processing"
  machine = var.machine
}
module "runtime_iam" {
  source     = "./modules/runtime-iam"
  api_policy = var.api_policy
}
module "schedulers" {
  source    = "./modules/schedulers"
  schedules = var.schedules
}
'''

PROCESSING_TF = '''variable "machine" { type = any }
resource "aws_sfn_state_machine" "processor" {
  count      = var.machine.enabled ? 1 : 0
  name       = "cnesdata-prod-processor"
  role_arn   = "arn:aws:iam::111122223333:role/cnesdata-prod-processor"
  definition = var.machine.definition
  publish    = false
  type       = "STANDARD"
  encryption_configuration {
    type = "AWS_OWNED_KEY"
  }
  logging_configuration {
    level                  = "OFF"
    include_execution_data = false
  }
  tracing_configuration {
    enabled = false
  }
}
'''

RUNTIME_IAM_TF = '''variable "api_policy" { type = string }
resource "aws_iam_role_policy" "api" {
  count  = 1
  name   = "cnesdata-prod-api-runtime"
  role   = "cnesdata-prod-api"
  policy = var.api_policy
}
'''

SCHEDULERS_TF = '''variable "schedules" { type = any }
locals {
  enabled  = { for mode, item in var.schedules : mode => item if item.enabled }
  outcomes = merge({ for mode in keys(local.enabled) : "${mode}_failed" => mode },
    contains(keys(local.enabled), "audit") ? { audit_succeeded = "audit" } : {})
}
resource "aws_scheduler_schedule_group" "mode" {
  for_each = local.enabled
  name     = "cnesdata-prod-${each.key}"
}
resource "aws_scheduler_schedule" "mode" {
  for_each                     = local.enabled
  name                         = "cnesdata-prod-${each.key}"
  group_name                   = aws_scheduler_schedule_group.mode[each.key].name
  schedule_expression          = "rate(1 hours)"
  schedule_expression_timezone = "UTC"
  state                        = "ENABLED"
  description                  = "cnesdata-prod-${each.key}"
  kms_key_arn                  = null
  start_date                   = null
  end_date                     = null
  name_prefix                  = null
  action_after_completion      = "NONE"
  flexible_time_window {
    mode = "OFF"
  }
  target {
    arn      = "arn:aws:ecs:us-east-2:111122223333:cluster/cnesdata-prod"
    role_arn = "arn:aws:iam::111122223333:role/cnesdata-prod-scheduler-${each.key}"
    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 0
    }
    ecs_parameters {
      task_definition_arn     = each.value.revision
      launch_type             = "FARGATE"
      task_count              = 1
      enable_ecs_managed_tags = false
      enable_execute_command  = false
      group                   = "cnesdata-prod-${each.key}"
      platform_version        = "LATEST"
      propagate_tags          = null
      reference_id            = null
      tags                    = {}
      network_configuration {
        assign_public_ip = true
        security_groups  = ["sg-0a1b2c3d4e5f6a7b8"]
        subnets          = ["subnet-0a1b2c3d4e5f6a7b8"]
      }
    }
  }
}
resource "aws_iam_role_policy" "run" {
  for_each = var.schedules
  name     = "cnesdata-prod-scheduler-${each.key}-run"
  role     = "cnesdata-prod-scheduler-${each.key}"
  policy   = each.value.policy
}
resource "aws_cloudwatch_event_rule" "task_outcome" {
  for_each      = local.outcomes
  name          = "cnesdata-prod-${replace(each.key, "_", "-")}"
  description   = each.key
  state         = "ENABLED"
  event_pattern = jsonencode({ source = ["aws.ecs"], detail = { group = ["cnesdata-prod-${each.value}"] } })
}
resource "aws_cloudwatch_metric_alarm" "repeated_failure" {
  for_each            = local.enabled
  alarm_name          = "cnesdata-prod-scheduler-${each.key}-repeated-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "TriggeredRules"
  namespace           = "AWS/Events"
  period              = 300
  statistic           = "Sum"
  threshold           = 2
  treat_missing_data  = "notBreaching"
  actions_enabled     = false
}
resource "aws_cloudwatch_metric_alarm" "lost_invocation" {
  for_each            = local.enabled
  alarm_name          = "cnesdata-prod-scheduler-${each.key}-lost-invocation"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "InvocationDroppedCount"
  namespace           = "AWS/Scheduler"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  actions_enabled     = false
}
resource "aws_cloudwatch_metric_alarm" "outbox_backlog" {
  count               = contains(keys(local.enabled), "audit") ? 1 : 0
  alarm_name          = "cnesdata-prod-scheduler-audit-outbox-backlog"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "OutboxBacklog"
  namespace           = "CnesData"
  period              = 300
  statistic           = "Maximum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  actions_enabled     = false
}
'''

SOURCES = {"main.tf": ROOT_TF, "modules/processing/main.tf": PROCESSING_TF,
           "modules/runtime-iam/main.tf": RUNTIME_IAM_TF, "modules/schedulers/main.tf": SCHEDULERS_TF}


def _policy(label):
    return json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": label, "Effect": "Allow", "Action": "s3:GetObject",
                                                                 "Resource": "*"}]})


def _schedule(mode, *, enabled=False, revision=1, policy="phase-a"):
    return {"enabled": enabled, "revision": REVISION.format(mode=mode, revision=revision), "policy": _policy(mode + "-" + policy)}


def _variables(*, machine=None, api="phase-a", recovery=None, audit=None):
    return {"machine": machine or MACHINE, "api_policy": _policy("api-" + api),
            "schedules": {"recovery": recovery or _schedule("recovery"), "audit": audit or _schedule("audit")}}


def _definition(label):
    return json.dumps({"Comment": label, "StartAt": "A", "States": {"A": {"Type": "Pass", "End": True}}})


B_ON = {"enabled": True, "definition": _definition("b-1")}
RECOVERY_ON = _schedule("recovery", enabled=True, revision=2, policy="c-1")
AUDIT_ON = _schedule("audit", enabled=True, revision=2, policy="c-1")
RUNS = [
    ("phase_a", "apply", _variables()),
    ("b_initial", "plan", _variables(machine=B_ON, api="b-1")),
    ("b_initial_apply", "apply", _variables(machine=B_ON, api="b-1")),
    ("b_established", "plan", _variables(machine={"enabled": True, "definition": _definition("b-2")}, api="b-1")),
    ("b_inverse", "plan", _variables()),
    ("c_recovery_initial", "plan", _variables(machine=B_ON, api="b-1", recovery=RECOVERY_ON)),
    ("c_recovery_initial_apply", "apply", _variables(machine=B_ON, api="b-1", recovery=RECOVERY_ON)),
    ("c_recovery_established", "plan", _variables(machine=B_ON, api="b-1",
                                                  recovery=_schedule("recovery", enabled=True, revision=3, policy="c-2"))),
    ("c_recovery_inverse", "plan", _variables(machine=B_ON, api="b-1")),
    ("c_audit_initial", "plan", _variables(machine=B_ON, api="b-1", recovery=RECOVERY_ON, audit=AUDIT_ON)),
    ("c_audit_initial_apply", "apply", _variables(machine=B_ON, api="b-1", recovery=RECOVERY_ON, audit=AUDIT_ON)),
    ("c_audit_established", "plan", _variables(machine=B_ON, api="b-1", recovery=RECOVERY_ON,
                                               audit=_schedule("audit", enabled=True, revision=3, policy="c-2"))),
    ("c_audit_inverse", "plan", _variables(machine=B_ON, api="b-1", recovery=RECOVERY_ON)),
]


def _hcl(value):
    return json.dumps(value)


def _test_file():
    blocks = ['mock_provider "aws" {}']
    for name, command, variables in RUNS:
        assignments = "\n".join(f"    {key} = {_hcl(value)}" for key, value in variables.items())
        blocks.append(f'run "{name}" {{\n  command = {command}\n  variables {{\n{assignments}\n  }}\n}}')
    return "\n".join(blocks) + "\n"


def bc_native_plans():
    """Returns: run name -> native plan JSON of each plan run, in one stateful tofu test. Raises: AssertionError."""
    from fixtures.cnesdata_delivery_roles_anywhere.native import Native, ROOT
    harness = Native()
    try:
        root = harness.base / "bc"
        for name, text in SOURCES.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        shutil.copy2(ROOT / ".terraform.lock.hcl", root / ".terraform.lock.hcl")
        (root / "contract.tftest.hcl").write_text(_test_file())
        init = harness.run(root, "init", "-backend=false", "-input=false", "-lockfile=readonly")
        assert init.returncode == 0, init.stdout + init.stderr
        result = harness.run(root, "test", "-json", "-verbose")
        assert result.returncode == 0, result.stdout + result.stderr
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        plans = [event for event in events if "test_plan" in event]
        names = [name for name, command, _ in RUNS if command == "plan"]
        assert len(plans) == len(names), [sorted(event) for event in events]
        return {name: event["test_plan"] for name, event in zip(names, plans)}
    finally:
        harness.temp.cleanup()
