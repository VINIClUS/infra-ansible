"""Small independent IAM evaluator for the policy subset emitted by these gates."""
from fnmatch import fnmatchcase
from datetime import datetime


def decision(policy, action, resource, context=None):
    context = context or {}
    accepted = False
    def matches(value, patterns):
        return any(fnmatchcase(value, pattern) for pattern in ([patterns] if isinstance(patterns, str) else patterns))
    for statement in policy["Statement"]:
        actions = statement.get("Action")
        if actions is not None and not matches(action.lower(), [x.lower() for x in ([actions] if isinstance(actions, str) else actions)]):
            continue
        if "NotAction" in statement and matches(action.lower(), [x.lower() for x in statement["NotAction"]]):
            continue
        if "Resource" in statement and not matches(resource, statement["Resource"]):
            continue
        if "NotResource" in statement and matches(resource, statement["NotResource"]):
            continue
        passed = True
        for operator, conditions in statement.get("Condition", {}).items():
            for key, patterns in conditions.items():
                if operator == "ForAllValues:StringEquals":
                    values = context.get(key)
                    values = [] if values is None else values
                    values = [values] if isinstance(values, str) else values
                    permitted = [patterns] if isinstance(patterns, str) else patterns
                    passed &= all(value in permitted for value in values)
                    continue
                if operator == "Null":
                    missing = key not in context or context[key] is None or context[key] == []
                    passed &= missing == (patterns == "true")
                    continue
                if operator == "DateLessThan":
                    if key not in context:
                        passed = False
                    else:
                        current = datetime.fromisoformat(context[key].replace("Z", "+00:00"))
                        deadline = datetime.fromisoformat(patterns.replace("Z", "+00:00"))
                        assert current.tzinfo is not None and deadline.tzinfo is not None
                        passed &= current < deadline
                    continue
                found = key in context and matches(context[key], patterns)
                if operator in {"StringEquals", "StringLike", "ArnEquals", "ArnLike"}:
                    passed &= found
                elif operator in {"StringNotLike", "StringNotEquals", "ArnNotLike"}:
                    passed &= not found
                else:
                    raise AssertionError("unsupported fixture condition " + operator)
        if not passed:
            continue
        if statement["Effect"] == "Deny":
            return "Deny"
        accepted = True
    return "Allow" if accepted else None


def allowed(policy, action, resource, context=None):
    return decision(policy, action, resource, context) == "Allow"


def effective(identity, managed, inline, action, resource, context=None):
    decisions = [decision(policy, action, resource, context) for policy in (identity, managed, inline)]
    return "Deny" not in decisions and decisions[0] == "Allow" and "Allow" in decisions[1:]
