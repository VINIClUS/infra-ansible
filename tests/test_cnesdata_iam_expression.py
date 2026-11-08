"""Ratified producer grammar and retained collection boundaries."""
import pytest

from tools.cnesdata_delivery.iam_expression import Budget, Evaluator, function, parse, source_blocks


def evaluate(source, values=None):
    budget = Budget()
    def lookup(path, scope):
        value = scope | (values or {})
        for part in path:
            value = value[part]
        return value
    return Evaluator(lookup, budget).value(parse(source, budget))


@pytest.mark.parametrize("source, expected", [
    ('format("a:%s:%s", "b", "c")', "a:b:c"),
    ('replace("a:b", ":", "/")', "a/b"),
    ('toset(["b", "a", "b"])', ["a", "b"]),
    ('keys({ z = 1, a = 2 })', ["a", "z"]),
    ('{ for key, value in { z = 1, a = 2 } : key => value if value != 1 }', {"a": 2}),
    ('element(reverse(split("/", "arn/role/name")), 0)', "name"),
])
def test_ratified_bootstrap_source_grammar(source, expected):
    assert evaluate(source) == expected


@pytest.mark.parametrize("name", ["sort", "setunion"])
def test_retained_collection_limit_128_deduplicates_before_limit(name):
    values = [str(i) for i in range(128)]
    args = [values, [values[-1]]] if name == "setunion" else [values]
    assert len(function(name, args)) == 128
    with pytest.raises(ValueError):
        function(name, [values + ["new"]])


def test_unratified_format_and_collection_expansion_are_closed():
    with pytest.raises(ValueError):
        evaluate('format("%d", 1)')
    with pytest.raises(ValueError):
        function("concat", [[str(i) for i in range(65)]])


def test_try_catches_only_admitted_api_null_error():
    source = 'try(element(reverse(split("/", var.runtime_grants.api_role_arn)), 0), null)'
    assert evaluate(source, {"var": {"runtime_grants": {"api_role_arn": None}}}) is None
    with pytest.raises(ValueError, match="try_scope"):
        evaluate('try(element([], 0), null)')
    def failed_authorization(*_):
        raise ValueError("authenticated source denied")
    budget = Budget()
    with pytest.raises(ValueError, match="authenticated source denied"):
        Evaluator(failed_authorization, budget).value(parse(source, budget))


def test_static_description_metadata_does_not_admit_evaluated_heredocs():
    assert source_blocks(b'output "a" {\n description = <<-EOT\n static text\n EOT\n value = "ok"\n}\n')[0][0:2] == ("output", "a")
    for field, value in [("value", "text"), ("description", "${var.secret}")]:
        with pytest.raises(ValueError):
            source_blocks(f'output "a" {{\n {field} = <<-EOT\n {value}\n EOT\n}}\n'.encode())
