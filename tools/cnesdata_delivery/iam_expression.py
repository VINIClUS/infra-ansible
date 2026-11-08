"""Gramática fechada e orçamento global das expressões IAM Phase A atuais."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from tools.cnesdata_delivery.contract import require
from tools.cnesdata_delivery.contract import canonical as canonical_bytes

type Expr = tuple[Any, ...]
type Node = dict[str, Any]
STRING = r'"(?:\\.|\$\{[^}\n]*\}|[^"\\\n])*"'
TOKEN = re.compile(
    rf"\s+|\#[^\n]*|//[^\n]*|/\*[\s\S]*?\*/|{STRING}|[A-Za-z_][\w-]*|[0-9]+|==|!=|\|\||=>|[^\s]"
)
FUNCTIONS = {"jsonencode", "trimsuffix", "concat", "sort", "setunion", "length", "one",
             "format", "replace", "toset", "split", "reverse", "element", "keys", "try"}


class DynamicError(ValueError):
    """Only admitted null/index errors may be handled by the API-role try."""


@dataclass
class Budget:
    counts: dict[str, int] = field(default_factory=dict)
    references: set[str] = field(default_factory=set)

    def spend(self, kind: str, count: int = 1) -> None:
        limits = {"tokens": 8192, "nodes": 4096, "steps": 20000}
        self.counts[kind] = self.counts.get(kind, 0) + count
        require(self.counts[kind] <= limits[kind], "iam=budget_" + kind)

    def reference(self, name: str) -> None:
        self.references.add(name)
        require(len(self.references) <= 128, "iam=references")

    def node(self, *parts: Any) -> Expr:
        self.spend("nodes")
        return tuple(parts)


@dataclass(frozen=True)
class Pending:
    identity: str


def lex(source: str, budget: Budget | None = None) -> list[str]:
    result = []
    for match in TOKEN.finditer(source):
        lexeme = match[0]
        if lexeme.isspace() or lexeme.startswith(("#", "//", "/*")):
            continue
        require(len(lexeme) <= 4096, "iam=token_length")
        if budget is not None:
            budget.spend("tokens")
        result.append(lexeme)
    return result


class Parser:
    def __init__(self, source: str, budget: Budget):
        self.tokens, self.index, self.budget = lex(source, budget), 0, budget

    def take(self, expected: str | None = None) -> str:
        require(self.index < len(self.tokens), "iam=expression_end")
        lexeme = self.tokens[self.index]
        require(expected is None or lexeme == expected, "iam=expression_token")
        self.index += 1
        return lexeme

    def peek(self, expected: str) -> bool:
        return self.index < len(self.tokens) and self.tokens[self.index] == expected

    def expression(self, depth: int = 0) -> Expr:
        require(depth <= 24, "iam=expression_depth")
        result = self.binary(0, depth)
        if self.peek("?"):
            self.take("?")
            first = self.expression(depth + 1)
            self.take(":")
            result = self.budget.node("conditional", result, first, self.expression(depth + 1))
        return result

    def binary(self, precedence: int, depth: int) -> Expr:
        result = self.primary(depth + 1)
        operators = {"||": 1, "==": 2, "!=": 2, ">": 2}
        while self.index < len(self.tokens):
            operator = self.tokens[self.index]
            rank = operators.get(operator, -1)
            if rank < precedence:
                break
            self.take()
            result = self.budget.node("binary", operator, result, self.binary(rank + 1, depth + 1))
        return result

    def primary(self, depth: int) -> Expr:
        require(depth <= 24, "iam=expression_depth")
        lexeme = self.take()
        if lexeme == "(":
            result = self.expression(depth + 1)
            self.take(")")
            return result
        if lexeme in {"{", "["}:
            return {"{": self.mapping, "[": self.array}[lexeme](depth + 1)
        if lexeme.startswith('"'):
            return self.string(lexeme, depth)
        if lexeme in {"true", "false", "null"} or lexeme.isdecimal():
            return self.budget.node("literal", json.loads(lexeme))
        require(bool(re.fullmatch(r"[A-Za-z_][\w-]*", lexeme)), "iam=expression_unsupported")
        if self.peek("("):
            return self.call(lexeme, depth + 1)
        return self.reference(lexeme)

    def mapping(self, depth: int) -> Expr:
        if self.peek("for"):
            return self.comprehension(depth, mapping=True)
        pairs = []
        while not self.peek("}"):
            key = self.take()
            require(key != "for", "iam=object_for_unsupported")
            require(key.startswith('"') or re.fullmatch(r"[A-Za-z_][\w-]*", key), "iam=object_key")
            name = json.loads(key) if key.startswith('"') else key
            require(type(name) is str and name not in [p[0] for p in pairs], "iam=object_key")
            require(self.take() in {"=", ":"}, "iam=object_assignment")
            pairs.append((name, self.expression(depth + 1)))
            require(len(pairs) <= 64, "iam=object_size")
            if self.peek(","):
                self.take(",")
        self.take("}")
        return self.budget.node("object", tuple(pairs))

    def array(self, depth: int) -> Expr:
        if self.peek("for"):
            return self.comprehension(depth)
        items = []
        while not self.peek("]"):
            items.append(self.expression(depth + 1))
            require(len(items) <= 64, "iam=array_size")
            if not self.peek("]"):
                self.take(",")
        self.take("]")
        return self.budget.node("list", tuple(items))

    def comprehension(self, depth: int, mapping: bool = False) -> Expr:
        self.take("for")
        names = [self.take()]
        if self.peek(","):
            self.take(",")
            names.append(self.take())
        require(all(re.fullmatch(r"[A-Za-z_]\w*", name) for name in names), "iam=iterator")
        self.take("in")
        iterable = self.expression(depth + 1)
        self.take(":")
        value = self.expression(depth + 1)
        key = None
        if mapping:
            self.take("=>")
            key, value = value, self.expression(depth + 1)
        condition = self.budget.node("literal", True)
        if self.peek("if"):
            self.take("if")
            condition = self.expression(depth + 1)
        self.take("}" if mapping else "]")
        return self.budget.node("mapfor", tuple(names), iterable, key, value, condition) if mapping else self.budget.node("for", tuple(names), iterable, value, condition)

    def reference(self, first: str) -> Expr:
        path: list[Any] = [first]
        while self.peek(".") or self.peek("["):
            lexeme = self.take()
            if lexeme == ".":
                item: Any = self.take()
                require(bool(re.fullmatch(r"[A-Za-z_][\w-]*", str(item))), "iam=attribute")
            else:
                raw = self.take()
                if raw == "each" or re.fullmatch(r"[A-Za-z_]\w*", raw) and raw not in {"true", "false", "null"}:
                    dynamic = self.reference(raw)
                    require(dynamic[1][0] == "each" or len(dynamic[1]) == 1, "iam=dynamic_index")
                    item = ("dynamic", dynamic[1])
                    self.take("]")
                    path.append(item)
                    continue
                item = raw if raw == "*" else json.loads(raw)
                require(type(item) is str or (type(item) is int and item == 0), "iam=index")
                if raw.startswith('"'):
                    item = ("key", item)
                self.take("]")
            path.append(item)
        return self.budget.node("ref", tuple(path))

    def call(self, name: str, depth: int) -> Expr:
        require(name in FUNCTIONS, "iam=function_unsupported")
        self.take("(")
        arguments = []
        while not self.peek(")"):
            arguments.append(self.expression(depth + 1))
            require(len(arguments) <= 64, "iam=argument_count")
            if not self.peek(")"):
                self.take(",")
        self.take(")")
        return self.budget.node("call", name, tuple(arguments))

    def string(self, lexeme: str, depth: int) -> Expr:
        raw, parts, offset = lexeme[1:-1], [], 0
        require("$${" not in raw and "%{" not in raw, "iam=template_unsupported")
        for match in re.finditer(r"\$\{([^{}]*)\}", raw):
            parts.append(json.loads('"' + raw[offset : match.start()] + '"'))
            nested = Parser(match[1], self.budget)
            parts.append(nested.expression(depth + 1))
            require(nested.index == len(nested.tokens), "iam=template_tail")
            offset = match.end()
        parts.append(json.loads('"' + raw[offset:] + '"'))
        require(not any("${" in item for item in parts if type(item) is str), "iam=template_tail")
        return self.budget.node("template", tuple(parts))


def parse(source: str, budget: Budget) -> Expr:
    parser = Parser(source, budget)
    result = parser.expression()
    require(parser.index == len(parser.tokens), "iam=expression_tail")
    return result


def pending(value: Any) -> bool:
    if isinstance(value, Pending):
        return True
    if type(value) in (list, tuple, dict):
        return any(pending(item) for item in (value.values() if type(value) is dict else value))
    return False


class Evaluator:
    def __init__(self, lookup: Any, budget: Budget):
        self.lookup, self.budget = lookup, budget

    def value(self, node: Expr, scope: dict[str, Any] | None = None, depth: int = 0) -> Any:
        self.budget.spend("steps")
        require(depth <= 24, "iam=evaluation_depth")
        environment = scope or {}
        kind = node[0]
        if kind == "literal":
            return node[1]
        if kind == "ref":
            return self.lookup(node[1], environment)
        if kind == "conditional":
            condition = self.value(node[1], environment, depth + 1)
            require(type(condition) is bool, "iam=conditional_unknown")
            return self.value(node[2] if condition else node[3], environment, depth + 1)
        if kind in {"object", "list"}:
            return self.container(node, environment, depth + 1)
        if kind == "call":
            if node[1] == "try":
                # Exactly the source API-role parser; this is not a generic exception bypass.
                expected = ('call', 'try', (('call', 'element', (('call', 'reverse', (('call', 'split', (('template', ('/',)), ('ref', ('var', 'runtime_grants', 'api_role_arn')))),)), ('literal', 0))), ('literal', None)))
                require(node == expected, "iam=try_scope")
                try:
                    return self.value(node[2][0], environment, depth + 1)
                except DynamicError:
                    return None
            args = [self.value(value, environment, depth + 1) for value in node[2]]
            return function(node[1], args)
        handlers = {"binary": self.binary, "for": self.comprehension, "mapfor": self.comprehension, "template": self.template}
        require(kind in handlers, "iam=ast_unsupported")
        return handlers[kind](node, environment, depth + 1)

    def container(self, node: Expr, scope: Node, depth: int) -> Any:
        if node[0] == "object":
            return {key: self.value(value, scope, depth) for key, value in node[1]}
        return [self.value(value, scope, depth) for value in node[1]]

    def binary(self, node: Expr, scope: dict[str, Any], depth: int) -> Any:
        if node[1] in {"==", "!="} and node[3] == ("literal", None) and node[2][0] == "ref":
            # Source object presence is known without resolving its identity-valued leaves.
            result = self.lookup(node[2][1] + ("__null__",), scope)
            require(type(result) is bool, "iam=null_comparison")
            return result if node[1] == "==" else not result
        operator, left = node[1], self.value(node[2], scope, depth)
        if operator == "||":
            require(type(left) is bool, "iam=boolean")
            if left:
                return True
        right = self.value(node[3], scope, depth)
        require(not pending(left) and not pending(right), "iam=condition_unknown")
        if operator == "||":
            require(type(right) is bool, "iam=boolean")
            return right
        if operator == "==":
            return left == right
        if operator == "!=":
            return left != right
        require(type(left) is int and type(right) is int, "iam=comparison")
        return left > right

    def comprehension(self, node: Expr, scope: dict[str, Any], depth: int) -> list[Any]:
        values = self.value(node[2], scope, depth)
        require(type(values) in (list, dict) and len(values) <= 64, "iam=iterations")
        items = values.items() if type(values) is dict else enumerate(values)
        mapping = node[0] == "mapfor"
        result: Any = {} if mapping else []
        for key, value in items:
            bindings = [value] if len(node[1]) == 1 else [key, value]
            current = scope | dict(zip(node[1], bindings, strict=True))
            condition = self.value(node[5] if mapping else node[4], current, depth + 1)
            require(type(condition) is bool, "iam=filter_unknown")
            if condition:
                if mapping:
                    key = self.value(node[3], current, depth + 1)
                    require(type(key) is str and key not in result, "iam=map_key")
                    result[key] = self.value(node[4], current, depth + 1)
                else:
                    result.append(self.value(node[3], current, depth + 1))
        return result

    def template(self, node: Expr, scope: dict[str, Any], depth: int) -> str | Pending:
        parts = [part if type(part) is str else self.value(part, scope, depth) for part in node[1]]
        if any(pending(part) for part in parts):
            return Pending("template")
        require(all(type(part) in (str, int) for part in parts), "iam=template_value")
        result = "".join(map(str, parts))
        require(len(result) <= 4096, "iam=string_length")
        return result


def function(name: str, args: list[Any]) -> Any:
    arity = {"jsonencode": 1, "trimsuffix": 2, "sort": 1, "length": 1, "one": 1,
             "replace": 3, "toset": 1, "split": 2, "reverse": 1, "element": 2, "keys": 1}
    require(name in FUNCTIONS and (name not in arity or len(args) == arity[name]), "iam=arity")
    if name == "length":
        require(type(args[0]) in (dict, list, str), "iam=length_type")
        return len(args[0])
    if pending(args):
        return Pending(name)
    if name == "jsonencode":
        return canonical_bytes(args[0], 65536).decode().rstrip("\n")
    if name == "trimsuffix":
        require(all(type(item) is str for item in args), "iam=trimsuffix_type")
        return args[0].removesuffix(args[1])
    if name in {"format", "replace", "toset", "split", "reverse", "element", "keys"}:
        return bootstrap_function(name, args)
    return collection_function(name, args)


def bootstrap_function(name: str, args: list[Any]) -> Any:
    if name == "format":
        require(bool(args) and all(type(item) is str for item in args), "iam=format_type")
        require('%' not in args[0].replace('%s', '') and args[0].count('%s') == len(args) - 1, "iam=format_scope")
        value = args[0] % tuple(args[1:])
        require(len(value) <= 4096, "iam=string_length")
        return value
    if name in {"replace", "split"}:
        if any(item is None for item in args):
            raise DynamicError("iam=null_string")
        require(all(type(item) is str for item in args), "iam=string_type")
        if name == "replace":
            require(not (len(args[1]) >= 2 and args[1].startswith('/') and args[1].endswith('/')), "iam=regex_replace_unsupported")
            value = args[0].replace(args[1], args[2])
            require(len(value) <= 4096, "iam=string_length")
            return value
        require(bool(args[0]), "iam=split_separator")
        result = args[1].split(args[0])
        require(len(result) <= 64, "iam=collection_size")
        return result
    if name == "keys":
        require(type(args[0]) is dict and len(args[0]) <= 64, "iam=keys_type")
        return sorted(args[0])
    require(type(args[0]) is list and len(args[0]) <= 64, "iam=collection_type")
    if name == "element":
        require(type(args[1]) is int and args[1] == 0, "iam=element_index")
        if not args[0]:
            raise DynamicError("iam=empty_element")
        return args[0][0]
    if name == "reverse":
        return list(reversed(args[0]))
    require(all(type(item) is str for item in args[0]), "iam=set_type")
    return sorted(set(args[0]))


def collection_function(name: str, args: list[Any]) -> Any:
    limit = 128 if name in {"sort", "setunion"} else 64
    require(all(type(item) is list and len(item) <= limit for item in args), "iam=collection_type")
    if name == "one":
        require(len(args[0]) <= 1, "iam=one_count")
        return args[0][0] if args[0] else None
    if name == "sort":
        require(all(type(item) is str for item in args[0]), "iam=sort_type")
        return sorted(args[0])
    result = [item for values in args for item in values]
    if name == "setunion":
        require(all(type(item) is str for item in result), "iam=set_type")
        result = list(dict.fromkeys(result))
    require(len(result) <= limit, "iam=collection_size")
    return result


def reference_sets(node: Expr, bound: tuple[str, ...] = ()) -> tuple[set[str], set[str]]:
    required, allowed = set(), set()
    if node[0] == "ref" and node[1][0] not in bound:
        value = ""
        for index, part in enumerate(node[1]):
            if part == "*":
                break
            if type(part) is tuple:
                if part[0] == "dynamic":
                    required.add(value)
                    first, second = reference_sets(("ref", part[1]), bound)
                    required |= first
                    allowed |= second
                    break
                value += "[" + json.dumps(part[1]) + "]"
            else:
                value += (
                    ("." if index else "") + part if type(part) is str else "[" + str(part) + "]"
                )
            if index:
                allowed.add(value)
        required.add(value)
    elif node[0] in {"for", "mapfor"}:
        pairs = [reference_sets(node[2], bound)]
        pairs += [reference_sets(item, bound + node[1]) for item in node[3:]]
        required = set().union(*(item[0] for item in pairs))
        allowed = set().union(*(item[1] for item in pairs))
    else:
        for part in node[1:]:
            for child in child_nodes(part):
                first, second = reference_sets(child, bound)
                required |= first
                allowed |= second
    return required, allowed


def child_nodes(value: Any) -> list[Expr]:
    kinds = {"ref", "for", "mapfor", "literal", "conditional", "binary", "call", "object", "list", "template"}
    if type(value) is not tuple:
        return []
    if value and type(value[0]) is str and value[0] in kinds:
        return [value]
    return [node for item in value for node in child_nodes(item)]


def source_blocks(data: bytes) -> list[tuple[str, str, str]]:
    require(len(data) <= 256 * 1024, "iam=source_size")
    text = data.decode("utf-8", "strict")
    # Descriptive output prose is never an expression or authority. Mask only
    # this static metadata assignment, preserving offsets; all other heredocs close.
    def description(match):
        require("${" not in match[0] and "%{" not in match[0], "iam=source_description_template")
        return "".join("\n" if character == "\n" else " " for character in match[0])
    text = re.sub(r"(?m)^\s*description\s*=\s*<<-?([A-Z][A-Z0-9_]*)\n[\s\S]*?^\s*\1\s*$", description, text)
    require("<<" not in text, "iam=source_heredoc")
    tokens = list(TOKEN.finditer(text))
    tokens = [
        lexeme
        for lexeme in tokens
        if not lexeme[0].isspace() and not lexeme[0].startswith(("#", "//", "/*"))
    ]
    blocks, depth, index = [], 0, 0
    kinds = {"resource": 2, "module": 1, "output": 1, "variable": 1, "locals": 0}
    while index < len(tokens):
        kind = tokens[index][0]
        if depth == 0 and kind in kinds:
            count = kinds[kind]
            labels = [json.loads(lexeme[0]) for lexeme in tokens[index + 1 : index + 1 + count]]
            start = index + count + 1
            require(start < len(tokens) and tokens[start][0] == "{", "iam=source_block")
            cursor, level = start + 1, 1
            while cursor < len(tokens) and level:
                level += (tokens[cursor][0] == "{") - (tokens[cursor][0] == "}")
                cursor += 1
            require(level == 0, "iam=source_braces")
            blocks.append(
                (kind, ".".join(labels), text[tokens[start].end() : tokens[cursor - 1].start()])
            )
            index = cursor
        else:
            depth += (kind == "{") - (kind == "}")
            require(depth >= 0, "iam=source_braces")
            index += 1
    require(depth == 0 and len(blocks) <= 512, "iam=source_blocks")
    return blocks


def attributes(body: str) -> Node:
    tokens = [
        lexeme
        for lexeme in TOKEN.finditer(body)
        if not lexeme[0].isspace() and not lexeme[0].startswith(("#", "//", "/*"))
    ]
    result, index, depth = {}, 0, 0
    while index < len(tokens):
        lexeme = tokens[index][0]
        if depth == 0 and index + 1 < len(tokens) and tokens[index + 1][0] == "=":
            key = json.loads(lexeme) if lexeme.startswith('"') else lexeme
            require(key not in result, "iam=source_duplicate_attribute")
            start, cursor, level = index + 2, index + 2, 0
            cursor, level = _attribute_end(body, tokens, start)
            require(cursor > start and level == 0, "iam=source_attribute")
            result[key] = body[tokens[start].start() : tokens[cursor - 1].end()]
            index = cursor
        else:
            depth += (lexeme == "{") - (lexeme == "}")
            index += 1
    return result


def _attribute_end(body: str, tokens: list[re.Match[str]], start: int) -> tuple[int, int]:
    cursor, level = start, 0
    while cursor < len(tokens):
        item = tokens[cursor][0]
        if (
            cursor > start
            and level == 0
            and "\n" in body[tokens[cursor - 1].end() : tokens[cursor].start()]
        ):
            break
        level += (item in {"{", "[", "("}) - (item in {"}", "]", ")"})
        require(level >= 0, "iam=source_attribute")
        cursor += 1
    return cursor, level
