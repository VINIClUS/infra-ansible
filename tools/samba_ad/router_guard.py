"""Prove the loaded nft router matrix and precedence, bound to a reviewed fingerprint.

--fingerprint reads nft JSON and emits its semantic SHA256 (counter values and
kernel handles excluded). Verification never trusts the on-disk hash alone.
"""
import hashlib
import ipaddress
import json
import re
import sys


def require(ok, field):
    if not ok:
        raise ValueError("S1 router runtime proof: " + field)


def normalize(value):
    if isinstance(value, list): return [normalize(x) for x in value]
    if not isinstance(value, dict): return value
    result = {}
    for key, item in value.items():
        if key == "counter" and isinstance(item, dict):
            item = {k: v for k, v in item.items() if k not in ["packets", "bytes"]}
        result[key] = normalize(item)
    return result


def semantic_ruleset(data):
    items = []
    for entry in data["nftables"]:
        if set(entry) == {"metainfo"}: continue
        copied = normalize(entry)
        for kind in ["table", "chain", "rule", "set", "map", "counter"]:
            if kind in copied:
                for field in ["handle", "index", "position"]: copied[kind].pop(field, None)
                if kind == "counter":
                    for field in ["packets", "bytes"]: copied[kind].pop(field, None)
        items.append(copied)
    return items


def fingerprint(data):
    return hashlib.sha256(json.dumps(semantic_ruleset(data), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def exact_address(value):
    if isinstance(value, dict) and set(value) == {"prefix"}:
        value = str(value["prefix"]["addr"]) + "/" + str(value["prefix"]["len"])
    require(isinstance(value, str), "address shape")
    address = ipaddress.ip_network(value if "/" in value else value + "/32")
    require(address.version == 4 and address.prefixlen == 32, "exact IPv4 endpoint")
    return str(address)


def port(value):
    if isinstance(value, dict) and set(value) == {"range"}:
        value = "-".join(str(x) for x in value["range"])
    value = str(value)
    require(re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", value), "port shape")
    parts = [int(x) for x in value.split("-")]
    require(1 <= min(parts) <= max(parts) <= 65535 and parts == sorted(parts), "port bounds")
    return value


def allow_rule(expr):
    result = {}; accepted = False
    for item in expr:
        if item == {"accept": None}:
            require(not accepted, "duplicate accept"); accepted = True; continue
        require(set(item) == {"match"} and not accepted, "unexpected matrix effect/order")
        match = item["match"]
        require(set(match) == {"op", "left", "right"} and match["op"] == "==", "matrix match")
        left, right = match["left"], match["right"]
        if left == {"meta": {"key": "iifname"}}: key, value = "iif", right
        elif left == {"meta": {"key": "oifname"}}: key, value = "oif", right
        elif left == {"payload": {"protocol": "ip", "field": "saddr"}}: key, value = "source", exact_address(right)
        elif left == {"payload": {"protocol": "ip", "field": "daddr"}}: key, value = "destination", exact_address(right)
        else:
            require(isinstance(left, dict) and set(left) == {"payload"}, "unknown matrix predicate")
            payload = left["payload"]
            require(payload in [{"protocol": "tcp", "field": "dport"}, {"protocol": "udp", "field": "dport"}]
                    and "proto" not in result, "protocol/port predicate")
            result["proto"] = payload["protocol"]; key, value = "port", port(right)
        require(key not in result, "duplicate matrix predicate"); result[key] = value
    require(accepted and set(result) == {"iif", "oif", "source", "destination", "proto", "port"}, "incomplete exact rule")
    return result


def safe_prefix(expr):
    expr = [item for item in expr if set(item) != {"counter"}]
    if len(expr) == 2 and expr[-1] == {"accept": None} and set(expr[0]) == {"match"}:
        match = expr[0]["match"]; states = match.get("right")
        if isinstance(states, dict) and set(states) == {"set"}: states = states["set"]
        return (match.get("left") == {"ct": {"key": "state"}} and match.get("op") in ["==", "in"]
                and isinstance(states, list) and set(states) == {"established", "related"})
    if len(expr) >= 2 and expr[-1] == {"drop": None}:
        return all(set(item) == {"match"} for item in expr[:-1])
    if expr and set(expr[-1]) == {"mangle"}:
        mangle = expr[-1]["mangle"]
        return (mangle.get("key") == {"tcp option": {"name": "maxseg", "field": "size"}}
                and type(mangle.get("value")) is int and all(set(item) == {"match"} for item in expr[:-1]))
    return False


def verify(data, contract, approved_sha256, zone):
    require(isinstance(approved_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", approved_sha256)
            and fingerprint(data) == approved_sha256, "stale or unapproved loaded ruleset")
    require(re.fullmatch(r"[a-z][a-z0-9]{0,15}", zone) and set(contract) == {"interface", "rules"}, "contract fields")
    interface = contract["interface"]; own = "restricted_" + zone
    require(re.fullmatch(r"eth[1-9]", interface), "restricted interface")
    chains = {}; rules = {}
    for entry in semantic_ruleset(data):
        if "chain" in entry:
            chain = entry["chain"]
            if chain.get("family") == "inet" and chain.get("table") == "filter":
                require(chain["name"] not in chains, "duplicate chain")
                chains[chain["name"]] = chain; rules[chain["name"]] = []
        if "rule" in entry:
            rule = entry["rule"]
            if rule.get("family") == "inet" and rule.get("table") == "filter":
                require(rule["chain"] in rules, "rule without declared chain")
                rules[rule["chain"]].append(rule["expr"])
    require(chains.get("forward", {}).get("hook") == "forward" and chains["forward"].get("type") == "filter"
            and chains["forward"].get("prio") == 0 and chains["forward"].get("policy") == "drop"
            and own in chains and "hook" not in chains[own], "active inet forward hook")
    wanted_jumps = [[{"match": {"op": "==", "left": {"meta": {"key": key}}, "right": interface}},
                     {"jump": {"target": own}}] for key in ["iifname", "oifname"]]
    indices = [i for i, expr in enumerate(rules["forward"]) if any(item.get("jump", {}).get("target") == own
               or item.get("goto", {}).get("target") == own for item in expr)]
    require(len(indices) == 2 and indices[1] == indices[0] + 1
            and [rules["forward"][i] for i in indices] == wanted_jumps, "exact interface jumps")
    require(all(safe_prefix(expr) for expr in rules["forward"][:indices[0]]), "permissive path before restriction")
    expected = []
    for flow in contract["rules"]:
        require(set(flow) == {"iif", "oif", "source", "destination", "proto", "port"}
                and interface in [flow["iif"], flow["oif"]] and flow["iif"] != flow["oif"]
                and flow["proto"] in ["tcp", "udp"], "approved exact matrix")
        expected.append({**flow, "source": exact_address(flow["source"]), "destination": exact_address(flow["destination"]),
                         "port": port(flow["port"])})
    actual = rules[own]
    require(len(actual) == len(expected) + 1 and actual[-1] == [{"counter": {}}, {"drop": None}], "terminal drop/order")
    require([allow_rule(expr) for expr in actual[:-1]] == expected, "stale/broader loaded matrix")


def main():
    try:
        data = json.load(sys.stdin)
        if "--fingerprint" in sys.argv: print(fingerprint(data))
        else:
            verify(data["runtime"], data["contract"], data["sha256"], data["zone"])
            print('{"verified":true}')
        return 0
    except (ValueError, TypeError, KeyError, IndexError):
        print("S1 loaded router proof failed; values suppressed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
