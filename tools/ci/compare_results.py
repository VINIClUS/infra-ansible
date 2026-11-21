import argparse
import json
import sys
from pathlib import Path


def _load(directory):
    rows, duplicates = {}, []
    for line in (Path(directory) / "results.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["nodeid"] in rows:
            duplicates.append(row["nodeid"])
        rows[row["nodeid"]] = row
    return rows, duplicates


def _ground_truth(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return {line.strip() for line in lines if line.strip()}


def _id_problems(name, ids, expected):
    absent = [f"ids_ausentes dir={name} nodeid={nodeid}" for nodeid in sorted(expected - ids)]
    return absent + [f"ids_extras dir={name} nodeid={nodeid}" for nodeid in sorted(ids - expected)]


def _truth_problems(name, ids, truth):
    extras = [f"fora_da_verdade dir={name} nodeid={nodeid}" for nodeid in sorted(ids - truth)]
    absent = [f"ausente_da_verdade dir={name} nodeid={nodeid}" for nodeid in sorted(truth - ids)]
    return extras + absent


def _missing_problems(name, rows):
    return [
        f"missing dir={name} nodeid={nodeid}"
        for nodeid, row in sorted(rows.items())
        if row["outcome"] == "missing"
    ]


def _value_problems(reference, other, field):
    problems = []
    for nodeid in sorted(set(reference) & set(other)):
        left, right = reference[nodeid].get(field), other[nodeid].get(field)
        if left != right:
            problems.append(f"{field}_diferente nodeid={nodeid} left={left} right={right}")
    return problems


def _unique_by_path(directories):
    unique, problems = {}, []
    for path in directories:
        key = str(Path(path).resolve())
        if key in unique:
            problems.append(f"diretorio_repetido dir={path}")
        else:
            unique[key] = path
    return list(unique.values()), problems


def compare(directories, truth=None):
    unique, problems = _unique_by_path(directories)
    loaded = {path: _load(path) for path in unique}
    reports = {name: rows for name, (rows, _) in loaded.items()}
    for name, (rows, duplicates) in loaded.items():
        problems += [f"nodeid_duplicado dir={name} nodeid={nodeid}" for nodeid in duplicates]
        problems += [f"relatorio_vazio dir={name}"] if not rows else []
    names = list(reports)
    union = set().union(*(set(rows) for rows in reports.values()))
    for name in names:
        ids = set(reports[name])
        problems += _id_problems(name, ids, union)
        problems += _missing_problems(name, reports[name])
        if truth is not None:
            problems += _truth_problems(name, ids, truth)
    reference = reports[names[0]]
    for name in names[1:]:
        problems += _value_problems(reference, reports[name], "outcome")
        problems += _value_problems(reference, reports[name], "skip_reason")
    return problems, len(union), len(reports)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("directories", nargs="+")
    parser.add_argument("--ground-truth")
    args = parser.parse_args(argv)
    truth = _ground_truth(args.ground_truth) if args.ground_truth else None
    problems, count, dirs = compare(args.directories, truth)
    for problem in problems:
        print(problem)
    if problems:
        print(f"compare_failed problems={len(problems)}")
        return 1
    print(f"compare_ok ids={count} dirs={dirs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
