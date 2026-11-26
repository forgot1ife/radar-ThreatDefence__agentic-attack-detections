#!/usr/bin/env python3
"""Check Sigma rules against sample events, offline.

    python3 tests/sigma/run_tests.py

Test events live in tests/sigma/fixtures/<rule file name without .yml>.jsonl, one JSON object per line:

    {"name": "what this case shows", "expected": true, "event": {"Image": "/usr/bin/nmap", "ParentImage": "/bin/zsh"}}

"event" uses the field names the rule itself uses (for process_creation: Image, CommandLine, ParentImage,
ParentCommandLine and so on). "expected" says whether the rule must match. Every file needs at least one event
that matches and one near miss that must not.

The rule is parsed by pySigma and its condition tree is evaluated here, so the test follows Sigma's own rules:
values match the whole field unless a modifier adds wildcards, and string matching ignores case. Every rule in
the repository is also evaluated once against an empty event, so a rule that uses something this evaluator
does not support fails the run instead of being skipped. Correlation rules are not evaluated.

Exit status is non-zero on any failure.
"""
import ipaddress
import json
import re
import sys
from pathlib import Path

import yaml
from sigma import conditions as C
from sigma import types as T
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL", msg)


def rule_files():
    folders = list(ROOT.glob("frameworks/*/sigma")) + [ROOT / "behaviors" / "sigma", ROOT / "general" / "sigma"]
    return sorted(p for d in folders for p in d.rglob("*.yml"))


def load_rule(path):
    """The detection rule in a file, or None when the file only holds correlation rules."""
    for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
        if doc and "correlation" not in doc:
            return SigmaRule.from_dict(doc)
    return None


def string_regex(value):
    parts = []
    for part in value.s:
        if isinstance(part, str):
            parts.append(re.escape(part))
        elif part == T.SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == T.SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            raise NotImplementedError(f"string part {part!r}")
    flags = re.DOTALL if isinstance(value, T.SigmaCasedString) else re.DOTALL | re.IGNORECASE
    return re.compile("".join(parts), flags)


def value_matches(value, actual):
    """One Sigma value against one event value."""
    if isinstance(value, T.SigmaExpansion):
        return any(value_matches(v, actual) for v in value.values)
    if isinstance(value, T.SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(value, T.SigmaString):
        return string_regex(value).fullmatch(str(actual)) is not None
    if isinstance(value, T.SigmaNumber):
        try:
            return float(actual) == float(value.number)
        except (TypeError, ValueError):
            return False
    if isinstance(value, T.SigmaBool):
        return bool(actual) == value.boolean
    if isinstance(value, T.SigmaRegularExpression):
        flags = 0
        for flag in value.flags:
            flags |= {"IGNORECASE": re.IGNORECASE, "MULTILINE": re.MULTILINE, "DOTALL": re.DOTALL}[flag.name]
        return re.search(str(value.regexp), str(actual), flags) is not None
    if isinstance(value, T.SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(value.cidr), strict=False)
        except ValueError:
            return False
    raise NotImplementedError(f"value type {type(value).__name__}")


def matches(node, event):
    if isinstance(node, C.ConditionAND):
        return all(matches(a, event) for a in node.args)
    if isinstance(node, C.ConditionOR):
        return any(matches(a, event) for a in node.args)
    if isinstance(node, C.ConditionNOT):
        return not matches(node.args[0], event)
    if isinstance(node, C.ConditionFieldEqualsValueExpression):
        actual = event.get(node.field)
        actuals = actual if isinstance(actual, list) else [actual]
        return any(value_matches(node.value, a) for a in actuals)
    raise NotImplementedError(f"condition type {type(node).__name__}")


def rule_matches(rule, event):
    return any(matches(cond.parsed, event) for cond in rule.detection.parsed_condition)


def main():
    rules = {}
    for path in rule_files():
        try:
            rule = load_rule(path)
            if rule is not None:
                rule_matches(rule, {})  # proves the evaluator supports everything the rule uses
                rules[path.stem] = rule
        except Exception as e:  # noqa: BLE001 - report every rule, then fail
            fail(f"{path.relative_to(ROOT).as_posix()}: cannot be evaluated: {type(e).__name__}: {e}")

    events = 0
    files = sorted(FIXTURES.glob("*.jsonl"))
    for f in files:
        rule = rules.get(f.stem)
        if rule is None:
            fail(f"{f.name}: no Sigma rule file is named {f.stem}.yml")
            continue
        seen = set()
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                case = json.loads(line)
                name, expected, event = case["name"], case["expected"], case["event"]
            except (ValueError, KeyError, TypeError) as e:
                fail(f"{f.name}:{n}: needs name, expected and event: {e}")
                continue
            if not isinstance(expected, bool) or not isinstance(event, dict):
                fail(f"{f.name}:{n}: expected must be true or false, and event an object")
                continue
            seen.add(expected)
            events += 1
            got = rule_matches(rule, event)
            if got != expected:
                fail(f"{f.name}:{n} {name!r}: expected {'a match' if expected else 'no match'}, got {'a match' if got else 'no match'}")
        if seen != {True, False}:
            fail(f"{f.name}: needs at least one event that matches and one that does not")

    print(f"{len(rules)} rules evaluated, {len(files)} with test events, {events} events checked")
    if failures:
        print(f"{len(failures)} failures")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
