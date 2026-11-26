#!/usr/bin/env python3
"""Run KQL hunts and analytics against sample rows in the Kusto emulator.

    docker run -d --name kusto -e ACCEPT_EULA=Y -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
    python3 tests/kql/run_tests.py

Test cases live in tests/kql/fixtures/<behaviors, general or framework>/<hunting or analytics>/<query file name>.jsonl,
one JSON object per line:

    {"name": "what this case shows", "expected": true,
     "rows": {"DnsEvents": [{"Computer": "{case}", "Name": "abc123.oast.fun"}]}}

"rows" gives the rows each table holds for this case. Columns left out are empty. The text {case} becomes an id that is
unique to the case, and the case counts as returned when that id appears anywhere in the query's results. Put {case} in
the columns the query groups or joins by, usually the device name, so one case cannot affect another. "_ago" on a
row is how long ago it happened (a KQL timespan such as "10m", the default) and fills Timestamp and TimeGenerated.

Every table the query names is replaced by the sample rows, with the columns of tools/kqlcheck/schema.json, so the
query runs as written. All the cases of a file run in one query. Every file needs a case that is returned and one
that is not.

Without an emulator the test is skipped. Pass --require to fail instead, and --wait SECONDS to wait for one to start.
The address is http://localhost:8080 or the KUSTO_EMULATOR_URL environment variable.

Exit status is non-zero on any failure.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
URL = os.environ.get("KUSTO_EMULATOR_URL", "http://localhost:8080").rstrip("/")
TIME_COLUMNS = ("Timestamp", "TimeGenerated")
failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL", msg)


def run_query(csl, timeout=120):
    """Rows of the first result table, each as a dict. Raises RuntimeError with Kusto's message on a query error."""
    body = json.dumps({"db": "NetDefaultDB", "csl": csl}).encode("utf-8")
    req = urllib.request.Request(URL + "/v1/rest/query", body, {"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            table = json.load(r)["Tables"][0]
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            text = json.loads(text)["error"]["@message"]
        except (ValueError, KeyError, TypeError):
            pass
        raise RuntimeError(text[:600]) from None
    columns = [c["ColumnName"] for c in table["Columns"]]
    return [dict(zip(columns, row)) for row in table["Rows"]]


def emulator_ready(wait):
    deadline = time.time() + wait
    while True:
        try:
            run_query("print 1", timeout=5)
            return True
        except (OSError, RuntimeError, ValueError, KeyError):
            if time.time() >= deadline:
                return False
            time.sleep(3)


def query_for(fixture):
    """The query a fixture file tests, found by its path under fixtures/."""
    scope, kind = fixture.parent.parent.name, fixture.parent.name
    base = ROOT / scope if scope in ("behaviors", "general") else ROOT / "frameworks" / scope
    if kind == "analytics":
        path = base / "sentinel" / "analytics" / (fixture.stem + ".yaml")
        return path, (yaml.safe_load(path.read_text(encoding="utf-8"))["query"] if path.exists() else None)
    path = base / "sentinel" / "hunting" / (fixture.stem + ".kql")
    return path, (path.read_text(encoding="utf-8") if path.exists() else None)


def literal(value, kql_type):
    """One cell of a datatable."""
    if kql_type == "dynamic":
        return "dynamic(null)" if value is None else f"dynamic({json.dumps(value)})"
    if value is None:
        return '""' if kql_type == "string" else f"{kql_type}(null)"
    if kql_type == "string":
        return json.dumps(str(value))  # KQL reads the same escapes inside double quotes
    if kql_type == "bool":
        return "true" if value else "false"
    if kql_type == "datetime":
        return f"datetime({value})"
    return f"{kql_type}({value})"


def table_statement(name, columns, rows):
    """let <table> = datatable(...)[...], with the time columns worked out from each row's _ago."""
    data = {c: t for c, t in columns.items() if c not in TIME_COLUMNS}
    header = ", ".join(f"['{c}']:{t}" for c, t in data.items()) + ", _ago:timespan"
    cells = []
    for row in rows:
        cells.append(", ".join(literal(row.get(c), t) for c, t in data.items()) + f", timespan({row.get('_ago', '10m')})")
    times = ", ".join(f"{c} = now() - _ago" for c in TIME_COLUMNS if c in columns)
    return (f"let {name} = datatable({header})[\n" + ",\n".join(cells) + "\n]"
            + (f" | extend {times}" if times else "") + " | project-away _ago;\n")


def fill(value, case_id):
    if isinstance(value, str):
        return value.replace("{case}", case_id)
    if isinstance(value, list):
        return [fill(v, case_id) for v in value]
    if isinstance(value, dict):
        return {k: fill(v, case_id) for k, v in value.items()}
    return value


def check(fixture, schema):
    name = fixture.relative_to(FIXTURES).as_posix()
    path, query = query_for(fixture)
    if query is None:
        fail(f"{name}: no query at {path.relative_to(ROOT).as_posix()}")
        return 0
    cases, rows = [], {}
    for n, line in enumerate(fixture.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
            title, expected, case_rows = case["name"], case["expected"], case["rows"]
        except (ValueError, KeyError, TypeError) as e:
            fail(f"{name}:{n}: needs name, expected and rows: {e}")
            continue
        if not isinstance(expected, bool) or not isinstance(case_rows, dict):
            fail(f"{name}:{n}: expected must be true or false, and rows an object of table names")
            continue
        case_id = f"case-{n:03d}-x"
        if "{case}" not in line:
            fail(f"{name}:{n}: no {{case}} in its rows, so the result cannot be tied to this case")
            continue
        for table, table_rows in case_rows.items():
            if table not in schema:
                fail(f"{name}:{n}: table {table} is not in tools/kqlcheck/schema.json")
                continue
            for row in table_rows:
                unknown = [c for c in row if c != "_ago" and c not in schema[table]]
                if unknown:
                    fail(f"{name}:{n}: {table} has no column {', '.join(unknown)}")
                rows.setdefault(table, []).append(fill(row, case_id))
        cases.append((n, title, expected, case_id))
    if {expected for _, _, expected, _ in cases} != {True, False}:
        fail(f"{name}: needs at least one case that is returned and one that is not")
    # Every table the query names gets a datatable, empty when no case has rows for it
    used = [t for t in schema if re.search(rf"\b{re.escape(t)}\b", query)]
    for table in rows:
        if table not in used:
            fail(f"{name}: has rows for {table}, which the query does not read")
    prefix = "".join(table_statement(t, schema[t], rows.get(t, [])) for t in used)
    try:
        result = json.dumps(run_query(prefix + query))
    except RuntimeError as e:
        # Kusto counts lines from the top of what it was sent: take off the sample tables to give the line in the query
        offset = prefix.count("\n")
        message = re.sub(r"line:position=(\d+):", lambda m: f"line:position={int(m.group(1)) - offset}:", str(e))
        fail(f"{name}: the query did not run: {message}")
        return len(cases)
    for n, title, expected, case_id in cases:
        got = case_id in result
        if got != expected:
            fail(f"{name}:{n} {title!r}: expected {'to be returned' if expected else 'not to be returned'}, "
                 f"{'was returned' if got else 'was not'}")
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description="Run KQL hunts and analytics against sample rows in the Kusto emulator.")
    parser.add_argument("--require", action="store_true", help="fail when no emulator answers, instead of skipping")
    parser.add_argument("--wait", type=int, default=0, metavar="SECONDS", help="wait this long for the emulator to start")
    args = parser.parse_args()
    files = sorted(FIXTURES.rglob("*.jsonl"))
    if not emulator_ready(args.wait):
        print(f"kql tests: {'FAIL' if args.require else 'skipped'} (no Kusto emulator at {URL})")
        sys.exit(1 if args.require else 0)
    schema = json.loads((ROOT / "tools" / "kqlcheck" / "schema.json").read_text(encoding="utf-8"))["tables"]
    cases = sum(check(f, schema) for f in files)
    print(f"{len(files)} queries run, {cases} cases checked")
    if failures:
        print(f"{len(failures)} failures")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
