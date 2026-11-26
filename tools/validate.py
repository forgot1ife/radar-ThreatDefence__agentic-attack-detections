#!/usr/bin/env python3
"""Validate everything in the repository. CI runs this on every push.

    pip install -r tools/requirements.txt
    python3 tools/validate.py

Checks:
    Sigma       pySigma parses every rule and correlation, ids are unique, no validator issues
    Sentinel    analytics YAML parses and has the required keys, hunts are non-empty
    KQL         every hunt and analytics query parses, and its tables and columns exist (when dotnet is installed)
    Elastic     TOML rules parse, rule_ids are unique, ES|QL files start with FROM, generated queries use ECS DNS and
                web fields, and the NDJSON import parses with every rule disabled
    Splunk      .conf files parse, every saved search ships disabled
    Suricata    SIDs are unique across both rule files
    YARA        rules compile (when yara-python is installed)
    Zeek        every Zeek package parses (when zeek is installed)
    osquery     pack is valid JSON
    Feeds       regenerating from iocs/indicators.csv changes nothing
"""
import configparser
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
errors = []


def err(msg):
    errors.append(msg)
    print("ERROR", msg)


def check_sigma():
    from sigma.collection import SigmaCollection
    from sigma.validators.core import validators
    from sigma.validation import SigmaValidator

    files = sorted(p for d in list(ROOT.glob("frameworks/*/sigma")) + [ROOT / "behaviors" / "sigma", ROOT / "general" / "sigma"] for p in d.rglob("*.yml"))
    coll = SigmaCollection.load_ruleset([str(p) for p in files])
    ids = [str(r.id) for r in coll.rules]
    if len(ids) != len(set(ids)):
        err("duplicate Sigma ids")
    v = SigmaValidator(validators.values())
    for issue in v.validate_rules(coll.rules):
        if issue.severity.name in ("HIGH", "MEDIUM"):
            err(f"sigma {issue.__class__.__name__}: {[str(r.source) for r in issue.rules]}")
    print(f"sigma: {len(files)} files parsed")


def check_sentinel():
    ids = []
    for p in sorted(ROOT.glob("*/**/sentinel/analytics/*.yaml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
        for k in ("id", "name", "severity", "query", "queryFrequency", "queryPeriod", "tactics", "kind"):
            if k not in d:
                err(f"{p.name}: missing {k}")
        ids.append(d.get("id"))
    if len(ids) != len(set(ids)):
        err("duplicate Sentinel analytics ids")
    hunts = sorted(ROOT.glob("*/**/sentinel/hunting/*.kql"))
    for p in hunts:
        if not re.search(r"^\s*[A-Za-z_(]", "\n".join(l for l in p.read_text(encoding="utf-8").splitlines() if not l.startswith("//")), re.M):
            err(f"{p.name}: no query body")
    print(f"sentinel: {len(hunts)} hunts")


def check_kql():
    """Parse every hunt and analytics query with Microsoft's Kusto.Language and check table and column names."""
    import shutil
    import tempfile
    if not shutil.which("dotnet"):
        print("kql: skipped (dotnet not installed)")
        return
    files = [str(p) for p in sorted(ROOT.glob("*/**/sentinel/hunting/*.kql"))]
    with tempfile.TemporaryDirectory() as tmp:
        for p in sorted(ROOT.glob("*/**/sentinel/analytics/*.yaml")):
            out = Path(tmp) / ("analytics__" + "__".join(p.relative_to(ROOT).parts).replace(".yaml", ".kql"))
            out.write_text(yaml.safe_load(p.read_text(encoding="utf-8"))["query"], encoding="utf-8")
            files.append(str(out))
        tool = ROOT / "tools" / "kqlcheck"
        r = subprocess.run(["dotnet", "run", "--project", str(tool), "-c", "Release", "--", str(tool / "schema.json"), *files],
                           capture_output=True, text=True)
    lines = [l.replace(str(ROOT) + "/", "") for l in r.stdout.strip().splitlines()]
    if r.returncode:
        err("kql:\n" + "\n".join(lines or [r.stderr.strip()[-2000:]]))
    else:
        print(lines[-1])


def check_elastic():
    ids = []
    for p in sorted(ROOT.glob("frameworks/*/elastic/rules/*.toml")):
        d = tomllib.loads(p.read_text(encoding="utf-8"))
        ids.append(d["rule"]["rule_id"])
    if len(ids) != len(set(ids)):
        err("duplicate Elastic rule_id")
    for p in sorted(ROOT.glob("frameworks/*/elastic/esql/*.esql")):
        body = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("//")]
        if not body or not body[0].upper().startswith("FROM"):
            err(f"{p.name}: ES|QL must start with FROM")
    sigma_fields = re.compile(r"(?<![\w.-])(QueryName|c-uri|cs-uri-query|cs-uri-stem|c-useragent|cs-user-agent|cs-host)(?![\w.-])")
    for p in sorted(ROOT.glob("generated/elastic_*/**/*.txt")):
        query = "\n".join(l for l in p.read_text(encoding="utf-8").splitlines() if not l.startswith("#"))
        found = sorted(set(sigma_fields.findall(query)))
        if found:
            err(f"{p.relative_to(ROOT).as_posix()}: Sigma field names instead of ECS: {', '.join(found)}")
    ndjson = ROOT / "generated" / "elastic_ndjson" / "agentic-attack-detections.ndjson"
    imported = [json.loads(line)["rule_id"] for line in ndjson.read_text(encoding="utf-8").splitlines()]
    if len(imported) != len(set(imported)):
        err("duplicate rule_id in generated/elastic_ndjson/")
    for line in ndjson.read_text(encoding="utf-8").splitlines():
        if json.loads(line).get("enabled") is not False:
            err(f"Elastic import rule not disabled: {json.loads(line).get('name')}")
    print(f"elastic: {len(ids)} rules, {len(imported)} in the NDJSON import")


def check_splunk():
    for p in sorted(ROOT.glob("frameworks/*/splunk/default/*.conf")) + sorted(ROOT.glob("deploy/splunk/*/default/*.conf")):
        cp = configparser.RawConfigParser(strict=False, interpolation=None)
        cp.optionxform = str
        cp.read_string(re.sub(r"\\\n", " ", p.read_text(encoding="utf-8")))
        if p.name == "savedsearches.conf":
            for s in cp.sections():
                if cp.get(s, "disabled", fallback="0").strip() != "1":
                    err(f"saved search not disabled: {s}")
            print(f"splunk: {len(cp.sections())} saved searches in {p.relative_to(ROOT).parts[0]}/")


def check_suricata():
    sids = []
    for p in sorted(ROOT.glob("*/**/suricata/*.rules")):
        sids += re.findall(r"\bsid:(\d+);", p.read_text(encoding="utf-8"))
    dup = {s for s in sids if sids.count(s) > 1}
    if dup:
        err(f"duplicate suricata sids {sorted(dup)}")
    print(f"suricata: {len(sids)} rules")


def check_yara():
    try:
        import yara
    except ImportError:
        print("yara: skipped (yara-python not installed)")
        return
    for p in sorted(ROOT.glob("*/**/yara/*.yar")):
        yara.compile(filepath=str(p))
    print("yara: compiled")


def check_zeek():
    import shutil
    if not shutil.which("zeek"):
        print("zeek: skipped (zeek not installed)")
        return
    pkgs = sorted(p.parent for p in ROOT.glob("*/**/zeek/*/__load__.zeek"))
    for pkg in pkgs:
        r = subprocess.run(["zeek", "-a", str(pkg)], capture_output=True, text=True)
        if r.returncode or r.stderr.strip():
            err(f"zeek {pkg.relative_to(ROOT)}: {r.stderr.strip()}")
    print(f"zeek: {len(pkgs)} packages parsed")


def check_osquery():
    for p in sorted(ROOT.glob("frameworks/*/osquery/*.conf")):
        json.loads(p.read_text(encoding="utf-8"))
    print("osquery: json ok")


def check_feeds():
    subprocess.run([sys.executable, str(ROOT / "tools" / "build_feeds.py")], check=True, capture_output=True)
    try:
        diff = subprocess.run(["git", "status", "--porcelain", "feeds", "frameworks"],
                              cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("feeds: rebuilt (not a git checkout, drift not checked)")
        return
    if diff:
        err("feeds are out of date with iocs/indicators.csv: run tools/build_feeds.py and commit\n" + diff)
    else:
        print("feeds: up to date")


for check in (check_sigma, check_sentinel, check_kql, check_elastic, check_splunk, check_suricata, check_yara, check_zeek, check_osquery, check_feeds):
    try:
        check()
    except Exception as exc:  # noqa: BLE001
        err(f"{check.__name__}: {type(exc).__name__}: {exc}")

if errors:
    print(f"\n{len(errors)} error(s)")
    sys.exit(1)
print("\nall checks passed")
