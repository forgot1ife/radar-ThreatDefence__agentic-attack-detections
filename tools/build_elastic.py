#!/usr/bin/env python3
"""Build the Elastic Security import: every rule in one NDJSON file, and the indicators to match them against.

    python3 tools/build_elastic.py                  # write generated/elastic_ndjson/
    python3 tools/build_elastic.py --check         # rebuild in memory, fail if the committed files differ

Reads:
    frameworks/*/sigma/, behaviors/sigma/, general/sigma/   every Sigma rule as a Lucene query rule, and every Sigma correlation
                                              as an ES|QL rule, both on ECS field names (tools/convert.py ecs())
    frameworks/artex/elastic/rules/           the hand-written ARTEX rules, read as Kibana rule objects
    iocs/indicators.csv                       the indicators for the indicator match rule

Writes:
    generated/elastic_ndjson/agentic-attack-detections.ndjson
        One line per rule, each disabled, carrying its severity, risk score, ATT&CK techniques, references and the
        file it came from. Import: Security > Rules > Import, or POST /api/detection_engine/rules/_import.
    generated/elastic_ndjson/agentic-attack-indicators.ndjson
        The medium and high confidence addresses, domains, URLs and file hashes as ECS threat.indicator documents,
        in _bulk format for the data stream INDICATORS. The indicator match rule in the rules file reads them.

The index patterns are one setting: INDEX below, ECS defaults. Output is deterministic: the same commit gives the
same bytes.
"""
import argparse
import copy
import json
import re
import sys
import tomllib
import uuid
from pathlib import Path

from sigma.backends.elasticsearch import ESQLBackend, LuceneBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from convert import SIGMA_DIRS, convert_one, ecs, rel_of  # noqa: E402
import build_feeds  # noqa: E402
import attack  # noqa: E402

NAME = "agentic-attack-detections"
OUT = ROOT / "generated" / "elastic_ndjson"
RULES = OUT / f"{NAME}.ndjson"
IOCS = OUT / "agentic-attack-indicators.ndjson"
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"

# Where the data lands: ECS defaults, plus the beats' own indices.
INDEX = ["logs-*", "filebeat-*", "winlogbeat-*", "packetbeat-*"]
# The indicators go to a data stream under logs-ti_*, the threat index Elastic Security reads by default.
INDICATORS = "logs-ti_agentic_attacks-default"
TAGS = ["Agentic Attack Detections"]

# Kibana's severity values and default risk scores. Kibana accepts low, medium, high and critical only.
LEVEL = {"informational": ("low", 21), "low": ("low", 21), "medium": ("medium", 47),
         "high": ("high", 73), "critical": ("critical", 99)}


def link(path):
    return f"{REPO}/blob/main/{path.relative_to(ROOT).as_posix()}"


def threat(tags):
    """Kibana's threat field from the rule's ATT&CK tags, named from the release pinned in tools/attack-enterprise.json
    so the import does not depend on the ATT&CK copy pySigma downloads."""
    names = [str(t) for t in tags]
    ids = [n.split(".", 1)[1].upper() for n in names if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", n, re.I)]
    tactics = [n.split(".", 1)[1] for n in names if n.lower().startswith("attack.")]
    return attack.elastic_threat(ids, tactics)


def common(rule, path):
    level = rule.level.name.lower() if rule.level else "medium"
    severity, risk = LEVEL[level]
    return {
        "rule_id": str(rule.id),
        "name": rule.title,
        "description": (rule.description or rule.title).strip(),
        "severity": severity,
        "risk_score": risk,
        "enabled": False,
        "author": [a.strip() for a in (rule.author or "ThreatDefence").split(",") if a.strip()],
        "references": list(rule.references or []),
        "false_positives": list(rule.falsepositives or []),
        "threat": threat(rule.tags),
        "tags": TAGS + [f"Source: {rel_of(path)}"],
        "from": "now-9m",
        "interval": "5m",
        "max_signals": 100,
        "note": link(path),
    }


def first_conversion(backend, collection):
    for pipe in (ecs(), None):
        try:
            out = convert_one(backend, pipe, copy.deepcopy(collection))
        except Exception:  # noqa: BLE001 - the next pipeline may map what this one could not
            continue
        if out:
            return out
    return None


def esql_from(query):
    """Sigma's ES|QL starts FROM *; a detection rule reads the same indices as the query rules."""
    return re.sub(r"^from \* metadata _id, _index, _version", "from " + ", ".join(INDEX) + " metadata _id, _index, _version",
                  query, count=1)


def from_sigma():
    """Every Sigma rule as a query rule, and every correlation as an ES|QL rule.

    A rule that only feeds a correlation (generate: false) is not a detection on its own, so it is left out; its
    correlation carries it.
    """
    files = sorted(p for d in SIGMA_DIRS for p in d.rglob("*.yml"))
    for rule in SigmaCollection.load_ruleset([str(p) for p in files]).rules:
        path = Path(str(rule.source.path))
        if isinstance(rule, SigmaCorrelationRule):
            out = first_conversion(ESQLBackend, SigmaCollection([r.rule for r in rule.rules] + [rule]))
            if not out:
                raise SystemExit(f"{rel_of(path)}: correlation has no ES|QL conversion")
            yield {**common(rule, path), "type": "esql", "language": "esql", "query": esql_from(out[-1])}
            continue
        if getattr(rule, "_output", True) is False:
            continue
        out = first_conversion(LuceneBackend, SigmaCollection([rule]))
        if not out:
            print(f"skip (no Elastic conversion): {rel_of(path)} {rule.title}")
            continue
        yield {**common(rule, path), "type": "query", "language": "lucene", "query": out[0], "index": INDEX,
               "timestamp_override": "event.ingested"}


def from_toml():
    """The hand-written ARTEX rules are already Kibana rule objects, one file each."""
    for path in sorted(ROOT.glob("frameworks/*/elastic/rules/*.toml")):
        rule = tomllib.loads(path.read_text(encoding="utf-8"))["rule"]
        rule.update(enabled=False, note=link(path))
        rule["tags"] = TAGS + [t for t in rule.get("tags", []) if t not in TAGS]
        if rule.get("type") != "esql":
            rule.setdefault("index", INDEX)
        rule.setdefault("from", "now-9m")
        rule.setdefault("interval", "5m")
        rule.setdefault("max_signals", 100)
        yield rule


# ----- indicators --------------------------------------------------------------------------------------------------

# indicators.csv type -> (threat.indicator.type, the threat.indicator field that holds the value)
IOC_FIELDS = {
    "ipv4": ("ipv4-addr", "threat.indicator.ip"),
    "ipv6": ("ipv6-addr", "threat.indicator.ip"),
    "domain": ("domain-name", "threat.indicator.url.domain"),
    "url": ("url", "threat.indicator.url.full"),
    "sha256": ("file", "threat.indicator.file.hash.sha256"),
    "md5": ("file", "threat.indicator.file.hash.md5"),
}

# Event field -> indicator field. Each entry is its own OR branch of the indicator match.
IOC_MAPPING = [
    ("source.ip", "threat.indicator.ip"),
    ("destination.ip", "threat.indicator.ip"),
    ("dns.question.name", "threat.indicator.url.domain"),
    ("url.domain", "threat.indicator.url.domain"),
    ("destination.domain", "threat.indicator.url.domain"),
    ("url.full", "threat.indicator.url.full"),
    ("url.original", "threat.indicator.url.full"),
    ("file.hash.sha256", "threat.indicator.file.hash.sha256"),
    ("process.hash.sha256", "threat.indicator.file.hash.sha256"),
    ("file.hash.md5", "threat.indicator.file.hash.md5"),
    ("process.hash.md5", "threat.indicator.file.hash.md5"),
]


def indicator_rows():
    """The rows the plain feeds carry: medium and high confidence, addresses not past their review date."""
    rows = [r for r in build_feeds.load()
            if r["type"] in IOC_FIELDS and r["confidence"] != "low" and build_feeds.active_ip(r)]
    return sorted(rows, key=lambda r: (r["type"], r["value"]))


def indicator_docs():
    for r in indicator_rows():
        kind, field = IOC_FIELDS[r["type"]]
        doc = {
            "@timestamp": f"{r['reported']}T00:00:00Z",
            "event.kind": "enrichment",
            "event.category": ["threat"],
            "event.type": ["indicator"],
            "threat.feed.name": "Agentic Attack Detections",
            "threat.feed.reference": REPO,
            "threat.indicator.type": kind,
            field: r["value"],
            "threat.indicator.confidence": r["confidence"].title(),
            "threat.indicator.description": r["context"],
            "threat.indicator.provider": r["source"],
            "threat.indicator.reference": r["source_url"],
            "threat.indicator.first_seen": f"{r['reported']}T00:00:00Z",
            "tags": build_feeds.fw_of(r),
        }
        if r.get("actor"):
            doc["threat.group.name"] = r["actor"]
        if r.get("review_by"):
            doc["threat.indicator.modified"] = f"{r['review_by']}T00:00:00Z"
        yield doc


def indicator_rule():
    """One indicator match rule over INDEX against the indicators in INDICATORS."""
    sources = sorted({src for src, _ in IOC_MAPPING})
    return {
        "rule_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{REPO}/indicator-match")),
        "name": "Agentic Attack Framework Indicator Match",
        "description": ("An event carries an address, domain, URL or file hash that public reporting ties to an agentic "
                        "attack framework (iocs/indicators.csv, medium and high confidence, addresses not past their "
                        "review date). Load generated/elastic_ndjson/agentic-attack-indicators.ndjson into "
                        f"{INDICATORS} first. Addresses from cloud and VPS providers are reassigned: check the "
                        "indicator's description and date before acting."),
        "severity": "high",
        "risk_score": 73,
        "enabled": False,
        "author": ["ThreatDefence"],
        "references": [f"{REPO}/blob/main/iocs/indicators.csv"],
        "false_positives": ["Reassigned cloud and VPS addresses", "Shared hosting behind a reported domain"],
        "tags": TAGS + ["Source: iocs/indicators.csv", "Rule Type: Indicator Match"],
        # As the indicator sweeps: traffic in from a reported address is scanning, traffic out to one is C2.
        "threat": attack.elastic_threat(["T1071", "T1595"]),
        "type": "threat_match",
        "language": "kuery",
        "index": INDEX,
        "query": " or ".join(f"{f}:*" for f in sources),
        "threat_index": [INDICATORS],
        "threat_query": "@timestamp >= \"now-3650d\"",
        "threat_language": "kuery",
        "threat_indicator_path": "threat.indicator",
        "threat_mapping": [{"entries": [{"field": src, "type": "mapping", "value": dst}]} for src, dst in IOC_MAPPING],
        "from": "now-65m",
        "interval": "1h",
        "max_signals": 100,
        "timestamp_override": "event.ingested",
        "note": f"{REPO}/blob/main/tools/build_elastic.py",
    }


def build():
    hand = list(from_toml())
    # A hand-written rule replaces the Sigma rule of the same name (it reads the integration's own data stream).
    names = {r["name"] for r in hand}
    rules = sorted([*(r for r in from_sigma() if r["name"] not in names), *hand, indicator_rule()],
                   key=lambda r: r["rule_id"])
    rules = [{k: v for k, v in r.items() if k != "threat" or v} for r in rules]
    ids = [r["rule_id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise SystemExit("two rules share a rule_id; Kibana import would overwrite one with the other")
    for r in rules:
        if r["severity"] not in ("low", "medium", "high", "critical") or not isinstance(r["author"], list):
            raise SystemExit(f"{r['name']}: severity or author would fail the Kibana import")
    return "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rules).encode("utf-8")


def build_indicators():
    return "".join(json.dumps({"create": {}}) + "\n" + json.dumps(d, sort_keys=True, ensure_ascii=False) + "\n"
                   for d in indicator_docs()).encode("utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed files differ from a fresh build")
    args = ap.parse_args()
    files = {RULES: build(), IOCS: build_indicators()}
    counts = f"{files[RULES].count(b'\n')} rules, {files[IOCS].count(b'\n') // 2} indicators"
    if args.check:
        stale = [p for p, data in files.items() if not p.exists() or p.read_bytes() != data]
        if stale:
            raise SystemExit(f"{', '.join(p.relative_to(ROOT).as_posix() for p in stale)} stale: "
                             "run tools/build_elastic.py and commit")
        print(f"elastic import: {counts}, committed")
        return
    OUT.mkdir(parents=True, exist_ok=True)
    for path, data in files.items():
        path.write_bytes(data)
    print(f"{OUT.relative_to(ROOT).as_posix()}/: {counts}")


if __name__ == "__main__":
    main()
