#!/usr/bin/env python3
"""Build ARM templates that deploy the Microsoft Sentinel content in one step.

    python3 tools/build_sentinel.py            # write deploy/sentinel/*.json
    python3 tools/build_sentinel.py --check    # rebuild in memory, validate, fail if deploy/sentinel/ differs

Reads frameworks/*/sentinel/, behaviors/sentinel/ and general/sentinel/:
    analytics/*.yaml   -> Microsoft.SecurityInsights/alertRules (kind Scheduled): query, frequency, period,
                          threshold, severity, tactics, techniques and entity mappings when the file has them
    hunting/*.kql      -> Microsoft.OperationalInsights/workspaces/savedSearches in the "Hunting Queries" category,
                          title and description from the file header
    feeds/sentinel-watchlist.csv -> Microsoft.SecurityInsights/watchlists, alias AGENTIC_IOCs, search key "value"

Writes deploy/sentinel/agentic-attack-detections.json (everything) and one template per framework (plus
behaviors.json for the AI agent behaviors and general.json for the general intrusion rules). Every template carries the whole watchlist under the same alias,
so deploying several of them leaves one complete watchlist. Parameters: workspace (name of the Log Analytics
workspace with Microsoft Sentinel on, in the resource group you deploy to) and enableRules (false by default).

Output is deterministic: the same commit gives the same bytes. Needs PyYAML (in tools/requirements.txt).
"""
import argparse
import csv
import io
import json
import re
import sys
import uuid
from pathlib import Path

import yaml

import attack
import build_attack

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "deploy" / "sentinel"
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"
RAW = "https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main"
NAME = "agentic-attack-detections"
WATCHLIST_ALIAS = "AGENTIC_IOCs"
API_SI = "2024-03-01"
API_SAVED = "2020-08-01"
NS = uuid.UUID("6f1c5a8e-3c2b-4f4e-9a57-2f0d8b1c7e11")  # fixed namespace: stable ids for hunting queries

TACTICS = {"Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation",
           "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement", "Collection", "Exfiltration",
           "CommandAndControl", "Impact", "PreAttack", "ImpairProcessControl", "InhibitResponseFunction"}
# MITRE ATT&CK technique -> the Microsoft Sentinel tactics it belongs to. Sentinel refuses a rule whose technique has
# none of its tactics in the rule's tactics field, so the builder checks the same. Add a technique here when a rule
# uses a new one (Enterprise ATT&CK, tactic names as Microsoft Sentinel spells them).
TECHNIQUE_TACTICS = {
    "T1036": {"DefenseEvasion"},
    "T1041": {"Exfiltration"},
    "T1046": {"Discovery"},
    "T1053": {"Execution", "Persistence", "PrivilegeEscalation"},
    "T1059": {"Execution"},
    "T1071": {"CommandAndControl"},
    "T1078": {"DefenseEvasion", "Persistence", "PrivilegeEscalation", "InitialAccess"},
    "T1098": {"Persistence", "PrivilegeEscalation"},
    "T1110": {"CredentialAccess"},
    "T1136": {"Persistence"},
    "T1190": {"InitialAccess"},
    "T1213": {"Collection"},
    "T1219": {"CommandAndControl"},
    "T1505": {"Persistence"},
    "T1543": {"Persistence", "PrivilegeEscalation"},
    "T1546": {"Persistence", "PrivilegeEscalation"},
    "T1547": {"Persistence", "PrivilegeEscalation"},
    "T1552": {"CredentialAccess"},
    "T1562": {"DefenseEvasion"},
    "T1580": {"Discovery"},
    "T1592": {"Reconnaissance"},
    "T1595": {"Reconnaissance"},
    "T1611": {"PrivilegeEscalation"},
}
# Techniques newer than Microsoft Sentinel's ATT&CK list. Sentinel refuses an analytics rule that names one, whatever
# its tactics ("No valid tactic corresponding to the technique T1699 was provided in the tactics field", seen in the
# lab on November 25, 2026, with each of its tactics), so the templates leave them out of relevantTechniques. The rule
# file, the coverage page, Sigma, Splunk, Elastic and the hunting query tags keep them.
SENTINEL_UNKNOWN = {"T1699"}
TAG_MAX = 256  # Log Analytics refuses a saved search whose tag value is longer (seen: 239 accepted, 260 refused)
OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
SEVERITIES = {"High", "Medium", "Low", "Informational"}
WS_SCOPE = "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspace'))]"


def iso_duration(value):
    """'1h' -> 'PT1H', '30m' -> 'PT30M', '1d' -> 'P1D'."""
    m = re.fullmatch(r"(\d+)([mhd])", str(value).strip())
    if not m:
        raise ValueError(f"duration {value!r} is not like 30m, 1h or 1d")
    n, unit = m.groups()
    return f"P{n}D" if unit == "d" else f"PT{n}{unit.upper()}"


def sources():
    """[(framework, folder)], AI agent behaviors and general intrusion first, then frameworks in name order."""
    out = [(s, ROOT / s / "sentinel") for s in ("behaviors", "general") if (ROOT / s / "sentinel").is_dir()]
    out += [(p.parent.name, p) for p in sorted(ROOT.glob("frameworks/*/sentinel")) if p.is_dir()]
    return out


def hunt_header(text):
    """Title = first comment line; description = the header comment block after the attribution line."""
    lines = text.splitlines()
    comments = []
    for line in lines:
        if not line.startswith("//"):
            break
        comments.append(line[2:].strip())
    if not comments:
        raise ValueError("no header comment")
    title = comments[0]
    body = [c for c in comments[1:] if not c.startswith(("Agentic attack detections by ThreatDefence", "ATT&CK:"))]
    desc = " ".join(c.lstrip("- ").strip() for c in body if c).strip()
    return title, shorten(desc, TAG_MAX - 6)


def shorten(text, limit):
    """Cut at a word boundary under the limit; the full text stays in the query's header comments."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:(")
    return cut + "…"


def analytics_rule(path, framework):
    d = yaml.safe_load(path.read_text(encoding="utf-8"))
    techniques = [t for t in d.get("relevantTechniques", [])]
    props = {
        "displayName": d["name"],
        "description": d["description"].strip(),
        "severity": d["severity"],
        "enabled": "[parameters('enableRules')]",
        "query": d["query"].rstrip("\n"),
        "queryFrequency": iso_duration(d["queryFrequency"]),
        "queryPeriod": iso_duration(d["queryPeriod"]),
        "triggerOperator": OPERATORS[d["triggerOperator"]],
        "triggerThreshold": int(d["triggerThreshold"]),
        "suppressionEnabled": False,
        "suppressionDuration": "PT5H",
        "tactics": list(d.get("tactics", [])),
        # API 2024-03-01 stores parent techniques only (a subTechniques field is accepted and dropped, seen in a test
        # deployment), so sub-techniques such as T1059.004 are sent as their parent T1059.
        "techniques": sorted({t.split(".")[0] for t in techniques} - SENTINEL_UNKNOWN),
        "eventGroupingSettings": {"aggregationKind": d.get("eventGroupingSettings", {}).get("aggregationKind", "SingleAlert")},
        "incidentConfiguration": {"createIncident": True, "groupingConfiguration": {
            "enabled": False, "reopenClosedIncident": False, "lookbackDuration": "PT5H",
            "matchingMethod": "AllEntities", "groupByEntities": [], "groupByAlertDetails": [], "groupByCustomDetails": []}},
        # No templateVersion: Sentinel only accepts it next to alertRuleTemplateName (a Content Hub template), and a
        # rule saved with it alone cannot be edited or enabled in the portal (#23).
    }
    if d.get("entityMappings"):
        props["entityMappings"] = d["entityMappings"]
    if d.get("customDetails"):
        props["customDetails"] = d["customDetails"]
    if d.get("alertDetailsOverride"):
        props["alertDetailsOverride"] = d["alertDetailsOverride"]
    return {
        "type": "Microsoft.SecurityInsights/alertRules",
        "apiVersion": API_SI,
        "scope": WS_SCOPE,
        "name": str(uuid.UUID(d["id"])),
        "kind": "Scheduled",
        "properties": props,
        "_source": path.relative_to(ROOT).as_posix(),
        "_framework": framework,
    }


# Hunts that moved keep the id they were first deployed with, so a redeploy updates the saved search in place instead
# of adding a second copy. New path -> the path its id was made from. Add a line here when a hunt file moves.
MOVED_HUNTS = {
    "behaviors/sentinel/hunting/04-user-agent-family-burst-from-one-source.kql":
        "frameworks/artex/sentinel/hunting/17-user-agent-family-burst-from-one-source.kql",
    "behaviors/sentinel/hunting/05-password-spray-at-a-fixed-rhythm.kql":
        "frameworks/artex/sentinel/hunting/02-password-spray-at-a-fixed-rhythm.kql",
    "behaviors/sentinel/hunting/06-one-application-hitting-many-resources.kql":
        "frameworks/artex/sentinel/hunting/19-one-application-hitting-many-resources.kql",
    "behaviors/sentinel/hunting/07-azure-capability-checks-validate-sweeps-and-kudu-sign-ins.kql":
        "frameworks/artex/sentinel/hunting/15-azure-capability-checks-validate-sweeps-and-kudu-sign-ins.kql",
    "behaviors/sentinel/hunting/09-aws-permission-testing-and-the-foothold-that-follows.kql":
        "frameworks/artex/sentinel/hunting/14-aws-permission-testing-and-the-foothold-that-follows.kql",
    "general/sentinel/hunting/01-one-site-probed-through-rotating-proxies.kql":
        "behaviors/sentinel/hunting/04-one-site-probed-through-rotating-proxies.kql",
    "general/sentinel/hunting/02-config-backup-theft-and-wsus-probes.kql":
        "behaviors/sentinel/hunting/05-config-backup-theft-and-wsus-probes.kql",
    "general/sentinel/hunting/03-kerbrute-enumeration-and-netexec-fan-out.kql":
        "behaviors/sentinel/hunting/06-kerbrute-enumeration-and-netexec-fan-out.kql",
    "general/sentinel/hunting/04-server-calls-back-to-the-address-that-probed-it.kql":
        "behaviors/sentinel/hunting/07-server-calls-back-to-the-address-that-probed-it.kql",
    "general/sentinel/hunting/05-servers-resolving-out-of-band-testing-domains.kql":
        "behaviors/sentinel/hunting/09-servers-resolving-out-of-band-testing-domains.kql",
    "general/sentinel/hunting/06-a-spray-that-ends-in-a-successful-sign-in.kql":
        "frameworks/artex/sentinel/hunting/03-a-spray-that-ends-in-a-successful-sign-in.kql",
    "general/sentinel/hunting/07-service-principal-secret-failures-then-success.kql":
        "frameworks/artex/sentinel/hunting/18-service-principal-secret-failures-then-success.kql",
    "general/sentinel/hunting/08-applications-changing-their-own-access.kql":
        "frameworks/artex/sentinel/hunting/05-applications-changing-their-own-access.kql",
    "general/sentinel/hunting/09-bulk-key-vault-secret-reads.kql":
        "frameworks/artex/sentinel/hunting/07-bulk-key-vault-secret-reads.kql",
    "general/sentinel/hunting/10-cloudwatch-log-searches-with-a-stolen-aws-key.kql":
        "frameworks/artex/sentinel/hunting/08-cloudwatch-log-searches-with-a-stolen-aws-key.kql",
    "general/sentinel/hunting/11-cognito-sign-up-abuse-and-the-discovery-sweep-after-it.kql":
        "frameworks/artex/sentinel/hunting/09-cognito-sign-up-abuse-and-the-discovery-sweep-after-it.kql",
    "general/sentinel/hunting/12-web-and-database-services-starting-shells-and-download-tools.kql":
        "frameworks/artex/sentinel/hunting/11-web-and-database-services-starting-shells-and-download-tools.kql",
    "general/sentinel/hunting/13-scripts-written-into-web-directories.kql":
        "frameworks/artex/sentinel/hunting/13-scripts-written-into-web-directories.kql",
    "general/sentinel/hunting/14-servers-calling-webhook-and-tunnel-services.kql":
        "frameworks/artex/sentinel/hunting/12-servers-calling-webhook-and-tunnel-services-or-downloading-f.kql",
    "general/sentinel/hunting/15-kerberoasting-dcsync-and-winrm-fan-out.kql":
        "frameworks/artex/sentinel/hunting/16-kerberoasting-dcsync-and-winrm-fan-out.kql",
    "general/sentinel/hunting/16-scripted-microsoft-graph-bursts-by-an-application.kql":
        "frameworks/artex/sentinel/hunting/06-scripted-microsoft-graph-bursts-by-an-application.kql",
}


EXAMPLE = re.compile(r"^// Example: *(.+)$")


def split_examples(text):
    """A hunt file that holds several '// Example:' queries -> [(example title, query text)], each with the file's
    header comment block in front. A saved hunting query runs its whole text as one query, so two tabular
    expressions in one file would not parse. Files with one example or none come back whole: [(None, text)]."""
    lines = text.rstrip("\n").splitlines()
    starts = [i for i, line in enumerate(lines) if EXAMPLE.match(line)]
    if len(starts) < 2:
        return [(None, text.rstrip("\n"))]
    header = []
    for line in lines:
        if not line.startswith("//"):
            break
        header.append(line)
    if any(line.strip() and not line.startswith("//") for line in lines[len(header):starts[0]]):
        raise ValueError("statements before the first '// Example:' would be lost when splitting")
    parts = []
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        block = "\n".join(lines[start:end]).strip("\n")
        parts.append((EXAMPLE.match(lines[start]).group(1).strip(), "\n".join(header) + "\n\n" + block))
    return parts


def hunt_attack(text, rel):
    """The hunt's `// ATT&CK:` line as the tactics and techniques tags Microsoft Sentinel shows on a hunting query:
    tactic names as Sentinel spells them, and parent techniques, the form Sentinel stores for its own rules."""
    ids = build_attack.hunt_techniques(text)
    if not ids:
        raise SystemExit(f"{rel}: no // ATT&CK: line in the header comment")
    for tid, why in attack.problems(ids):
        raise SystemExit(f"{rel}: {tid} is {why}")
    tactics = sorted({attack.sentinel_tactic(s) for t in ids for s in attack.techniques()[t]["tactics"]})
    techniques = sorted({t.split(".")[0] for t in ids})
    return ",".join(tactics), ",".join(techniques)


def hunting_queries(path, framework):
    rel = path.relative_to(ROOT).as_posix()
    text = path.read_text(encoding="utf-8")
    title, desc = hunt_header(text)
    parts = split_examples(text)
    tactics, techniques = hunt_attack(text, rel)
    out = []
    for n, (example, query) in enumerate(parts, 1):
        id_rel = MOVED_HUNTS.get(rel, rel)
        key = id_rel if len(parts) == 1 else f"{id_rel}#{n}"
        name = title if example is None else f"{title}, part {n}: {example}"
        out.append({
            "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
            "apiVersion": API_SAVED,
            "name": f"[concat(parameters('workspace'), '/{uuid.uuid5(NS, key)}')]",
            "properties": {
                "category": "Hunting Queries",
                "displayName": f"{name} ({framework})",
                "query": query,
                "version": 2,
                "tags": [
                    {"name": "description", "value": desc},
                    {"name": "tactics", "value": tactics},
                    {"name": "techniques", "value": techniques},
                    {"name": "source", "value": f"{REPO}/blob/main/{rel}"},
                ],
            },
            "_source": rel if len(parts) == 1 else f"{rel} part {n}",
            "_framework": framework,
        })
    return out


def watchlist():
    raw = (ROOT / "feeds" / "sentinel-watchlist.csv").read_text(encoding="utf-8")
    return {
        "type": "Microsoft.SecurityInsights/watchlists",
        "apiVersion": API_SI,
        "scope": WS_SCOPE,
        "name": WATCHLIST_ALIAS,
        "properties": {
            "displayName": "Agentic attack detections indicators",
            "description": f"Indicators for agentic attack frameworks. Source: {REPO}/blob/main/feeds/sentinel-watchlist.csv",
            "provider": "Agentic attack detections",
            "source": "sentinel-watchlist.csv",
            "itemsSearchKey": "value",
            "contentType": "text/csv",
            "numberOfLinesToSkip": 0,
            "rawContent": raw,
        },
        "_source": "feeds/sentinel-watchlist.csv",
        "_framework": "*",
    }


def template(resources, title):
    clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in resources]
    n_rules = sum(r["type"].endswith("alertRules") for r in resources)
    n_hunts = sum(r["type"].endswith("savedSearches") for r in resources)
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": title,
            "description": f"{n_rules} analytics rules, {n_hunts} hunting queries and the {WATCHLIST_ALIAS} watchlist. "
                           f"Built by tools/build_sentinel.py from {REPO}",
        },
        "parameters": {
            "workspace": {"type": "string", "metadata": {
                "description": "Name of the Log Analytics workspace with Microsoft Sentinel on. It must be in the resource group you deploy to."}},
            "enableRules": {"type": "bool", "defaultValue": False, "metadata": {
                "description": "Start the analytics rules enabled. Off by default: review and baseline them first."}},
        },
        "resources": clean,
        "outputs": {
            "analyticsRules": {"type": "int", "value": n_rules},
            "huntingQueries": {"type": "int", "value": n_hunts},
            "watchlistAlias": {"type": "string", "value": WATCHLIST_ALIAS},
        },
    }


def collect():
    rules, hunts = [], []
    for framework, folder in sources():
        rules += [analytics_rule(p, framework) for p in sorted((folder / "analytics").glob("*.yaml"))]
        for p in sorted((folder / "hunting").glob("*.kql")):
            hunts += hunting_queries(p, framework)
    return rules, hunts, watchlist()


def validate(rules, hunts, wl):
    errors = []
    seen = {}
    for r in rules:
        p, src = r["properties"], r["_source"]
        if r["name"] in seen:
            errors.append(f"{src}: rule id {r['name']} also used by {seen[r['name']]}")
        seen[r["name"]] = src
        if p["severity"] not in SEVERITIES:
            errors.append(f"{src}: severity {p['severity']!r}")
        for t in p["tactics"]:
            if t not in TACTICS:
                errors.append(f"{src}: tactic {t!r} is not a Microsoft Sentinel tactic name")
        for t in p["techniques"]:
            if not re.fullmatch(r"T\d{4}", t):
                errors.append(f"{src}: technique {t!r}")
        for t in p["techniques"]:
            if t not in TECHNIQUE_TACTICS:
                errors.append(f"{src}: technique {t} is not in TECHNIQUE_TACTICS in tools/build_sentinel.py; add it with its tactics")
            elif not TECHNIQUE_TACTICS[t] & set(p["tactics"]):
                errors.append(f"{src}: technique {t} needs one of the tactics {sorted(TECHNIQUE_TACTICS[t])}; "
                              "Microsoft Sentinel refuses the rule otherwise")
        if p.get("templateVersion") and not p.get("alertRuleTemplateName"):
            errors.append(f"{src}: templateVersion without alertRuleTemplateName; the rule could not be enabled in the portal")
        if not p["query"].strip():
            errors.append(f"{src}: empty query")
        if len(p["query"]) > 10000:
            errors.append(f"{src}: query is {len(p['query'])} characters; scheduled rules allow 10,000")
        if not p["displayName"].strip() or len(p["description"]) > 5000:
            errors.append(f"{src}: name missing or description over 5,000 characters")
    names = set()
    for h in hunts:
        p, src = h["properties"], h["_source"]
        if h["name"] in names:
            errors.append(f"{src}: duplicate hunting query id")
        names.add(h["name"])
        if not p["query"].strip() or not p["displayName"].strip():
            errors.append(f"{src}: empty title or query")
        for tag in p["tags"]:
            if len(tag["value"]) > TAG_MAX:
                errors.append(f"{src}: tag {tag['name']} is {len(tag['value'])} characters; Log Analytics allows {TAG_MAX}")
    rows = list(csv.DictReader(io.StringIO(wl["properties"]["rawContent"])))
    if not rows or "value" not in rows[0]:
        errors.append("feeds/sentinel-watchlist.csv: no rows or no 'value' column")
    if any(not r["value"] for r in rows):
        errors.append("feeds/sentinel-watchlist.csv: a row has an empty search key")
    return errors


def build():
    rules, hunts, wl = collect()
    errors = validate(rules, hunts, wl)
    files = {f"{NAME}.json": template(rules + hunts + [wl], "Agentic attack detections for Microsoft Sentinel: everything")}
    for framework, _ in sources():
        r = [x for x in rules if x["_framework"] == framework]
        h = [x for x in hunts if x["_framework"] == framework]
        if r or h:
            files[f"{framework}.json"] = template(r + h + [wl], f"Agentic attack detections for Microsoft Sentinel: {framework}")
    rendered = {name: json.dumps(t, indent=2, ensure_ascii=False) + "\n" for name, t in files.items()}
    for name, text in rendered.items():
        if len(text.encode()) > 4 * 1024 * 1024:
            errors.append(f"{name}: {len(text.encode())} bytes; ARM templates are limited to 4 MB")
    return rendered, errors, (len(rules), len(hunts), len(list(csv.DictReader(io.StringIO(wl["properties"]["rawContent"])))))


def deploy_url(name):
    from urllib.parse import quote
    return "https://portal.azure.com/#create/Microsoft.Template/uri/" + quote(f"{RAW}/deploy/sentinel/{name}", safe="")


def readme(rendered, counts):
    lines = ["# Deploy to Microsoft Sentinel", "",
             f"One deployment creates the analytics rules, the hunting queries and the `{WATCHLIST_ALIAS}` watchlist "
             "in a workspace that has Microsoft Sentinel on. Built by `tools/build_sentinel.py`; do not edit by hand.", "",
             "Deploy into the resource group that holds the workspace and give the workspace name. You need Contributor "
             "(or Microsoft Sentinel Contributor plus deployment rights) on that resource group. Analytics rules start "
             "disabled unless you set `enableRules` to true: enable each one once its data source is connected and you "
             "have baselined it. Every template carries the whole watchlist, so deploying several of them is safe, and "
             "deploying again updates what is there instead of adding copies.", "",
             "Hunts that hold several example queries become one hunting query per example (\"part 1\", \"part 2\"), "
             "because a hunting query runs as one query. MITRE sub-techniques show as their parent technique: the "
             "Microsoft Sentinel API keeps parent techniques only.", "",
             "| Template | Analytics rules | Hunting queries | Deploy |", "| --- | --- | --- | --- |"]
    for name, text in rendered.items():
        t = json.loads(text)
        o = t["outputs"]
        label = "Everything" if name == f"{NAME}.json" else name[:-5]
        lines.append(f"| [`{name}`]({name}) {label} | {o['analyticsRules']['value']} | {o['huntingQueries']['value']} | "
                     f"[![Deploy to Azure](https://aka.ms/deploytoazurebutton)]({deploy_url(name)}) |")
    lines += ["", "Command line:", "", "```bash",
              f"az deployment group create -g <resource-group> --template-uri {RAW}/deploy/sentinel/{NAME}.json \\",
              "  --parameters workspace=<workspace-name> enableRules=false", "```", ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="validate and fail if deploy/sentinel/ is not up to date")
    args = ap.parse_args()
    rendered, errors, (n_rules, n_hunts, n_rows) = build()
    rendered["README.md"] = readme({k: v for k, v in rendered.items()}, (n_rules, n_hunts, n_rows))
    for e in errors:
        print(f"ERROR {e}", file=sys.stderr)
    if args.check:
        stale = [n for n, text in rendered.items()
                 if not (OUT / n).is_file() or (OUT / n).read_text(encoding="utf-8") != text]
        extra = sorted(p.name for p in OUT.glob("*") if p.name not in rendered) if OUT.is_dir() else []
        for n in stale:
            print(f"STALE deploy/sentinel/{n}: run python3 tools/build_sentinel.py and commit", file=sys.stderr)
        for n in extra:
            print(f"EXTRA deploy/sentinel/{n}: not produced by the builder", file=sys.stderr)
        if errors or stale or extra:
            sys.exit(1)
        print(f"deploy/sentinel up to date: {n_rules} analytics rules, {n_hunts} hunting queries, {n_rows} watchlist rows")
        return
    if errors:
        sys.exit(1)
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.json"):
        if old.name not in rendered:
            old.unlink()
    for name, text in rendered.items():
        (OUT / name).write_text(text, encoding="utf-8")
    print(f"wrote {len(rendered)} files to deploy/sentinel: {n_rules} analytics rules, {n_hunts} hunting queries, "
          f"{n_rows} watchlist rows")


if __name__ == "__main__":
    main()
