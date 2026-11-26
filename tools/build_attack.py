#!/usr/bin/env python3
"""Build the ATT&CK coverage page and the ATT&CK Navigator layers.

    python3 tools/build_attack.py             # write docs/attack-coverage.md and generated/attack/
    python3 tools/build_attack.py --check     # rebuild in memory; fail if the committed files differ, a rule names
                                              # no technique, or a rule names one that is not in the pinned release

Reads, for every framework folder and for behaviors/ and general/:
    sigma/**/*.yml                attack.tNNNN and attack.<tactic> tags
    sentinel/analytics/*.yaml     relevantTechniques and tactics
    sentinel/hunting/*.kql        the `// ATT&CK:` line in the header comment
    suricata/*.rules              mitre_technique_id in each rule's metadata (the -ip.rules too)
    yara/*.yar                    mitre_att in each rule's meta
    zeek/**/*.zeek                `ATT&CK:` in each notice's ## comment

Techniques are checked against the ATT&CK release pinned in tools/attack-enterprise.json (tools/attack.py), so the
build needs no network and a typo or a retired technique fails here rather than in the Navigator or a SIEM.
Output is deterministic: the same commit gives the same bytes.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

import attack

ROOT = Path(__file__).resolve().parent.parent
MD = ROOT / "docs" / "attack-coverage.md"
LAYERS = ROOT / "generated" / "attack"
NAME = "agentic-attack-detections"
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"
KINDS = {"sigma": "Sigma", "sentinel": "Sentinel analytics", "hunt": "KQL hunt", "suricata": "Suricata",
         "yara": "YARA", "zeek": "Zeek notice"}
TECHNIQUE = attack.TECHNIQUE


def folders():
    """[(framework, folder)]: AI agent behaviors, general intrusion, then the frameworks in name order."""
    return [("behaviors", ROOT / "behaviors"), ("general", ROOT / "general")] + [(p.name, p) for p in sorted((ROOT / "frameworks").iterdir())
                                                  if p.is_dir()]


def entry(framework, kind, rule, path, techniques, tactics=()):
    return {"framework": framework, "kind": kind, "rule": rule, "path": path.relative_to(ROOT).as_posix(),
            "techniques": sorted({t.upper() for t in techniques}), "tactics": sorted(set(tactics))}


def from_sigma(fw, base):
    for path in sorted(base.glob("sigma/**/*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        tags = [str(t).lower() for t in doc.get("tags") or []]
        techniques = [t.split(".", 1)[1] for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
        tactics = [t.split(".", 1)[1] for t in tags
                   if t.startswith("attack.") and t.split(".", 1)[1] in attack.tactic_by_shortname()]
        yield entry(fw, "sigma", doc.get("title") or path.stem, path, techniques, tactics)


def from_sentinel(fw, base):
    for path in sorted(base.glob("sentinel/analytics/*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        yield entry(fw, "sentinel", doc.get("name") or path.stem, path, doc.get("relevantTechniques") or [])


def hunt_techniques(text):
    """The ids on the `// ATT&CK:` line of a hunt's header comment, or []."""
    for line in text.splitlines():
        if not line.startswith("//"):
            break
        if line.startswith("// ATT&CK:"):
            return TECHNIQUE.findall(line)
    return []


def from_hunting(fw, base):
    for path in sorted(base.glob("sentinel/hunting/*.kql")):
        text = path.read_text(encoding="utf-8")
        title = text.splitlines()[0].lstrip("/ ").strip()
        yield entry(fw, "hunt", title, path, hunt_techniques(text))


def from_suricata(fw, base):
    for path in sorted(base.glob("suricata/*.rules")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("alert"):
                continue
            msg = re.search(r'msg:"([^"]*)"', line).group(1)
            sid = re.search(r"sid:(\d+);", line).group(1)
            yield entry(fw, "suricata", f"{sid} {msg}", path, re.findall(r"mitre_technique_id (T[\d.]+)", line))


def from_yara(fw, base):
    for path in sorted(base.glob("yara/*.yar")):
        text = path.read_text(encoding="utf-8")
        for name, meta in re.findall(r"^rule\s+(\w+)\s*\{(.*?)^\s*(?:strings|condition):", text, re.S | re.M):
            line = re.search(r'mitre_att\s*=\s*"([^"]*)"', meta)
            yield entry(fw, "yara", name, path, TECHNIQUE.findall(line.group(1)) if line else [])


def from_zeek(fw, base):
    for path in sorted(base.glob("zeek/**/*.zeek")):
        text = path.read_text(encoding="utf-8")
        module = re.search(r"^module (\w+);", text, re.M)
        for block in re.findall(r"redef enum Notice::Type \+= \{(.*?)\}", text, re.S):
            doc = []
            for line in block.splitlines():
                s = line.strip()
                if s.startswith("##"):
                    doc.append(s)
                    continue
                m = re.fullmatch(r"([A-Za-z_]\w*),?", s)
                if m:
                    found = [t for d in doc if "ATT&CK" in d for t in TECHNIQUE.findall(d.split("ATT&CK", 1)[1])]
                    name = f"{module.group(1)}::{m.group(1)}" if module else m.group(1)
                    yield entry(fw, "zeek", name, path, found)
                doc = []


SOURCES = (from_sigma, from_sentinel, from_hunting, from_suricata, from_yara, from_zeek)


def collect():
    return [e for fw, base in folders() for source in SOURCES for e in source(fw, base)]


def problems(entries):
    """(rules that name no technique, [(rule, id, why)] for ids outside the pinned release)"""
    gaps = [e for e in entries if not e["techniques"]]
    bad = dict(attack.problems({t for e in entries for t in e["techniques"]}))
    wrong = [(e, t, bad[t]) for e in entries for t in e["techniques"] if t in bad]
    return gaps, wrong


def known(entries):
    return [dict(e, techniques=[t for t in e["techniques"] if t in attack.techniques()]) for e in entries]


def layer(title, entries):
    by_technique = defaultdict(list)
    for e in entries:
        for t in e["techniques"]:
            by_technique[t].append(f"{KINDS[e['kind']]}: {e['rule']}")
    most = max((len(v) for v in by_technique.values()), default=1)
    return {
        "name": title,
        "versions": {"attack": attack.major(), "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{sum(1 for e in entries if e['techniques'])} rules from {REPO}, checked against ATT&CK "
                       f"{attack.version()}. Score: the number of rules that name the technique.",
        "techniques": [{"techniqueID": t, "score": len(v), "comment": "; ".join(sorted(set(v))),
                        "enabled": True, "showSubtechniques": True}
                       for t, v in sorted(by_technique.items())],
        "gradient": {"colors": ["#ffe9e9", "#dc2626"], "minValue": 0, "maxValue": most},
        "legendItems": [],
        "showTacticsRow": True,
        "selectTechniquesAcrossTactics": True,
        "hideDisabled": False,
        "links": [{"label": "Rules", "url": REPO}],
    }


def link(e):
    return f"[{e['rule']}](../{e['path']})"


def technique_link(t):
    return f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"


def tactic_names(t):
    by_short = attack.tactic_by_shortname()
    return ", ".join(by_short[s][1] for s in sorted(attack.techniques()[t]["tactics"], key=lambda s: by_short[s][0]))


def cell(rules):
    """The rules behind one technique, grouped by kind. Suricata rules are listed by sid to keep the row short."""
    out = []
    for kind in KINDS:
        mine = sorted((e for e in rules if e["kind"] == kind), key=lambda e: (e["path"], e["rule"]))
        if not mine:
            continue
        if kind == "suricata":
            by_file = defaultdict(list)
            for e in mine:
                by_file[e["path"]].append(e["rule"].split(" ", 1)[0])
            out.append("Suricata " + "; ".join(f"[{Path(p).name}](../{p}) {', '.join(s)}" for p, s in by_file.items()))
        else:
            out.append(f"{KINDS[kind]}: " + "; ".join(link(e) for e in mine))
    return "<br>".join(out)


def coverage(entries):
    entries = known(entries)
    frameworks = [fw for fw, _ in folders() if any(e["framework"] == fw for e in entries)]
    all_techniques = sorted({t for e in entries for t in e["techniques"]})
    out = ["# ATT&CK coverage", "",
           f"Generated by `tools/build_attack.py` from the rules in this repository, checked against MITRE ATT&CK "
           f"Enterprise {attack.version()} (pinned in `tools/attack-enterprise.json`). Every rule names at least one "
           "technique, and CI fails a pull request that adds a rule without one or names a technique that is not in "
           "that release.", "",
           f"{len(entries)} rules cover {len(all_techniques)} techniques. Open the layers in "
           "[`generated/attack/`](../generated/attack) with the [ATT&CK Navigator]"
           "(https://mitre-attack.github.io/attack-navigator/) (Open Existing Layer, Upload from local): one per "
           f"framework and `{NAME}.json` for everything. Each release carries them as `{NAME}-attack.zip`.", "",
           "A technique says what a rule sees, not everything the framework can do. Rules that find a framework's "
           "software on a host map to Obtain Capabilities: Tool (T1588.002). Indicator sweeps and address rules map "
           "to Active Scanning (T1595) for traffic in from a reported address and Application Layer Protocol (T1071) "
           "for traffic out to one.", "",
           "| Framework | Rules | Techniques | " + " | ".join(KINDS.values()) + " |",
           "|---|---|---|" + "---|" * len(KINDS)]
    for fw in frameworks:
        mine = [e for e in entries if e["framework"] == fw]
        counts = [str(sum(1 for e in mine if e["kind"] == k) or "") for k in KINDS]
        out.append(f"| [{fw}](#{fw}) | {len(mine)} | {len({t for e in mine for t in e['techniques']})} | "
                   + " | ".join(counts) + " |")
    out += ["", "## Techniques across all frameworks", "",
            "| Technique | Name | Tactics | Rules | Frameworks |", "|---|---|---|---|---|"]
    for t in all_techniques:
        rules = [e for e in entries if t in e["techniques"]]
        fws = [fw for fw in frameworks if any(e["framework"] == fw for e in rules)]
        out.append(f"| {technique_link(t)} | {attack.name(t)} | {tactic_names(t)} | {len(rules)} | {', '.join(fws)} |")
    for fw in frameworks:
        mine = [e for e in entries if e["framework"] == fw]
        by_technique = defaultdict(list)
        for e in mine:
            for t in e["techniques"]:
                by_technique[t].append(e)
        out += ["", f"## {fw}", "", "| Technique | Name | Rules |", "|---|---|---|"]
        for t in sorted(by_technique):
            out.append(f"| {technique_link(t)} | {attack.name(t)} | {cell(by_technique[t])} |")
    return "\n".join(out) + "\n"


def build(entries):
    good = known(entries)
    files = {MD: coverage(entries)}
    for fw, _ in folders():
        mine = [e for e in good if e["framework"] == fw]
        if mine:
            files[LAYERS / f"{fw}.json"] = layer(fw, mine)
    files[LAYERS / f"{NAME}.json"] = layer("Agentic attack detections: all frameworks", good)
    return {p: (text if isinstance(text, str) else json.dumps(text, indent=1, sort_keys=True) + "\n")
            for p, text in files.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed files differ from a fresh build or a rule's mapping is missing or wrong")
    args = ap.parse_args()
    entries = collect()
    gaps, wrong = problems(entries)
    files = build(entries)
    stale = []
    for path, text in files.items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(path.relative_to(ROOT).as_posix())
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    if not args.check:
        for old in LAYERS.glob("*.json"):
            if old not in files:
                old.unlink()
    print(f"attack: {len(entries) - len(gaps)} of {len(entries)} rules mapped to "
          f"{len({t for e in entries for t in e['techniques']})} techniques (ATT&CK {attack.version()}), {len(files)} files")
    for e in gaps:
        print(f"  {e['path']}: {KINDS[e['kind']]} {e['rule']!r} names no ATT&CK technique")
    for e, t, why in wrong:
        print(f"  {e['path']}: {KINDS[e['kind']]} {e['rule']!r} names {t}, {why}")
    for s in stale:
        print(f"  {s} is stale: run python3 tools/build_attack.py and commit it")
    if args.check and (gaps or wrong or stale):
        raise SystemExit(1)
    if wrong or gaps:
        print("  fix these before committing: CI runs this with --check")


if __name__ == "__main__":
    sys.exit(main())
