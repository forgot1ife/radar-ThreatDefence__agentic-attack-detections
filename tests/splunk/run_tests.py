#!/usr/bin/env python3
"""Run the Splunk app's searches in a real Splunk and check what they find.

    python3 tests/splunk/run_tests.py --url https://localhost:8089 --hec https://localhost:8088

Needs a Splunk with deploy/splunk/TA-agentic-attack-detections and tests/splunk/TA-aad-test installed, the admin
password in SPLUNK_PASSWORD and a HTTP Event Collector token in SPLUNK_HEC_TOKEN. The CI workflow starts one in Docker.

For every search built from a Sigma rule, the test writes events into index aad_test with CIM field names and the
tags a Splunk add-on would give them: the rule's own test events from tests/sigma/fixtures/, plus a matching event
made from each branch of the rule's condition and a near miss for each. The Sigma rule decides whether each event
should match; the search must agree on every event. Searches that aggregate (correlations, the hand-written ARTEX
searches) must run without an error. The indicator searches must find planted addresses, domains, hashes and user
agents, skip expired indicators and near misses, and the summary index must receive the results the dashboard reads.

Exit status is non-zero on any failure.
"""
import argparse
import copy
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "sigma"))
import attack  # noqa: E402
import build_splunk  # noqa: E402
import run_tests as sigma_eval  # noqa: E402
from sigma import conditions as C  # noqa: E402
from sigma import types as T  # noqa: E402

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
SOURCETYPE = {"process_creation": "aad:test:process", "file_event": "aad:test:file", "registry_set": "aad:test:registry",
              "dns_query": "aad:test:dns", "proxy": "aad:test:proxy", "webserver": "aad:test:web",
              ("aws", "cloudtrail"): "aws:cloudtrail", ("azure", "signinlogs"): "azure:aad:signin",
              ("azure", "auditlogs"): "azure:aad:audit", ("azure", "activitylogs"): "azure:monitor:activity",
              ("okta", "okta"): "OktaIM2:log"}
failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL", msg)


class Splunk:
    def __init__(self, url, hec, password, token):
        self.url, self.hec, self.token = url.rstrip("/"), hec.rstrip("/"), token
        import base64
        self.auth = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()

    def rest(self, path, data=None, method=None):
        body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
        req = urllib.request.Request(self.url + path + ("&" if "?" in path else "?") + "output_mode=json", data=body,
                                     headers={"Authorization": self.auth}, method=method)
        with urllib.request.urlopen(req, context=CTX, timeout=300) as r:
            return json.loads(r.read() or b"{}")

    def send(self, events):
        payload = "".join(json.dumps(e) for e in events).encode()
        req = urllib.request.Request(self.hec + "/services/collector/event", data=payload,
                                     headers={"Authorization": f"Splunk {self.token}"})
        with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
            r.read()

    def search(self, spl, earliest="-7d", latest="now"):
        """(results, messages). Messages hold Splunk's errors and warnings for the search."""
        if not spl.lstrip().startswith("|"):
            spl = "search " + spl
        try:
            return self._search(spl, earliest, latest)
        except urllib.error.HTTPError as e:
            return [], [f"HTTP {e.code}: {e.read().decode(errors='replace')[:500]}"]

    def _search(self, spl, earliest, latest):
        job = self.rest("/services/search/jobs", {"search": spl, "earliest_time": earliest, "latest_time": latest,
                                                  "exec_mode": "blocking", "max_count": 50000})
        sid = job["sid"]
        info = self.rest(f"/services/search/jobs/{sid}")["entry"][0]["content"]
        msgs = [f"{m['type']}: {m['text']}" for m in info.get("messages", []) if m.get("type") in ("FATAL", "ERROR")]
        res = self.rest(f"/services/search/jobs/{sid}/results?count=0")
        return res.get("results", []), msgs


# ----- events from a Sigma condition -----------------------------------------------------------------------------

def example(value):
    """A string the Sigma value matches, or None."""
    if isinstance(value, T.SigmaExpansion):
        return example(value.values[0])
    if isinstance(value, T.SigmaString):
        out = ""
        for part in value.s:
            if isinstance(part, str):
                out += part
            elif part == T.SpecialChars.WILDCARD_SINGLE:
                out += "a"
        return out
    if isinstance(value, T.SigmaNumber):
        return str(value.number)
    if isinstance(value, T.SigmaCIDRExpression):
        net = ipaddress.ip_network(str(value.cidr), strict=False)
        return str(next(net.hosts(), net.network_address))
    if isinstance(value, T.SigmaRegularExpression):
        return None
    return None


def branches(node, limit=40):
    """Partial events (field -> list of example strings) that each satisfy one way through the condition."""
    if isinstance(node, C.ConditionOR):
        out = []
        for a in node.args:
            out += branches(a, limit)
            if len(out) >= limit:
                break
        return out[:limit]
    if isinstance(node, C.ConditionAND):
        combos = [{}]
        for a in node.args:
            if isinstance(a, C.ConditionNOT):
                continue
            opts = branches(a, limit)
            if not opts:
                return []
            new = []
            for c in combos:
                for o in opts[:4]:
                    m = {k: list(v) for k, v in c.items()}
                    for k, v in o.items():
                        m.setdefault(k, []).extend(v)
                    new.append(m)
            combos = new[:limit]
        return combos
    if isinstance(node, C.ConditionNOT):
        return [{}]
    if isinstance(node, C.ConditionFieldEqualsValueExpression):
        v = example(node.value)
        return [{node.field: [v]}] if v is not None else []
    return []


def to_event(partial):
    return {k: " ".join(v) if len(v) > 1 else v[0] for k, v in partial.items()}


def near_miss(event):
    """Each field's value changed so a contains/exact match on it fails."""
    return {k: re.sub(r"[A-Za-z0-9]", "x", v) if v else "benign" for k, v in event.items()}


def cim(event, category):
    fields = build_splunk.CIM_FIELDS.get(category, {})
    out = {}
    for k, v in event.items():
        if fields.get(k) == "_raw":
            out["request_headers"] = v
        else:
            out[fields.get(k, k)] = v
    return out


def rule_events(rule, fixture_dir):
    """[(name, expected, sigma event)] for one rule."""
    cases = []
    fx = fixture_dir / f"{Path(str(rule.source.path)).stem}.jsonl"
    if fx.exists():
        for line in fx.read_text(encoding="utf-8").splitlines():
            if line.strip():
                c = json.loads(line)
                cases.append((c["name"], c["expected"], c["event"]))
    for cond in rule.detection.parsed_condition:
        for i, partial in enumerate(branches(cond.parsed)):
            ev = to_event(partial)
            cases.append((f"branch {i}", sigma_eval.rule_matches(rule, ev), ev))
            miss = near_miss(ev)
            cases.append((f"branch {i} near miss", sigma_eval.rule_matches(rule, miss), miss))
    return cases


# ----- the checks ------------------------------------------------------------------------------------------------

def stanza_search(conf, name):
    return conf[name]["search"].replace("\n", " ")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="https://localhost:8089")
    ap.add_argument("--hec", default="https://localhost:8088")
    args = ap.parse_args()
    sp = Splunk(args.url, args.hec, os.environ["SPLUNK_PASSWORD"], os.environ["SPLUNK_HEC_TOKEN"])
    conf = build_splunk.read_conf(ROOT / "deploy" / "splunk" / build_splunk.APP / "default" / "savedsearches.conf")
    run = uuid.uuid4().hex[:8]
    now = int(time.time()) - 600

    # Sigma rules: which saved search each one became.
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule
    dirs = sorted(ROOT.glob("frameworks/*/sigma")) + [ROOT / "behaviors" / "sigma", ROOT / "general" / "sigma"]
    rules = SigmaCollection.load_ruleset([str(p) for d in dirs for p in sorted(d.rglob("*.yml"))])
    by_id = {}
    for _, name, s in build_splunk.sigma_searches():
        m = re.search(r"id ([0-9a-f-]{36})\.$", s["description"])
        by_id[m.group(1)] = name
    referenced = {id(r.rule) for c in rules.rules if isinstance(c, SigmaCorrelationRule) for r in c.rules}

    events, plan = [], []
    for rule in rules.rules:
        if isinstance(rule, SigmaCorrelationRule) or id(rule) in referenced:
            continue
        name = by_id[str(rule.id)]
        ls = rule.logsource
        key = ls.category if ls.category in SOURCETYPE else (ls.product, ls.service)
        cases = rule_events(rule, ROOT / "tests" / "sigma" / "fixtures")
        if not any(e for _, e, _ in cases):
            fail(f"{name}: no matching test event could be made")
        for i, (cname, expected, ev) in enumerate(cases):
            case = f"{run}-{rule.id}-{i}"
            body = dict(cim(ev, ls.category), aad_case=case)
            events.append({"time": now, "index": "aad_test", "sourcetype": SOURCETYPE[key], "host": "test-host", "event": body})
            plan.append((name, case, cname, expected))

    # Indicator searches: planted values and near misses.
    rows = build_splunk.indicator_rows()
    today = time.strftime("%Y-%m-%d")
    active = lambda r: not r["review_by"] or r["review_by"] >= today  # noqa: E731
    ip = next(r for r in rows if r["type"] == "ipv4" and "/" not in r["value"] and active(r))
    cidr = next((r for r in rows if r["type"] == "ipv4" and "/" in r["value"] and active(r)), None)
    expired = next((r for r in rows if r["type"] == "ipv4" and r["review_by"] and r["review_by"] < today), None)
    dom = next(r for r in rows if r["type"] == "domain" and active(r))
    sha = next(r for r in rows if r["type"] == "sha256" and active(r))
    md5 = next(r for r in rows if r["type"] == "md5" and active(r))
    ua = next(r for r in rows if r["type"] == "user_agent" and active(r))
    planted = [
        ("Indicators - Reported addresses", "aad:test:traffic", {"src": "10.0.0.5", "dest": ip["value"]}, True),
        ("Indicators - Reported addresses", "aad:test:traffic", {"src": "10.0.0.5", "dest": "198.51.100.200"}, False),
        ("Indicators - Reported domains", "aad:test:dns", {"src": "10.0.0.6", "query": "cdn." + dom["value"].upper()}, True),
        ("Indicators - Reported domains", "aad:test:dns", {"src": "10.0.0.6", "query": "not" + dom["value"]}, False),
        ("Indicators - Reported file hashes", "aad:test:process", {"process_path": "C:\\x.exe", "Hashes": f"MD5=00000000000000000000000000000000,SHA256={sha['value'].upper()}"}, True),
        ("Indicators - Reported file hashes", "aad:test:file", {"file_path": "/tmp/x", "file_hash": md5["value"]}, True),
        ("Indicators - Reported file hashes", "aad:test:file", {"file_path": "/tmp/y", "file_hash": "0" * 64}, False),
        ("Indicators - Reported user agents", "aad:test:web", {"src": "203.0.113.7", "http_user_agent": f"Mozilla/5.0 {ua['value']} extra"}, True),
        ("Indicators - Reported user agents", "aad:test:web", {"src": "203.0.113.8", "http_user_agent": "Mozilla/5.0 (Windows NT 10.0)"}, False),
    ]
    if cidr:
        host = str(next(ipaddress.ip_network(cidr["value"], strict=False).hosts()))
        planted.append(("Indicators - Reported addresses", "aad:test:traffic", {"src": host, "dest": "10.0.0.9"}, True))
    if expired:
        planted.append(("Indicators - Reported addresses", "aad:test:traffic", {"src": "10.0.0.10", "dest": expired["value"]}, False))
    ind_plan = []
    for i, (name, st, body, expected) in enumerate(planted):
        case = f"{run}-ioc-{i}"
        events.append({"time": now, "index": "aad_test", "sourcetype": st, "host": f"ioc-{i}", "event": dict(body, aad_case=case)})
        ind_plan.append((name, case, body, expected))

    for i in range(0, len(events), 200):
        sp.send(events[i:i + 200])
    deadline = time.time() + 180
    while True:
        got, _ = sp.search(f'index=aad_test aad_case="{run}-*" | stats count', earliest="-1d")
        n = int(got[0]["count"]) if got else 0
        if n >= len(events) or time.time() > deadline:
            break
        time.sleep(3)
    if n < len(events):
        fail(f"only {n} of {len(events)} test events were indexed")
    print(f"{len(events)} test events indexed")

    # 1. Searches from Sigma rules agree with the Sigma rule on every event.
    checked = 0
    names = sorted({p[0] for p in plan})
    for name in names:
        mine = [p for p in plan if p[0] == name]
        spl = stanza_search(conf, name) + f' | search aad_case="{run}-*" | stats values(aad_case) AS cases'
        res, msgs = sp.search(spl, earliest="-1d")
        if msgs:
            fail(f"{name}: {msgs}")
            continue
        found = set()
        for r in res:
            c = r.get("cases", [])
            found |= set(c if isinstance(c, list) else [c])
        for _, case, cname, expected in mine:
            checked += 1
            if (case in found) != expected:
                fail(f"{name}: event {cname!r} should {'match' if expected else 'not match'}, Splunk {'matched' if case in found else 'did not'}")
    print(f"sigma searches: {len(names)} searches, {checked} events compared with the Sigma rule")

    # 2. Every other search runs without an error.
    others = [n for n in conf if n not in names and not n.startswith("Indicators - ")]
    for name in others:
        _, msgs = sp.search(stanza_search(conf, name) + " | head 1", earliest="-1d")
        if msgs:
            fail(f"{name}: {msgs}")
    print(f"other searches: {len(others)} run without an error")

    # 3. Indicator searches find the planted values and nothing else.
    for name in sorted({p[0] for p in ind_plan}):
        res, msgs = sp.search(stanza_search(conf, name), earliest="-1d")
        if msgs:
            fail(f"{name}: {msgs}")
            continue
        values = {r.get("aad_value") if not isinstance(r.get("aad_value"), list) else r["aad_value"][0] for r in res}
        for n2, case, body, expected in [p for p in ind_plan if p[0] == name]:
            v = {k: x for k, x in body.items()}
            hit = any(str(x).lower() in {str(a).lower() for a in values if a} for x in v.values()) or \
                (name.endswith("hashes") and any(h.lower() in {str(a).lower() for a in values if a}
                                                  for h in re.findall(r"[0-9A-Fa-f]{32,64}", " ".join(map(str, v.values())))))
            if name.endswith("domains"):
                hit = v["query"].lower() in {str(a).lower() for a in values if a}
            if name.endswith("user agents"):
                hit = v["http_user_agent"] in values
            if hit != expected:
                fail(f"{name}: {body} should {'match' if expected else 'not match'}")
        frameworks = {r.get("aad_framework") for r in res}
        if res and not all(isinstance(f, str) for f in frameworks):
            fail(f"{name}: aad_framework should be one framework per row, got {frameworks}")
    print(f"indicator searches: {len(ind_plan)} planted events checked")

    # 4. Every saved search can be enabled as shipped (Splunk checks its schedule and actions), and a scheduled run of
    # each kind writes to the summary index with the fields the dashboard reads.
    base = "/servicesNS/nobody/" + build_splunk.APP + "/saved/searches/"
    for name in conf:
        path = base + urllib.parse.quote(name, safe="")
        try:
            sp.rest(path, {"disabled": "0"})
        except urllib.error.HTTPError as e:
            fail(f"{name}: Splunk refuses to enable it: {e.read().decode(errors='replace')[:300]}")
        finally:
            try:
                sp.rest(path, {"disabled": "1"})
            except urllib.error.HTTPError:
                pass
    print(f"saved searches: {len(conf)} enabled and disabled again")
    # Every saved search carries its ATT&CK techniques where Enterprise Security reads them, as Splunk stored them.
    pinned = 0
    for name in conf:
        entry = sp.rest(base + urllib.parse.quote(name, safe=""))["entry"][0]["content"]
        try:
            techniques = json.loads(entry.get("action.correlationsearch.annotations") or "{}").get("mitre_attack", [])
        except ValueError:
            techniques = None
        if not techniques:
            fail(f"{name}: no ATT&CK techniques in action.correlationsearch.annotations")
        elif attack.problems(techniques):
            fail(f"{name}: {attack.problems(techniques)}")
        else:
            pinned += 1
    print(f"att&ck: {pinned} of {len(conf)} saved searches carry techniques from ATT&CK {attack.version()}")
    # The search stays enabled until its actions have run: Splunk drops the alert of a search disabled meanwhile.
    targets = ["Indicators - Reported user agents", "ARTEX - User agent naming ARTEX in any source"]
    paths = [base + urllib.parse.quote(t, safe="") for t in targets]
    try:
        for path in paths:
            sp.rest(path, {"disabled": "0"})
            sp.rest(path + "/dispatch", {"trigger_actions": "1", "dispatch.earliest_time": "-1d", "dispatch.latest_time": "now"})
        for target in targets:
            deadline, rows_ = time.time() + 240, []
            while time.time() < deadline:
                rows_, _ = sp.search(f'index=summary search_name="{target}" aad_framework=* aad_entity=* | stats count BY aad_framework aad_entity', earliest="-2d")
                if rows_:
                    break
                time.sleep(5)
            if rows_:
                print(f"summary index: {len(rows_)} rows from {target!r}")
            else:
                fail(f"summary index: no results with aad_framework and aad_entity from {target!r}")
    finally:
        for path in paths:
            sp.rest(path, {"disabled": "1"})

    # 5. Every dashboard query runs without an error, and each framework card gets a value.
    view = (ROOT / "deploy" / "splunk" / build_splunk.APP / "default" / "data" / "ui" / "views" / "agentic_attack_activity.xml").read_text(encoding="utf-8")
    definition = json.loads(view.split("<![CDATA[", 1)[1].split("]]>", 1)[0])
    sources = definition["dataSources"]
    for key, ds in sources.items():
        q = ds["options"]["query"]
        if ds["type"] == "ds.chain":
            q = sources[ds["options"]["extend"]]["options"]["query"] + "\n" + q
        earliest = "0" if "alltime" in (key, ds["options"].get("extend")) else "-30d@d"
        res, msgs = sp.search(q.replace("\n", " "), earliest=earliest)
        if msgs:
            fail(f"dashboard query {key}: {msgs}")
        elif key.startswith(("t_", "a_")) and not res:
            fail(f"dashboard query {key}: no row, so the card would show no value")
    print(f"dashboard: {len(sources)} queries run")

    print(f"{len(failures)} failures" if failures else "PASS")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
