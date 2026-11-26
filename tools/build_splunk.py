#!/usr/bin/env python3
"""Build the Splunk app with the searches for every framework and the shared behaviors.

    python3 tools/build_splunk.py                  # write deploy/splunk/TA-agentic-attack-detections/
    python3 tools/build_splunk.py --check          # rebuild in memory, fail if deploy/splunk/ differs
    python3 tools/build_splunk.py --package DIR    # also write DIR/agentic-attack-detections-splunk.tgz
    python3 tools/build_splunk.py --appinspect-result report.json   # fail on any failure in a splunk-appinspect report

Reads:
    frameworks/*/sigma/, behaviors/sigma/      every Sigma rule, converted with pySigma to SPL on CIM field names
    frameworks/artex/splunk/                   the hand-written ARTEX searches and macros
    iocs/indicators.csv                        the indicator lookups and the searches that use them

Every search ships disabled and scheduled, carries its ATT&CK techniques in
action.correlationsearch.annotations, adds aad_framework and aad_entity to its results, and writes what it finds
to the summary index, which the Agentic Attack Activity dashboard reads. Data sources are chosen in macros.conf:
aad_indexes plus one macro per data source.

Output is deterministic: the same commit gives the same bytes. Needs pySigma and the Splunk backend
(tools/requirements.txt).
"""
import argparse
import configparser
import copy
import csv
import hashlib
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
APP = "TA-agentic-attack-detections"
OUT = ROOT / "deploy" / "splunk"
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"
NAME = "agentic-attack-detections"
ARTEX_APP = ROOT / "frameworks" / "artex" / "splunk"

# Framework folder -> display name, card color, console port, one-line description (README "What each framework is").
FRAMEWORKS = {
    "artex": ("ARTEX", "#4C8DF6", "8787", "Go planner and worker agents with a web console. AntiFox is the same code renamed."),
    "cyberstrikeai": ("CyberStrikeAI", "#F0703A", "8080", "Go operator console with its own implants, C2 listeners and webshell manager."),
    "pentagi": ("PentAGI", "#2EBD85", "8443", "Go multi-agent platform that runs Kali tools in a container per engagement."),
    "cairn": ("Cairn", "#E6A817", "8000", "Python engine that drives coding agents in Kali containers."),
    "hermes": ("Hermes Agent", "#E5508A", "9119", "General-purpose agent turned attack console: approvals off, jailbreak skill, red-team personas."),
    "strix": ("Strix", "#3FBF3F", "8080", "Python AI pentest agent that runs teams of agents in a Kali sandbox."),
    "hexstrike": ("HexStrike", "#8E7CF0", "8888", "Python MCP server that gives any AI assistant about 150 security tools."),
    "agent-zero": ("Agent Zero", "#2BB5C8", "50080", "General-purpose agent in a Kali container with a hacker profile and an open web UI."),
    "redamon": ("RedAmon", "#EF5A5A", "3000", "Self-hosted pentest platform: web console, recon pipeline and a Metasploit agent."),
    "xalgorix": ("Xalgorix", "#C9A0FF", "9137", "Go binary with a web dashboard whose agent tests web apps and re-exploits findings."),
    "pentestswarm": ("Pentest Swarm AI", "#9AA4B2", "8080", "Go command-line tool that runs recon, exploit and report agents."),
    "shannon": ("Shannon", "#5B8DEF", "", "TypeScript white-box AI pentester: Temporal workers drive model agents and a headless browser."),
    "pentestgpt": ("PentestGPT", "#7FD1AE", "", "Python agent that drives the Claude Code or Codex CLI with permission checks off."),
    "cyber-autoagent": ("Cyber-AutoAgent", "#F2A65A", "3000", "Python agent on the Strands SDK in a Kali container, with a bundled Langfuse stack."),
    "cai": ("CAI", "#B784E0", "8000", "Alias Robotics agent framework: shell agents, optional HTTP API, session-log telemetry."),
    "hacksynth": ("HackSynth", "#6FB3B8", "", "Research CTF agent: a planner model runs one bash command per step in a Kali container."),
    "vulnbot": ("VulnBot", "#D98880", "7861", "Research multi-agent pentester that runs Kali tools over SSH, with an optional knowledge base API."),
    "autopt": ("AutoPT", "#C39BD3", "5000", "Research web pentest agent with an unauthenticated Flask console that runs vulhub exploits."),
    "pentestagent": ("PentestAgent (paper)", "#A3B18A", "", "Research agent from arXiv 2411.05185: nmap, CVE lookup and public exploit runs."),
    "ghostcrew-pentestagent": ("PentestAgent (GH05TCREW)", "#E0B354", "8080", "Python pentest agent with a terminal UI, crews and an unauthenticated MCP server."),
    "darkmoon": ("Dark Moon", "#7D8CC4", "8181", "OpenCode-based agent stack with 51 attack prompts and an unauthenticated MCP server."),
    "decepticon": ("Decepticon", "#E05D5D", "3000", "LangGraph red team agents in a Kali sandbox with on-demand Sliver and Havoc C2."),
    "sapper-v2": ("sapper-v2", "#8FBC8F", "8765", "Contest kit that drives Claude Code sessions in tmux around a shared engagement graph."),
    "nyxstrike": ("NyxStrike", "#6C7BD9", "8888", "HexStrike derivative with a web dashboard, a decision engine and about 200 tools over MCP."),
    "neurosploit": ("NeuroSploit", "#D4699A", "4173", "Rust multi-model harness with an unauthenticated web console, out-of-band channel and optional C2."),
    "h-pentest": ("H-Pentest", "#B5838D", "8000", "Small contest pentest platform: unauthenticated FastAPI backend with the Docker socket, Vue console."),
    "hexstrike-redteam": ("Hexstrike-redteam", "#9C6ADE", "8888", "HexStrike copy with BOAZ payload evasion routes, bound to every interface with no auth."),
    "vigilo": ("Vigilo", "#5DADE2", "8080", "CERT-EU assessment platform: coding agents with approvals off, and a grey-box agent that names itself."),
    "chying-agent": ("CHYing-agent", "#F1948A", "8080", "Contest agent on the Claude Agent SDK with an unauthenticated dashboard and web terminal markers."),
    "incalmo": ("Incalmo", "#45B39D", "8888", "CMU research system for multistage attacks: unauthenticated Flask C2 driving Caldera Sandcat implants."),
    "pentest-copilot": ("Pentest Copilot", "#F7DC6F", "3000", "BugBase web app whose agent runs commands in Kali, with a browser agent and Mythic C2 integration."),
    "virga": ("Virga", "#AF7AC5", "5173", "Go C2 whose beacon can embed a local model; unauthenticated MCP servers and admin API."),
    "pentest-ai": ("pentest-ai", "#85C1E9", "8888", "Python CLI and MCP server whose every request carries its name and a per-install id."),
    "cyber-harness": ("cyber-harness", "#76D7C4", "8080", "chainreactors Go agent harness: scan agent, code audit and a Web Hub that controls nodes."),
    "lazyown": ("LazyOwn", "#CD6155", "4444", "Python red team framework with a multi-operator C2, HTTP and DNS beacons, driven by an agent over MCP."),
    "mcp-kali-server": ("MCP Kali Server", "#D5A42A", "5000", "Flask API and MCP bridge that lets an AI assistant run any command on a Kali host, with no auth."),
    "aria-x": ("ARIA-X", "#F1AA19", "8787", "Python engine with a console on 8787 whose agent sends its own ARIA-X user agent to targets."),
    "mitsu": ("Mitsu", "#92B561", "", "Terminal AI pentest agent with a 165-tool catalog that drives Codex or Claude Code over local MCP."),
    "burp-ai-agent": ("Custom AI Agent (burp-ai-agent)", "#34B76E", "9876", "Burp Suite extension that lets models and MCP clients drive Burp, with AI active scan payloads."),
    "raptor": ("RAPTOR", "#200765", "", "Claude Code research framework: code and binary analysis, a web scanner that names itself, exploit and patch generation."),
    "blitzstrike": ("Blitz Strike", "#1EF5DB", "", "MCP server for AI coding clients that runs a one-call web engagement with fixed markers."),
    "nebula": ("Nebula", "#2852DE", "8000", "Operator workstation: agents and missions driving commands in a local Kali container."),
    "clearwing": ("Clearwing", "#877EA8", "8899", "Network pentest agent and source-code hunter with a Kali container, signed payloads and callbacks."),
    "breachweave": ("BreachWeave", "#B136B0", "3000", "Multi-agent contest pentest platform with Kali solver containers and an NPS tunnel hand-off."),
    "numasec": ("numasec", "#88BEB7", "4096", "OpenCode-based terminal security agent with its own AppSec probe and directory fuzzer markers."),
    "pentest-harness": ("Pentest Harness", "#FE69BC", "2323", "Rebrand of the dsh agent harness with a pentest persona and a local web UI with no login."),
    "agentic-bug-hunter": ("Agentic Bug Hunter", "#F66BB7", "8777", "Bug bounty toolkit for coding agents: fixed verifier user agents, password spraying, OOB markers."),
    "zerosecurity": ("0security", "#FBA6CC", "48123", "Harness for persistent AI security agents with LLM probes and a server-mode console."),
    "sage-mythic": ("Sage (Mythic)", "#04CB01", "6006", "AI operator inside the Mythic C2 framework that proposes tasks with fixed proof markers."),
    "pentestcode": ("PentestCode", "#CABBA6", "4096", "OpenCode fork with thirteen pentest agents, injection probe markers and pivot and persistence recipes."),
    "behaviors": ("Shared behaviors", "#D9DEE5", "", "What every agentic framework does: coding agents with approvals off, agent tooling, callbacks."),
}

# Sigma field -> CIM field, per log source category. Cloud log sources keep their own JSON field names, as the Splunk
# add-ons for AWS, Azure and Okta extract them.
CIM_FIELDS = {
    "process_creation": {"CommandLine": "process", "Image": "process_path", "ParentImage": "parent_process_path",
                         "ParentCommandLine": "parent_process", "User": "user", "OriginalFileName": "original_file_name",
                         "CurrentDirectory": "process_current_directory"},
    "file_event": {"TargetFilename": "file_path"},
    "registry_set": {"TargetObject": "registry_path", "Details": "registry_value_data"},
    "dns_query": {"QueryName": "query"},
    "proxy": {"c-uri": "url", "c-useragent": "http_user_agent", "cs-host": "url_domain"},
    # Request headers are rarely a field in web server logs; a header marker is searched for in the whole event.
    "webserver": {"cs-uri-stem": "uri_path", "cs-uri-query": "uri_query", "cs-user-agent": "http_user_agent",
                  "cs-method": "http_method", "cs-referer": "http_referrer", "cs-headers": "_raw"},
}
SOURCE_MACRO = {"process_creation": "aad_process", "file_event": "aad_file", "registry_set": "aad_registry",
                "dns_query": "aad_dns", "proxy": "aad_proxy", "webserver": "aad_web",
                ("aws", "cloudtrail"): "aad_aws_cloudtrail", ("azure", "signinlogs"): "aad_azure_signin",
                ("azure", "auditlogs"): "aad_azure_audit", ("azure", "activitylogs"): "aad_azure_activity",
                ("okta", "okta"): "aad_okta"}
SEVERITY = {"informational": 2, "low": 3, "medium": 4, "high": 5, "critical": 6}

MACROS = [
    ("aad_indexes", "index=*",
     "The indexes every search reads. Ships as index=* so the searches run on install. Narrow it to the indexes that\n"
     "# hold your endpoint, web, DNS and cloud logs before you enable a search: index=* scans every index on every run."),
    ("aad_process", "`aad_indexes` tag=process tag=report", "Process starts (CIM Endpoint.Processes: Sysmon event 1, Windows 4688, Linux auditd or Sysmon for Linux, EDR)."),
    ("aad_file", "`aad_indexes` tag=endpoint tag=filesystem", "File creation (CIM Endpoint.Filesystem: Sysmon event 11, EDR)."),
    ("aad_registry", "`aad_indexes` tag=endpoint tag=registry", "Registry writes (CIM Endpoint.Registry: Sysmon events 12 to 14, EDR)."),
    ("aad_dns", "`aad_indexes` tag=network tag=resolution tag=dns", "DNS queries (CIM Network_Resolution: Sysmon event 22, DNS server, Zeek dns.log)."),
    ("aad_proxy", "`aad_indexes` tag=web tag=proxy", "Outbound web proxy and secure web gateway logs (CIM Web)."),
    ("aad_web", "`aad_indexes` tag=web NOT tag=proxy", "Web server, load balancer and WAF access logs for your own sites (CIM Web)."),
    ("aad_aws_cloudtrail", "`aad_indexes` sourcetype=aws:cloudtrail", "AWS CloudTrail (Splunk Add-on for AWS)."),
    ("aad_azure_signin", "`aad_indexes` (sourcetype=azure:aad:signin OR sourcetype=ms:aad:signin OR (sourcetype=mscs:azure:eventhub category=SignInLogs))",
     "Entra ID sign-ins."),
    ("aad_azure_audit", "`aad_indexes` (sourcetype=azure:aad:audit OR sourcetype=ms:aad:audit OR (sourcetype=mscs:azure:eventhub category=AuditLogs))",
     "Entra ID audit log."),
    ("aad_azure_activity", "`aad_indexes` (sourcetype=azure:monitor:activity OR (sourcetype=mscs:azure:eventhub category=Administrative))",
     "Azure activity log."),
    ("aad_okta", "`aad_indexes` (sourcetype=OktaIM2:log OR sourcetype=okta:im2)", "Okta system log."),
    ("aad_network", "`aad_indexes` (tag=network OR tag=web OR tag=authentication OR sourcetype=aws:cloudtrail)",
     "Events searched for reported addresses: network traffic, web, sign-ins and CloudTrail."),
    ("aad_domains", "`aad_indexes` ((tag=network tag=resolution tag=dns) OR tag=web)", "Events searched for reported domains: DNS and web."),
    ("aad_hashes", "`aad_indexes` ((tag=process tag=report) OR (tag=endpoint tag=filesystem))", "Events searched for reported file hashes."),
    ("aad_user_agents", "`aad_indexes` (tag=web OR tag=authentication OR sourcetype=aws:cloudtrail OR sourcetype=OktaIM2:log)",
     "Events searched for reported user agents."),
    ("aad_entity", "eval aad_entity=coalesce(aad_entity, src, src_ip, clientip, c_ip, sourceIPAddress, ipAddress, IPAddress, callerIpAddress, "
     "'client.ipAddress', 'userIdentity.arn', caller, dest, dest_host, Computer, host)",
     "The host or address a result is about: the source for web, sign-in and cloud events, the machine for endpoint events."),
    ("aad_active_indicator", "where isnull(review_by) OR review_by=\"\" OR strptime(review_by, \"%Y-%m-%d\") >= relative_time(now(), \"-1d@d\")",
     "Indicators past their review date are leads to recheck, not matches."),
]

ARTEX_TECHNIQUES = {
    "ARTEX - User agent naming ARTEX in any source": ["T1595"],
    "ARTEX - Password spray at a fixed rhythm": ["T1110.003"],
    "ARTEX - Spray that ends in a successful sign-in": ["T1110.003", "T1078"],
    "ARTEX - Web probe artifacts": ["T1595.002", "T1190"],
    "ARTEX - User agent family burst from one source": ["T1595"],
    "ARTEX - Web or database service spawns a shell or download tool": ["T1505.003", "T1059"],
    "ARTEX - Artifact names in processes and files": ["T1059", "T1105"],
    "ARTEX - CloudWatch logs searched for secrets": ["T1552"],
    "ARTEX - EC2 DryRun burst": ["T1580"],
    "ARTEX - AWS access denied sweep": ["T1580"],
    "ARTEX - Cognito sign-up burst": ["T1136.003"],
    "ARTEX - Service principal assigns a role to itself": ["T1098.003"],
    "ARTEX - Bulk Key Vault secret reads": ["T1555.006"],
    "ARTEX - Azure Resource Manager validate sweep": ["T1580"],
    "ARTEX - Indicator sweep": ["T1071"],
}

HEADER = """# Agentic Attack Detections for Splunk. Built by tools/build_splunk.py from {repo}
# Do not edit here: change the Sigma rule, frameworks/artex/splunk/ or tools/build_splunk.py and rebuild.
"""


def conf_value(text):
    """A multi-line value: each line but the last ends in a backslash."""
    lines = [l.rstrip() for l in text.strip().split("\n")]
    for l in lines:
        if l.endswith("\\"):
            raise SystemExit(f"a line of a .conf value ends in a backslash, which Splunk reads as a continuation: {l!r}")
    return " \\\n".join(lines)


def stanza(name, settings):
    out = [f"[{name}]"]
    for k, v in settings.items():
        out.append(f"{k} = {conf_value(str(v))}")
    return "\n".join(out) + "\n"


def split_pipes(spl):
    """Put each pipe on its own line, outside quoted strings."""
    parts, cur, quote, i = [], "", False, 0
    while i < len(spl):
        ch = spl[i]
        if ch == "\\" and i + 1 < len(spl):
            cur += spl[i:i + 2]
            i += 2
            continue
        if ch == '"':
            quote = not quote
        if ch == "|" and not quote and cur.strip():
            parts.append(cur.rstrip())
            cur = "|"
        else:
            cur += ch
        i += 1
    parts.append(cur.rstrip())
    return "\n".join(p.strip() for p in parts if p.strip())


def top_level_split(spl):
    """(search part, '|', rest) split at the first pipe outside quotes, or (spl, '', '')."""
    quote, i = False, 0
    while i < len(spl):
        ch = spl[i]
        if ch == "\\":
            i += 2
            continue
        if ch == '"':
            quote = not quote
        elif ch == "|" and not quote:
            return spl[:i], "|", spl[i + 1:]
        i += 1
    return spl, "", ""


def minute_for(name):
    return int(hashlib.sha256(name.encode()).hexdigest(), 16) % 60


def read_conf(path):
    """Stanzas of a .conf file in order, with continuation lines joined and comments kept out."""
    text = path.read_text(encoding="utf-8")
    out, cur = {}, None
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        m = re.match(r"^\[(.*)\]\s*$", line)
        if m:
            cur = m.group(1)
            out[cur] = {}
            i += 1
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        parts = []
        while val.endswith("\\"):
            parts.append(val[:-1].rstrip())
            i += 1
            val = lines[i].strip()
        parts.append(val)
        out[cur][key.strip()] = "\n".join(parts)
        i += 1
    return out


def techniques_of(tags):
    out = []
    for t in tags:
        t = str(t)
        m = re.fullmatch(r"attack\.t(\d{4})(?:\.(\d{3}))?", t, re.I)
        if m:
            out.append(f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else ""))
    return sorted(set(out))


def annotations(techniques):
    return json.dumps({"mitre_attack": techniques}, separators=(", ", ": "))


def fix_or_with_regex(spl):
    """Repair the Splunk backend's output for an OR whose first branch is a plain term and a later one a regex.

    The backend keeps the plain term as the base search and starts the final `search` with a bare OR, which
    Splunk refuses, and which would drop the other branches anyway. Move the term into that `search`.
    """
    head, nl, rest = spl.partition("\n")
    if not nl or head.lstrip().startswith("|") or "\n| search OR " not in rest:
        return spl
    return rest.replace("\n| search OR ", f"\n| search ({head.strip()}) OR ", 1)


def sigma_searches():
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule
    from sigma.processing.conditions import LogsourceCondition
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation

    from sigma.processing.transformations.base import ValueTransformation
    from sigma import types as T

    class LiteralAsterisk(ValueTransformation):
        """Splunk cannot escape * in a search term, so a value with a literal * becomes a regular expression."""
        def apply_value(self, field, val):
            if not isinstance(val, T.SigmaString) or not any(isinstance(p, str) and "*" in p for p in val.s):
                return None
            rx = "".join(re.escape(p) if isinstance(p, str) else (".*" if p == T.SpecialChars.WILDCARD_MULTI else ".")
                         for p in val.s)
            return T.SigmaRegularExpression("(?i)^" + rx + "$")

    pipeline = ProcessingPipeline(name="CIM field names", priority=20, items=[
        ProcessingItem(identifier=f"cim_{cat}", transformation=FieldMappingTransformation(fields),
                       rule_conditions=[LogsourceCondition(category=cat)]) for cat, fields in CIM_FIELDS.items()] + [
        ProcessingItem(identifier="literal_asterisk", transformation=LiteralAsterisk())])
    dirs = sorted(ROOT.glob("frameworks/*/sigma")) + [ROOT / "behaviors" / "sigma"]
    files = sorted(p for d in dirs for p in d.rglob("*.yml"))
    rules = SigmaCollection.load_ruleset([str(p) for p in files])
    searches = []
    referenced = {id(r.rule) for c in rules.rules if isinstance(c, SigmaCorrelationRule) for r in c.rules}
    for rule in rules.rules:
        if id(rule) in referenced:
            continue  # converted as part of the correlation rule that uses it
        path = Path(str(rule.source.path))
        fw = "behaviors" if "behaviors" in path.relative_to(ROOT).parts[:1] else path.relative_to(ROOT).parts[1]
        if isinstance(rule, SigmaCorrelationRule):
            base = rule.rules[0].rule
            coll = copy.deepcopy(SigmaCollection([r.rule for r in rule.rules] + [rule]))
            tags, level, logsource = base.tags + list(getattr(rule, "tags", []) or []), rule.level or base.level, base.logsource
            timeframe = rule.timespan.spec if rule.timespan else None
        else:
            coll = copy.deepcopy(SigmaCollection([rule]))
            tags, level, logsource, timeframe = rule.tags, rule.level, rule.logsource, None
        spl = SplunkBackend(processing_pipeline=copy.deepcopy(pipeline)).convert(coll)
        if not spl:
            raise SystemExit(f"{path}: the Splunk backend returned no query")
        spl = str(spl[-1]) if isinstance(rule, SigmaCorrelationRule) else "\n".join(map(str, spl))
        spl = fix_or_with_regex(spl)
        key = logsource.category if logsource.category in SOURCE_MACRO else (logsource.product, logsource.service)
        macro = SOURCE_MACRO.get(key)
        if not macro:
            raise SystemExit(f"{path}: no data source macro for log source {key}")
        title = re.sub(r"\s+", " ", rule.title).strip()
        display = FRAMEWORKS[fw][0]
        for prefix in (display, display.split()[0]):
            if title.lower().startswith(prefix.lower() + " ") and fw != "behaviors":
                title = title[len(prefix):].strip()
                title = title[0].upper() + title[1:]
                break
        name = f"{display} - {title}"
        description = re.sub(r"\s+", " ", (rule.description or title)).strip()
        head, sep, tail = top_level_split(spl.strip())
        query = (f"`{macro}` ({head.strip()})" if head.strip() else f"`{macro}`") + (f" {sep}{tail}" if sep else "")
        query = split_pipes(query) + f'\n| eval aad_framework="{fw}", aad_rule="{name}"\n| `aad_entity`'
        searches.append((fw, name, {
            "description": f"{description} Sigma rule {path.relative_to(ROOT).as_posix()}, id {rule.id}.",
            "search": query,
            "_level": str(level).lower() if level else "medium",
            "_techniques": techniques_of(tags),
            "_timeframe": timeframe,
        }))
    return searches


def artex_searches():
    conf = read_conf(ARTEX_APP / "default" / "savedsearches.conf")
    out = []
    for name, s in conf.items():
        if name not in ARTEX_TECHNIQUES:
            raise SystemExit(f"frameworks/artex/splunk: add ATT&CK techniques for {name!r} to ARTEX_TECHNIQUES")
        s = dict(s)
        s["search"] = s["search"] + f'\n| eval aad_framework="artex", aad_rule="{name}"\n| `aad_entity`'
        s["_techniques"] = ARTEX_TECHNIQUES[name]
        out.append(("artex", name, s))
    return out


def indicator_rows():
    with open(ROOT / "iocs" / "indicators.csv", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def csv_text(rows, cols):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, lineterminator="\n", extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def lookups():
    rows = indicator_rows()
    cols = ["value", "type", "confidence", "framework", "actor", "source", "source_url", "reported", "review_by", "context"]
    files = {"aad_indicators.csv": csv_text(rows, cols)}
    short = ["match", "value", "type", "confidence", "framework", "actor", "source", "review_by"]
    # A CIDR lookup matches only values written as ranges, so single addresses get /32 or /128.
    ip = [dict(r, match=r["value"] if "/" in r["value"] else r["value"] + ("/128" if ":" in r["value"] else "/32"))
          for r in rows if r["type"] in ("ipv4", "ipv6")]
    dom = []
    for r in rows:
        if r["type"] == "domain":
            v = r["value"].lower().strip(".")
            dom += [dict(r, match=v), dict(r, match="*." + v)]
    hashes = [dict(r, match=r["value"].lower()) for r in rows if r["type"] in ("md5", "sha256")]
    uas = [dict(r, match="*" + r["value"] + "*") for r in rows if r["type"] == "user_agent"]
    files["aad_ioc_ip.csv"] = csv_text(ip, short)
    files["aad_ioc_domain.csv"] = csv_text(dom, short)
    files["aad_ioc_hash.csv"] = csv_text(hashes, short)
    files["aad_ioc_user_agent.csv"] = csv_text(uas, short)
    files["artex_iocs.csv"] = (ARTEX_APP / "lookups" / "artex_iocs.csv").read_text(encoding="utf-8")
    counts = {"ip": len(ip), "domain": len(dom) // 2, "hash": len(hashes), "user_agent": len(uas), "all": len(rows)}
    return files, counts


TRANSFORMS = [
    ("aad_indicators", {"filename": "aad_indicators.csv", "case_sensitive_match": "false"}),
    ("aad_ioc_ip", {"filename": "aad_ioc_ip.csv", "match_type": "CIDR(match)", "max_matches": "10"}),
    ("aad_ioc_domain", {"filename": "aad_ioc_domain.csv", "match_type": "WILDCARD(match)", "case_sensitive_match": "false", "max_matches": "10"}),
    ("aad_ioc_hash", {"filename": "aad_ioc_hash.csv", "case_sensitive_match": "false", "max_matches": "10"}),
    ("aad_ioc_user_agent", {"filename": "aad_ioc_user_agent.csv", "match_type": "WILDCARD(match)", "case_sensitive_match": "false", "max_matches": "10"}),
]

INDICATOR_TAIL = """| lookup {lookup} match AS aad_value OUTPUT value AS indicator type AS indicator_type confidence framework actor source review_by
| where isnotnull(indicator)
| eval i=mvrange(0, mvcount(indicator))
| mvexpand i
| eval indicator=mvindex(indicator, i), indicator_type=mvindex(indicator_type, i), confidence=mvindex(confidence, i), framework=mvindex(framework, i), actor=mvindex(actor, i), source=mvindex(source, i), review_by=mvindex(review_by, i)
| `aad_active_indicator`
| eval aad_framework=split(framework, " ")
| {entity}
| stats count min(_time) AS first_seen max(_time) AS last_seen values(sourcetype) AS sourcetypes values(host) AS hosts BY aad_entity aad_value indicator indicator_type confidence aad_framework actor source
| eval _time=last_seen, aad_rule="{name}"
| convert ctime(first_seen) ctime(last_seen)"""

INDICATOR_SEARCHES = [
    ("Indicators - Reported addresses", "aad_ioc_ip", ["T1071"],
     "Traffic, web requests, sign-ins and CloudTrail calls to or from an address reported for an agentic attack framework.",
     "`aad_network`\n| eval aad_value=mvdedup(mvappend(src, src_ip, dest, dest_ip, clientip, c_ip, sourceIPAddress, ipAddress, IPAddress, callerIpAddress))\n| mvexpand aad_value\n| where match(aad_value, \"^[0-9a-fA-F:.]+$\")"),
    ("Indicators - Reported domains", "aad_ioc_domain", ["T1071.004", "T1583.001"],
     "DNS queries and web requests for a domain, or a subdomain of one, reported for an agentic attack framework.",
     "`aad_domains`\n| eval aad_value=lower(trim(coalesce(query, url_domain, dest_host, site), \".\"))\n| where isnotnull(aad_value)"),
    ("Indicators - Reported file hashes", "aad_ioc_hash", ["T1105"],
     "A process or file whose MD5 or SHA-256 was reported for an agentic attack framework or its implants.",
     "`aad_hashes`\n| rex field=Hashes \"(?i)MD5=(?<aad_md5>[0-9a-f]{32})\"\n| rex field=Hashes \"(?i)SHA256=(?<aad_sha256>[0-9a-f]{64})\"\n| eval aad_value=mvdedup(mvappend(lower(file_hash), lower(process_hash), lower(aad_md5), lower(aad_sha256), lower(md5), lower(sha256)))\n| mvexpand aad_value"),
    ("Indicators - Reported user agents", "aad_ioc_user_agent", ["T1595"],
     "A web request, sign-in or cloud API call whose user agent contains one reported for an agentic attack framework.",
     "`aad_user_agents`\n| eval aad_value=coalesce(http_user_agent, useragent, userAgent, user_agent, cs_user_agent, 'client.userAgent.rawUserAgent', 'properties.userAgent')\n| where isnotnull(aad_value)"),
]


def indicator_searches():
    out = []
    for name, lookup, techs, desc, head in INDICATOR_SEARCHES:
        out.append((None, name, {"description": desc + " Uses the indicator lookups built from iocs/indicators.csv.",
                                 "search": head + "\n" + INDICATOR_TAIL.format(
                                     lookup=lookup, name=name,
                                     entity="eval aad_entity=aad_value" if lookup == "aad_ioc_ip" else "`aad_entity`"),
                                 "_level": "high", "_techniques": techs, "_window": ("-25h@h", "-1h@h"),
                                 "_cron": f"{minute_for(name)} * * * *"}))
    return out


def saved_search_settings(name, s, artex=False):
    out = {"description": s["description"], "search": s["search"]}
    if artex:
        for k, v in s.items():
            if k.startswith("_") or k in ("description", "search"):
                continue
            out[k] = v
    else:
        earliest, latest = s.get("_window", ("-70m@m", "-10m@m"))
        out.update({"dispatch.earliest_time": earliest, "dispatch.latest_time": latest,
                    "cron_schedule": s.get("_cron", f"{minute_for(name)} * * * *"),
                    "enableSched": "1", "disabled": "1",
                    "counttype": "number of events", "relation": "greater than", "quantity": "0",
                    "alert.track": "1", "alert.digest_mode": "1",
                    "alert.severity": str(SEVERITY.get(s.get("_level", "medium"), 4))})
    out["disabled"] = "1"
    out["counttype"] = "number of events"
    out["relation"] = "greater than"
    out["quantity"] = "0"
    out["alert.track"] = "1"
    if out.get("alert.digest_mode", "1").strip() == "0":
        # Splunk refuses the summary index action on a search that alerts per result. The Log Event action writes
        # the same fields for each result that is not suppressed.
        out["action.logevent"] = "1"
        out["action.logevent.param.index"] = "summary"
        out["action.logevent.param.sourcetype"] = "aad:result"
        out["action.logevent.param.source"] = name
        out["action.logevent.param.event"] = ('search_name="$name$" aad_framework="$result.aad_framework$" '
                                              'aad_entity="$result.aad_entity$" aad_rule="$result.aad_rule$"')
    else:
        out["action.summary_index"] = "1"
        out["action.summary_index._name"] = "summary"
    out["action.correlationsearch.annotations"] = annotations(s["_techniques"])
    return out


def savedsearches():
    sig = sigma_searches()
    art = artex_searches()
    ind = indicator_searches()
    names = [n for _, n, _ in sig + art + ind]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        raise SystemExit(f"duplicate saved search names: {dup}")
    order = list(FRAMEWORKS)
    rows = []
    for fw, name, s in art:
        rows.append((order.index("artex"), 0, name, saved_search_settings(name, s, artex=True)))
    for fw, name, s in sig:
        rows.append((order.index(fw), 1, name, saved_search_settings(name, s)))
    for _, name, s in ind:
        rows.append((len(order), 0, name, saved_search_settings(name, s)))
    rows.sort(key=lambda r: (r[0], r[1], r[2].lower()))
    text = HEADER.format(repo=REPO) + (
        "# Every search ships disabled. Point the macros in macros.conf at your data, run a search over 30 days to baseline it,\n"
        "# then enable it. Results go to the summary index for the Agentic Attack Activity dashboard and to Triggered Alerts.\n"
        "# ATT&CK techniques are in action.correlationsearch.annotations, which Splunk Enterprise Security reads.\n\n")
    text += "\n".join(stanza(name, s) for _, _, name, s in rows)
    per_fw = {}
    for fw, _, _ in sig + art:
        per_fw[fw] = per_fw.get(fw, 0) + 1
    return text, per_fw, len(rows), len(ind)


def macros_conf():
    text = HEADER.format(repo=REPO) + "# Point aad_indexes at your indexes. Change a data source macro if your data is not tagged for the CIM.\n\n"
    for name, definition, comment in MACROS:
        text += f"# {comment}\n" + stanza(name, {"definition": definition}) + "\n"
    artex = read_conf(ARTEX_APP / "default" / "macros.conf")
    text += "# Macros used by the hand-written ARTEX searches. artex_indexes follows aad_indexes.\n"
    for name, s in artex.items():
        s = dict(s)
        if name == "artex_indexes":
            s["definition"] = "`aad_indexes`"
        text += stanza(name, s) + "\n"
    return text.rstrip("\n") + "\n"


def transforms_conf():
    text = HEADER.format(repo=REPO) + "\n"
    for name, s in TRANSFORMS:
        text += stanza(name, s) + "\n"
    artex = read_conf(ARTEX_APP / "default" / "transforms.conf")
    for name, s in artex.items():
        text += stanza(name, s) + "\n"
    return text.rstrip("\n") + "\n"


def app_conf(version):
    return HEADER.format(repo=REPO) + f"""
[install]
is_configured = 0
build = {version.replace('.', '')}

[ui]
is_visible = 1
label = Agentic Attack Detections

[launcher]
author = Agentic Attack Detections contributors
description = Searches, indicator lookups and a dashboard for agentic attack frameworks: ARTEX, CyberStrikeAI, PentAGI, Cairn, Hermes Agent, Strix, HexStrike, Agent Zero, RedAmon, Xalgorix and Pentest Swarm AI.
version = {version}

[package]
id = {APP}
check_for_updates = 0

[id]
name = {APP}
version = {version}
"""


NAV = """<nav search_view="search" color="#1A1C20">
  <view name="agentic_attack_activity" default="true" />
  <collection label="Searches">
    <saved source="unclassified" match="" />
  </collection>
  <view name="search" />
</nav>
"""

META = """[]
access = read : [ * ], write : [ admin, sc_admin ]
export = system

[views]
export = none

[savedsearches]
export = none
"""


def dashboard(counts):
    """Dashboard Studio definition: one card per framework, then the latest results."""
    bg, card, line, muted, text = "#0F1117", "#1A1C20", "#2A2E35", "#9AA0A6", "#E8EAED"
    W, cw, ch, gap, top = 1440, 342, 300, 18, 18
    viz, ds, layout = {}, {}, []
    ds["base"] = {"type": "ds.search", "name": "Results by framework", "options": {
        "query": ("index=summary search_name=* aad_framework=* aad_entity=*\n| fields _time aad_framework aad_entity aad_rule\n"
                  "| append [| makeresults | eval aad_framework=\"none\"]"),
        "queryParameters": {"earliest": "$global_time.earliest$", "latest": "$global_time.latest$"}}}
    ds["alltime"] = {"type": "ds.search", "name": "All time", "options": {
        "query": ("index=summary search_name=* aad_framework=* aad_entity=*\n"
                  "| stats min(_time) AS first_seen BY aad_framework aad_entity\n"
                  "| stats dc(aad_entity) AS all_time count(eval(first_seen >= relative_time(now(), \"-7d@d\"))) AS new BY aad_framework"),
        "queryParameters": {"earliest": "0", "latest": "now"}}}
    for i, (fw, (display, color, port, desc)) in enumerate(FRAMEWORKS.items()):
        col, row = i % 4, i // 4
        x, y = gap + col * (cw + gap), top + row * (ch + gap)
        k = re.sub(r"[^a-z0-9]", "_", fw)
        ds[f"t_{k}"] = {"type": "ds.chain", "options": {"extend": "base", "query": (
            f"| eval h=if(aad_framework=\"{fw}\", 1, 0), e=if(aad_framework=\"{fw}\", aad_entity, null())\n"
            "| eventstats dc(e) AS sources\n"
            "| timechart span=1d sum(h) AS hits max(sources) AS sources\n| fillnull value=0 hits\n"
            "| eventstats max(sources) AS sources sum(hits) AS total_hits\n| fillnull value=0 sources total_hits")}}
        ds[f"a_{k}"] = {"type": "ds.chain", "options": {"extend": "alltime", "query": f"| search aad_framework=\"{fw}\"\n| append [| makeresults | eval all_time=0, new=0]\n| stats max(all_time) AS all_time max(new) AS new"}}
        items = [
            (f"bg_{k}", {"type": "splunk.rectangle", "options": {"fillColor": card, "strokeColor": line, "rx": 8}}, x, y, cw, ch),
            (f"bar_{k}", {"type": "splunk.rectangle", "options": {"fillColor": color, "strokeColor": color}}, x + 6, y, cw - 12, 3),
            (f"dot_{k}", {"type": "splunk.rectangle", "options": {"fillColor": color, "strokeColor": color, "rx": 2}}, x + 20, y + 24, 10, 10),
            (f"name_{k}", {"type": "splunk.markdown", "options": {"markdown": f"**{display}**", "fontColor": text, "fontSize": "large"}}, x + 38, y + 14, cw - 50, 30),
            (f"desc_{k}", {"type": "splunk.markdown", "options": {"markdown": desc, "fontColor": muted, "fontSize": "small"}}, x + 20, y + 46, cw - 36, 48),
            (f"big_{k}", {"type": "splunk.singlevalue", "dataSources": {"primary": f"t_{k}"}, "options": {
                "majorValue": "> primary | seriesByName('sources') | lastPoint()",
                "sparklineValues": "> primary | seriesByName('hits')",
                "trendDisplay": "off", "sparklineDisplay": "below", "showSparklineAreaGraph": True,
                "sparklineStrokeColor": color, "sparklineAreaColor": color, "majorColor": text,
                "underLabel": "hosts and addresses", "underLabelFontSize": 12, "backgroundColor": card, "majorFontSize": 40}}, x + 14, y + 96, cw - 28, 130),
            (f"rule_{k}", {"type": "splunk.rectangle", "options": {"fillColor": line, "strokeColor": line}}, x + 20, y + 234, cw - 40, 1),
            (f"hits_{k}", {"type": "splunk.singlevalue", "dataSources": {"primary": f"t_{k}"}, "options": {
                "majorValue": "> primary | seriesByName('total_hits') | lastPoint()", "trendDisplay": "off", "sparklineDisplay": "off",
                "majorColor": text, "majorFontSize": 18, "backgroundColor": card, "underLabel": "results", "underLabelFontSize": 12}}, x + 14, y + 240, 80, 54),
            (f"new_{k}", {"type": "splunk.singlevalue", "dataSources": {"primary": f"a_{k}"}, "options": {
                "majorValue": "> primary | seriesByName('new') | lastPoint()", "trendDisplay": "off", "sparklineDisplay": "off",
                "majorColor": text, "majorFontSize": 18, "backgroundColor": card, "underLabel": "new, 7 days", "underLabelFontSize": 12}}, x + 96, y + 240, 84, 54),
            (f"all_{k}", {"type": "splunk.singlevalue", "dataSources": {"primary": f"a_{k}"}, "options": {
                "majorValue": "> primary | seriesByName('all_time') | lastPoint()", "trendDisplay": "off", "sparklineDisplay": "off",
                "majorColor": text, "majorFontSize": 18, "backgroundColor": card, "underLabel": "all time", "underLabelFontSize": 12}}, x + 182, y + 240, 76, 54),
            (f"port_{k}", {"type": "splunk.markdown", "options": {
                "markdown": (f"**{port}**  \nconsole port" if port else "**any**  \nframework"), "fontColor": muted, "fontSize": "small"}}, x + 262, y + 246, 76, 48),
        ]
        for name, v, ix, iy, iw, ih in items:
            viz[name] = v
            layout.append({"item": name, "type": "block", "position": {"x": ix, "y": iy, "w": iw, "h": ih}})
    rows = (len(FRAMEWORKS) + 3) // 4
    ty = top + rows * (ch + gap) + 10
    ds["latest"] = {"type": "ds.search", "name": "Latest results", "options": {
        "query": ("index=summary search_name=* aad_framework=* aad_entity=*\n"
                  "| stats count AS results max(_time) AS last_seen BY aad_framework search_name aad_entity\n"
                  "| sort - last_seen\n| head 200\n| eval last_seen=strftime(last_seen, \"%Y-%m-%d %H:%M\")\n"
                  "| rename aad_framework AS framework search_name AS search aad_entity AS \"host or address\""),
        "queryParameters": {"earliest": "$global_time.earliest$", "latest": "$global_time.latest$"}}}
    viz["latest_title"] = {"type": "splunk.markdown", "options": {"markdown": "### Latest results", "fontColor": text}}
    viz["latest"] = {"type": "splunk.table", "dataSources": {"primary": "latest"}, "options": {"backgroundColor": card}}
    layout.append({"item": "latest_title", "type": "block", "position": {"x": gap, "y": ty, "w": 600, "h": 36}})
    layout.append({"item": "latest", "type": "block", "position": {"x": gap, "y": ty + 40, "w": W - 2 * gap, "h": 420}})
    height = ty + 40 + 420 + gap
    background = {"bg": None}
    definition = {
        "title": "Agentic Attack Activity",
        "description": "",
        "inputs": {"time": {"type": "input.timerange", "title": "Time range", "options": {"token": "global_time", "defaultValue": "-30d@d,now"}}},
        "defaults": {"dataSources": {"ds.search": {"options": {"queryParameters": {"earliest": "$global_time.earliest$", "latest": "$global_time.latest$"}}}}},
        "visualizations": viz,
        "dataSources": ds,
        "layout": {"type": "absolute", "options": {"width": W, "height": height, "backgroundColor": bg, "display": "auto-scale"},
                   "structure": layout, "globalInputs": ["time"]},
    }
    del background
    body = json.dumps(definition, indent=2, sort_keys=False)
    return ('<dashboard version="2" theme="dark">\n  <label>Agentic Attack Activity</label>\n  <description></description>\n'
            f"  <definition><![CDATA[\n{body}\n  ]]></definition>\n"
            '  <meta type="hiddenElements"><![CDATA[\n{\n  "hideEdit": false,\n  "hideOpenInSearch": false,\n  "hideExport": false\n}\n  ]]></meta>\n'
            "</dashboard>\n")


def readme(version, per_fw, total, n_ind, counts):
    lines = [f"Agentic Attack Detections for Splunk, version {version}", "", REPO, "",
             f"{total} saved searches, all disabled, and the Agentic Attack Activity dashboard.", "",
             "Searches per framework:"]
    for fw, (display, *_rest) in FRAMEWORKS.items():
        if fw in per_fw:
            lines.append(f"  {display}: {per_fw[fw]}")
    lines += [f"  Indicator searches: {n_ind} (addresses, domains, file hashes, user agents)", "",
              f"Lookups: aad_indicators.csv has all {counts['all']} rows of iocs/indicators.csv. aad_ioc_ip, aad_ioc_domain,",
              "aad_ioc_hash and aad_ioc_user_agent hold the rows the indicator searches match on.", "",
              "Set up:",
              "  1. Install the app (Apps > Manage Apps > Install app from file).",
              "  2. Settings > Advanced search > Search macros: point aad_indexes at your indexes. The data source macros",
              "     (aad_process, aad_file, aad_registry, aad_dns, aad_proxy, aad_web, aad_aws_cloudtrail, aad_azure_*,",
              "     aad_okta) use CIM tags and sourcetypes; change one if your data is tagged differently.",
              "  3. Run a search over 30 days to baseline it, then enable it.",
              "  4. Enabled searches write their results to the summary index; the dashboard reads them from there.", ""]
    return "\n".join(lines)


def build(version):
    ss, per_fw, total, n_ind = savedsearches()
    files_lookups, counts = lookups()
    files = {
        "default/app.conf": app_conf(version),
        "default/savedsearches.conf": ss,
        "default/macros.conf": macros_conf(),
        "default/transforms.conf": transforms_conf(),
        "default/data/ui/nav/default.xml": NAV,
        "default/data/ui/views/agentic_attack_activity.xml": dashboard(counts),
        "metadata/default.meta": META,
        "README.txt": readme(version, per_fw, total, n_ind, counts),
    }
    for name, text in files_lookups.items():
        files[f"lookups/{name}"] = text
    return files, per_fw, total


def version_from_changelog():
    m = re.search(r"^## (\d+\.\d+\.\d+)", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    return m.group(1)


def package(files, out_dir):
    from build_release import write_splunk_tgz
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{NAME}-splunk.tgz"
    write_splunk_tgz(path, files, APP)
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if deploy/splunk/ is not what this script writes")
    ap.add_argument("--package", metavar="DIR", help="also write DIR/agentic-attack-detections-splunk.tgz")
    ap.add_argument("--version", default=None, help="app version, default: the top entry in CHANGELOG.md")
    ap.add_argument("--appinspect-result", metavar="JSON", help="read a splunk-appinspect JSON report and fail on any failure or error")
    args = ap.parse_args()
    if args.appinspect_result:
        report = json.loads(Path(args.appinspect_result).read_text(encoding="utf-8"))
        bad = []
        for r in report["reports"]:
            for g in r["groups"]:
                for c in g["checks"]:
                    if c["result"] in ("failure", "error"):
                        bad.append(f"{c['result']}: {c['name']}: " + "; ".join(m["message"] for m in c["messages"])[:500])
        print("\n".join(bad) if bad else f"appinspect: {report['summary']}")
        return 1 if bad else 0
    version = (args.version or version_from_changelog()).lstrip("v")
    files, per_fw, total = build(version_from_changelog())
    app_dir = OUT / APP
    if args.check:
        on_disk = {p.relative_to(app_dir).as_posix(): p.read_text(encoding="utf-8") for p in app_dir.rglob("*") if p.is_file()}
        if on_disk != files:
            changed = sorted(set(on_disk) ^ set(files) | {k for k in files if on_disk.get(k) != files[k]})
            print("deploy/splunk/ is out of date. Run tools/build_splunk.py and commit it. Differs: " + ", ".join(changed))
            return 1
        print(f"splunk app: {total} saved searches, up to date")
    else:
        for p in sorted(app_dir.rglob("*"), reverse=True) if app_dir.exists() else []:
            p.unlink() if p.is_file() else p.rmdir()
        for n, text in files.items():
            dest = app_dir / n
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
        print(f"deploy/splunk/{APP}: {total} saved searches ({', '.join(f'{k} {v}' for k, v in per_fw.items())}), {len(files)} files")
    if args.package:
        if version != version_from_changelog():
            files, _, _ = build(version)
        print(f"{package(files, Path(args.package))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
