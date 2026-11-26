#!/usr/bin/env python3
"""Build every indicator feed from iocs/indicators.csv, the single source of truth for all frameworks.

    python3 tools/build_feeds.py

Each row names the framework(s) it belongs to in the "framework" column (space separated, for example "artex cairn").

Writes:
    feeds/ipv4.txt, ipv6.txt, domains.txt, urls.txt, user_agents.txt, sha256.txt, md5.txt   plain lists for all frameworks,
                                                                         medium and high confidence only
    feeds/by-framework/<framework>/*.txt                                 the same lists per framework
    feeds/sentinel-watchlist.csv      Microsoft Sentinel watchlist (alias AGENTIC_IOCs, search key "value")
    feeds/stix2.1-bundle.json         STIX 2.1 bundle: indicators, one tool per framework and the actors
    frameworks/<framework>/zeek/intel/<framework>.intel      Zeek Intel framework file
    frameworks/<framework>/suricata/<framework>-ip.rules     Suricata rules for the reported addresses
    frameworks/artex/splunk/lookups/artex_iocs.csv           Splunk lookup used by the ARTEX Splunk app

Standard library only, so it runs anywhere Python 3.9+ does.
"""
import csv
import re
import datetime as dt
import hashlib
import json
import uuid
from collections import defaultdict
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import attack  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "iocs" / "indicators.csv"
NOW = "2026-11-21T00:00:00.000Z"
# Stable release cutoff, synchronized with waf/signatures.yaml.
# Wall-clock time must not make feed regeneration non-reproducible.
ACTIVE_AS_OF = "2026-11-23"
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
NS = uuid.UUID("5b2d4b5e-6c3a-4f0e-9a1e-7d8c2f3a4b10")  # fixed namespace so STIX ids stay stable between builds

FRAMEWORKS = {
    "artex": {"name": "ARTEX", "sid": 3800500, "created": "2026_11_20",
              "aliases": ["ScopeWeaver", "LUCK", "Guanlan SEC", "ARTEX PRO", "AntiFox"],
              "description": "Open-source agentic AI penetration testing framework published by Autumn-27 in July 2026 and abused in real intrusions.",
              "own_actor": "ARTEX operators"},
    "cairn": {"name": "Cairn", "sid": 3801500, "created": "2026_11_21",
              "aliases": ["oritera/Cairn"],
              "description": "Open-source agentic problem-solving engine (oritera/Cairn, April 2026) that drives Claude Code, Codex and Pi coding agents in Kali containers; abused for web intrusions and payment-card theft since mid-2026.",
              "own_actor": "Cairn operators"},
    "pentagi": {"name": "PentAGI", "sid": 3802500, "created": "2026_11_21",
                "aliases": ["vxcontrol/pentagi", "Penetration Testing Artificial General Intelligence"],
                "description": "Open-source and commercial multi-agent penetration testing platform by VXControl that runs its tools in Kali Linux containers; abused in the wild since at least August 2026.",
                "own_actor": "PentAGI operators"},
    "hexstrike": {"name": "HexStrike", "sid": 3803500, "created": "2026_11_21",
                  "aliases": ["HexStrike AI", "0x4m4/hexstrike-ai"],
                  "description": "Open-source MCP tool server that exposes about 150 security tools to any AI assistant over an unauthenticated HTTP API; discussed for NetScaler exploitation in 2025 and seen by GTIG and Mandiant in intrusions.",
                  "own_actor": "HexStrike operators"},
    "cyberstrikeai": {"name": "CyberStrikeAI", "sid": 3804500, "created": "2026_11_21",
                      "aliases": ["AIPentest/CyberStrikeAI", "Ed1s0nZ/CyberStrikeAI", "DarkAI"],
                      "description": "Open-source Go operator console (Ed1s0nZ, later AIPentest, November 2025) whose AI agents run about 90 security tools and which builds its own implants, C2 listeners and webshell manager; tied to the FortiGate mass-exploitation infrastructure, an AWS intrusion and attacks on education organizations.",
                      "own_actor": "CyberStrikeAI operators"},
    "strix": {"name": "Strix", "sid": 3805500, "created": "2026_11_21",
              "aliases": ["usestrix/strix", "strix-agent"],
              "description": "Open-source Python AI penetration testing agent (usestrix/strix, August 2025) that runs teams of agents in a Kali sandbox container through a Caido proxy; used for vulnerability discovery in the 2026 retail card-theft campaign before Cairn exploitation.",
              "own_actor": "Strix operators"},
    "hermes": {"name": "Hermes Agent", "sid": 3806500, "created": "2026_11_21",
               "aliases": ["NousResearch/hermes-agent", "Hermes"],
               "description": "Open-source general-purpose AI agent from Nous Research with persistent memory, self-written skills, a SOUL.md persona, a Telegram gateway and a yolo mode; used as the attack console by knaithe/KnYuan, the Gambit retail card-theft operator, the Carbonato Docker botnet and against Thailand's Ministry of Finance.",
               "own_actor": "Hermes Agent operators"},
    "agent-zero": {"name": "Agent Zero", "sid": 3807500, "created": "2026_11_21",
                   "aliases": ["agent0ai/agent-zero", "AgentZero"],
                   "description": "Open-source general-purpose AI agent framework that runs in a Kali-based container with a built-in hacker profile and a web UI; GTIG reported threat-actor experimentation with it in 2026.",
                   "own_actor": "Agent Zero operators"},
    "redamon": {"name": "RedAmon", "sid": 3808500, "created": "2026_11_23",
                "aliases": ["samugit83/redamon"],
                "description": "Open-source self-hosted penetration testing platform (samugit83/redamon, December 2025): a Docker stack with a web console, a recon pipeline and an agent that exploits from a Kali sandbox with Metasploit; no public report of use in an intrusion.",
                "own_actor": "RedAmon operators"},
    "xalgorix": {"name": "Xalgorix", "sid": 3809500, "created": "2026_11_23",
                 "aliases": ["xalgorix/xalgorix", "xalgord/xalgorix"],
                 "description": "Open-source Go binary with a web dashboard (xalgorix/xalgorix, March 2026) whose agent runs a web and API penetration test without approval steps and re-exploits each finding; no public report of use in an intrusion.",
                 "own_actor": "Xalgorix operators"},
    "pentestswarm": {"name": "Pentest Swarm AI", "sid": 3810500, "created": "2026_11_23",
                     "aliases": ["Armur-Ai/Pentest-Swarm-AI", "pentestswarm"],
                     "description": "Open-source Go command-line tool (Armur-Ai/Pentest-Swarm-AI, 2026) that runs recon, exploit and report agents over about 40 security tools; no public report of use in an intrusion.",
                     "own_actor": "Pentest Swarm AI operators"},
    # Console-level frameworks added from the November 25, 2026 exposure snapshot. Each has a block of 100 SIDs:
    # hand-written rules from base - 49 to base - 1, address rules from base (docs/adding-a-framework.md).
    "autocve": {"name": "AutoCVE", "sid": 3811050, "created": "2026_11_25",
        "aliases": ["larlarua/AutoCVE"],
        "description": "Open-source agent-driven CVE discovery platform (larlarua/AutoCVE, June 2026) that audits source code, verifies findings and writes reports, with a web console on port 3000 and an API on port 8000; no public report of use in an intrusion.",
        "own_actor": "AutoCVE operators"},
    "cyberstrike": {"name": "CyberStrike", "sid": 3811150, "created": "2026_11_25",
        "aliases": ["CyberStrikeus/CyberStrike", "CyberStrikeus/cyberstrike"],
        "description": "Open-core TypeScript offensive security harness (CyberStrikeus/CyberStrike, February 2026) whose agents run web and network tests with a browser extension and a callback server, with a web console on port 4096; not related to CyberStrikeAI; no public report of use in an intrusion.",
        "own_actor": "CyberStrike operators"},
    "vulnerator-ai": {"name": "Vulnerator AI", "sid": 3811250, "created": "2026_11_25",
        "aliases": ["irraz/vulnerator-ai", "Vulnerator"],
        "description": "Open-source OODA-loop penetration testing agent (irraz/vulnerator-ai, October 2026) that drives Kali and Playwright tools over MCP from a Hermes Agent brain, with an operator console on port 9100; no public report of use in an intrusion.",
        "own_actor": "Vulnerator AI operators"},
    "decepticon": {"name": "Decepticon", "sid": 3811350, "created": "2026_11_25",
        "aliases": ["BitterSecurity/Decepticon"],
        "description": "Open-source autonomous red team agent (BitterSecurity/Decepticon, June 2025) built on LangGraph with a Kali sandbox and on-demand Sliver and Havoc C2, whose installer turns on usage telemetry unless the operator declines; its open web console on port 3000 was removed in November 2026 in favour of a hosted one; no public report of use in an intrusion.",
        "own_actor": "Decepticon operators"},
    "aida": {"name": "AIDA", "sid": 3811450, "created": "2026_11_25",
        "aliases": ["Vasco0x4/AIDA", "AI-Driven Security Assessment"],
        "description": "Open-source platform (Vasco0x4/AIDA, January 2026) that turns a model into a penetration tester working from its own tool container or Exegol, with a web console on port 31337; no public report of use in an intrusion.",
        "own_actor": "AIDA operators"},
    "bugtraceai": {"name": "BugTraceAI", "sid": 3811550, "created": "2026_11_25",
        "aliases": ["BugTraceAI/BugTraceAI", "BugTraceAI-CLI", "BugTraceAI-WEB"],
        "description": "Open-source self-hosted web penetration testing suite (BugTraceAI, February 2026) with agentic scanning, a web interface, an API on port 8000 and MCP servers; no public report of use in an intrusion.",
        "own_actor": "BugTraceAI operators"},
    "z3r0": {"name": "Z3r0", "sid": 3811650, "created": "2026_11_25",
        "aliases": ["yv1ing/Z3r0"],
        "description": "Open-source AI red team workbench (yv1ing/Z3r0, April 2026) with specialist agents, sandboxed tools and an egress proxy pool, with a web console on port 8000; no public report of use in an intrusion.",
        "own_actor": "Z3r0 operators"},
    "airecon": {"name": "AIRecon", "sid": 3811750, "created": "2026_11_25",
        "aliases": ["pikpikcu/airecon"],
        "description": "Open-source autonomous reconnaissance agent (pikpikcu/airecon, March 2026) that drives a Kali Docker sandbox from a local Ollama model and runs its own SearXNG instance; no public report of use in an intrusion.",
        "own_actor": "AIRecon operators"},
    "luan1aoagent": {"name": "LuaN1aoAgent", "sid": 3811850, "created": "2026_11_25",
        "aliases": ["SanMuzZzZz/LuaN1aoAgent", "鸾鸟渗透智能体", "LuaN1ao"],
        "description": "Open-source autonomous penetration testing agent with graph-based planning (SanMuzZzZz/LuaN1aoAgent, December 2025), with a web workbench on port 8787 and a chisel tunnel server for its sandbox; no public report of use in an intrusion.",
        "own_actor": "LuaN1aoAgent operators"},
    "open-kritt": {"name": "open-kritt", "sid": 3811950, "created": "2026_11_25",
        "aliases": ["Kritt-ai/open-kritt", "kritt"],
        "description": "Open-source self-hosted AI vulnerability research tool (Kritt-ai/open-kritt, July 2026) whose agents find and validate flaws in code, with a web interface on port 5173 and an executor view on port 8090; no public report of use in an intrusion.",
        "own_actor": "open-kritt operators"},
    "redcell": {"name": "REDCELL", "sid": 3812050, "created": "2026_11_25",
        "aliases": ["martian56/redcell"],
        "description": "Open-source AI red team platform (martian56/redcell, August 2026) whose LangGraph agents run a penetration test end to end inside a Kali container and write the report; no public report of use in an intrusion.",
        "own_actor": "REDCELL operators"},
    "t3mp3st": {"name": "T3MP3ST", "sid": 3812150, "created": "2026_11_25",
        "aliases": ["elder-plinius/T3MP3ST"],
        "description": "Open-source multi-agent red teaming harness (elder-plinius/T3MP3ST, July 2026) with a command and control dashboard on port 3333; no public report of use in an intrusion.",
        "own_actor": "T3MP3ST operators"},
    "wormxgpt": {"name": "WormXGPT", "sid": 3812250, "created": "2026_11_25",
        "aliases": ["gaur-avvv/wormxgpt", "WormGPT Red Terminal"],
        "description": "Open-source hacker-themed AI tooling suite (gaur-avvv/wormxgpt, January 2026) with a web terminal on port 3000 that calls security tools from a model told to ignore its limits; it borrows the WormGPT name but is not the criminal service; no public report of use in an intrusion.",
        "own_actor": "WormXGPT operators"},
    "chufeng": {"name": "Chufeng Agent Core", "sid": 3812350, "created": "2026_11_25",
        "aliases": ["楚锋 Agent Core"],
        "description": "Self-hosted agent workspace titled 楚锋 Agent Core, seen on Chinese cloud hosts in November 2026, whose sign-in page offers CTF, digital forensics and authorised penetration testing tasks; no public source code or report found.",
        "own_actor": "Chufeng Agent Core operators"},
    "hacksynth": {"name": "HackSynth", "sid": 3812450, "created": "2026_11_26",
                  "aliases": ["aielte-research/HackSynth"],
                  "description": "Open-source Python research agent from ELTE (aielte-research/HackSynth, November 2024, arXiv 2412.01778) for autonomous penetration testing in CTF games: a Planner model writes one bash command per step, run in a Kali container through the Docker API, and a Summarizer model keeps the history; no web UI.",
                  "own_actor": "HackSynth operators"},
    "autopt": {"name": "AutoPT", "sid": 3812650, "created": "2026_11_26",
        "aliases": ["evenhu9/AutoPT", "Dizzy-K/AutoPT"],
        "description": "Research LLM web penetration testing agent (Dizzy-K/AutoPT, September 2024, code of the AutoPT paper; evenhu9/AutoPT, December 2025, the same engine with a Flask console) that scans one IP with nmap and xray and runs public vulhub exploits for 20 benchmark CVEs, with an unauthenticated web console on port 5000; no public report of use in an intrusion.",
        "own_actor": "AutoPT operators"},
    "pentestgpt": {"name": "PentestGPT", "sid": 3814500, "created": "2026_11_26",
                   "aliases": ["GreyDGL/PentestGPT", "pentestgpt-agent", "pentestgpt-legacy"],
                   "description": "Open-source Python AI penetration testing agent from the USENIX Security 2024 paper (GreyDGL/PentestGPT, February 2023) that drives the Claude Code or Codex CLI with permission checks off; v1.0.0 sent Langfuse telemetry by default. No web console; no public report of use in an intrusion.",
                   "own_actor": "PentestGPT operators"},
    "cai": {"name": "CAI", "sid": 3816500, "created": "2026_11_26",
            "aliases": ["aliasrobotics/cai", "cai-framework", "Cybersecurity AI"],
            "description": "Open-source Python AI security agent framework from Alias Robotics (aliasrobotics/cai, March 2025, archived August 2026) with red team, bug bounty and web pentest agents that run shell commands locally, in a Kali container or over SSH, default model alias1 through Alias's gateway, an optional HTTP API backend and session-log telemetry to logs.aliasrobotics.com.",
            "own_actor": "CAI operators"},
    "shannon": {"name": "Shannon", "sid": 3813500, "created": "2026_11_26",
                "aliases": ["KeygraphHQ/shannon", "@keygraph/shannon", "Shannon Lite", "keygraph/shannon"],
                "description": "Open-source white-box AI penetration testing agent from Keygraph (KeygraphHQ/shannon, September 2025, AGPL-3.0) that reads an application's source code and exploits the running web application with model-driven agents in a Docker worker orchestrated by Temporal; ships an experimental php2shell PHP crash probe.",
                "own_actor": "Shannon operators"},
    "vulnbot": {"name": "VulnBot", "sid": 3812550, "created": "2026_11_26",
        "aliases": ["KHenryAegis/VulnBot", "DeepPentest"],
        "description": "Open-source multi-agent autonomous penetration testing framework from an academic paper (KHenryAegis/VulnBot, arXiv 2501.13411, January 2025) whose reconnaissance, scanning and exploitation agents run Kali tools over SSH on a Kali host, with an optional unauthenticated knowledge base API on port 7861 and Streamlit page on 8501; no public report of use in an intrusion.",
        "own_actor": "VulnBot operators"},
    "cyber-autoagent": {"name": "Cyber-AutoAgent", "sid": 3815500, "created": "2026_11_26",
                        "aliases": ["westonbrown/Cyber-AutoAgent", "cyber-autoagent", "Cyber AutoAgent"],
                        "description": "Open-source Python agent on the Strands SDK with a terminal front end (westonbrown/Cyber-AutoAgent, May 2025, archived) that runs a penetration test from a Kali container without approval steps and ships a Langfuse stack with a fixed login; no public report of use in an intrusion.",
                        "own_actor": "Cyber-AutoAgent operators"},
    "pentestagent": {"name": "PentestAgent (paper code)", "sid": 3812750, "created": "2026_11_26",
        "aliases": ["nbshenxm/pentest-agent", "pentest-agent", "PentestAgent arXiv 2411.05185"],
        "description": "Open-source research code of the PentestAgent paper (nbshenxm/pentest-agent, arXiv 2411.05185, February 2025) whose Python agents run nmap, look up CVEs and public exploits and run one against a target; no web interface; not GH05TCREW/pentestagent; no public report of use in an intrusion.",
        "own_actor": "PentestAgent (nbshenxm paper code) operators"},
    "ghostcrew-pentestagent": {"name": "PentestAgent (GH05TCREW)", "sid": 3812850, "created": "2026_11_26",
        "aliases": ["GH05TCREW/pentestagent", "gh05tcrew/pentestagent"],
        "description": "Open-source Python AI agent framework for black-box testing (GH05TCREW/pentestagent, May 2025) with a terminal UI, a multi-agent crew mode, Kali sandbox images and an MCP server that listens on 0.0.0.0:8080 without authentication; not the nbshenxm/pentest-agent paper code; no public report of use in an intrusion.",
        "own_actor": "PentestAgent (GH05TCREW) operators"},
    "darkmoon": {"name": "DarkMoon", "sid": 3812950, "created": "2026_11_26",
        "aliases": ["ASCIT31/Dark-Moon", "Dark-Moon", "Darkmoon", "ascit/darkmoon"],
        "description": "Open-source autonomous AI penetration testing stack from ASC IT (ASCIT31/Dark-Moon, November 2024) that runs about 50 OpenCode agents whose commands go through an MCP server into a root toolbox container; no web console in the open-source edition and no public report of use in an intrusion.",
        "own_actor": "DarkMoon operators"},
    "sapper-v2": {"name": "sapper-v2", "sid": 3817150, "created": "2026_11_26",
        "aliases": ["N1nEmAn/sapper-v2"],
        "description": "Open-source contest kit (N1nEmAn/sapper-v2, October 2026) that runs several Claude Code and Codex sessions in tmux with approvals off against penetration-testing targets, sharing an engagement graph on disk, with an unauthenticated web board; no public report of use in an intrusion.",
        "own_actor": "sapper-v2 operators"},
    "nyxstrike": {"name": "NyxStrike", "sid": 3817050, "created": "2026_11_26",
                  "aliases": ["CommonHuman-Lab/nyxstrike", "HexStrike AI Community Edition", "CommonHuman-Lab/hexstrike-ai-community-edition"],
                  "description": "Open-source AGPL-3.0 derivative of HexStrike AI (CommonHuman-Lab/nyxstrike, renamed from HexStrike AI Community Edition in April 2026) that exposes about 200 offensive tools to any MCP client or its own LLM agents through a Flask server on port 8888, with a React dashboard, a decision engine and a hash-chained evidence log; no public report of use in an intrusion.",
                  "own_actor": "NyxStrike operators"},
    "neurosploit": {"name": "NeuroSploit", "sid": 3817250, "created": "2026_11_26",
        "aliases": ["JoasASantos/NeuroSploit", "neurosploit-rs"],
        "description": "Open-source Rust harness with a Node.js web console (JoasASantos/NeuroSploit, August 2025) that runs reconnaissance, about 490 specialist agent prompts, replay and multi-model voting against a web target, with its own out-of-band listener and an opt-in C2 and web shell manager; it signs its requests with a NeuroSploit user agent and header by default; no public report of use in an intrusion.",
        "own_actor": "NeuroSploit operators"},
    "h-pentest": {"name": "H-Pentest", "sid": 3818250, "created": "2026_11_26",
                  "aliases": ["hexian2001/H-Pentest", "H-Pentest 2.0"],
                  "description": "Small open-source LLM penetration testing platform for CTF contests (hexian2001/H-Pentest, November 2025, unchanged since December 2025): a FastAPI backend on port 8000 and a Vue console on port 5173, both without authentication, a Docker sandbox for model-written Python, nuclei and dirsearch, defaulting to Zhipu GLM-4.6; no public report of use in an intrusion.",
                  "own_actor": "H-Pentest operators"},
    "hexstrike-redteam": {"name": "Hexstrike-redteam", "sid": 3817950, "created": "2026_11_26",
                          "aliases": ["Yenn503/Hexstrike-redteam", "HexStrike-BOAZ", "Hexstrike Red Team"],
                          "description": "Copy of HexStrike AI 6.0 (Yenn503/Hexstrike-redteam, October 2025) that adds the BOAZ payload evasion framework, so an AI assistant connected over MCP can wrap Windows payloads with 77 loaders and 12 encoders through the same unauthenticated Flask server on 0.0.0.0:8888; no public report of use in an intrusion.",
                          "own_actor": "Hexstrike-redteam operators"},
    "vigilo": {"name": "Vigilo", "sid": 3817450, "created": "2026_11_26",
        "aliases": ["certeu/vigilo", "Vigilo Platform API", "Vigilo-Greybox"],
        "description": "Open-source platform published by CERT-EU (certeu/vigilo, EUPL-1.2, July 2026) for AI-driven assessment of applications the operator is responsible for: white-box review with Claude Code, Codex CLI or OpenCode agents that prove findings and write fix branches, and a grey-box agent that tests a running web application, API or network through scope-checked tools; its grey-box requests carry the user agent Vigilo-Greybox/1 (authorised security test) and inert vigilo/vgl markers; no public report of use in an intrusion.",
        "own_actor": "Vigilo operators"},
    "chying-agent": {"name": "CHYing-agent", "sid": 3817750, "created": "2026_11_26",
        "aliases": ["yhy0/CHYing-agent", "CHYing Agent", "chying-agent-docker"],
        "description": "Open-source contest agent from the Tencent Cloud hackathon (yhy0/CHYing-agent, November 2025) whose Claude Agent SDK orchestrator, with permissions bypassed, drives a privileged Kali container, headless Chrome, a Ghidra MCP server and Metasploit, with an unauthenticated dashboard on port 8080; no public report of use in an intrusion.",
        "own_actor": "CHYing-agent operators"},
    "incalmo": {"name": "Incalmo", "sid": 3818350, "created": "2026_11_26",
                "aliases": ["cylabcyberautonomy/Incalmo", "bsinger98/Incalmo"],
                "description": "Open-source research system from Carnegie Mellon CyLab (cylabcyberautonomy/Incalmo, May 2025, arXiv 2501.16466) in which a language model plans a multi-host network attack through high-level actions that run as shell commands on hosts held by MITRE Caldera's Sandcat implant, tasked from an unauthenticated Flask C2 server on port 8888; no public report of use in an intrusion.",
                "own_actor": "Incalmo operators"},
    "pentest-copilot": {"name": "Pentest Copilot", "sid": 3817550, "created": "2026_11_26",
        "aliases": ["bugbasesecurity/pentest-copilot", "BugBase Pentest Copilot"],
        "description": "Open-source MIT web application from the bug bounty company BugBase (bugbasesecurity/pentest-copilot, March 2025, rebuilt as an agent in March 2026) whose LLM agent runs commands on a Kali box or SSH host, drives a browser agent, Burp Suite, Caido and VPNs, and can task implants through the operator's Mythic C2 server; also sold as a hosted service; no public report of use in an intrusion.",
        "own_actor": "Pentest Copilot operators"},
    "virga": {"name": "Virga", "sid": 3818450, "created": "2026_11_26",
              "aliases": ["r74tech/virga", "Virga C2"],
              "description": "Open-source experimental Go C2 framework (r74tech/virga, December 2025) whose beacon can carry a local language model that runs commands on the compromised host by itself, with unauthenticated MCP servers and admin API that let any MCP client drive the beacons; no public report of use in an intrusion.",
              "own_actor": "Virga operators"},
    "pentest-ai": {"name": "pentest-ai", "sid": 3818050, "created": "2026_11_26",
        "aliases": ["0xSteph/pentest-ai", "ptai"],
        "description": "Open-source Python command-line tool and MCP server (0xSteph/pentest-ai, PyPI ptai, 2026) that runs web, API, Active Directory and cloud probes driven by a model or an AI coding client and re-runs each finding before reporting it; it brands its requests with a pentest-ai user agent and an X-Request-ID that carry a per-machine id; no public report of use in an intrusion.",
        "own_actor": "pentest-ai operators"},
    "cyber-harness": {"name": "cyber-harness", "sid": 3817650, "created": "2026_11_26",
        "aliases": ["chainreactors/cyber-harness", "AIScan", "chainreactors/aiscan", "cyber-scan"],
        "description": "Open-source AGPL-3.0 Go agent harness from the chainreactors group (chainreactors/cyber-harness, May 2026, formerly AIScan) whose cyber-scan agent drives the gogo, spray, zombie and neutron scanners, a headless browser and shell commands without approval, with a cyber-audit code-audit agent and a Web Hub that scan nodes connect to; no public report of use in an intrusion.",
        "own_actor": "cyber-harness operators"},
    "lazyown": {"name": "LazyOwn", "sid": 3818150, "created": "2026_11_26",
        "aliases": ["grisuno/LazyOwn", "LazyOwn RedTeam Framework"],
        "description": "Open-source Python red team framework (grisuno/LazyOwn, AGPL-3.0) with a command shell of several hundred attack commands, a multi-operator Flask C2 (lazyc2.py) on port 4444 with HTTP and DNS beacon channels, a decoy page that captures visitors' camera and microphone, and an MCP server through which an AI agent drives the framework; public reports of use in intrusions were not searched for this draft.",
        "own_actor": "LazyOwn operators"},
}
ZEEK_TYPES = {"ipv4": "Intel::ADDR", "ipv6": "Intel::ADDR", "md5": "Intel::FILE_HASH", "domain": "Intel::DOMAIN", "user_agent": "Intel::SOFTWARE", "sha256": "Intel::FILE_HASH", "url": "Intel::URL"}


def load():
    with SRC.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def fw_of(r):
    return r.get("framework", "").split()


def only(rows, fw):
    return [r for r in rows if fw in fw_of(r)]


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def active_ip(r, as_of=ACTIVE_AS_OF):
    """Retain expired IP records in the historical CSV/STIX, not active feeds."""
    if r["type"] not in ("ipv4", "ipv6"):
        return True
    return not r.get("review_by") or r["review_by"] >= as_of


def plain_lists(rows, folder):
    for kind, name in [("ipv4", "ipv4.txt"), ("ipv6", "ipv6.txt"), ("domain", "domains.txt"), ("user_agent", "user_agents.txt"), ("sha256", "sha256.txt"), ("md5", "md5.txt"), ("url", "urls.txt")]:
        # Low-confidence rows stay out of the plain lists: many are legitimate services (AI model APIs, callback and
        # lookup services) that only mean something with their context, which a bare list cannot carry. They remain
        # in indicators.csv, the Sentinel watchlist, the STIX bundle and the Zeek intel files.
        values = sorted({r["value"] for r in rows if r["type"] == kind and r["confidence"] != "low" and active_ip(r)})
        write(folder / name, "\n".join(values) + "\n")


def table_csv(rows, path, cols):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def zeek_intel(rows, fw):
    label = FRAMEWORKS[fw]["name"]
    lines = ["#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url"]
    for r in rows:
        if not active_ip(r):
            continue
        t = "Intel::SUBNET" if r["type"] == "ipv4" and "/" in r["value"] else ZEEK_TYPES.get(r["type"])
        if not t:
            continue
        desc = f"{label} {r['confidence']}: {r['context']} ({r['actor']})".replace("\t", " ")
        value = r["value"].split("://", 1)[-1] if r["type"] == "url" else r["value"]  # Zeek URLs carry no scheme
        lines.append("\t".join([value, t, f"threatdefence-{fw}", desc, r["source_url"]]))
    write(ROOT / "frameworks" / fw / "zeek" / "intel" / f"{fw}.intel", "\n".join(lines) + "\n")


# A host of yours talking to a reported address is treated as command and control, and a reported address sending
# traffic in as scanning: the addresses are operator and scanning infrastructure, not victims.
IP_OUTBOUND = ", ".join(attack.suricata_metadata([("command-and-control", "T1071")]))
IP_INBOUND = ", ".join(attack.suricata_metadata([("reconnaissance", "T1595")]))


def suricata_ip(rows, fw):
    meta = FRAMEWORKS[fw]
    label = meta["name"]
    by_actor = defaultdict(list)
    for r in rows:
        if r["type"] in ("ipv4", "ipv6"):
            by_actor[(r["actor"], r["context"])].append(r)
    out = ["# Generated by tools/build_feeds.py from iocs/indicators.csv. Do not edit by hand.",
           f"# Reported {label} addresses. Overdue IPs omitted as of {ACTIVE_AS_OF}; historical rows remain in CSV/STIX."]
    sid = meta["sid"]
    for (actor, ctx), entries in sorted(by_actor.items()):
        active = [r for r in entries if active_ip(r)]
        if not active:
            # Preserve the historical pair so later groups retain their SIDs.
            sid += 2
            continue
        group = "[" + ",".join(sorted({r["value"] for r in active})) + "]"
        # An entire mixed-confidence rule must not claim higher confidence
        # than its least-supported member.
        confidence = min((r["confidence"] for r in active), key=CONFIDENCE_RANK.__getitem__).title()
        classtype = "misc-activity" if confidence == "Low" else "trojan-activity"
        msg = f"TD {label} reported address, {actor}, {ctx}".replace(";", ",").replace('"', "'")
        out.append(f'alert ip $HOME_NET any -> {group} any (msg:"{msg} (outbound)"; classtype:{classtype}; sid:{sid}; rev:2; metadata:created_at {meta["created"]}, confidence {confidence}, {IP_OUTBOUND};)')
        out.append(f'alert ip {group} any -> $HOME_NET any (msg:"{msg} (inbound)"; classtype:{classtype}; sid:{sid + 1}; rev:2; metadata:created_at {meta["created"]}, confidence {confidence}, {IP_INBOUND};)')
        sid += 2
    write(ROOT / "frameworks" / fw / "suricata" / f"{fw}-ip.rules", "\n".join(out) + "\n")

def sid_for(kind, value):
    return f"{kind}--{uuid.uuid5(NS, kind + ':' + value)}"


def stix_pattern(r):
    v = r["value"].replace("\\", "\\\\").replace("'", "\\'")
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "user_agent": f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{v}']",
        "ipv6": f"[ipv6-addr:value = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v.lower()}']",
        "file_name": f"[file:name LIKE '{v}%']",
        "file_path": f"[directory:path = '{v}']",
        "uri_string": f"[url:value LIKE '%{v}%']",
        "url": f"[url:value = '{v}']",
        "account_name": f"[user-account:account_login LIKE '%{v}%']",
    }.get(r["type"])


def stix(rows):
    identity = {"type": "identity", "spec_version": "2.1", "id": sid_for("identity", "ThreatDefence"), "created": NOW, "modified": NOW,
                "name": "ThreatDefence", "identity_class": "organization"}
    tools = {}
    for fw, meta in FRAMEWORKS.items():
        tools[fw] = {"type": "tool", "spec_version": "2.1", "id": sid_for("tool", meta["name"]), "created": NOW, "modified": NOW,
                     "name": meta["name"], "aliases": meta["aliases"], "description": meta["description"],
                     "tool_types": ["exploitation", "vulnerability-scanning"]}
    objects = [identity] + list(tools.values())
    own = tuple(m["own_actor"] for m in FRAMEWORKS.values()) + ("Related", "Unknown", "Unattributed")
    actors, uses = {}, set()
    for r in rows:
        a = r["actor"]
        if a and not a.startswith(own):
            actors.setdefault(a, {"type": "intrusion-set", "spec_version": "2.1", "id": sid_for("intrusion-set", a), "created": NOW, "modified": NOW, "name": a})
            for fw in fw_of(r):
                uses.add((a, fw))
    objects += actors.values()
    for a, fw in sorted(uses):
        name = actors[a]["name"]
        objects.append({"type": "relationship", "spec_version": "2.1", "id": sid_for("relationship", name + "-uses-" + fw),
                        "created": NOW, "modified": NOW, "relationship_type": "uses", "source_ref": actors[a]["id"], "target_ref": tools[fw]["id"]})
    for r in rows:
        pat = stix_pattern(r)
        if not pat:
            continue
        ind = {"type": "indicator", "spec_version": "2.1", "id": sid_for("indicator", r["type"] + r["value"]),
               "created": NOW, "modified": NOW, "created_by_ref": identity["id"],
               "name": f"{' and '.join(FRAMEWORKS[f]['name'] for f in fw_of(r))} {r['type']}: {r['value']}", "description": f"{r['context']}. Reported by {r['source']}.",
               "indicator_types": ["malicious-activity"] if r["confidence"] != "low" else ["anomalous-activity"],
               "pattern": pat, "pattern_type": "stix", "valid_from": f"{r['reported']}T00:00:00Z",
               "confidence": {"high": 85, "medium": 60, "low": 30}[r["confidence"]],
               "labels": fw_of(r) + [r["confidence"]],
               "external_references": [{"source_name": r["source"], "url": r["source_url"]}]}
        if r.get("review_by"):
            ind["valid_until"] = f"{r['review_by']}T00:00:00Z"
        objects.append(ind)
        targets = [actors[r["actor"]]] if r["actor"] in actors else [tools[f] for f in fw_of(r)]
        for target in targets:
            objects.append({"type": "relationship", "spec_version": "2.1", "id": sid_for("relationship", ind["id"] + target["id"]),
                            "created": NOW, "modified": NOW, "relationship_type": "indicates", "source_ref": ind["id"], "target_ref": target["id"]})
    digest = hashlib.sha256(json.dumps(objects, sort_keys=True).encode()).hexdigest()
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid5(NS, digest)}", "objects": objects}
    write(ROOT / "feeds" / "stix2.1-bundle.json", json.dumps(bundle, indent=1, ensure_ascii=False) + "\n")
    return sum(1 for o in objects if o["type"] == "indicator")


def main():
    rows = load()
    seen = set()
    for r in rows:
        key = (r["type"], r["value"])
        if key in seen:
            raise SystemExit(f"duplicate indicator {key}")
        seen.add(key)
        if r["confidence"] not in ("high", "medium", "low"):
            raise SystemExit(f"bad confidence for {key}")
        if r.get("review_by"):
            dt.date.fromisoformat(r["review_by"])
        hash_len = {"md5": 32, "sha256": 64}.get(r["type"])
        if hash_len and not re.fullmatch(f"[0-9a-fA-F]{{{hash_len}}}", r["value"]):
            raise SystemExit(f"{r['type']} must be {hash_len} hex characters: {key}")
        dt.date.fromisoformat(r["reported"])
        bad = [f for f in fw_of(r) if f not in FRAMEWORKS]
        if not fw_of(r) or bad:
            raise SystemExit(f"unknown or missing framework for {key}: {r.get('framework')!r}")
    cols = ["value", "type", "confidence", "context", "actor", "source", "source_url", "reported", "review_by", "framework"]
    plain_lists(rows, ROOT / "feeds")
    table_csv(rows, ROOT / "feeds" / "sentinel-watchlist.csv", cols)
    for fw in FRAMEWORKS:
        sub = only(rows, fw)
        plain_lists(sub, ROOT / "feeds" / "by-framework" / fw)
        zeek_intel(sub, fw)
        suricata_ip(sub, fw)
    table_csv(only(rows, "artex"), ROOT / "frameworks" / "artex" / "splunk" / "lookups" / "artex_iocs.csv", cols[:-1])
    n = stix(rows)
    print(f"{len(rows)} indicators, {n} STIX indicators, feeds written")


if __name__ == "__main__":
    main()
