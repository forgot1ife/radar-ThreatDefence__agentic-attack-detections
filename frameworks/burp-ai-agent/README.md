# Custom AI Agent (burp-ai-agent) Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Custom AI Agent**, formerly Burp AI Agent: an open-source Kotlin extension for Burp Suite that connects Burp to a model (Burp AI, Anthropic, OpenAI-compatible servers, Ollama, LM Studio, NVIDIA NIM, Perplexity, or the Claude, Codex, Gemini, OpenCode and Copilot CLIs), lets any MCP client drive Burp through up to 59 tools, and adds AI passive and active scanners. offensive.agency lists it as "Custom AI Agent".

| | |
|---|---|
| Tool | [six2dez/burp-ai-agent](https://github.com/six2dez/burp-ai-agent) (releases `Custom-AI-Agent-full-<version>.jar` and `Custom-AI-Agent-bapp-<version>.jar`), reviewed at `b1738c0e` (version 1.1.0) |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion, Suricata on crafted traffic and Sigma on sample events. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: the extension on a host, watchlist sweep, and its payload markers in web, proxy and DNS logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: its payload markers in web or proxy logs |
| [`sigma/`](sigma) | 5 Sigma rules for web server, proxy, DNS, file and process logs |
| [`suricata/`](suricata) | Rules for its active scanner payloads, lookups of its test domains, its MCP server certificate, health route and initialize answer, and its MCP client name |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the extension JAR and its source or unpacked classes |
| Docs | [What it leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

The extension sends target traffic through Burp, so it has no user agent, TLS fingerprint or address of its own. Its active scanners use a fixed payload table with its own markers (`XSS-BURP-AI-1337`, `burp-ai-test`, `evil-burp-ai*.com`), and those carry the target-side detection. Requests an outside model sends through its MCP tools carry no marker; the cross-framework rules in [`behaviors/`](../../behaviors) cover those, and Burp Collaborator lookups are in behaviors hunt 09.

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `burp-ai-agent`.
