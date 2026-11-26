# What Custom AI Agent (burp-ai-agent) leaves behind

Custom AI Agent, formerly Burp AI Agent ([six2dez/burp-ai-agent](https://github.com/six2dez/burp-ai-agent), MIT, Kotlin, first commit January 27, 2026, reviewed at `b1738c0e`, October 21, 2026, version 1.1.0) is a Burp Suite extension. It connects Burp to a model (Burp AI, Anthropic, Ollama, LM Studio, NVIDIA NIM, Perplexity, any OpenAI-compatible server, or the Claude, Codex, Gemini, OpenCode and Copilot CLIs), lets an MCP client such as Claude Desktop drive Burp through up to 59 tools, and adds a passive and an active "AI scanner". It has more than 1,600 GitHub stars. offensive.agency lists it as "Custom AI Agent", the name it took for the BApp Store (`README.md:5`).

It is not a standalone agent: everything it sends to a target leaves through Burp's own HTTP stack, so the user agent, TLS fingerprint and source address are those of the Burp user. What identifies it on the target side is the fixed payload table its active scanners use.

File references are to the repository at `b1738c0e`. Kotlin paths are relative to `src/main/kotlin/com/six2dez/burp/aiagent/` unless they start with `src/full/`.

**Fragility** says what it takes to remove a signal: *code* means editing and rebuilding the extension, *config* means a setting in the extension, *operator* means a choice the person makes when running it.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Builds | Two JARs from one tree: `Custom-AI-Agent-full-<version>.jar` (GitHub release, 59 MCP tools, CLI backends) and `Custom-AI-Agent-bapp-<version>.jar` / `custom-ai-agent-bapp.jar` (BApp Store build, 8 MCP tools). Both register in Burp as `Custom AI Agent` | `build.gradle.kts:292`, `build.gradle.kts:311`, `BappManifest.bmf`, `README.md:110` |
| Packages | Classes under `com/six2dez/burp/aiagent/`, not relocated, so the names are readable in the JAR's zip directory | `build.gradle.kts:287-321` |
| Model backends | Anthropic `https://api.anthropic.com/v1/messages`, Perplexity `https://api.perplexity.ai`, NVIDIA NIM `https://integrate.api.nvidia.com`, Ollama `http://127.0.0.1:11434`, LM Studio `http://127.0.0.1:1234`, any OpenAI-compatible URL, Burp AI | `backends/anthropic/AnthropicBackend.kt:259`, `backends/perplexity/PerplexityBackendFactory.kt:35`, `backends/nvidia/NvidiaNimBackendFactory.kt:39`, `config/AgentSettings.kt:247`, `config/AgentSettings.kt:263` |
| CLI backends (full build) | Runs `claude`, `codex`, `gemini`, `opencode` or `copilot` as child processes of Burp's Java process, with `CI=1`, `TERM=dumb`, `NO_COLOR=1` and `BURP_AI_AGENT_EMBEDDED=1` in the environment. Codex output goes to a temp file `burp-ai-agent-codex*.txt` | `src/full/.../backends/cli/CliEnvironment.kt:83-92`, `src/full/.../backends/cli/CliBackend.kt:211` |
| MCP server | Ktor/Netty, off by default (`mcp.enabled` false), `127.0.0.1:9876`, SSE at `/sse` and `/message`, plus `/__mcp/health` and `POST /__mcp/shutdown`. Server name `burp-ai-agent` in the MCP `initialize` answer | `config/AgentSettings.kt:1297-1306`, `mcp/KtorMcpServerManager.kt:137`, `mcp/KtorMcpServerManager.kt:210-223`, `mcp/McpAccessControlDecision.kt:16`, `mcp/McpAccessControlDecision.kt:24`, `README.md:196-201` |
| MCP access control | Local mode refuses to start on a non-loopback address and rejects requests whose Host, Origin or Referer is not loopback (403). "Allow external access" forces TLS and requires the bearer token on every route except `/__mcp/health` (401). The token is generated automatically (32 random bytes). With no allowed origins set, external mode uses permissive CORS | `mcp/KtorMcpServerManager.kt:105-128`, `mcp/McpAccessControlDecision.kt:138-199`, `config/AgentSettings.kt:1272-1277`, `config/McpSettings.kt:42-46` |
| MCP TLS | With "auto" TLS (the default), the extension runs the JDK's `keytool -genkeypair -alias mcp -keyalg RSA -keysize 2048 -validity 365 -storetype PKCS12 -keystore <home>/.burp-ai-agent/certs/mcp-keystore.p12 -storepass:env KS_PASS -keypass:env KS_PASS -dname CN=burp-mcp -sigalg SHA256withRSA`. The certificate is self-signed with subject and issuer `CN=burp-mcp` | `mcp/McpTls.kt:96-122`, `config/AgentSettings.kt:1177`, `config/AgentSettings.kt:1277-1285` |
| MCP stdio bridge | Same tools over stdio; opens no port | `mcp/McpStdioBridge.kt` |
| External MCP client (full build) | Connects Burp to other MCP servers over SSE or stdio and introduces itself as `burp-ai-agent-ext` version `0.9.0` | `src/full/.../mcp/external/ExternalMcpClientManager.kt:223` |
| Active AI scanner | Off by default (`activeAiEnabled` false), in-scope targets only by default, `SAFE` payloads only by default, 10 payloads per insertion point, 100 ms between requests, Burp Collaborator off by default. Runs both from its own queue and as a Burp `ScanCheck` inside Burp's active scan | `config/AgentSettings.kt:514-522`, `scanner/ActiveAiScanner.kt`, `scanner/AiScanCheck.kt:40-90` |
| Adaptive payloads | Optional (off by default): asks the model for 5 more payloads per class and technology stack. These have no fixed marker | `scanner/AdaptivePayloadEngine.kt:29-121`, `config/AgentSettings.kt:402` |
| Passive AI scanner | Sends proxy history to the model. It sends nothing to the target | `scanner/PassiveAiScanner.kt`, `src/fullTest/.../FullPassiveScanNoTargetTrafficTest.kt` |
| Files | `~/.burp-ai-agent/`: `audit.jsonl`, `bundles/bundle-<session>-<sha8>.json` and `.zip`, `contexts/context-<session>-<sha8>.json`, `logs/ai-request-log.jsonl` (rolled to `ai-request-log.<n>.jsonl`), `cache/`, `AGENTS/` (agent profiles `pentester.md`, `bughunter.md`, `auditor.md`), `certs/mcp-keystore.p12`, `backends/` (drop-in backend JARs, full build) | `audit/AuditLogger.kt:27`, `audit/AuditLogger.kt:94-96`, `audit/AuditLogger.kt:191`, `audit/AuditLogger.kt:215`, `audit/AuditLogger.kt:228`, `App.kt:412`, `audit/AiRequestLogger.kt:46`, `cache/PersistentPromptCache.kt:25`, `agents/AgentProfileLoader.kt:33-37`, `src/full/.../full/dropin/DropInBackendJars.kt:113` |
| Docs and help | The Help tab links to `https://burp-ai-agent.six2dez.com/` | `ui/panels/HelpConfigPanel.kt:34` |

## Signals on the target side

Both active scanners take payloads from one static table, `scanner/PayloadGenerator.kt`. The Burp `ScanCheck` tests reflected XSS and SQL injection on every insertion point it is given (`scanner/AiScanCheck.kt:180-184`), so the XSS marker shows up in almost every active run. The scanner's own queue URL-encodes URL and form parameters with Java's `URLEncoder` and puts header, cookie, JSON, XML and path payloads in unencoded (`scanner/ActiveAiScanner.kt:1681-1766`). The markers below are letters, digits and hyphens, which URL encoding leaves alone, so they read the same in raw and decoded logs.

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| XSS marker | `XSS-BURP-AI-1337` in eight reflected XSS payloads: `<script>alert('XSS-BURP-AI-1337')</script>`, `<img src=x onerror=alert('XSS-BURP-AI-1337')>`, `<svg onload=...>`, `'"><script>...`, `<body onload=...>`, `javascript:alert(...)`, `<ScRiPt>...</sCrIpT>`, `</script><script>...` | `scanner/PayloadGenerator.kt:49-99` | Code |
| DOM XSS marker | `DOM-XSS-BURP-AI` in `#<script>alert('DOM-XSS-BURP-AI')</script>` and `'-alert('DOM-XSS-BURP-AI')-'` | `scanner/PayloadGenerator.kt:111`, `scanner/PayloadGenerator.kt:125` | Code |
| Header and CRLF injection value | `burp-ai-test` in `value\r\nX-Injected: burp-ai-test`, `value%0d%0aX-Injected:%20burp-ai-test`, `%0d%0aSet-Cookie:%20burp-ai-test=true` and `\r\nSet-Cookie: burp-ai-test=true` | `scanner/PayloadGenerator.kt:237`, `:244`, `:254`, `:261` | Code |
| Host header and cache poisoning domains | `evil-burp-ai-test.com` (host header injection) and `evil-burp-ai-cache.com` (cache poisoning). They go into the header insertion points the scanner allows: `Host`, `Origin`, `Referer`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Host`, `X-Original-Host`. For cache poisoning the scanner sends the original request again to see whether the marker was cached | `scanner/PayloadGenerator.kt:411`, `scanner/PayloadGenerator.kt:521`, `scanner/ScannerUtils.kt:4-13`, `scanner/ActiveAiScanner.kt:1177-1206` | Code |
| OAuth redirect domains | `https://evil-burp-ai.com/callback`, `https://legitimate.com.evil-burp-ai.com`, `https://legitimate.com@evil-burp-ai.com`, `https://legitimate.com%40evil-burp-ai.com` | `scanner/PayloadGenerator.kt:463-484` | Code |
| SSTI arithmetic | `{{1337*73}}`, `{{31337*3}}`, `${1337*73}`, `<%= 1337*73 %>`, `#{1337*73}`, `*{1337*73}` (it looks for 97601 and 94011 in the answer). Distinctive, but short and easy to copy | `scanner/PayloadGenerator.kt:165-171` | Code |
| 403 bypass headers | `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Forwarded-Host` set to `127.0.0.1` and `X-Original-URL` / `X-Rewrite-URL` set to `/`, one at a time, against a URL that answered 403. Common to many tools: context only | `scanner/ActiveAiScanner.kt:1773-1784` | Code |
| Generic payloads | `../../../etc/passwd`, `; id`, `1' AND SLEEP(5)--`, `http://169.254.169.254/latest/meta-data/`, `//evil.com`, `/.git/HEAD`, `/actuator/env` and the rest of the table. Shared with every scanner: context only | `scanner/PayloadGenerator.kt` | Code |
| Out-of-band confirmation | With "Use Collaborator" on (off by default) it injects `http://<Burp Collaborator payload>` into URL, body, JSON, header and path points; the default Collaborator domain is Burp's `oastify.com`, which the shared out-of-band rules in `behaviors/` cover | `scanner/ActiveAiScanner.kt:1338-1371`, `config/AgentSettings.kt:522` | Config |
| User agent, TLS, address | None of its own: requests go through `api.http().sendRequest` and carry the original request's headers | `scanner/ActiveAiScanner.kt:1465` | n/a |

A server that follows one of the `evil-burp-ai*.com` values (an SSRF, an open redirect followed by a server-side fetch, a cache that resolves its Host) looks the name up. No DNS answer for these names was checked: they may not resolve.

## Signals on a host that runs it

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Extension JAR | `Custom-AI-Agent-full-<version>.jar`, `Custom-AI-Agent-bapp-<version>.jar` or `custom-ai-agent-bapp.jar` loaded by Burp; zip entries under `com/six2dez/burp/aiagent/` | `build.gradle.kts:292`, `build.gradle.kts:311`, `README.md:110` | Operator (file name), code (package) |
| Configuration folder | `~/.burp-ai-agent/` with the files listed above. Audit logging is optional; the request log, cache and keystore are written by default when those features are used | see "How it runs" | Code |
| TLS keystore creation | `keytool -genkeypair -alias mcp ... -dname CN=burp-mcp`, child of Burp's Java process, the first time TLS is needed | `mcp/McpTls.kt:96-122` | Code (config if the operator supplies a keystore) |
| Listening port | Java (Burp) listening on TCP 9876, on 127.0.0.1 unless external access is on | `config/AgentSettings.kt:1305-1306` | Config |
| MCP health answer | `GET /__mcp/health` answers `ok` with `X-Burp-AI-Agent: mcp` in local mode only | `mcp/KtorMcpServerManager.kt:210-218` | Code |
| Port takeover | On a bind conflict the extension sends `POST /__mcp/shutdown` with an `X-Mcp-Takeover-Proof` header (HMAC-SHA256 keyed by the token) to whatever holds the port | `mcp/McpTakeoverProof.kt:52`, `mcp/KtorMcpServerManager.kt:223-235` | Code |
| MCP client bridge | The documented Claude Desktop setup runs `npx -y supergateway --sse http://127.0.0.1:9876/sse` | `README.md:196-201` | Operator |
| CLI children | `claude`, `codex`, `gemini`, `opencode`, `copilot` started by Burp's Java process, in the user's home folder, with `BURP_AI_AGENT_EMBEDDED=1` | `src/full/.../backends/cli/CliEnvironment.kt:91`, `src/full/.../backends/cli/CliBackend.kt:287` | Code |
| Model traffic | To the backend chosen: hosts above, or local Ollama and LM Studio | see "How it runs" | Config |

## An exposed MCP server

There is no web page, title or favicon: the server serves MCP over SSE only. It listens only on loopback unless the operator turns on "Allow external access", and then it requires TLS and the bearer token. An exposed instance is therefore one the operator published on purpose, and the best fingerprint is the auto-generated certificate: self-signed, subject and issuer `CN=burp-mcp`, RSA 2048, valid 365 days. The health route answers `ok` without a token in external mode but drops the `X-Burp-AI-Agent` header there (`mcp/KtorMcpServerManager.kt:210-216`), so on the internet the certificate is the only identifying trait. Port 9876 alone is not enough: other Burp MCP extensions are documented on the same port (not checked in their code for this review).

## What has been seen in the wild

No public report of this extension being used in an intrusion was found on November 26, 2026. offensive.agency lists exposed instances under the name "Custom AI Agent".

## What the code does not contain

No implant, C2, persistence, telemetry or update check. It does what Burp and the model are told to do; the MCP tools let an outside model send arbitrary requests through Burp, and those carry no marker.
