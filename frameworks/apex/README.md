# Pensar Apex Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Pensar Apex** ([pensarai/apex](https://github.com/pensarai/apex), reviewed at `6e3c5488`, November 25, 2026, version 2.7.0). A terminal agent from the security company Pensar that runs black-box and white-box penetration tests of web applications: model agents drive a shell, a headless browser, an HTTP client, a PoC runner and an out-of-band callback listener. It is published on npm as `@pensar/apex` (command `pensar`) and as standalone binaries, and it is the open core of the commercial Pensar Console. No vendor or CERT report of Apex in a real intrusion was found on November 26, 2026.

Apex has no web console and no API server, so there is nothing to find on the internet. It does leave fixed strings on targets: by default every request from its HTTP tool, and every curl, wget or scanner command the model aims at the target, carries `User-Agent: pensar-apex`.

| | |
|---|---|
| Tool | [pensarai/apex](https://github.com/pensarai/apex), reviewed at `6e3c5488`. npm `@pensar/apex`, Homebrew `pensarai/tap/apex`, binaries `pensar-<os>-<arch>` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What Apex leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Baseline every rule on your own data before alerting |

## What Apex leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| User agent | `pensar-apex` on its HTTP tool and added with `-H` to curl, wget, nuclei, ffuf, gobuster, httpx, feroxbuster, dirb, wfuzz, wpscan, sqlmap and nikto for in-scope hosts (curl and wget also get `--max-redirs 0` / `--max-redirect=0`). The operator can change it | `src/core/config/config.ts:19`, `src/core/http/targetHeaders.ts:242-316` |
| Page reader | `Mozilla/5.0 (compatible; PensarBot/1.0; +https://pensar.dev)` | `src/core/tools/backends/local.ts:83-84` |
| Callback listener | Node HTTP server on an ephemeral port, payload URL `<base>/<32 hex>/cb`, answer `apex-callback <32 hex>`; started as `node -e "eval(Buffer.from('InVzZSBzdHJpY3QiOwovLyBBcGV4IGNhbGxiYWNr...` | `src/core/agents/offSecAgent/tools/callbackListener.ts:32-35,126-175,262` |
| Sign-up account | `testuser-<13 digits>`, `test-<13 digits>@example.com`, password `TestPassword123!@#`, from a prompt | `src/core/agents/specialized/authenticationAgent/prompts.ts:410-412` |
| Host | `pensar pentest --target ...`, `bash --norc --noprofile -c` children, helper markers `APEX_CB_PROBE`, `APEX_HIDDEN_PAYLOAD_COUNT`, `__APEX_GREP_EXIT_`, `APEX_GLOB_PY`; files under `~/.pensar/` (`sessions/<id>/`, `runtime/runs.sqlite`); container `kali-apex` | `src/cli.ts`, `perCommandShell.ts:156-173`, `src/core/session/index.ts:393-469` |
| Network | `gateway.pensar.dev` and `api.pensar.dev` when signed in to Pensar, update check `registry.npmjs.org/@pensar/apex/latest` | `src/core/api/constants.ts:1-3`, `src/core/installation/index.ts:35` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Apex on a host, the watchlist sweep, and its user agents and sign-up account in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: Apex agent command markers on a host |
| [`sigma/`](sigma) | 5 Sigma rules for web, process, file and proxy logs |
| [`suricata/`](suricata) | 5 rules: the two user agents, the sign-up account, an example prompt injection marker and the callback listener answer |
| [`yara/`](yara) | Rules for the source, npm bundle or binary, the staged callback listener and the session README |

Model traffic from servers, Kali tools against your sites and callback services are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `apex`.

## Limits

- `pensar-apex` is a default header. `pensar config headers`, `--header` and `--no-global-headers` change or remove it, and the browser never sends it. A target that sees the user agent knows Apex ran; a target that does not see it learns nothing.
- The sign-up account comes from a prompt, so the model can change it. The example prompt injection markers apply only when the operator uses the shipped example library.
- A match means Apex, not an attacker: Pensar sells it for authorized testing, and Pensar Console runs the same agent for customers. Check who ran it and whether the test was agreed.
