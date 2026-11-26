# Zeek

`agentic-behaviors/` is the network version of the hunts in [`behaviors/`](..) (AI agent) and [`general/`](../../general) (general intrusion). Each check raises a Zeek notice:

| Notice | Behavior | Hunt | Needs |
|---|---|---|---|
| `Model_API_From_Server` | A server, container host or build agent opens TLS to a model API: Chinese models (DeepSeek, Qwen on DashScope, GLM, Kimi, MiniMax, Doubao, SiliconFlow and others), gateways such as OpenRouter, or OpenAI, Anthropic and Google | AI agent 02 | TLS server name, `server_nets` |
| `AI_Agent_Attacking_Site` | One address reads a site with an AI agent's page reader (Qwen Code, Kimi CLI, opencode, Claude Code) and then sends it attack tool traffic or payloads within an hour | AI agent 03 | Cleartext HTTP |
| `Rotating_Proxy_Probing` | 50 or more outside addresses, 10 probes or fewer each, probe one site within 40 minutes. A probe is a request with a payload, or a login or admin request the server refuses (4xx or 5xx); probes must be at least half of the site's login and admin traffic, so a login page in normal use stays quiet | General 01 | Cleartext HTTP |
| `Backup_File_Served`, `Backup_Path_Sweep` | A server answers 200 or 206 to a configuration or backup file with a body that is not a web page (16 bytes or more, not HTML or JSON, and not text for an archive path), or one address asks for 5 or more such paths | General 02 | Cleartext HTTP |
| `WSUS_Admin_From_Internet`, `WSUS_Port_From_Internet` | An outside address reaches a WSUS admin or sync web service, or ports 8530 and 8531 | General 02 | Cleartext HTTP for the path, nothing for the port |
| `Kerberos_Enumeration` | One address asks the KDC about 25 or more accounts with 10 or more unknown-name or bad-password errors | General 03 | Kerberos on the wire |
| `SMB_WinRM_Fan_Out` | One address exchanges data over SMB or WinRM with 10 or more hosts within 10 minutes. SYN and connect scans do not count | General 03 | Connections only |
| `Callback_To_Prober` | A server connects out to an outside address that sent your servers 3 or more payload requests in the last hour, flagged when the port is in PentAGI's 28000 to 29999 range. Requests relayed by a CDN or proxy (they carry `Via` or `X-Forwarded-For`) do not make the relay a prober | General 04 | Cleartext HTTP for the probes, `server_nets` |
| `Out_Of_Band_Lookup` | A server looks up a name under an out-of-band testing service (interactsh `oast.*`, Burp Collaborator, dnslog.cn and others): a blind injection, SSRF or XXE payload ran on it. `polling.oastify.com` and `polling.burpcollaborator.net` are Burp's own client checking for results and are skipped; a payload name with a `polling.` label in front is not. One notice per source per hour | General 05 | DNS, `server_nets` |

The other hunts read process, sign-in or cloud logs, so they have no network version.

## Load and tune

Install with the Zeek package manager, which also runs the package's tests:

```bash
zkg install https://github.com/ThreatDefence/agentic-attack-detections
```

Then load it and set your networks. Without `zkg`, load the folder by path instead.

```zeek
@load packages                                    # or: @load /path/to/behaviors/zeek/agentic-behaviors

# Your servers, container hosts and build agents. Required for the server checks.
redef AgenticBehaviors::server_nets += { 10.20.0.0/16 };
# Developer subnets and approved AI gateways, ignored by the model API check.
redef AgenticBehaviors::allowed_ai_nets += { 10.30.0.0/16 };
# CDN, uptime monitoring and partner ranges that are never probers.
redef AgenticBehaviors::callback_ignore_nets += { 198.51.100.0/24 };
```

Set `server_nets`. While it is empty, `Model_API_From_Server`, `Callback_To_Prober` and `Out_Of_Band_Lookup` are off and Zeek logs one warning at startup saying so. Treating every local address as a server makes laptops that call model APIs and testers running Burp fire them.

Every threshold, path pattern, port set and host list is exported with `&redef`. Set `Site::local_nets` before loading: the checks use it to tell your addresses from outside ones. Zeek treats private and documentation ranges as local by default (`Site::private_address_space_is_local`).

## Clusters

The package runs the same on one process and on a cluster. Counts (`Rotating_Proxy_Probing`, `Backup_Path_Sweep`, `Kerberos_Enumeration`, `SMB_WinRM_Fan_Out`) go through SumStats, so the manager adds up every worker's share and raises the notice within a minute of the threshold or at the end of the window. `AI_Agent_Attacking_Site` and `Callback_To_Prober` pair different events: the worker that sees the first half tells the manager, the manager tells every worker, and the worker that sees the second half raises the notice. The other notices need one connection only. State is kept for addresses that showed the first half of a pattern, for an hour, never for every visitor.

## Test

```bash
python3 tests/make_pcap.py    # needs scapy; rewrites tests/behaviors-sample.pcap
bash tests/run_tests.sh       # needs zeek on the PATH
```

The pcap holds synthetic traffic for every notice, plus near misses and benign traffic that must stay quiet: a login page in normal use, a site that answers 200 to every path, a CDN edge, SYN and connect scans, a laptop outside `server_nets` and Burp's polling lookups. The Kerberos part is real AS-REQ and TGS-REQ traffic, and the test checks that Zeek parsed it into `kerberos.log`.
