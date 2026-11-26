# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| BreachWeave console, solver containers, image build and solver binary build on a host | EDR | S | N | | | Y |
| BreachWeave home folder, solver state, solver image marker and crawler output | EDR, disk | S | N | | | Y |
| Host config with model keys, contest token or Argon2id user hashes | Disk | | | | | Y |
| Exposed web console: page, status and stream answers, provider list with keys, auth answers | Network | | N | N | | |
| Someone driving a console: shell commands to a solver, host settings with binds, JWT in stream URLs | Network, proxy | S | N | N | | |
| Observer, planner, solver and search prompts in cleartext or decrypted model requests | Network (AI gateway, TLS inspection) | | | N | | |
| Challenge platform calls with `Agent-Token` | Network | | | N | | |
| Redis web root pages (`redis_test.php`, `redis_diag.php`, `redis_exec.php`) and `cmd=RCOK` | Web, network, disk | S | N | N | | Y |
| NPS client fetched from `/files/nps/npc_...` and started with `-vkey=auto` | EDR, proxy, network | S | N (analytics) | N | | |
| Indicators in the watchlist | Proxy, web, EDR, DNS | | N | | | |

BreachWeave has no published addresses or domains and sends no telemetry, so there are no generated address rules or Zeek intel entries for it. Model traffic goes to providers the operator picks, over TLS, so the prompt rules only see it on a plain-HTTP gateway or behind TLS inspection.
