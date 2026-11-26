# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| `ARES-<8 hex>$` machine account created | Domain controller security log (4741), SMB | S (attack box command line) | N, analytics | N | | |
| `ARES-<8 hex>$` as the client of TGT and S4U requests | Domain controller security log (4768, 4769), Kerberos | | N | N | | |
| GPO probe task `ARES_GPO_Probe_<8 hex>` | Windows security log (4698), EDR, SMB | | N | N | | Y (binary, source) |
| SQL Server hive dump through `xp_cmdshell` (fixed `-EncodedCommand`, `reg save` to `a/b/c.hive`) | EDR on the SQL Server, PowerShell 4104, TDS | S | N | N | | Y |
| `___ARES_HIVE_` rows in the result set | TDS, PowerShell 4104 | | N | N | | Y |
| ESC8 probe, `HEAD /certsrv/certfnsh.asp` with no user agent | IIS on the CA, proxy, network | | N | N | | |
| Shadow Credentials with `ares-shadow-cred` and `/tmp/ares_shadowcred_` | EDR (Linux) | S | N | | | Y (binary, source) |
| certipy output names with the Ares run token | EDR (Linux) | S | | | | |
| hashcat and John session names `ares-hc-`, `ares-jtr-` | EDR (Linux) | S | N | | | |
| `/tmp/ares-tickets/` and `cross_realm_tgs.py` | EDR (Linux), disk | S | N | | | Y (helper) |
| `ares` worker as parent of impacket, NetExec, certipy and the rest | EDR (Linux) | S | N | | | |
| Orchestrator and worker units, `system-ares.slice` | EDR (Linux) | S | N | | | |
| Working files: `/tmp/ares_relay_*`, `ares-hive-*`, `/var/log/ares/`, `~/.ares/` | EDR (Linux), disk | S | N | | | |
| ares binary, source and `config/ares.yaml` on disk | Disk | | | | | Y |
| Kerberoasting, AS-REP roasting, DCSync, relay, ADCS abuse by the wrapped tools | Windows logs, network | behaviors | behaviors | behaviors | behaviors | |
| Model traffic from the attack box | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Exposed console | none: Ares has no web UI or API. NATS (`ares-nats`) is on loopback by default | | | | | |
