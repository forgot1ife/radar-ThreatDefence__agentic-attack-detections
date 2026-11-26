# Where to start

1. **Look for the implant spreading.** Run `02-incalmo-implant-and-commands-on-your-hosts.kql`. A process started with `-server http://... -group red`, a file named `sandcat_tmp.go`, a `splunkd` outside a Splunk install, or a shell running `dynamic_payload_*.sh` means a Caldera-style implant is taking commands on that host. Incalmo's `scp`/`ssh` with `StrictHostKeyChecking=no` and `ConnectTimeout=3` shows where it came from.
2. **Find the C2 server.** Hunt 03 and the Suricata rules find the beacon (`POST /beacon`, answer starting `eyJwYXciOiAi`), downloads from `/file/download` with a `File` header, and the root JSON `Incalmo C2 Server API`. The C2 is plain HTTP, by default on 8888, so these work without decryption. Every implant on your network talks to the same address.
3. **Check your own hosts.** Hunt 01 finds the C2 server, its Celery worker and `msfrpcd -P password` on a machine you monitor. The server has no authentication and is published on every interface, so anyone who reaches port 8888 can list its implants and send them commands.
4. **Run the watchlist sweep** (hunt 04) for Incalmo's strings, paths and the console fingerprint.
5. **Then the cross-framework hunts** in `behaviors/`: Incalmo runs stock nmap, nikto and nuclei, and an attack tool started by a non-interactive shell looks the same from any agent.
