# Where to start

1. **Look for the command line** (analytics rule, hunt 01). `cain-agent run --target <host>` names the target in clear; the same host is the only `in_scope` entry of the `scope.yaml` it writes. With `--backend pi`, the `bash -c` children of `node .../toolchain/pi/bridge.mjs` are the model's commands, in order.
2. **Read the workspace** on that host (default `./workspace`, `/workspaces/cain` in Docker): `scope.yaml`, `recon/endpoints.json`, `test/test-output.txt` and `report/report.md` show what was tested and what the model claimed. Run the YARA rules over the disk to find workspaces and clones you did not know about.
3. **Check the target side** with hunt 03 and the Suricata rules: `cainxss7f3a` in a query or body is Cain's XSS skill at work. Then follow the same source address through the shared `behaviors/` hunts for the tools it ran.
4. **If you log model traffic** (AI gateway, TLS inspection, a plain-HTTP `PI_BASE_URL` gateway), apply the prompt rules or search for the prompt strings in the indicators.
5. **Sweep the watchlist** with hunt 02 for the file names, paths and strings in the indicators.
