# Where to start

1. **Look for CAI telemetry.** DNS or TLS to `logs.aliasrobotics.com` from a machine you own means CAI ran there and sent its session log to Alias Robotics. The intermediate upload runs every 5 model turns even with `CAI_TELEMETRY=false`, so most CAI hosts send it.
2. **Look for the Alias gateway.** TLS to `api.aliasrobotics.com` on TCP 666 (or 665) and to `packages.aliasrobotics.com` on TCP 664 is the licence check, the default `alias1` model and the private package index. Few other products use those ports.
3. **Search web and WAF logs for the fetch_url user agent**, `... Chrome/124.0 Safari/537.36` with a two-part version, next to scanning from the same address.
4. **Check for model traffic from servers** (behaviors hunt 02), which catches CAI on any model.
5. **Check your own hosts** for the `cai` command with `--api`, `--yolo` or `--unrestricted`, shells under the `cai` process, `~/.cai/logs/cai_*.jsonl`, the `kali-security` container and a `cai-cops-*.service` user unit, and scan with the YARA rules. A CAI API listening on anything but 127.0.0.1 without `ALIAS_API_KEY` set gives a shell to anyone who reaches it.
