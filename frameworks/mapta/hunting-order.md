# Where to start

MAPTA has no console to find on the internet and sends nothing fixed to a target, so start on your own hosts.

1. **Look for the run files.** `scan_usage.log` next to one or more `*_usage_log_<YYYYMMDD_HHMMSS>.json` files and a `targets.txt` means MAPTA ran in that folder (hunt 01, Sigma `file_event_mapta_files`). The log lines `Main Agent Usage - Target:` name every target it scanned; the YARA rule `MAPTA_Run_Output` matches the log and the usage files.
2. **If you run sandboxes locally** (Docker or VM hosts with an EDR that sees inside them), look for root `python3 /home/user/temp_script_<8 hex>.py` processes started by `source .venv/bin/activate && ...` (hunt 01, Sigma `proc_creation_mapta_sandbox_python_runner`). Each is one Python tool call by the model.
3. **Check proxy logs** for a server that sends many `POST /v1/responses` requests to `api.openai.com` and posts to `hooks.slack.com` in the same hour (hunt 02). This is weak on its own; with TLS inspection, `security_scan`, `sandbox_agent` and `validator_agent` in the request metadata make it specific.
4. **Scan code folders** with the YARA rules for the MAPTA source and its shipped benchmark logs.
5. **On the target side,** rely on the cross-framework rules in `behaviors/` (model API calls from servers, curl and directory brute-forcing from one source).
