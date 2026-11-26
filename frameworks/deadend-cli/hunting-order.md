# Where to start

1. **Check your web, WAF and network logs** for `deadend7x7probe` (hunt 02, Suricata 3813421-3813422). It is the clearest sign that Deadend CLI tested you. Then look at request bodies from the same address for `deadendtester`, `deadendpassword` or `hacker@straylabs.ai` (Suricata 3813423-3813424), or `<dummy_username>` and `<dummy_password>` from builds of the current code (3813425).
2. **Check your own hosts** with hunt 01 and the analytics rule: the backend `deadend.sh --log-file ...rpc-server-<ms>.log` or `deadend_cli.jsonrpc_server`, and `~/.deadend/reusable_credentials.json`, which is written on every start. A container from `xoxruns/sandboxed_kali` on the host network is the agent's shell. Scan source trees and Python environments with the YARA rules.
3. **Check proxy and DNS logs** (hunt 02) for pulls of `xoxruns/sandboxed_kali`, the release archives, and `crunch.straylabs.ai`, which only shows up when the operator turned tracing on.
4. **Check for model traffic from servers** (behaviors hunt 02), which catches Deadend CLI whatever model it uses. Its HTTP user agents are ordinary Chrome strings, so do not hunt on them.
