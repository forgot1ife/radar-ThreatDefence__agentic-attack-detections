# Where to start

1. **Look for Decepticon telemetry.** DNS or TLS to `decepticon-telemetry-gateway.purpleailab.workers.dev` from any machine you own means Decepticon ran there. The launcher's setup wizard turns it on unless the operator says no.
2. **Check your own hosts** with hunt 01: the installer (`decepticon.red/install`), `ghcr.io/bittersecurity/decepticon-*` images, the sandbox daemon and the `@dcptn_completion` tmux hook, and the Sliver operator `decepticon`. Scan Docker volumes and `~/.decepticon/workspace/` with the YARA rules; the session logs hold every command the agent ran.
3. **Look for exposed consoles and services.** Old installs serve the web console on port 3000 with no login (title `Decepticon — Autonomous Red Team Platform`, favicon hash `-1814445533`). A published sandbox daemon on port 9999 runs any command it is sent.
4. **Check web and proxy logs** with hunt 03. Decepticon's own user agents show up in proxy logs with TLS inspection; target-side markers are few, because most of its traffic comes from Kali tools and impersonated browsers.
5. **Run the behaviors hunts** for model traffic from servers (hunt 02) and out-of-band lookups (hunt 09), which catch Decepticon whatever model and tools it uses.
