# Where to start

1. **Check your own hosts** (hunt 01, the analytics rule, the Sigma rules): `node` running `<tool>-mcp/build/index.js` with a tool path after it, `docker run ... cyprox/mcp-for-security`, and tools whose parent is such a wrapper. The tool's command line under the wrapper shows the target and options the assistant chose.
2. **Find the checkout or image** (YARA, hunt 01 file events): `mcp-config.json` with `"dockerContainer": ""` entries, `start.sh`, the wrappers' `build/index.js`, and `/opt/commix`, `/opt/smuggler`, `/opt/sqlmap` in the image. The MCP host's configuration names the wrappers it loads.
3. **Check for model traffic** from those hosts (behaviors hunts). With TLS inspection, the Suricata rules name the wrappers' tool descriptions in model requests, which says which tools the assistant had.
4. **Check the side requests** (hunt 03, the proxy rule): the nuclei wrapper's tag lookup and axios calls to a MobSF server.
5. **Check what reached your targets** with the cross-framework rules: the wrappers send stock tool traffic only.
