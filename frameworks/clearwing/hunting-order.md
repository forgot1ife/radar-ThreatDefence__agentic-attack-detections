# Where to start

1. **Search web and proxy logs for its user agents** (hunt 03). `Clearwing/1.0` and `clearwing-asm/` are hard-coded and nothing else sends them.
2. **Look for its callbacks leaving your network.** A server that calls `/callback/<24 characters>` on ports 9999 to 10008 ran a payload the agent sent.
3. **Scan web roots, upload folders and `/tmp` with the YARA rules** for scripts that start with `### WATERMARK OPID:`, the XOR `exec` stub or the beacon.
4. **Check your own hosts** for the `clearwing` command line, the `clearwing-kali` container and `~/.clearwing/` (hunt 01). On macOS, also Python reading the `Claude Code-credentials` keychain item.
5. **Check for model traffic from servers** (behaviors hunt 02), which catches Clearwing whatever model it runs on.
6. **Sweep the watchlist** (hunt 02) once the indicators are loaded.
