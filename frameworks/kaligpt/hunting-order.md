# Where to start

KaliGPT has no console to find on the internet, so start with your web logs and your own hosts.

1. **Search web server and WAF logs for its user agents.** `HackerX WebRequestFramework/1.0` on a request to your site is KaliGPT's HTTP analysis tool; `LocalScraper/1.0` is its page reader (hunt 02, Sigma web rule, Suricata 3813221-3813222). Then look at the same source address for curl, nmap or gau traffic in the minutes around it.
2. **Look for its processes.** `python /opt/KaliGPT/OpenSearchAPI/app.py`, `/usr/local/bin/kaligpt`, or `python3 -m agents.gemini` (or `.ollama`, `.openrouter`, `.chatgpt`) running in `/opt/KaliGPT` is KaliGPT on that host (hunt 01, the analytics rule, Sigma process rules).
3. **Look under the provider process.** Its children are the commands the model chose, started without a shell and without approval, in `/opt/KaliGPT` (hunt 01, Sigma tool-command rule).
4. **Check for its files.** `/opt/KaliGPT/agents/utils/api.config.json` holds the operator's provider API keys in clear text and is world-writable after install; `/usr/local/bin/kaligpt`, `/usr/local/bin/opensearchapi` and `kaligptinstaller.sh` date the install (hunt 01, Sigma file rule, YARA).
5. **Check proxy logs** for the installer (`raw.githubusercontent.com/SudoHopeX/KaliGPT/`), the OpenSearchAPI clone and `chatgpt.com/g/g-xouSQobsE-kaligpt` (hunt 02, Sigma proxy rules). Model traffic from servers (behaviors hunt 02) catches KaliGPT whatever provider it uses.
