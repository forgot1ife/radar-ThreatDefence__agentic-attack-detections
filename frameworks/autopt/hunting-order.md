# Where to start

1. **Look for an exposed console.** If you run servers that researchers use, check for a page titled `AutoPT - 自动化渗透测试平台` on port 5000. It has no login: anyone can read its model key and start runs, and through the model setting run commands on the host. Take it off the network first.
2. **Check your own hosts** with hunt 01: `python main.py --name ... --ip_addr ...`, `python app.py` listening on 5000, `nmap -sS -p- --min-rate 3000 -T4` started by Python, and `*_FSM.jsonl` result files. Scan the repository with the YARA rules.
3. **Check your web and proxy logs** with hunt 03 for `AutoPT/1.0` and the truncated Chrome user agent. A hit on the truncated string alone may be CyberStrikeAI or Xalgorix; look for nmap and xray from the same address just before it.
4. **Check for model traffic from servers** (behaviors hunt 02), which catches AutoPT whatever model it uses.
