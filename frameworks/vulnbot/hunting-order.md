# Where to start

1. **Check Linux hosts for the shell setup** (analytics rule, hunt 01). `sudo touch /etc/legal` with `rm -f /etc/motd` or `/etc/update-motd.d/*` from one SSH session is VulnBot opening its shell. The host is the Kali box it uses; the account and source address of that SSH login lead to the controller.
2. **Read the commands that follow in the same session.** They are the model's reconnaissance, scanning and exploitation steps and show which targets it was pointed at.
3. **Look for the controller** with hunt 01: `cli.py vulnbot`, `logs/Auto-Pentest.log`, and listeners on 7861 and 8501.
4. **If you log model traffic** (AI gateway, TLS inspection, Ollama on plain HTTP), apply the Suricata prompt rules or search the logs for the prompt strings in the indicators.
5. **Check for model traffic from servers and Kali tool traffic** against your sites with the `behaviors/` hunts, which catch VulnBot whatever model it uses.
