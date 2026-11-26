# Where to start

ARTEX attacks move fast but leave a lot behind. Work in this order, because each step narrows the next.

1. **Sweep the indicators.** Load the watchlist or lookup and run the indicator sweep over the last 90 days. A hit on a high-confidence user agent or a reported address tells you where to look first. No hit proves nothing: addresses rotate within minutes and user agents are easy to change.
2. **Check identity.** Run the one-second spray, spray-then-success and service principal hunts. Storm-0940 went from first targeting to privileged cloud access in under three hours, mostly through Entra ID and compromised applications.
3. **Check applications and APIs.** Run the web probe artifacts and user agent family burst searches on your internet-facing applications. ARTEX maps an application before it attacks it, and the mapping is noisy.
4. **Check cloud accounts.** Run the CloudTrail and Azure activity searches for any identity that appeared in steps 1 to 3, then for every long-term access key.
5. **Check servers.** Run the web service child process, artifact name and callback searches. A web or database service starting a shell is the point where an attack became an intrusion.
6. **Check inside the network.** Run the Kerberoasting, DCSync, WinRM fan-out and remote tasklist hunts, then the Zeek and Suricata content on internal sensors.

The spray, service principal, cloud, server and network hunts named in steps 2 to 6 now sit in [`behaviors/`](../../behaviors/sentinel/hunting) because they work for every framework ([where each one went](README.md#moved-to-shared-behaviors)). Run them in the same order.

Hunts 23 to 30 come from the ARTEX source code rather than from reported intrusions ([what the code shows](source-code-signals.md)). Run 23, 24 and 26 with step 3, 28 and 29 with step 6, and 25 when an operator may have turned on a noise profile to stay quiet.

Start the time range at August 1, 2026, the earliest malicious use the FBI and Google report.

## Tuning

- Scanners, load tests and red team exercises match several of these rules. Keep a list of authorized testing sources and exclude them.
- The burst and correlation thresholds are starting points. Run each search over 30 days before enabling it, and raise the threshold until the noise is gone.
- Treat a low-confidence indicator (legitimate services such as webhook.site or AI model APIs) as context for another finding, never as a finding on its own.
