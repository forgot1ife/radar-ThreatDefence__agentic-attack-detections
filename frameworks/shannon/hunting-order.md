# Where to start

1. **Check your PHP sites for the php2shell probe.** Suricata rules 3813001 and 3813002 see its boundary `----shannonPhp2shellProbe` and its header flood; hunt 03 finds the two probe sizes (1,029,023 and 7,449,023 bytes) in web and proxy logs. A hit means someone tested whether your PHP runtime crashes, which only an unpatched one does.
2. **Check your own hosts** for the Shannon CLI, the `shannon-worker-` and `shannon-temporal` containers and `.shannon/` workspace folders (hunt 01, the analytics rule), and scan file shares and mail stores for its reports with the YARA rules. Shannon has no telemetry, so the host is where it shows.
3. **Check for model traffic from servers** (behaviors hunt 02), which catches Shannon whatever model it runs on: by default the Anthropic API, from a Docker container.
4. **Use the browser user agent only as context.** Chrome 124 on Linux in your web logs next to scripted requests, many paths in minutes, or payloads from the same address fits Shannon's agents; on its own it is a real browser.
5. **Look for exposed Temporal Web UIs** on port 8233 in your own address space. One that lists `pentestPipelineWorkflow` runs shows Shannon's targets to anyone who opens it.
