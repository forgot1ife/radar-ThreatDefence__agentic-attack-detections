/*
   Agentic attack detections by ThreatDefence: hackingBuddyGPT
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Written from ipa-lab/hackingBuddyGPT at e23d9185. Tested against the text files of that commit,
   a synthetic run log and synthetic shell history files.
*/

rule HackingBuddyGPT_Source
{
    meta:
        description = "hackingBuddyGPT source or installed package: its CLI entry point, connector names, shell markers, run log keys or package description"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/ipa-lab/hackingBuddyGPT"
        confidence = "medium"
    strings:
        $entry = "wintermute = \"hackingBuddyGPT.cli.wintermute:main\"" ascii
        $desc = "Helping Ethical Hackers use LLMs in 50 lines of code" ascii
        $conn = "connects to a remote host over a single persistent interactive SSH shell" ascii
        $marker = "start = f\"__CMDSTART_{uuid.uuid4().hex[:8]}__\"" ascii
        $runkey = "HB_RUN_NAME = \"hackingbuddygpt.run.name\"" ascii
        $lse = "Linux Privilege Escalation using lse.sh for initial guidance" ascii
        $tmux = "attaches to a running local shell inside tmux using tmux" ascii
    condition:
        filesize < 2MB and any of them
}

rule HackingBuddyGPT_Run_Log
{
    meta:
        description = "hackingBuddyGPT per-run log (logs/log-<YYYYMMDD-HHMMSS>.jsonl): OpenTelemetry-style spans with every prompt, command and command output of a run"
        mitre_att = "T1059.006"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/ipa-lab/hackingBuddyGPT"
        confidence = "high"
    strings:
        $trace = "{\"trace_id\": \"" ascii
        $name = "\"hackingbuddygpt.run.name\": \"" ascii
        $config = "\"hackingbuddygpt.run.configuration\": \"" ascii
        $result = "\"hackingbuddygpt.tool.result\": " ascii
        $cost = "\"hackingbuddygpt.cost.usd\": " ascii
    condition:
        filesize < 500MB and $trace at 0 and $name and any of ($config, $result, $cost)
}

rule HackingBuddyGPT_Shell_Markers
{
    meta:
        description = "hackingBuddyGPT command framing in a shell history file or terminal capture: echo __CMDSTART_<hex>__ and echo \"__CMDEND_<hex>__:$?:$(id -u):$(id -un)\" typed over SSH on a Linux target, or echo 'CMDSTART<hex>' typed through tmux by its local shell connector"
        mitre_att = "T1059.004,T1033"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/ipa-lab/hackingBuddyGPT"
        confidence = "high"
    strings:
        $ssh_start = /echo __CMDSTART_[0-9a-f]{8}__/ ascii
        $ssh_end = /echo "__CMDEND_[0-9a-f]{8}__:\$\?:\$\(id -u\):\$\(id -un\)"/ ascii
        $tmux_start = /echo 'CMDSTART[0-9a-f]{8}'/ ascii
        $tmux_end = /echo 'CMDEND[0-9a-f]{8}'/ ascii
    condition:
        filesize < 50MB and any of them
}
