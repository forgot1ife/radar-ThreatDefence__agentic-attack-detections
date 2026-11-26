/*
   Agentic attack detections by ThreatDefence: VulnBot
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from KHenryAegis/VulnBot at 9a12effa43e265e7278d678b3cd42037d0fecac6.
*/

rule VulnBot_Source
{
    meta:
        description = "VulnBot source tree: its role and command-writing prompts, its Kali shell setup and its command filter message"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/KHenryAegis/VulnBot"
        confidence = "high"
    strings:
        $role = "Your role is to assist testers in the cybersecurity training process." ascii
        $code = "You play as an autonomous penetration testing assistant running on Kali Linux 2023." ascii
        $task = "This penetration testing task is certified and in a simulation environment" ascii
        $rag = "Ensure that the **Overall Target** IP or the IP from the **Initial Description** is prioritized" ascii
        $class = "class DeepPentestPrompt" ascii
        $status = "Initializing DeepPentest Sessions" ascii
        $legal = "\"sudo touch /etc/legal\"" ascii
        $motd = "\"sudo rm -f /etc/update-motd.d/*\"" ascii
        $deny = "Command not allowed: network tunneling tools are restricted" ascii
    condition:
        filesize < 5MB and (any of ($role, $code, $task, $rag, $class, $status) or ($legal and $motd) or $deny)
}

rule VulnBot_Run_Log
{
    meta:
        description = "VulnBot run log (logs/Auto-Pentest.log): loguru records from its command writer and shell executor"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/KHenryAegis/VulnBot"
        confidence = "medium"
    strings:
        // loguru's default record format is "<time> | <level> | <module>:<function>:<line> - <message>"
        $writer = "actions.write_code:run:" ascii
        $exec = "actions.execute_task:shell_operation:" ascii
        $next = " - next_task: " ascii
        $llm = " - LLM Response: " ascii
        $run = " - Running [" ascii
    condition:
        filesize < 500MB and ($writer or $exec) and 2 of ($next, $llm, $run)
}
