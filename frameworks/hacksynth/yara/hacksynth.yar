/*
   Agentic attack detections by ThreatDefence: HackSynth
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the HackSynth source code (aielte-research/HackSynth at 48a41f79).
*/

rule HackSynth_Source
{
    meta:
        description = "HackSynth agent source: pentest_agent.py, docker_setup.py or run_bench.py, or a fork that keeps their strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/aielte-research/HackSynth"
        confidence = "high"
    strings:
        $a1 = "class PentestAgent()" ascii
        $a2 = "<CMD>(.*?)</CMD>" ascii
        $a3 = "timeout {self.timeout_duration}s /bin/bash -c {safe_cmd}" ascii
        $a4 = "def plan_and_run_cmd(" ascii
        $d1 = "/data/cyberml_attackbox" ascii
        $d2 = "kali-linux-headless sshpass curl" ascii
        $d3 = "[ATTACKBOX]" ascii
        $r1 = "pentest_agent.plan_and_run_cmd(" ascii
        $r2 = "benckmark_challenges" ascii
    condition:
        filesize < 200KB and (2 of ($a*) or ($d3 and 1 of ($d1, $d2)) or all of ($r*))
}

rule HackSynth_Run_Config
{
    meta:
        description = "HackSynth run configuration (configs/*.json): Neptune project, attackbox name and Planner prompt"
        mitre_att = "T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/aielte-research/HackSynth/tree/48a41f795dda186df66561c4fd2b58ae84e3e4f8/configs"
        confidence = "medium"
    strings:
        $k1 = "\"attackbox\"" ascii
        $k2 = "\"new_observation_length_limit\"" ascii
        $k3 = "\"summarizer\"" ascii
        $v1 = "aielte/CyberML2024" ascii
        $v2 = "attackbox_kali_" ascii
        $p1 = "You are a penetration testing command generator in a CTF game" ascii
        $p2 = "ENCLOSE THE COMMAND WITHIN <CMD></CMD> TAGS" ascii
        $p3 = "You are an autonomous agent summarizing your history" ascii
    condition:
        filesize < 64KB and uint8(0) == 0x7b and $k1 and $k3 and ($k2 or 1 of ($v*)) and (1 of ($v*) or 1 of ($p*))
}
