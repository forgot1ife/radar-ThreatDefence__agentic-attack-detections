/*
   Agentic attack detections by ThreatDefence: MAPTA
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the MAPTA source code (arthurgervais/mapta at 0c167b86).
*/

rule MAPTA_Source
{
    meta:
        description = "MAPTA agent source (main.py) or a fork that keeps its tool names, sandbox runner and prompts"
        mitre_att = "T1059.006"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/arthurgervais/mapta/blob/0c167b86aedeb4f27745a84a8f7324518b0c960a/main.py"
        confidence = "high"
    strings:
        $a1 = "@function_tool(name_override=\"sandbox_agent\")" ascii
        $a2 = "@function_tool(name_override=\"validator_agent\")" ascii
        $a3 = "source .venv/bin/activate && python3 {script_path}" ascii
        $a4 = "temp_script_{uuid.uuid4().hex[:8]}.py" ascii
        $a5 = "SANDBOX_FACTORY" ascii
        $p1 = "You validate security PoCs inside an isolated sandbox using two tools" ascii
        $p2 = "You are an agent that autonomously interacts with an isolated sandbox using two tools" ascii
        $p3 = "i m only insterested in real world vulnerabilities" ascii
        $p4 = "SYSTEM_PROMPT_REDACTED" ascii
        $s1 = "\"username\": \"Security Scanner Bot\"" ascii
        $s2 = "\"name\": \"security_scan\"" ascii
    condition:
        filesize < 300KB and (3 of ($a*) or 2 of ($p*) or (1 of ($a*) and 1 of ($p*) and 1 of ($s*)))
}

rule MAPTA_Run_Output
{
    meta:
        description = "MAPTA run log (scan_usage.log) or per-target usage file (<site>_usage_log_<time>.json)"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/arthurgervais/mapta/blob/0c167b86aedeb4f27745a84a8f7324518b0c960a/main.py#L71-L119"
        confidence = "medium"
    strings:
        $l1 = " - INFO - Main Agent Usage - Target: " ascii
        $l2 = " - INFO - Sandbox Agent Usage - Target: " ascii
        $l3 = " - INFO - Usage data saved to " ascii
        $j1 = "\"main_agent_calls\": " ascii
        $j2 = "\"sandbox_agent_calls\": " ascii
        $j3 = "\"main_agent_usage\": [" ascii
        $j4 = "\"agent_type\": \"main_agent\"" ascii
        $j5 = "\"agent_type\": \"sandbox_agent\"" ascii
        $j6 = "\"scan_duration\": " ascii
    condition:
        filesize < 50MB and (2 of ($l*) or (uint8(0) == 0x7b and $j1 and $j2 and 2 of ($j3, $j4, $j5, $j6)))
}

rule MAPTA_Benchmark_Logs
{
    meta:
        description = "Benchmark trace.log or metrics.json in the format MAPTA ships in ctf-logs/ (XBOW runs with E2B sandbox tools)"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/arthurgervais/mapta/tree/0c167b86aedeb4f27745a84a8f7324518b0c960a/ctf-logs"
        confidence = "medium"
    strings:
        $t1 = "Tool call: e2b_run_command (total: " ascii
        $t2 = "Tool call: e2b_run_python (total: " ascii
        $t3 = "' usage count: " ascii
        $t4 = "Metrics saved to logs/" ascii
        $m1 = "\"e2b_run_command\": " ascii
        $m2 = "\"benchmark_name\": " ascii
        $m3 = "\"command_usage\": {" ascii
        $m4 = "\"log_directory\": \"logs/" ascii
    condition:
        filesize < 5MB and ((1 of ($t1, $t2) and ($t3 or $t4)) or (uint8(0) == 0x7b and $m1 and 2 of ($m2, $m3, $m4)))
}
