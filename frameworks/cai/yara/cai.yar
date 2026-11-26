/*
   Agentic attack detections by ThreatDefence: CAI (Cybersecurity AI, Alias Robotics)
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the CAI source code (aliasrobotics/cai at 6dc79257, v1.1.5), tested against the CAI source tree.
*/

rule CAI_Package
{
    meta:
        description = "CAI (Cybersecurity AI) Python package files (pip cai-framework), or a fork that keeps its strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/aliasrobotics/cai"
        confidence = "high"
    strings:
        $s1 = "api.aliasrobotics.com:666" ascii
        $s2 = "packages.aliasrobotics.com:664" ascii
        $s3 = "Backend HTTP state for the Cybersecurity AI Framework" ascii
        $s4 = "You are operating inside CAI, a cybersecurity-specialized framework." ascii
        $s5 = "cai.continuous_ops.loop_runner" ascii
        $s6 = "X-CAI-API-Key" ascii
        $s7 = "CAI_LICENSE_OFF" ascii
        $s8 = "cai.internal.components." ascii
    condition:
        filesize < 5MB and 2 of them
}

rule CAI_Telemetry_Endpoint_Module
{
    meta:
        description = "CAI telemetry endpoint module: https://logs.aliasrobotics.com/upload hidden as three base64 pieces (src/cai/internal/components/endpoints.py)"
        mitre_att = "T1071.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/aliasrobotics/cai/blob/6dc79257777f5f1c9500b4d2319935d34a47412e/src/cai/internal/components/endpoints.py"
        confidence = "high"
    strings:
        $b1 = "aHR0cHM6Ly9sb2dzLg==" ascii
        $b2 = "YWxpYXNyb2JvdGljcy5jb20v" ascii
        $b3 = "dXBsb2Fk" ascii
    condition:
        filesize < 1MB and all of them
}

rule CAI_Session_Log
{
    meta:
        description = "CAI session log ~/.cai/logs/cai_<uuid>_<time>_<user>_<os>_<ip>.jsonl; the first line carries the operator's ALIAS_API_KEY (src/cai/sdk/agents/run_to_jsonl.py:151-158)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/aliasrobotics/cai"
        confidence = "medium"
    strings:
        $start = "{\"event\": \"session_start\", \"timestamp\": \"" ascii
        $key = "\"alias_api_key\": \"" ascii
    condition:
        filesize < 200MB and $start at 0 and $key in (0..400)
}

rule CAI_Continuous_Ops_Systemd_Unit
{
    meta:
        description = "Systemd user unit written by the CAI continuous-ops wizard, cai-cops-run_<hex>.service (src/cai/continuous_ops/systemd_unit.py:59-75)"
        mitre_att = "T1543.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/aliasrobotics/cai"
        confidence = "high"
    strings:
        $d = "Description=CAI Continuous Ops worker (" ascii
        $m = "-m cai.continuous_ops.loop_runner --run-dir " ascii
        $e = "Environment=CAI_CONTINUOUS_OPS_SYSTEMD_PLAIN_LOG=1" ascii
    condition:
        filesize < 64KB and $d and ($m or $e)
}
