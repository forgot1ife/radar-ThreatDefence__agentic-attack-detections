/*
   Agentic attack detections by ThreatDefence: 0security
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from 0sec-labs/0security at eec0d4c7. Tested for syntax and against synthetic files; the
   release binaries (Bun-compiled) and the Docker image were not scanned, so the first rule rests on strings in the
   TypeScript source that a bundle keeps as literals.
*/

rule ZeroSecurity_CLI_Bundle_Or_Binary
{
    meta:
        description = "0security CLI bundle (dist/0.js) or compiled binary: console control-token meta tag, server-mode host refusal, ready line, session cookie name, remote engine folder, probe prompt, verifier container name"
        mitre_att = "T1588.002,T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/0sec-labs/0security"
        confidence = "high"
    strings:
        $meta = "<meta name=\"0-control-token\" content=" ascii
        $host = "This host name is not allowed. Add it with --allowed-host." ascii
        $ready = "ZERO_DASHBOARD_READY" ascii
        $cookie = "zero_access" ascii
        $worker = "/tmp/zero-engine" ascii
        $probe = "DAN confirms it is active by beginning every reply with the token" ascii
        $verify = "0-verify-" ascii
        $label = "0.verify=1" ascii
        $update = "@0/cli/update-check" ascii
        $title = "Sign in - 0security" ascii
    condition:
        filesize < 400MB and 4 of them
}

rule ZeroSecurity_Probe_Report
{
    meta:
        description = "Report written by `0 probe`: a finding per probe the endpoint failed, with the probe id, the target and the reply that shows the attack worked"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/0sec-labs/0security"
        confidence = "medium"
    strings:
        $worked = "; the reply shows the attack worked: " ascii
        $probe = /Probe (direct-override|delimiter-injection|indirect-document|encoded-instruction|persona-jailbreak|system-prompt-extraction|secret-request|tool-execution|markdown-exfiltration|raw-html-output) sent to / ascii
    condition:
        filesize < 50MB and $worked and $probe
}
