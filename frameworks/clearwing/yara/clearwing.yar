/*
   Agentic attack detections by ThreatDefence: Clearwing
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from Lazarus-AI-OSS/clearwing at 08fe47d2. Tested against synthetic samples written from the
   source code, not against the repository files themselves.
*/

rule Clearwing_Source_Or_Package
{
    meta:
        description = "Clearwing source tree or installed Python package: its system prompt, hard-coded user agents, deconfliction secret or browser hook names"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Lazarus-AI-OSS/clearwing"
        confidence = "medium"
    strings:
        $prompt = "You are Clearwing Agent, an AI-powered penetration testing assistant" ascii
        $ua_asm = "clearwing-asm/0.5" ascii
        $ua_browser = "AppleWebKit/537.36 Clearwing/1.0" ascii
        $ua_fallback = "clearwing (aiohttp openai fallback)" ascii
        $ua_codex = "codex_cli_rs/0.0.0 (clearwing)" ascii
        $op_ua = "1|B|2248|clearwing|" ascii
        $secret = "US-ARMY-CYBER-DECONFL-SECRET" ascii
        $hook = "__clearwing_crypto_log" ascii
        $kali = "clearwing-kali" ascii
    condition:
        filesize < 20MB and 2 of them
}

rule Clearwing_Signed_Payload
{
    meta:
        description = "Script signed by Clearwing's cryptographically_sign_payload tool: a first line '### WATERMARK OPID:<id> SIG:<64 hex> ###'. The system prompt tells the agent to sign every script and payload; the default operation id is OP-IRONRAIN"
        mitre_att = "T1105"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Lazarus-AI-OSS/clearwing"
        confidence = "high"
    strings:
        $wm = /### WATERMARK OPID:[^\n]{0,128} SIG:[0-9a-f]{64} ###/ ascii
    condition:
        filesize < 5MB and $wm at 0
}

rule Clearwing_Python_Payload_Wrapper
{
    meta:
        description = "Python stub from Clearwing's obfuscate_payload (base64 key and data, XOR, exec) or the sleeper beacon from generate_c2_beacon (C2 + /checkin, C2 + /result, JITTER)"
        mitre_att = "T1027.013, T1105"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Lazarus-AI-OSS/clearwing"
        confidence = "medium"
    strings:
        $xor = /[a-z]{8} = bytes\(a \^ b for a, b in zip\([a-z]{8}, [a-z]{8} \* \(len\([a-z]{8}\) \/\/ len\([a-z]{8}\) \+ 1\)\)\)\.decode\(\)\nexec\([a-z]{8}\)/ ascii
        $b1 = "C2 + \"/checkin\"" ascii
        $b2 = "C2 + \"/result\"" ascii
        $b3 = "JITTER = " ascii
        $b4 = "sleep_variance = SLEEP * JITTER" ascii
    condition:
        filesize < 5MB and ($xor or 3 of ($b*))
}
