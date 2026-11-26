/*
   Agentic attack detections by ThreatDefence: Pensar Apex
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the Pensar Apex source code (pensarai/apex at 6e3c5488).
*/

rule Pensar_Apex_Code
{
    meta:
        description = "Pensar Apex source, the bundled npm build (build/cli.js of @pensar/apex) or a compiled pensar binary: its target user agents, callback listener and tool helper markers"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/pensarai/apex"
        confidence = "high"
    strings:
        $ua1 = "\"User-Agent\": \"pensar-apex\"" ascii
        $ua2 = "\"User-Agent\":\"pensar-apex\"" ascii
        $ua3 = "Mozilla/5.0 (compatible; PensarBot/1.0; +https://pensar.dev)" ascii
        $cb1 = "[apex-callback] listening " ascii
        $cb2 = "Apex callback listener (generated)" ascii
        $cb3 = "__apex_ready__" ascii
        $h1 = "APEX_HIDDEN_PAYLOAD_COUNT" ascii
        $h2 = "__APEX_GREP_EXIT_" ascii
        $h3 = "APEX_GLOB_PY" ascii
        $h4 = "APEX_CB_PROBE" ascii
        $p1 = "@pensar/apex" ascii
        $p2 = "gateway.pensar.dev" ascii
    condition:
        (1 of ($ua*) and 1 of ($cb*, $h*)) or (2 of ($cb*) and 1 of ($h*)) or (3 of ($h*) and 1 of ($p*))
}

rule Pensar_Apex_Callback_Listener_Script
{
    meta:
        description = "Callback listener script Pensar Apex generates and stages as callback-listeners/listener-<nonce>.cjs (callbackListener.ts:126-175)"
        mitre_att = "T1071.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/pensarai/apex/blob/6e3c5488d1dcdc63b1c37fd207e65919873489e6/src/core/agents/offSecAgent/tools/callbackListener.ts#L126-L175"
        confidence = "high"
    strings:
        $a1 = "// Apex callback listener (generated). Config is embedded below." ascii
        $a2 = "[apex-callback] hit " ascii
        $a3 = "'apex-callback ' + nonce" ascii
        $a4 = "__apex_ready__" ascii
    condition:
        filesize < 16KB and $a1 and 1 of ($a2, $a3, $a4)
}

rule Pensar_Apex_Session_Readme
{
    meta:
        description = "README.md Pensar Apex writes in each session folder (~/.pensar/sessions/<id>/README.md, src/core/session/index.ts:445-469)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/pensarai/apex/blob/6e3c5488d1dcdc63b1c37fd207e65919873489e6/src/core/session/index.ts#L445-L469"
        confidence = "medium"
    strings:
        $h = "# Penetration Test Session" ascii
        $s1 = "**Session ID:**" ascii
        $s2 = "**Objective:**" ascii
        $s3 = "`pocs/` - Proof-of-concept exploit scripts" ascii
        $s4 = "Security findings will be documented in the `findings/` directory as individual files." ascii
    condition:
        filesize < 64KB and $h at 0 and 3 of ($s*)
}
