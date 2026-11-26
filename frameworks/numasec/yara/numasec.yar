/*
   Agentic attack detections by ThreatDefence: numasec
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from FrancescoStabile/numasec at 1237a2f (May 8, 2026). Compiled with YARA 4.6 and tested
   against synthetic copies of the files numasec writes; the replay header is the JSON.stringify output of the header
   object in src/core/replay/format.ts:139-151, not a literal in the code.
*/

rule numasec_Binary_Or_Source
{
    meta:
        description = "numasec binary (Bun single-file executable) or source: probe user agents, markers and the server's client header"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/FrancescoStabile/numasec"
        confidence = "high"
    strings:
        $ua_probe = "numasec-appsec-probe/1.2" ascii
        $ua_broker = "numasec-knowledge-broker/1.2" ascii
        $baseline = "numasec_404_check_" ascii
        $xss = "<script>numasec-xss</script>" ascii
        $login = "numasec-probe@example.invalid" ascii
        $header = "x-numasec-directory" ascii
        $warn = "NUMASEC_SERVER_PASSWORD is not set; server is unsecured." ascii
    condition:
        filesize < 300MB and 2 of them
}

rule numasec_Replay_Export
{
    meta:
        description = "numasec replay export (.numasec file): JSON lines whose header names the numasec/1 format"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/FrancescoStabile/numasec/blob/1237a2f3515aebbd5260383c7088aa0ea806b600/docs/NUMASEC_FILE_FORMAT.md"
        confidence = "high"
    strings:
        $header = "{\"type\":\"header\",\"format\":\"numasec/1\"" ascii
        $version = "\"numasec_version\":\"" ascii
    condition:
        $header at 0 and $version
}

rule numasec_Operation_Context
{
    meta:
        description = "numasec operation context (context/active-context.md) or notebook (numasec.md) under .numasec/operation/<slug>/ or in a share bundle"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/FrancescoStabile/numasec/blob/1237a2f3515aebbd5260383c7088aa0ea806b600/packages/numasec/src/core/operation/operation.ts#L367"
        confidence = "medium"
    strings:
        $context = "# Active Operation Context" ascii
        $op = "# Operation: " ascii
        $derived = "Derived markdown projection from the cyber kernel." ascii
        $kernel = "## Kernel Summary" ascii
        $opsec = "opsec: " ascii
    condition:
        filesize < 5MB and (($context at 0 and $kernel and $opsec) or ($op at 0 and $derived))
}

rule numasec_Interact_Sessions
{
    meta:
        description = "numasec out-of-band session store (interact-sessions.json): interactsh or webhook.site sessions with int_ ids"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/FrancescoStabile/numasec/blob/1237a2f3515aebbd5260383c7088aa0ea806b600/packages/numasec/src/tool/interact.ts#L31"
        confidence = "medium"
    strings:
        $id = /"id": "int_[0-9a-f]{12}"/ ascii
        $scheme_i = "\"scheme\": \"interactsh\"" ascii
        $scheme_w = "\"scheme\": \"webhook\"" ascii
    condition:
        filesize < 1MB and $id and 1 of ($scheme_*)
}
