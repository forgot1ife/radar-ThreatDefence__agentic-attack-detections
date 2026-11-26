/*
   Agentic attack detections by ThreatDefence: RAPTOR
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from gadievron/raptor at ac734352 (November 25, 2026). Each string was checked against the
   source file it comes from.
*/

rule RAPTOR_Source_Or_Install
{
    meta:
        description = "RAPTOR (gadievron/raptor) checkout or copied modules: its web scanner user agent and probe values, its HTTP client user agent, or its launcher's Claude Code session name"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/gadievron/raptor"
        confidence = "high"
    strings:
        $ua = "RAPTOR Security Scanner (Authorized Testing)" ascii
        $probe_host = "evil-raptor-probe.example.com" ascii
        $pp = "raptor_pp_probe_value_8472" ascii
        $enum_user = "raptor_nonexistent_user_xyzzy_9291" ascii
        $xss = "window.__raptor_hits" ascii
        $clzero = "/raptor-clzero-probe" ascii
        $client_ua = "(+https://github.com/gadievron/raptor)" ascii
        $launcher = "CLAUDE_ARGS=(\"-n\" \"RAPTOR\")" ascii
        $name = "Recursive Autonomous Penetration Testing and Observation Robot" ascii
    condition:
        filesize < 10MB and any of them
}

rule RAPTOR_Claude_Code_Settings
{
    meta:
        description = "The .claude/settings.json RAPTOR ships: its Claude Code environment file, SessionStart and lifecycle hooks, and allow list for its libexec helpers"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/gadievron/raptor/blob/ac734352c8d00c40678ff74b58d18cff4e8a37a1/.claude/settings.json"
        confidence = "high"
    strings:
        $env = "\"CLAUDE_ENV_FILE\": \".claude/raptor.env\"" ascii
        $init = "libexec/raptor-session-init" ascii
        $hook = "libexec/raptor-lifecycle-hook" ascii
        $title = "libexec/raptor-session-title" ascii
        $allow = "Bash(libexec/raptor-agentic *)" ascii
    condition:
        filesize < 200KB and ($env or 2 of ($init, $hook, $title, $allow))
}

rule RAPTOR_Web_PoC_Artifacts
{
    meta:
        description = "Proof-of-concept files the RAPTOR web scanner writes to pocs/: a nuclei replay template (<finding>-replay.yaml) or a callback reproducer script (<finding>-reproducer.sh)"
        mitre_att = "T1587.004"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/gadievron/raptor/blob/ac734352c8d00c40678ff74b58d18cff4e8a37a1/packages/web/poc.py"
        confidence = "medium"
    strings:
        $id = "id: raptor-replay-" ascii
        $name = "RAPTOR replay " ascii
        $author = "author: raptor" ascii
        $tag = ",raptor-replay\"" ascii
        $callback = "${RAPTOR_CALLBACK_URL:?set to a URL you control" ascii
    condition:
        filesize < 1MB and ($callback or ($id and ($author or $tag or $name)))
}
