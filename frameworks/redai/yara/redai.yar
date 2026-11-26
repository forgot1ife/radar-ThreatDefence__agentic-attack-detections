/*
   Agentic attack detections by ThreatDefence: RedAI
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the RedAI source code (kpolley/redai at 3ba2a98f). RedAI ships as TypeScript source (npm
   package @kpolley/redai, run by Bun), so the first rule matches the source files themselves. The other rules match the
   files it writes under ~/.redai/runs/<runId>/ and agent session logs that carry its prompts.
*/

rule RedAI_Source_Or_Package
{
    meta:
        description = "RedAI AI vulnerability validation workbench: a source file of the npm package @kpolley/redai or a checkout of kpolley/redai"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/kpolley/redai"
        confidence = "high"
    strings:
        $p1 = "You are RedAI's web validation agent." ascii
        $p2 = "You are RedAI's iOS simulator validation agent." ascii
        $p3 = "You are RedAI's micro vulnerability scanner." ascii
        $p4 = "You are RedAI's threat-modeling agent." ascii
        $p5 = "You are RedAI's vulnerability discovery analyst." ascii
        $c1 = "getRedaiHomeDir" ascii
        $c2 = "REDAI_UNIT_SCAN_TIMEOUT_MS" ascii
        $c3 = "redai-template-" ascii
        $c4 = "Emit the structured RedAI validation result." ascii
        $c5 = "@kpolley/redai" ascii
        $c6 = "agent-browser-home" ascii
    condition:
        filesize < 5MB and (any of ($p*) or 2 of ($c*))
}

rule RedAI_Report
{
    meta:
        description = "RedAI scan report ~/.redai/runs/<runId>/report.md or report.html (header from src/reporting/report-builder.ts and filesystem-report-writer.ts)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/kpolley/redai/blob/3ba2a98fb70e0855a28f97951af82ece9ecfe633/src/reporting/report-builder.ts#L55"
        confidence = "high"
    strings:
        $md = "# RedAI Report: " ascii
        $html = "<title>RedAI Report: " ascii
        $intro = "RedAI ran a security review of " ascii
    condition:
        filesize < 100MB and ($md at 0 or $html or $intro)
}

rule RedAI_Run_State
{
    meta:
        description = "RedAI run record ~/.redai/runs/<runId>/run.json, state.json or report.json (run settings keys from src/domain/run-settings.ts)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/kpolley/redai/blob/3ba2a98fb70e0855a28f97951af82ece9ecfe633/src/domain/run-settings.ts#L6"
        confidence = "medium"
    strings:
        $k1 = "\"validatorEnvironmentId\"" ascii
        $k2 = "\"scannerProvider\"" ascii
        $k3 = "\"scanCoverage\"" ascii
        $k4 = "\"unitAgentConcurrency\"" ascii
        $k5 = "\"validatorAgentConcurrency\"" ascii
    condition:
        filesize < 200MB and uint8(0) == 0x7b and all of them
}

rule RedAI_Prompt_In_Agent_Session_Log
{
    meta:
        description = "A Claude Code or Codex session log (for example ~/.claude/projects/*/*.jsonl or ~/.codex/sessions/**/rollout-*.jsonl) or a RedAI transcript holding a RedAI agent prompt"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/kpolley/redai/blob/3ba2a98fb70e0855a28f97951af82ece9ecfe633/src/validators/web-agent-browser/prompt.ts#L7"
        confidence = "medium"
    strings:
        $p = "You are RedAI's " ascii
        $p_json = "You are RedAI\\u0027s " ascii
    condition:
        filesize < 200MB and uint8(0) == 0x7b and any of them
}
