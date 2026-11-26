/*
   Agentic attack detections by ThreatDefence: Shannon
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the Shannon source code (KeygraphHQ/shannon at 3760d2f9), tested against the Shannon source
   tree, the sample reports it ships and the published run records in KeygraphHQ/xbow-validation-benchmarks.
*/

rule Shannon_Package
{
    meta:
        description = "Shannon AI pentest agent code (npm @keygraph/shannon, image keygraph/shannon), or a fork that keeps its strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/KeygraphHQ/shannon"
        confidence = "high"
    strings:
        $s1 = "@keygraph/shannon" ascii
        $s2 = "shannon.worker-protocol" ascii
        $s3 = "pentestPipelineWorkflow" ascii
        $s4 = "shannonPhp2shellProbe" ascii
        $s5 = "SHANNON_AI_MODEL" ascii
        $s6 = "AI Pentester by Keygraph" ascii
        $s7 = "shannon-worker-" ascii
        $s8 = "TEMPORAL_ADDRESS=shannon-temporal:7233" ascii
    condition:
        filesize < 10MB and 2 of them
}

rule Shannon_Report_PDF
{
    meta:
        description = "PDF penetration test report rendered by Shannon (Typst template, default author wordmark)"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/KeygraphHQ/shannon/blob/3760d2f9df9f3afa374a8eb2473adadfbf9ed991/apps/worker/templates/typst/report.typ#L50"
        confidence = "high"
    strings:
        $author = "Shannon | AI Pentester by Keygraph" ascii
        $typst = "Typst " ascii
        $title = "Security Assessment Report" ascii
    condition:
        uint32(0) == 0x46445025 and $author and ($typst or $title)
}

rule Shannon_Report_Markdown
{
    meta:
        description = "Markdown penetration test report rendered by Shannon (Security-Assessment-Report.md, comprehensive_security_assessment_report.md)"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/KeygraphHQ/shannon/blob/3760d2f9df9f3afa374a8eb2473adadfbf9ed991/apps/worker/src/services/report-renderer.ts#L256"
        confidence = "high"
    strings:
        $h = "# Security Assessment Report" ascii
        $b = { 53 68 61 6E 6E 6F 6E 20 E2 80 94 20 41 49 20 50 65 6E 74 65 73 74 65 72 20 62 79 20 4B 65 79 67 72 61 70 68 } // Shannon — AI Pentester by Keygraph
        $e = "## Executive Summary" ascii
    condition:
        filesize < 20MB and $h at 0 and $b and $e
}

rule Shannon_Session_Record
{
    meta:
        description = "Shannon run record session.json from <workspace>/.shannon/ (keys written by the worker's metrics tracker; older runs kept it in audit-logs/)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/KeygraphHQ/shannon/blob/3760d2f9df9f3afa374a8eb2473adadfbf9ed991/apps/worker/src/audit/metrics-tracker.ts#L160"
        confidence = "medium"
    strings:
        $k1 = "\"webUrl\"" ascii
        $k2 = "\"total_cost_usd\"" ascii
        $k3 = "\"phases\"" ascii
        $k4 = "\"agents\"" ascii
        $o1 = "\"originalWorkflowId\"" ascii
        $o2 = "\"resumeAttempts\"" ascii
        $o3 = "_shannon-" ascii
        $p1 = "\"pre-recon\"" ascii
        $p2 = "\"duration_percentage\"" ascii
    condition:
        filesize < 5MB and (uint8(0) == 0x7b or uint16(0) == 0x7b0a) and all of ($k*) and (1 of ($o*) or all of ($p*))
}

rule Shannon_Playwright_Stealth_Files
{
    meta:
        description = "Browser config and init script Shannon writes to .shannon/.playwright/ (cli.config.json with a fixed Chrome 124 user agent, scripts/stealth.js)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/KeygraphHQ/shannon/blob/3760d2f9df9f3afa374a8eb2473adadfbf9ed991/apps/worker/src/ai/playwright-config-writer.ts#L29"
        confidence = "medium"
    strings:
        $ua = "Chrome/124.0.0.0 Safari/537.36" ascii
        $arg = "--disable-blink-features=AutomationControlled" ascii
        $init = "\"initScript\"" ascii
        $path = "scripts/stealth.js" ascii
        $js1 = "delete Object.getPrototypeOf(navigator).webdriver;" ascii
        $js2 = "mhjfbmdgcfjbbpaeojofohoefgiehjai" ascii
        $js3 = "PlatformNaclArch" ascii
        $js4 = "OnRestartRequiredReason" ascii
    condition:
        filesize < 64KB and (($ua and $arg and $init and $path) or ($js1 at 0 and $js2 and $js3 and $js4))
}
