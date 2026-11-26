/*
   Agentic attack detections by ThreatDefence: Vigilo
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from certeu/vigilo at 82c2d353 (v1.0.0). Vigilo is a CERT-EU tool for assessing your own
   applications; a match means Vigilo is installed or has written results, not an attack.
*/

rule Vigilo_Source_Or_Install
{
    meta:
        description = "Vigilo source or installed code (API, grey-box worker or white-box worker): its grey-box and preflight user agents, probe host prefix, GraphQL operation name or white-box engagement prompt"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/certeu/vigilo"
        confidence = "high"
    strings:
        $ua = "Vigilo-Greybox/1 (authorised security test)" ascii
        $preflight = "Vigilo-Preflight/1.0" ascii
        $probe = "https://vigilo-probe-{token}.invalid" ascii
        $graphql = "VigiloInvoke" ascii
        $prompt = "This is an authorised security assessment run by Vigilo." ascii
        $ledger = "vigilo-record show leads" ascii
    condition:
        filesize < 20MB and any of them
}

rule Vigilo_Assessment_Output
{
    meta:
        description = "Results Vigilo writes: white-box proof harnesses and evidence with VIGILO_RESULT lines, and grey-box defense exports with vigilo-greybox ModSecurity tags or Sigma metadata"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/certeu/vigilo"
        confidence = "medium"
    strings:
        $harness1 = "VIGILO_RESULT: VULNERABLE" ascii
        $harness2 = "VIGILO_RESULT: NOT_VULNERABLE" ascii
        $defenses = "# Vigilo grey-box defenses for run" ascii
        $modsec = "tag:'vigilo-greybox'" ascii
        $sigma_author = "author: Vigilo grey-box" ascii
        $sigma_run = "vigilo_verified:" ascii
    condition:
        filesize < 20MB and any of them
}
