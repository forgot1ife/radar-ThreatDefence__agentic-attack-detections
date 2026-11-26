/*
   Agentic attack detections by ThreatDefence: Ares (dreadnode)
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the Ares source code (dreadnode/ares at 786b2987). The compiled ares binary keeps its
   string literals, so the binary rule uses values that appear as literals in the Rust source.
*/

rule Ares_Binary
{
    meta:
        description = "Compiled ares binary (Rust, one binary for orchestrator, workers and CLI) or a build that keeps its tool wrapper strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/dreadnode/ares"
        confidence = "high"
    strings:
        $s1 = "ares-shadow-cred" ascii
        $s2 = "ares_shadowcred_" ascii
        $s3 = "___ARES_HIVE_SAM_B64___" ascii
        $s4 = "ARES_GPO_Probe_" ascii
        $s5 = "RELAY_BIND_BUSY" ascii
        $s6 = "ares-orchestrator starting" ascii
        $s7 = "ares_unresolved_principal" ascii
        $s8 = "ares-projector-pg" ascii
        $s9 = "Workaround for impacket #315" ascii
        $s10 = "esc8_relay_probe url=" ascii
    condition:
        (uint32(0) == 0x464c457f or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe) and 4 of them
}

rule Ares_Source
{
    meta:
        description = "Ares Rust source (ares-tools, ares-cli) with its fixed shadow credentials, machine account and hive dump markers"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/dreadnode/ares/tree/786b2987bfeb08284b93802c3f533c54738e1e48/ares-tools/src"
        confidence = "high"
    strings:
        $a1 = "SHADOW_CRED_PFX_PASSPHRASE: &str = \"ares-shadow-cred\"" ascii
        $a2 = "MINTED_MACHINE_ACCOUNT_PREFIX: &str = \"ARES-\"" ascii
        $a3 = "HIVE_MARK_SAM_BEGIN: &str = \"___ARES_HIVE_SAM_B64___\"" ascii
        $a4 = "format!(\"ARES_GPO_Probe_{}\"" ascii
        $a5 = "format!(\"ares-{tool}-{}-{}\"" ascii
        $a6 = "const RELAY_LOCK_PORT: u16 = 41445;" ascii
        $a7 = "PathBuf::from(\"/tmp/ares-tickets\")" ascii
        $a8 = "SKEW_ENV_VAR: &str = \"ARES_KERBEROS_TIME_OFFSET_SECS\"" ascii
    condition:
        filesize < 300KB and 1 of them
}

rule Ares_Cross_Realm_TGS_Helper
{
    meta:
        description = "cross_realm_tgs.py, the impacket helper Ares embeds and writes next to a forged inter-realm ticket before running it"
        mitre_att = "T1558.001,T1550.003"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/dreadnode/ares/blob/786b2987bfeb08284b93802c3f533c54738e1e48/ares-tools/src/privesc/cross_realm_tgs.py"
        confidence = "high"
    strings:
        $h1 = "Workaround for impacket #315" ascii
        $h2 = "re-homed ccache principal realm to" ascii
        $h3 = "no cross-realm TGT for" ascii
        $h4 = "--rehome-realm" ascii
        $h5 = "getKerberosTGS" ascii
    condition:
        filesize < 50KB and 3 of them
}

rule Ares_Kerberos_Skew_Shim
{
    meta:
        description = "Ares sitecustomize.py that shifts Python's clock for impacket and certipy by ARES_KERBEROS_TIME_OFFSET_SECS (in the repository; not called at 786b2987)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/dreadnode/ares/blob/786b2987bfeb08284b93802c3f533c54738e1e48/ares-tools/python/ares_krb_skew/sitecustomize.py"
        confidence = "high"
    strings:
        $k1 = "ARES_KERBEROS_TIME_OFFSET_SECS" ascii
        $k2 = "[ares-krb-skew] applied offset" ascii
        $k3 = "class _ShiftedDateTime(_datetime.datetime)" ascii
    condition:
        filesize < 20KB and 2 of them
}

rule Ares_MSSQL_Hive_Dump_Script
{
    meta:
        description = "Ares far-host hive dump PowerShell (reg save SAM, SYSTEM, SECURITY to a/b/c.hive and base64 between ___ARES_HIVE_ rows), in script block logs, transcripts, memory or captured output"
        mitre_att = "T1003.002,T1059.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/dreadnode/ares/blob/786b2987bfeb08284b93802c3f533c54738e1e48/ares-tools/src/lateral/mssql.rs#L345-L385"
        confidence = "high"
    strings:
        $m1 = "___ARES_HIVE_SAM_B64___" ascii wide
        $m2 = "___ARES_HIVE_SYSTEM_B64___" ascii wide
        $m3 = "___ARES_HIVE_SECURITY_B64___" ascii wide
        $m4 = "___ARES_HIVE_SAM_END___" ascii wide
        $p1 = "$a=\"$t\\a.hive\";$b=\"$t\\b.hive\";$c=\"$t\\c.hive\"" ascii wide
        $e1 = "JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQA9ACcAUwB0AG8AcAAnAAoAJAB0AD0AJABlAG4AdgA6AFQARQBNAFAACgAkAGEAPQAiACQAdABcAGEALgBoAGkAdgBlACIA" ascii wide
    condition:
        2 of ($m*) or $p1 or $e1
}

rule Ares_Config
{
    meta:
        description = "Ares red team configuration (config/ares.yaml or /etc/ares/config.yaml) with its operation name, agent dispatch tools and dashboard id"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/dreadnode/ares/blob/786b2987bfeb08284b93802c3f533c54738e1e48/config/ares.yaml"
        confidence = "medium"
    strings:
        $c1 = "name: \"ares-multi-agent\"" ascii
        $c2 = "dashboard_uid: \"ares-redteam\"" ascii
        $c3 = "- dispatch_privesc_exploit" ascii
        $c4 = "- dispatch_coercion" ascii
        $c5 = "stop_on_golden_ticket:" ascii
        $c6 = "/var/log/ares/operation.log" ascii
    condition:
        filesize < 100KB and 3 of them
}
