/*
   Agentic attack detections by ThreatDefence: Decepticon
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the Decepticon source code (BitterSecurity/Decepticon at 6b15092d), tested against the
   Decepticon source tree. The launcher rule is written from the strings the Go source embeds and was not run against
   a release binary.
*/

rule Decepticon_Package
{
    meta:
        description = "Decepticon Python package, sandbox runtime or container image layer (pip decepticon, ghcr.io/bittersecurity/decepticon-*), or a fork that keeps its strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BitterSecurity/Decepticon"
        confidence = "high"
    strings:
        $ua1 = "decepticon-http-sandbox/1" ascii
        $ua2 = "decepticon-roe/1" ascii
        $ua3 = "decepticon-telemetry/1.0" ascii
        $t1 = "decepticon-telemetry-gateway" ascii
        $p1 = "[DCPTN:" ascii
        $p2 = "@dcptn_completion" ascii
        $p3 = "__DECEPTICON_ENV_SYNC_" ascii
        $d1 = "Decepticon sandbox daemon" ascii
        $d2 = "decepticon_sandbox.server" ascii
        $d3 = "Decepticon plugin bundle API" ascii
    condition:
        filesize < 5MB and 2 of them
}

rule Decepticon_Launcher
{
    meta:
        description = "Decepticon Go launcher (the decepticon command, release asset decepticon-<os>-<arch>), which embeds the .env template with the telemetry gateway and the default stack secrets"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BitterSecurity/Decepticon/tree/main/clients/launcher"
        confidence = "medium"
    strings:
        $e1 = "decepticon-telemetry-gateway.purpleailab.workers.dev" ascii
        $e2 = "LITELLM_SALT_KEY=sk-decepticon-salt-change-me" ascii
        $e3 = "NEO4J_PASSWORD=decepticon-graph" ascii
        $e4 = "DECEPTICON_TELEMETRY_ENDPOINT" ascii
        $r1 = "BitterSecurity/Decepticon" ascii
        $r2 = "decepticon-%s-%s" ascii
    condition:
        (uint32(0) == 0x464c457f or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint16(0) == 0x5a4d)
        and filesize < 120MB and 2 of ($e*) and 1 of ($r*)
}

rule Decepticon_Sandbox_Session_Log
{
    meta:
        description = "Decepticon sandbox tmux session log (<workspace>/.sessions/<session>.log): prompt markers [DCPTN:<exit code>:<cwd>] around every command the agent ran"
        mitre_att = "T1059.004"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BitterSecurity/Decepticon/blob/6b15092d2e0b41f2ef5af79a16333582cc3fb353/packages/decepticon/decepticon_sandbox/kernel/tmux.py#L536-L553"
        confidence = "high"
    strings:
        $ps1 = /\[DCPTN:\d{1,3}:\/[^\]\r\n]{0,200}\] /
        $hook = "__dcptn_status=$?" ascii
    condition:
        filesize < 200MB and (#ps1 > 2 or ($hook and $ps1))
}

rule Decepticon_Sliver_Operator_Config
{
    meta:
        description = "Sliver operator config the Decepticon c2-sliver container writes to /workspace/.sliver-configs/decepticon.cfg (operator decepticon, lhost c2-sliver)"
        mitre_att = "T1219"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BitterSecurity/Decepticon/blob/6b15092d2e0b41f2ef5af79a16333582cc3fb353/containers/c2-sliver-entrypoint.sh#L39"
        confidence = "medium"
    strings:
        $op = /"operator"\s*:\s*"decepticon"/
        $lh = /"lhost"\s*:\s*"c2-sliver"/
        $ca = "\"ca_certificate\"" ascii
    condition:
        filesize < 64KB and $op and ($lh or $ca)
}

rule Decepticon_Havoc_Default_Profile
{
    meta:
        description = "Havoc teamserver profile the Decepticon c2-havoc container generates: operator decepticon, password decepticon-havoc-c2, listener decepticon-https"
        mitre_att = "T1219"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BitterSecurity/Decepticon/blob/6b15092d2e0b41f2ef5af79a16333582cc3fb353/containers/c2-havoc-entrypoint.sh#L20-L31"
        confidence = "high"
    strings:
        $p = "decepticon-havoc-c2" ascii
        $l = "decepticon-https" ascii
        $t = "Teamserver" ascii
    condition:
        filesize < 1MB and $t and ($p or $l)
}

rule Decepticon_RoE_File
{
    meta:
        description = "Decepticon engagement scope file plan/roe.json (engagement_name plus machine_enforcement with in_scope and out_of_scope)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BitterSecurity/Decepticon/blob/6b15092d2e0b41f2ef5af79a16333582cc3fb353/packages/decepticon-core/decepticon_core/types/roe.py#L282-L288"
        confidence = "low"
    strings:
        $k1 = "\"machine_enforcement\"" ascii
        $k2 = "\"engagement_name\"" ascii
        $k3 = "\"in_scope\"" ascii
        $k4 = "\"out_of_scope\"" ascii
    condition:
        filesize < 1MB and uint8(0) == 0x7b and all of them
}
