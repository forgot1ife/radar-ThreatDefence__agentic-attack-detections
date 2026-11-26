/*
   Agentic attack detections by ThreatDefence: CHYing-agent
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from yhy0/CHYing-agent at 0d2ee81f. Tested against synthetic samples built from those strings
   (no matches on the near misses), not against a full checkout of the repository.
*/

rule CHYingAgent_Source
{
    meta:
        description = "CHYing-agent source or a copy of it: web terminal markers, orchestrator identity, MCP tool names, dashboard title, tools container name and the Python work-directory header"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/yhy0/CHYing-agent"
        confidence = "high"
    strings:
        $probe = "__WSS_PROBE_7b3e__" ascii
        $exit = "__WSS_EXIT_c1a4__" ascii
        $delim = "__WSS_CMD_END_9f7a__" ascii
        $identity = "You are CHYing Orchestrator - an autonomous security automation system" ascii
        $tool = "CHYING_EXEC = \"mcp__chying__exec\"" ascii
        $server = "_MCP_SERVER_NAME = \"chying\"" ascii
        $title = "title=\"CHYing Agent Dashboard\"" ascii
        $container = "DOCKER_CONTAINER_NAME=chying-agent-docker" ascii
        $header = { 23 20 3D 3D 3D 20 E8 87 AA E5 8A A8 E6 B3 A8 E5 85 A5 EF BC 9A E5 B7 A5 E4 BD 9C E7 9B AE E5 BD 95 E8 AE BE E7 BD AE 20 3D 3D 3D }  // # === 自动注入：工作目录设置 ===
    condition:
        filesize < 20MB and 2 of them
}

rule CHYingAgent_Web_Terminal_Command_Trace
{
    meta:
        description = "Shell history, terminal recording or log on a target that holds the command wrapper CHYing-agent types into a web terminal (__chy_rc=$?; printf ... __WSS_EXIT_c1a4__ ...; echo __WSS_CMD_END_9f7a__)"
        mitre_att = "T1059.004, T1133"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/yhy0/CHYing-agent"
        confidence = "high"
    strings:
        $rc = "__chy_rc=$?" ascii
        $exit = "__WSS_EXIT_c1a4__" ascii
        $delim = "__WSS_CMD_END_9f7a__" ascii
        $probe = "echo __WSS_PROBE_7b3e__" ascii
    condition:
        filesize < 50MB and ($rc or $probe or ($exit and $delim))
}

rule CHYingAgent_Work_Files
{
    meta:
        description = "CHYing-agent work folder files: findings.log entries with its trust labels, or progress.md with its auto-synced sections"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/yhy0/CHYing-agent"
        confidence = "medium"
    strings:
        $f_next = "**paths_not_tried** (candidates for next agent):" ascii
        $f_verified = " [VERIFIED-BY-EXECUTION]" ascii
        $f_inferred = " [UNVERIFIED-INFERENCE]" ascii
        $f_verification = "- verification: " ascii
        $p_plan = "### Attack Plan (auto-synced from TodoWrite)" ascii
        $p_checkpoint = "## Auto Checkpoint" ascii
    condition:
        filesize < 50MB and (
            ($f_verification and ($f_verified or $f_inferred or $f_next)) or
            ($p_plan and $p_checkpoint)
        )
}
