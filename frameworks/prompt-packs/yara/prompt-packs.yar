/*
   Agentic attack detections by ThreatDefence: offensive prompt packs for AI coding agents
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. These packs ship instructions for a coding agent (skills, subagent definitions, system prompts),
   not an agent of their own. The rules find their files on a host: in a home folder, a project folder or a
   container layer. Strings checked against the source files at these commits:
     SnailSploit/Claude-Red            6196ba7464662de34e8744d359f175d1a7bca530 (2026-11-17)
     0xSteph/pentest-ai-agents         e5d7aa02c4c0c29a90e4789034b45e0cb7488e89 (2026-08-16, 3.4.0)
     chAng-L19/codex-redteam-mode      cd8db548fd379d67fe6ec74e382ce7c101ca603f (2026-08-24, 2.1.0)
     ok-helloworld/vibe-pentest        0b80fbf18d48d30950097c9531d6e05737901b51 (2026-09-21, 1.0.32)
*/

rule ClaudeRed_Offensive_Skill
{
    meta:
        description = "Claude-Red skill file: SKILL.md whose front matter names an offensive-<topic> skill and which cites the SnailSploit offensive-checklist (48 of the 79 skills)"
        mitre_att = "T1588.002, T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/SnailSploit/Claude-Red"
        confidence = "medium"
    strings:
        $fm = "---\nname: offensive-" ascii
        $fm_crlf = "---\r\nname: offensive-" ascii
        $checklist = "github.com/SnailSploit/offensive-checklist" ascii
    condition:
        filesize < 2MB and ($fm at 0 or $fm_crlf at 0) and $checklist
}

rule ClaudeRed_Offensive_Skill_Broad
{
    meta:
        description = "SKILL.md whose front matter starts with name: offensive-<topic>, the naming of all 79 Claude-Red skills; other skill packs can use the same prefix"
        mitre_att = "T1588.002, T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/SnailSploit/Claude-Red"
        confidence = "low"
    strings:
        $fm = "---\nname: offensive-" ascii
        $fm_crlf = "---\r\nname: offensive-" ascii
    condition:
        filesize < 2MB and ($fm at 0 or $fm_crlf at 0)
}

rule ClaudeRed_Manifest
{
    meta:
        description = "Claude-Red skill manifest claude-skills.json"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/SnailSploit/Claude-Red"
        confidence = "medium"
    strings:
        $name = "\"name\": \"claude-red\"" ascii
        $home = "github.com/SnailSploit/claude-red" ascii nocase
        $skill = "\"offensive-active-directory\"" ascii
    condition:
        filesize < 256KB and all of them
}

rule PentestAIAgents_Subagent_Or_Command
{
    meta:
        description = "pentest-ai-agents Claude Code subagent or slash command: a front matter file that logs to its findings.sh database, its scope guard block, or its agents-for and recommend commands"
        mitre_att = "T1588.002, T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/0xSteph/pentest-ai-agents"
        confidence = "medium"
    strings:
        $fm = "---\nname: " ascii
        $fm_crlf = "---\r\nname: " ascii
        $db_check = "command -v findings.sh &>/dev/null" ascii
        $db_log = "findings.sh log \"" ascii
        $guard = "# Scope Guard (Shared Prompt Block for Tier 2 Agents)" ascii
        $cmd_rec = "Recommend the right pentest-ai agent" ascii
        $cmd_list = "List pentest-ai agents relevant to" ascii
    condition:
        filesize < 1MB and (
            (($fm at 0 or $fm_crlf at 0) and ($db_check or $db_log))
            or $guard or $cmd_rec or $cmd_list
        )
}

rule PentestAIAgents_Findings_Database_Scripts
{
    meta:
        description = "pentest-ai-agents findings database helpers its installer copies to ~/.pentest-ai/bin (findings.sh, lib/common.sh, schema.sql)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/0xSteph/pentest-ai-agents"
        confidence = "medium"
    strings:
        $cli = "# pentest-ai findings database CLI" ascii
        $lib = "# Shared functions for pentest-ai findings database" ascii
        $schema = "-- pentest-ai findings database" ascii
        $env = "PENTEST_AI_ENGAGEMENT" ascii
    condition:
        filesize < 256KB and ($cli or $lib or ($schema and filesize < 64KB) or ($env and #env > 2))
}

rule CodexRedteamMode_Jailbreak_Prompt
{
    meta:
        description = "codex-redteam-mode jailbreak prompt profile (Jailbreak.default.md, Jailbreak.gpt-5.4/5.5/5.6.md) that its installer copies to ~/.codex/prompts/ and loads into Codex's system layer"
        mitre_att = "T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/chAng-L19/codex-redteam-mode"
        confidence = "high"
    strings:
        $mode_compat = "[MODE: UNRESTRICTED COMPATIBILITY]" ascii
        $mode = "[MODE: UNRESTRICTED]" ascii
        $h54 = "# GPT-5.4 CTF / Red-Team Core Contract" ascii
        $sandbox = "professional sandbox operations" ascii
        $p56_role = "hands-on sandbox executor" ascii
        $p56_compiler = "SINGLE-PASS TASK COMPILER:" ascii
    condition:
        filesize < 64KB and (
            $h54 at 0
            or ($mode_compat at 0 and $sandbox)
            or ($mode at 0 and ($sandbox or $p56_role or $p56_compiler))
        )
}

rule CodexRedteamMode_Installed_Files
{
    meta:
        description = "Files codex-redteam-mode writes into a Codex home: the managed AGENTS.md block, the combined system-instructions.md, config.toml with its MCP server and rewrite proxy provider, hooks.json, and its own source copied there"
        mitre_att = "T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/chAng-L19/codex-redteam-mode"
        confidence = "high"
    strings:
        $agents_block = "<!-- codex-redteam-optin-mode:start -->" ascii
        $sys_profile = "<!-- codex-redteam-system-profile:start -->" ascii
        $model_catalog = "<!-- codex-redteam-model-profiles:start -->" ascii
        $base_hdr = "# Codex red-team base instructions" ascii
        $runtime_hdr = "# Codex Red-Team Runtime Profile" ascii
        $proxy_provider = "codex-redteam-rewrite-proxy" ascii
        $mcp_server = "codex-redteam-runtime" ascii
        $hook_status = "Dispatching durable red-team workflow" ascii
        $app = "codex-redteam-optin-mode" ascii
    condition:
        filesize < 2MB and any of them
}

rule VibePentest_Skill_Files
{
    meta:
        description = "vibe-pentest skill: its SKILL.md, the sub-agent definitions it copies into <project>/.<agent>/agents/, and the reports it writes"
        mitre_att = "T1588.002, T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/ok-helloworld/vibe-pentest"
        confidence = "medium"
    strings:
        $fm = "---\nname: vibe-pentest\n" ascii
        $fm_crlf = "---\r\nname: vibe-pentest\r\n" ascii
        $update = "scripts/auto_update_skill.py {SKILL_ROOT}" ascii
        $subagent = "vibe-pentest Phase 5" ascii
        $tester = "vibe-pentest-agent-v1" ascii
        $deser_ua = "vibe-pentest-deserialization-payload/1.0" ascii
        $workspace_help = "Path to vibe-pentest workspace directory" ascii
    condition:
        filesize < 5MB and (($fm at 0 or $fm_crlf at 0) or any of ($update, $subagent, $tester, $deser_ua, $workspace_help))
}
