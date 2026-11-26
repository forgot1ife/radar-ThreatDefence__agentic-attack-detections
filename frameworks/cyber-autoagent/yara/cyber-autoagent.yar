/*
   Agentic attack detections by ThreatDefence: Cyber-AutoAgent
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the Cyber-AutoAgent source code (westonbrown/Cyber-AutoAgent at 54897ff9), tested against
   the Cyber-AutoAgent source tree.
*/

rule CyberAutoAgent_Source
{
    meta:
        description = "Cyber-AutoAgent Python or TypeScript source files, or a fork that keeps their strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/westonbrown/Cyber-AutoAgent"
        confidence = "high"
    strings:
        $s1 = "__CYBER_EVENT__" ascii
        $s2 = "__CYBER_EVENT_END__" ascii
        $s3 = "cyber_operations.log" ascii
        $s4 = "CYBER_OPERATION_ID" ascii
        $s5 = "admin@cyber-autoagent.com" ascii
        $s6 = "dalfox-xss-test.com" ascii
        $s7 = "mem0_faiss_" ascii
        $s8 = "cyber/system/system_prompt" ascii
        $s9 = "via environment" ascii
        $s10 = "cyber-autoagent:latest" ascii
    condition:
        filesize < 5MB and 3 of them
}

rule CyberAutoAgent_System_Prompt
{
    meta:
        description = "Cyber-AutoAgent 'Ghost' system prompt template (src/modules/prompts/templates/system_prompt.md)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/westonbrown/Cyber-AutoAgent/blob/54897ff91d16ed05bacfb9b96526021d7aaa3026/src/modules/prompts/templates/system_prompt.md"
        confidence = "high"
    strings:
        $p1 = "You are Ghost, an autonomous cyber operations specialist" ascii
        $p2 = "Ghost - Elite Cyber Operations Specialist" ascii
        $p3 = "Finding Write Ritual" ascii
        $p4 = "Proof Pack" ascii
    condition:
        filesize < 1MB and ($p1 or $p2) and ($p3 or $p4)
}

rule CyberAutoAgent_Compose_Stack
{
    meta:
        description = "Cyber-AutoAgent docker-compose file with the seeded Langfuse org, project and admin account"
        mitre_att = "T1078.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/westonbrown/Cyber-AutoAgent/blob/54897ff91d16ed05bacfb9b96526021d7aaa3026/docker/docker-compose.yml"
        confidence = "high"
    strings:
        $c1 = "cyber-project-id" ascii
        $c2 = "admin@cyber-autoagent.com" ascii
        $c3 = "container_name: cyber-langfuse" ascii
        $c4 = "LANGFUSE_INIT_PROJECT_SECRET_KEY: cyber-secret" ascii
        $c5 = "cyber-autoagent_default" ascii
    condition:
        filesize < 256KB and 3 of them
}

rule CyberAutoAgent_Frontend_Config
{
    meta:
        description = "Cyber-AutoAgent front-end settings ~/.cyber-autoagent/config.json, which can hold model provider keys in clear text"
        mitre_att = "T1552.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/westonbrown/Cyber-AutoAgent/blob/54897ff91d16ed05bacfb9b96526021d7aaa3026/src/modules/interfaces/react/src/contexts/ConfigContext.tsx"
        confidence = "medium"
    strings:
        $k1 = "\"dockerImage\": \"cyber-autoagent:latest\"" ascii
        $k2 = "\"langfusePublicKey\"" ascii
        $k3 = "\"modelProvider\"" ascii
        $k4 = "\"memoryBackend\"" ascii
        $k5 = "\"reportSettings\"" ascii
    condition:
        filesize < 1MB and uint8(0) == 0x7b and $k1 and 2 of ($k2, $k3, $k4, $k5)
}
