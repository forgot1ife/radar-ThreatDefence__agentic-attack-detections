/*
   Agentic attack detections by ThreatDefence: Incalmo
   https://github.com/ThreatDefence/agentic-attack-detections
   Strings from cylabcyberautonomy/Incalmo at 8cd02e0e94889461bd04924c1db5b79cf7dc256c.
   The Sandcat implant binary Incalmo ships (incalmo/c2server/agents/sandcat.go) is MITRE Caldera's and is not covered here.
*/

rule Incalmo_C2_Server_Source
{
    meta:
        description = "Incalmo C2 server or action-layer source code: the Flask C2 root message and routes, per-command script names and the implant spreading commands"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/cylabcyberautonomy/Incalmo/blob/8cd02e0e94889461bd04924c1db5b79cf7dc256c/incalmo/c2server/c2server.py"
        mitre_att = "T1071.001, T1105"
    strings:
        $root = "Incalmo C2 Server API" ascii
        $health = "Flask + Celery" ascii
        $dyn = "dynamic_payload_" ascii
        $manual = "send_manual_command" ascii
        $delq = "agent_deletion_queue" ascii
        $llmq = "get_llm_agent_action" ascii
        $tmpgo = "sandcat_tmp.go" ascii
        $sclog = ">/tmp/sc.log" ascii
        $spawn = "-H \"file:sandcat.go\" -H \"platform:linux\"" ascii
    condition:
        filesize < 2MB and ($root or 3 of them or ($tmpgo and $sclog) or ($dyn and $manual))
}

rule Incalmo_Model_Prompts
{
    meta:
        description = "Incalmo prompt files: the planner prompt that names the Incalmo framework, and the sub-agent prompts that tell the model to fetch the Sandcat implant from a Caldera server and save it as splunkd"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/cylabcyberautonomy/Incalmo/tree/8cd02e0e94889461bd04924c1db5b79cf7dc256c/incalmo/core/strategies/llm/interfaces/preprompts"
        mitre_att = "T1588.002"
    strings:
        $planner = "you will be using the Incalmo framework in Python" ascii
        $caldera1 = "There is a Caldera command and control server running with an address" ascii
        $caldera2 = "A Caldera C2 server is reachable at" ascii
        $fetch = "file:sandcat.go" ascii
        $name = "splunkd" ascii
        $range = "white hat hacker testing a network for a cybersecurity exercise" ascii
    condition:
        filesize < 200KB and ($planner or (1 of ($caldera*) and $fetch and $name) or ($range and $fetch))
}

rule Incalmo_Run_Configuration
{
    meta:
        description = "Incalmo run configuration (config/config.json) or the AttackerConfig body posted to /startup: the keys strategy, environment and c2c_server"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/cylabcyberautonomy/Incalmo/blob/8cd02e0e94889461bd04924c1db5b79cf7dc256c/config/config_example.json"
        mitre_att = "T1071.001"
    strings:
        $c2 = "\"c2c_server\"" ascii
        $strategy = "\"strategy\"" ascii
        $env = "\"environment\"" ascii
    condition:
        filesize < 64KB and all of them
}
