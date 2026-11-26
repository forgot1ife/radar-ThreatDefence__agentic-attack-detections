/*
   Agentic attack detections by ThreatDefence: Cochise
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the Cochise source code (andreashappe/cochise at 4db4fded).
*/

rule Cochise_Source
{
    meta:
        description = "Cochise agent source: ssh_connection.py, executor.py, planner.py or logger.py, or a fork that keeps their strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/andreashappe/cochise/tree/4db4fded894305083366b83e5cdba5fb68fcebc3/src/cochise"
        confidence = "high"
    strings:
        $a1 = "async def execute_command(self, command: str, mitre_attack_technique: str, mitre_attack_procedure: str)" ascii
        $a2 = "Timeout during command execution over SSH command execution." ascii
        $a3 = "async def perform_task(self, next_step: str, next_step_context: str, mitre_attack_tactic: str, mitre_attack_technique: str)" ascii
        $a4 = "You MUST call the perform_task tool to delegate work to the executor." ascii
        $a5 = "logs/run-{formatted_timestamp}" ascii
        $a6 = "Save information on identified/compromised account" ascii
        $b1 = "log_llm_call('planner_task_selection'" ascii
        $b2 = "log_llm_call('executor_next_cmds'" ascii
        $b3 = "Experiment was not successful in gaining any relevant information for the task." ascii
        $b4 = "noted compromised account {username} with context" ascii
        $b5 = "logger.log_data(\"starting test-run\")" ascii
        $b6 = "def log_llm_call(self, name:str, result, costs: dict, duration:float" ascii
        $b7 = "ExecutorFactory(model, api_key, SCENARIO, tools, logger)" ascii
    condition:
        filesize < 100KB and 2 of them
}

rule Cochise_Scenario_Prompt
{
    meta:
        description = "Cochise scenario prompt (templates/scenario.md), in the clone or copied into a run log or a fork"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/andreashappe/cochise/blob/4db4fded894305083366b83e5cdba5fb68fcebc3/src/cochise/templates/scenario.md"
        confidence = "medium"
    strings:
        $s1 = "is a list of potential usernames gathered through OSINT" ascii
        $s2 = "Mandiant Attack Lifecycle Model or the Lockheed-Martin Cyber Killchain" ascii
        $s3 = "ignore and do not attack/use the vagrant user" ascii
        $s4 = "it's `impacket-GetNPUsers` not `impacket-getNPUsers`" ascii
        $s5 = "/osint_users.txt" ascii
    condition:
        filesize < 50MB and 3 of them
}

rule Cochise_Run_Log
{
    meta:
        description = "Cochise run log logs/run-<YYYYmmdd-HHMMSS>.json: JSON lines with every prompt, command, output and saved credential"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/andreashappe/cochise/blob/4db4fded894305083366b83e5cdba5fb68fcebc3/src/cochise/logger.py#L33-L52"
        confidence = "high"
    strings:
        $h1 = "\"event\": \"starting test-run\"" ascii
        $h2 = "\"ssh-host\": " ascii
        $e1 = "\"planner_initial_plan\"" ascii
        $e2 = "\"planner_task_selection\"" ascii
        $e3 = "\"executor_next_cmds\"" ascii
        $e4 = "\"mitre_attack_procedure\"" ascii
        $e5 = "\"history_append\"" ascii
    condition:
        uint8(0) == 0x7b and filesize < 200MB and (($h1 and $h2) or 3 of ($e*))
}
