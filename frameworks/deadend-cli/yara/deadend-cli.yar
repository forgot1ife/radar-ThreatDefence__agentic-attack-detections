/*
   Agentic attack detections by ThreatDefence: Deadend CLI
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Written from straylabs-ai/deadend-cli at 34e83717 (August 7, 2026). The strings were checked against
   its prompt, wallet, component manager and RPC server files at that commit, and the rules were run against this
   repository (no matches there).
   Not tested against the PyOxidizer release build, which embeds the same Python package.
*/

rule DeadendCLI_Source
{
    meta:
        description = "Deadend CLI source or package (deadend_cli, deadend_agent, deadend_prompts): its reflection marker prompt, sandbox image name, default trace collector, RPC banner or shipped test account"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/straylabs-ai/deadend-cli"
        confidence = "medium"
    strings:
        $marker = "Send unique marker: deadend7x7probe" ascii
        $image = "\"xoxruns/sandboxed_kali\"" ascii
        $collector = "https://crunch.straylabs.ai/" ascii
        $rpc = "RPC Server started and listening on stdin" ascii
        $pw = "deadendpassword123!" ascii
        $mail = "hacker@straylabs.ai" ascii
    condition:
        filesize < 50MB and any of them
}

rule DeadendCLI_Credential_Wallet
{
    meta:
        description = "Deadend CLI test-credential wallet (reusable_credentials.json): dummy values the model sees and the real ones pw_send_payload swaps in before sending"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/straylabs-ai/deadend-cli"
        confidence = "high"
    strings:
        $accounts = "\"accounts\"" ascii
        $dummy_user = "\"dummy_username\"" ascii
        $dummy_pass = "\"dummy_password\"" ascii
        $shipped1 = "deadenduser" ascii
        $shipped2 = "deadendtester" ascii
    condition:
        filesize < 1MB and $accounts and $dummy_user and $dummy_pass and any of ($shipped*)
}
