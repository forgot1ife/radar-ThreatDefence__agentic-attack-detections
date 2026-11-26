/*
   Agentic attack detections by ThreatDefence: OpenHack
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from openhackai/OpenHack: the v2 source-code scanner at f94e153c and the v0.x pentest agent
   at tag v0.2.4 (8fdfdddf, PyPI openhack 0.2.4). Tested against synthetic samples written from the source code, not
   against the repository files or release executables themselves.
*/

rule OpenHack_V2_Executable_Or_Source
{
    meta:
        description = "OpenHack v2 source tree or Bun standalone executable (~/.local/bin/openhack): its dashboard error strings, its subscription worker prompt and temporary folder prefix. The standalone build embeds the bundled JavaScript, so the strings are present as text"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/openhackai/OpenHack"
        confidence = "medium"
    strings:
        $host = "This dashboard only accepts requests addressed to localhost." ascii
        $client = "The X-OpenHack-Client dashboard header is required." ascii
        $owner = "This dashboard can only be stopped by its local owner." ascii
        $worker = "You are a source-review worker inside OpenHack." ascii
        $tmp = "openhack-subscription-" ascii
        $login = "openhack-login-" ascii
        $picker = "Choose a project to scan" ascii
    condition:
        filesize < 200MB and 3 of them
}

rule OpenHack_V0_Python_Package
{
    meta:
        description = "OpenHack v0.x Python package (PyPI openhack, 0.2.4) or its source: agent prompts, the out-of-band collector and model gateway URLs, the canary marker and the sandbox project prefix"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/openhackai/OpenHack/tree/v0.2.4"
        confidence = "medium"
    strings:
        $hunter = "You are the Hunter agent for OpenHack Agent" ascii
        $validator = "You are the Validator agent for OpenHack Agent" ascii
        $swiss = "the Swiss-army knife for hackers" ascii
        $oob = "https://oob.openhack.com" ascii
        $api = "https://api.openhack.com/v1" ascii
        $updates = "https://api.openhack.com/updates" ascii
        $canary = "__openhack_test_probe" ascii
        $sandbox = "openhack-sandbox-" ascii
        $evidence = ".openhack-evidence" ascii
    condition:
        filesize < 10MB and 2 of them
}

rule OpenHack_V2_Scan_Report
{
    meta:
        description = "OpenHack v2 scan report (~/.openhack/projects/<hash>/scans/<ms epoch>-<8 hex>.json): findings with verbatim source evidence, data flow and remediation for the scanned code, written as two-space indented JSON"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/openhackai/OpenHack/blob/f94e153c5e6cc55218692ff6827ca1ac4e17e6a9/src/harness/types.ts"
        confidence = "medium"
    strings:
        $read = "\"readFiles\": [" ascii
        $inventory = "\"inventory\": {" ascii
        $validation = "\"validationReason\": " ascii
        $flow = "\"dataFlow\": " ascii
        $role_adv = "\"role\": \"advocate\"" ascii
        $role_judge = "\"role\": \"judge\"" ascii
        $plan = "\"planVersion\": 2" ascii
        $state = /"state": "(running|complete|cancelled|failed|partial)"/ ascii
    condition:
        filesize < 64MB and uint8(0) == 0x7B and $read and $inventory and $state and 1 of ($validation, $flow, $role_adv, $role_judge, $plan)
}
