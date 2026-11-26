/*
   Agentic attack detections by ThreatDefence: BreachWeave
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from m-sec-org/BreachWeave at bc2d9502 (main, package tch-agent) and 6957a55f (pentest branch).
   The compiled tch-agent binaries (bun build --compile) carry the bundled TypeScript source as text, so the source
   strings below are expected in them too; no compiled binary was available to check this.
*/

rule BreachWeave_TchAgent_Binary_Or_Source
{
    meta:
        description = "BreachWeave (tch-agent) host or solver binary, or its source: CLI description, solver container and image names, injected env vars, observer prompt, console script marker"
        mitre_att = "T1588.002,T1610"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/m-sec-org/BreachWeave"
        confidence = "high"
    strings:
        $cli = "tch-agent by ez team" ascii
        $label = "ai.tch-agent.dockerfile-sha256" ascii
        $inject = "/opt/tch-agent/tch-agent" ascii
        $prefix = "\"tch-solver\"" ascii
        $env_ws = "TCH_SOLVER_WORKSPACE" ascii
        $env_sess = "TCH_SOLVER_SESSION_DIR" ascii
        $env_tok = "TCH_CHALLENGE_AGENT_TOKEN" ascii
        $runtime_pkg = "tch-agent-runtime" ascii
        $observer = { E4 BD A0 E6 98 AF 20 43 54 46 20 E8 A7 A3 E9 A2 98 20 41 67 65 6E 74 20 E7 9A 84 20 6F 62 73 65 72 76 65 72 20 73 69 64 65 63 61 72 }
        $ui_marker = "__tchResizeObserverPatched" ascii
        $kimi = "security_kimi_search" ascii
    condition:
        filesize < 300MB and ($cli or $label or $inject or 3 of them)
}

rule BreachWeave_Solver_Image_Dockerfile
{
    meta:
        description = "BreachWeave solver image Dockerfile (Kali base, marker file, tool set), synced to ~/.tch-agent/runtime/Dockerfile"
        mitre_att = "T1610,T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/m-sec-org/BreachWeave"
        confidence = "high"
    strings:
        $marker = "THIS_IS_DOCKER_CONTAINER_NOT_TARGET_MACHINE" ascii
        $kali = "kalilinux/kali-rolling" ascii
        $ab = "AGENT_BROWSER_EXECUTABLE_PATH" ascii
        $fscan = "shadow1ng/fscan/releases/download/1.8.4/fscan" ascii
        $mirror = "mirrors.ustc.edu.cn/kali" ascii
    condition:
        filesize < 1MB and $marker and 2 of ($kali, $ab, $fscan, $mirror)
}

rule BreachWeave_Host_Config_Files
{
    meta:
        description = "BreachWeave host configuration under ~/.tch-agent/config: settings.json with the tch runtime/challenge/auth block, or users.json with Argon2id hashes"
        mitre_att = "T1552.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/m-sec-org/BreachWeave"
        confidence = "medium"
    strings:
        $tch = "\"tch\": {" ascii
        $runtime = "\"runtime\": {" ascii
        $challenge = "\"agentToken\"" ascii
        $mappings = "\"baseUrlMappings\"" ascii
        $auth = "\"registrationEnabled\"" ascii
        $jwt = "\"jwtSecret\"" ascii
        $users = "\"users\": [" ascii
        $hash = "\"passwordHash\": \"$argon2id$" ascii
    condition:
        filesize < 2MB and (($tch and $runtime and 1 of ($challenge, $mappings, $auth, $jwt)) or ($users and $hash))
}

rule BreachWeave_Redis_Webroot_Pages
{
    meta:
        description = "PHP pages written into a web root through Redis CONFIG SET dbfilename by the redis-webroot-rce and intranet-pentest skills (diagnostic page and command page); the file is a Redis RDB dump with the PHP inside"
        mitre_att = "T1505.003"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/m-sec-org/BreachWeave"
        confidence = "medium"
    strings:
        $diag1 = "echo \"DIAG_START\\n\";" ascii
        $diag2 = "\"com_loaded: \".(class_exists(\"COM\")?\"yes\":\"no\")" ascii
        $diag3 = "@system(\"echo SYS_OK\")" ascii
        $exec = "<?php set_time_limit(0); ini_set('max_execution_time','0'); system($_POST['cmd'].' 2>&1'); ?>" ascii
        $echo = "<?php echo $_POST[\"cmd\"]; ?>" ascii
        $rdb = "REDIS00" ascii
    condition:
        filesize < 5MB and (($diag1 and ($diag2 or $diag3)) or ($rdb at 0 and ($exec or $echo)))
}
