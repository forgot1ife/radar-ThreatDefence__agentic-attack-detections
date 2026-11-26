/*
   Agentic attack detections by ThreatDefence: LazyOwn
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the LazyOwn source code (grisuno/LazyOwn at f4e54de9, November 25, 2026) and tested against
   the files named in each rule. No rule here looks at LazyOwn's implants, loaders or shellcode; those were not reviewed.
*/

rule LazyOwn_C2_Server
{
    meta:
        description = "LazyOwn C2 server source (lazyc2.py and the lazyc2 package): DNS C2 zone, staging and BOF answers, Basic auth challenge, dashboard banner"
        mitre_att = "T1071.001,T1071.004"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/grisuno/LazyOwn"
        confidence = "high"
    strings:
        $d1 = "c2.lazyown.org." ascii
        $d2 = "Servidor C2 activo" ascii
        $d3 = "esporalibre.cl." ascii
        $s1 = "STAGE_FORBIDDEN" ascii
        $s2 = "STAGE_UNAVAILABLE" ascii
        $s3 = "BOF_NOT_FOUND" ascii
        $s4 = "_bsb_beacon_clients" ascii
        $s5 = "route_malleable" ascii
        $a1 = "Invalid credentials. Please provide valid username and password." ascii
        $a2 = "First GPL Ai Powered C&C" ascii
        $a3 = "LAZY_CSRF_TOKEN" ascii
    condition:
        filesize < 2MB and 3 of them
}

rule LazyOwn_Payload_Config
{
    meta:
        description = "LazyOwn payload.json, the settings file the CLI, the C2 and the MCP server share (C2 port and credentials, malleable route, beacon user agents, backdoor accounts); also matches LazyOwn code that reads it"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/grisuno/LazyOwn/blob/f4e54de958740c421071ac20c98eff1bd6ab7957/payload.example.json"
        confidence = "high"
    strings:
        $k1 = "\"c2_malleable_route\"" ascii
        $k2 = "\"user_agent_win\"" ascii
        $k3 = "\"c2_require_beacon_hmac\"" ascii
        $k4 = "\"c2_decoy_mode\"" ascii
        $k5 = "\"backdoor_linux_home\"" ascii
        $k6 = "\"backdoor_win_service_path\"" ascii
        $k7 = "\"enable_c2_implant_debug\"" ascii
        $v1 = "LAzyOwnRedTeam" ascii
        $v2 = "/home/.lazyown" ascii
    condition:
        filesize < 512KB and 4 of them
}

rule LazyOwn_C2_Decoy_Page
{
    meta:
        description = "Decoy page the LazyOwn C2 serves to addresses outside its operator allowlist: a template site preview that asks for camera and microphone and posts frames and recordings back to the C2"
        mitre_att = "T1125,T1123"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/grisuno/LazyOwn/blob/f4e54de958740c421071ac20c98eff1bd6ab7957/templates/decoy.html"
        confidence = "high"
    strings:
        $t1 = "Live View Page -  564 plot listing Template" ascii
        $t2 = "templatemo_564_plot_listing" ascii
        $c1 = "urlCompleta + 'capture'" ascii
        $c2 = "urlCompleta + 'audio'" ascii
        $c3 = "getUserMedia({ video: true, audio: true })" ascii
    condition:
        filesize < 200KB and 1 of ($t*) and 2 of ($c*)
}

rule LazyOwn_C2_Launch_Files
{
    meta:
        description = "C2 launcher files fast_run_as_r00t.sh writes into sessions/ (c2_launch.env with the C2 port, user and password, and c2_launch.sh)"
        mitre_att = "T1059.004"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/grisuno/LazyOwn/blob/f4e54de958740c421071ac20c98eff1bd6ab7957/fast_run_as_r00t.sh#L245-L256"
        confidence = "high"
    strings:
        $e1 = "LAZY_C2_PORT=" ascii
        $e2 = "LAZY_C2_USER=" ascii
        $e3 = "LAZY_C2_PASS=" ascii
        $l1 = "sessions/c2_launch.env" ascii
        $l2 = "lazyc2.py \"$LAZY_C2_PORT\"" ascii
    condition:
        filesize < 64KB and (all of ($e*) or all of ($l*))
}

rule LazyOwn_Beacon_Runtime_Config
{
    meta:
        description = "Runtime configuration the LazyOwn C2 builds for its BlackSandBeacon Linux client, served on /stage/config and written next to the beacon (C2 URL, poll URI, AES key, timing, user agents)"
        mitre_att = "T1071.001,T1573.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/grisuno/LazyOwn/blob/f4e54de958740c421071ac20c98eff1bd6ab7957/modules/bof_delivery.py#L258-L332"
        confidence = "medium"
    strings:
        $k1 = "\"master_key_hex\"" ascii
        $k2 = "\"replay_window_seconds\"" ascii
        $k3 = "\"curl_connect_timeout_seconds\"" ascii
        $k4 = "\"report_uri\"" ascii
        $k5 = "\"download_chunk_size\"" ascii
        $u1 = "Chrome/120.0.0.0 Firefox/120.0" ascii
    condition:
        filesize < 64KB and 4 of them
}
