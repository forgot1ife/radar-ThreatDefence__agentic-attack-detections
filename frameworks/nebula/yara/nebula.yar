/*
   Agentic attack detections by ThreatDefence: Nebula
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from BerylliumSec/nebula at 409bf4f9 (November 25, 2026). Checked against the source files
   they come from. The packaged nebula-core is a frozen Python build whose modules are compressed, so these rules
   target the source tree, the built browser workspace, and the files Nebula writes; scan a packaged install's
   runtime/releases/ folder and its ui/ files rather than the executable.
*/

rule Nebula_Core_Source
{
    meta:
        description = "Nebula (BerylliumSec/nebula) core source: its command wrapper, container names, Kali image recipe, pairing and authentication messages, user agents or the core placeholder page"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BerylliumSec/nebula"
        confidence = "medium"
    strings:
        $wrapper = "os.execv('/bin/bash',['/bin/bash','--noprofile','--norc','-c',sys.argv[2]])" ascii
        $pidfile = "/tmp/nebula-process-{process_id}.pid" ascii
        $image = "localhost/nebula-kali-headless" ascii
        $label = "org.nebula.human-terminal.profile" ascii
        $placeholder = "Nebula Core is running. Connect with a paired client." ascii
        $pairing = "new device pairings may be created only from the local machine" ascii
        $protocol = "nebula-desktop-runtime-v1" ascii
        $ua_terminal = "Nebula-Terminal/1" ascii
        $ua_fetch = "Nebula/3 knowledge-source-fetcher" ascii
        $origin = "Nebula provider session. " ascii
        $ready = "nebula-api-ready" ascii
    condition:
        filesize < 2MB and any of them
}

rule Nebula_Browser_Workspace
{
    meta:
        description = "Nebula browser workspace page or web manifest, as served by an exposed core or kept in its release bundle"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BerylliumSec/nebula"
        confidence = "high"
    strings:
        $desc = "Nebula 3 local-first security engagement workspace" ascii
        $title = "<title>Nebula 3</title>" ascii
        $boot = "aria-label=\"Nebula is starting\"" ascii
        $noscript = "Nebula requires JavaScript to render the engagement workspace." ascii
        $manifest_name = "\"Nebula Operator Companion\"" ascii
        $manifest_desc = "Secure mobile companion for Nebula engagements" ascii
    condition:
        filesize < 200KB and (($desc and $title) or $boot or $noscript or all of ($manifest_*))
}

rule Nebula_Runtime_And_Container_Files
{
    meta:
        description = "Files Nebula writes: the core connection file in runtime/connection.json, the Kali image's public address cron entry, and the terminal entrypoint baked into that image"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/BerylliumSec/nebula"
        confidence = "high"
    strings:
        $conn_protocol = "\"protocol\": \"nebula-desktop-runtime-v1\"" ascii
        $conn_startup = "\"startup_id\"" ascii
        $cron = "root /usr/local/lib/nebula-public-ip-update >/dev/null 2>&1" ascii
        $entry_dir = "mkdir -p -m 0700 /run/nebula" ascii
        $entry_update = "/usr/local/lib/nebula-public-ip-update >/dev/null 2>&1 &" ascii
    condition:
        filesize < 64KB and (all of ($conn_*) or $cron or all of ($entry_*))
}
