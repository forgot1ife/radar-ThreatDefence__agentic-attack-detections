/*
   Agentic attack detections by ThreatDefence: sapper-v2
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the sapper-v2 source code (N1nEmAn/sapper-v2 at 7b75e6f1), tested against its source tree.
*/

rule sapper_v2_Source_Or_Image_Scripts
{
    meta:
        description = "sapper-v2 CLI, Claude Code hook, or the commander, worker and watchdog scripts of its contest image"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/N1nEmAn/sapper-v2"
        confidence = "high"
    strings:
        $executor = "You are an autonomous executor in a penetration-testing fact-graph agent system" ascii
        $commander = "You are the autonomous field commander of a pentest campaign (TSecBench)" ascii
        $operator = "You are an autonomous pentest operator in a CTF benchmark" ascii
        $pane = "DRIVE_PANE_EXITED" ascii
        $poll = "__sapper_graph__" ascii
        $pool = "SAPPER_KEY_POOL" ascii
        $hook = "sapper-hook.py" ascii
        $session = "SESSION=sapper-cmd" ascii
    condition:
        filesize < 2MB and any of them
}

rule sapper_v2_Board_Page
{
    meta:
        description = "sapper-v2 engagement graph board: the HTML template, a saved sapper-graph.html snapshot (with the graph inlined) or the page from sapper view --serve"
        mitre_att = "T1071.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/N1nEmAn/sapper-v2/blob/7b75e6f1f5d5b4ae0c55878b0dd0994d9b08f1fb/lib/view_template.html"
        confidence = "high"
    strings:
        // <title>sapper — engagement graph</title>, em dash in UTF-8
        $title = { 3C 74 69 74 6C 65 3E 73 61 70 70 65 72 20 E2 80 94 20 65 6E 67 61 67 65 6D 65 6E 74 20 67 72 61 70 68 3C 2F 74 69 74 6C 65 3E }
        $marker = "/*__GRAPH_JSON__*/" ascii
        $end = "/*__END__*/" ascii
        $poll = "const POLL_URL = \"" ascii
    condition:
        filesize < 50MB and ($title or ($marker and $end and $poll))
}
