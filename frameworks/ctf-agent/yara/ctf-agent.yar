/*
   Agentic attack detections by ThreatDefence: CTF Agent
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the CTF Agent source code (verialabs/ctf-agent at 3366d569).
*/

rule CTF_Agent_Source
{
    meta:
        description = "CTF Agent (verialabs/ctf-agent) source: CTFd client, sandbox, solvers, coordinators or prompts, or a fork that keeps their strings"
        mitre_att = "T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/verialabs/ctf-agent/tree/3366d569557c4fda3fd153040632de65e255396d/backend"
        confidence = "high"
    strings:
        $ua = "USER_AGENT = \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36\"" ascii
        $lbl = "CONTAINER_LABEL = \"ctf-agent\"" ascii
        $ws = "prefix=\"ctf-workspace-\"" ascii
        $wrap = "timeout --signal=KILL --kill-after=5 {timeout_s} bash -c" ascii
        $rw = "docker exec -i {self._container_id} bash -c" ascii
        $ci1 = "\"clientInfo\": {\"name\": \"ctf-agent\"" ascii
        $ci2 = "\"clientInfo\": {\"name\": \"ctf-coordinator\"" ascii
        $msg = "Operator message endpoint listening on" ascii
        $p1 = "IMPORTANT: You are running inside a Docker sandbox. " ascii
        $p2 = "You are a CTF competition coordinator running for the ENTIRE duration of a live competition." ascii
        $p3 = "You are an expert CTF solver. Find the real flag for the challenge below." ascii
        $p4 = "mcp__coordinator__read_solver_trace" ascii
        $pkg = "name = \"ctf-agent-two\"" ascii
        $cli = "ctf-solve = \"backend.cli:main\"" ascii
    condition:
        filesize < 200KB and (2 of them)
}

rule CTF_Agent_Solver_Trace
{
    meta:
        description = "CTF Agent per-solver JSONL trace (logs/trace-<challenge>-<model>-<timestamp>.jsonl): start event, then tool calls, results, bumps and flag events"
        mitre_att = "T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/verialabs/ctf-agent/blob/3366d569557c4fda3fd153040632de65e255396d/backend/tracing.py#L15-L58"
        confidence = "medium"
    strings:
        $start = "\"type\": \"start\", \"challenge\": \"" ascii
        $call = "\"type\": \"tool_call\", \"tool\": \"" ascii
        $res = "\"type\": \"tool_result\", \"tool\": \"" ascii
        $e1 = "\"type\": \"flag_confirmed\"" ascii
        $e2 = "\"type\": \"bump\", \"insights\": \"" ascii
        $e3 = "\"type\": \"loop_break\", \"tool\": \"" ascii
        $e4 = "\"type\": \"finish\", \"status\": \"" ascii
        $e5 = "\"type\": \"turn_complete\", \"duration\": " ascii
    condition:
        uint16(0) == 0x227b and filesize < 50MB and $start in (0..256) and ($call or $res) and 1 of ($e*)
}
