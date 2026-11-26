/*
   Agentic attack detections by ThreatDefence: KaliGPT (HackerX)
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the KaliGPT source code (SudoHopeX/KaliGPT at b15b8d48, branch hackerx, KaliGPT v1.3).
*/

rule KaliGPT_Source
{
    meta:
        description = "KaliGPT (HackerX) AI agent source, a clone in /opt/KaliGPT or a fork that keeps its strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/SudoHopeX/KaliGPT"
        confidence = "high"
    strings:
        $ua = "HackerX WebRequestFramework/1.0" ascii
        $s1 = "[HackerX Tool Use]" ascii
        $s2 = "HackerX CLI (KaliGPT v1.3) - by SudoHopeX" ascii
        $s3 = "hackerx-28b-4k" ascii
        $s4 = "g-xouSQobsE-kaligpt" ascii
        $s5 = "\"User-Agent\": \"LocalScraper/1.0\"" ascii
        $s6 = "( HackerX - Available Tools )" ascii
        $s7 = "HackerX-CLI Ai Response Markdown renderer" ascii
        $s8 = "Exiting HackerX. See you later!" ascii
    condition:
        filesize < 200KB and ($ua or 2 of ($s*))
}

rule KaliGPT_Launcher
{
    meta:
        description = "KaliGPT launcher script written by its installer (/usr/local/bin/kaligpt, Termux .../usr/bin/kaligpt) or the installer itself (kaligptinstaller.sh)"
        mitre_att = "T1059.006"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/SudoHopeX/KaliGPT/blob/b15b8d48367f9d2b9b3bd7edc40daa42445a1228/installers/installer.deb.sh#L141-L283"
        confidence = "high"
    strings:
        $l1 = "KaliGPT v1.3 Launcher Script" ascii
        $l2 = "st_opensearchapi" ascii
        $l3 = "start_opensearchapi" ascii
        $l4 = "/opt/KaliGPT/its_venv/bin/activate" ascii
        $l5 = "/OpenSearchAPI/app.py" ascii
        $m1 = "python3 -m agents.gemini" ascii
        $m2 = "python3 -m agents.openrouter" ascii
    condition:
        filesize < 50KB and 2 of ($l*) and 1 of ($m*)
}

rule KaliGPT_Provider_Config
{
    meta:
        description = "KaliGPT provider configuration agents/utils/api.config.json: Gemini, OpenAI, OpenRouter keys and the Ollama URL in clear text; the installer makes it mode 666"
        mitre_att = "T1552.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/SudoHopeX/KaliGPT/blob/b15b8d48367f9d2b9b3bd7edc40daa42445a1228/agents/utils/agent_configs.py#L18-L87"
        confidence = "medium"
    strings:
        $k1 = "\"default_provider\":" ascii
        $k2 = "\"gemini\":" ascii
        $k3 = "\"chatgpt\":" ascii
        $k4 = "\"openrouter\":" ascii
        $k5 = "\"ollama\":" ascii
        $k6 = "\"api_key\":" ascii
        $v1 = "gpt-5.6-cyber" ascii
        $v2 = "openai/gpt-oss-120b:free" ascii
        $v3 = "YOUR_OPENROUTER_API_KEY" ascii
        $v4 = "sk-or-v1-" ascii
    condition:
        uint8(0) == 0x7b and filesize < 20KB and all of ($k*) and 1 of ($v*)
}
