/*
   Agentic attack detections by ThreatDefence: Sage (Mythic)
   https://github.com/ThreatDefence/agentic-attack-detections
   Strings from MythicAgents/sage at cbff42f0abc54d3c64b40d3a71cffce01a057023.
   Mythic, its payload types (Apollo and others) and the tools Sage tasks (Mimikatz, Rubeus, SharpHound) are not covered here.
*/

rule SageMythic_Source
{
    meta:
        description = "Sage source code (the Mythic AI operator chat container): its default proof markers, proof file names, task and drive names, PFX password prefixes and Mythic GraphQL operation names"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/MythicAgents/sage/tree/cbff42f0abc54d3c64b40d3a71cffce01a057023/Payload_Type/sage/ai/langgraph"
        mitre_att = "T1047, T1059.001, T1649"
    strings:
        $m1 = "SAGE_REMOTE_EXEC_PROOF_" ascii
        $m2 = "SAGE_EP_ADJUST_PROOF" ascii
        $m3 = "SAGE_CA_EXPORT_PROOF" ascii
        $m4 = "SAGE_CERT_ENROLL_PROOF" ascii
        $m5 = "SAGE_CERT_AUTH_PROOF" ascii
        $t1 = "SageExec_" ascii
        $t2 = "SagePfx-v1-" ascii
        $t3 = "SageNetOnlyContext1!" ascii
        $t4 = "New-PSDrive -Name SAGEPROOF" ascii
        $t5 = "New-PSDrive -Name SAGEEP" ascii
        $f1 = "sage_remote_exec_" ascii
        $f2 = "sage_cert_enroll_" ascii
        $f3 = "sage_ca_export_" ascii
        $q1 = "query sageWhoamiScopes" ascii
        $q2 = "query SageReconcileTasks" ascii
        $c1 = "class SageChat(Chat)" ascii
    condition:
        filesize < 5MB and (2 of ($m*) or 3 of them)
}

rule SageMythic_Prompts
{
    meta:
        description = "Sage agent prompt files (prompts/mythic_operator.md, prompts/bloodhound.md, prompts/supervisor.md) as shipped in the Mythic service directory"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/MythicAgents/sage/tree/cbff42f0abc54d3c64b40d3a71cffce01a057023/Payload_Type/sage/prompts"
        mitre_att = "T1588.007"
    strings:
        $op = "you drive all Mythic C2 operations and in-memory offensive tradecraft" ascii
        $bh = "the single owner of the BloodHound attack-graph in Sage" ascii
        $sup = "Has native tools for list_callbacks, issue_task, get_task_history" ascii
    condition:
        filesize < 1MB and ($op or $bh or $sup)
}

rule SageMythic_Target_Proof_File
{
    meta:
        description = "Proof or output file a Sage task leaves on a Windows host (C:\\Windows\\Temp\\sage_remote_exec_*.txt, sage_ep_adjust_*.txt, sage_ca_export_*.txt): a SAGE_*_PROOF marker line followed by whoami/hostname output or Sage's KEY=VALUE status lines"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/MythicAgents/sage/blob/cbff42f0abc54d3c64b40d3a71cffce01a057023/Payload_Type/sage/ai/langgraph/mythic_capability_adapter.py"
        mitre_att = "T1047, T1685"
    strings:
        $marker = /SAGE_(REMOTE_EXEC|EP_ADJUST|CA_EXPORT|CERT_ENROLL|CERT_AUTH)_PROOF[A-Za-z0-9_.-]* ?\r?\n/ ascii
        $ep1 = "EP_REALTIME_BEFORE=" ascii
        $ep2 = "EP_EXCLUSION_STATUS=" ascii
        $ca1 = "CA_EXPORT_STATUS=" ascii
        $ca2 = "CERTUTIL_BACKUP_OUTPUT_BEGIN" ascii
        $ce1 = "CERT_ENROLL_METHOD=native-certreq" ascii
        $au1 = "CERT_AUTH_METHOD=schannel-ldap" ascii
    condition:
        filesize < 256KB and ($marker at 0 or ($marker and any of ($ep*, $ca*, $ce*, $au*)))
}

rule SageMythic_Phoenix_Trace_Database
{
    meta:
        description = "Arize Phoenix SQLite trace store holding Sage spans (InstalledServices/sage/.phoenix/phoenix.db); its spans carry full prompts and tool results, which can include credentials"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/MythicAgents/sage/blob/cbff42f0abc54d3c64b40d3a71cffce01a057023/Payload_Type/sage/ai/langgraph/autonomous_controller.py"
        mitre_att = "T1552"
    strings:
        $sqlite = "SQLite format 3" ascii
        $k1 = "sage.kernel.episode" ascii
        $k2 = "sage.kernel.cycle" ascii
        $p1 = "sage.policy.disposition" ascii
    condition:
        $sqlite at 0 and any of ($k*, $p*)
}
