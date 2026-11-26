##! Kerberos user enumeration and SMB or WinRM fan-out from one address (general hunt 03)
##!
##! Agent workers ship kerbrute, netexec and Impacket. Kerbrute sends bare AS-REQs: unknown names fail with
##! KDC_ERR_C_PRINCIPAL_UNKNOWN (6) and its password spray fails with KDC_ERR_PREAUTH_FAILED (24). Netexec then fans out
##! over SMB (445) and WinRM (5985, 5986). Zeek sees all of it on the wire, with no domain controller auditing needed.
##!
##! Cluster: every count here is a SumStats stream, so the manager adds up what each worker saw.

@load base/frameworks/sumstats
@load base/protocols/krb
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## One address asked the KDC about many accounts, most of them unknown or with bad passwords. ATT&CK: T1087.002, T1110.003.
        Kerberos_Enumeration,
        ## One address opened SMB or WinRM to many hosts. ATT&CK: T1021.002, T1021.006.
        SMB_WinRM_Fan_Out,
    };

    const krb_min_accounts: count = 25 &redef;
    const krb_min_failures: count = 10 &redef;
    const fan_out_min_hosts: count = 10 &redef;
    const fan_out_ports: set[port] = { 445/tcp, 5985/tcp, 5986/tcp } &redef;
    const lateral_window: interval = 10min &redef;
}

## How far a value is toward its minimum: 1.0 or more once the minimum is met.
function share_of(v: double, min: count): double
    {
    return min == 0 ? 1.0 : v / min;
    }

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="agentic.krb.accounts", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="agentic.krb.failures", $apply=set(SumStats::SUM));
    SumStats::create([$name="agentic-kerberos-enum",
                      $epoch=lateral_window,
                      $reducers=set(r1, r2),
                      # The smaller of the two shares, so 1.0 means both minimums are met. A share rather than a
                      # yes or no lets a worker that holds part of each ask the manager for the cluster total.
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          local a = share_of(result["agentic.krb.accounts"]$unique + 0.0, krb_min_accounts);
                          local f = share_of(result["agentic.krb.failures"]$sum, krb_min_failures);
                          return a < f ? a : f;
                          },
                      $threshold=1.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=Kerberos_Enumeration,
                                  $msg=fmt("%s asked the KDC about %d accounts, %.0f failed as unknown or bad password",
                                           key$host, result["agentic.krb.accounts"]$unique,
                                           result["agentic.krb.failures"]$sum),
                                  $src=key$host, $identifier=cat(key$host), $suppress_for=suppress_for]);
                          }]);

    local r3 = SumStats::Reducer($stream="agentic.fanout.hosts", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="agentic-smb-winrm-fan-out",
                      $epoch=lateral_window,
                      $reducers=set(r3),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          { return result["agentic.fanout.hosts"]$unique + 0.0; },
                      $threshold=fan_out_min_hosts + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=SMB_WinRM_Fan_Out,
                                  $msg=fmt("%s opened SMB or WinRM to %d hosts", key$host, result["agentic.fanout.hosts"]$unique),
                                  $src=key$host, $identifier=cat(key$host), $suppress_for=suppress_for]);
                          }]);
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    if ( msg?$client_name )
        SumStats::observe("agentic.krb.accounts", [$host=c$id$orig_h], [$str=to_lower(msg$client_name)]);
    }

event krb_error(c: connection, msg: KRB::Error_Msg)
    {
    if ( msg$error_code == 6 || msg$error_code == 24 )
        {
        SumStats::observe("agentic.krb.failures", [$host=c$id$orig_h], [$num=1]);
        if ( msg?$client_name )
            SumStats::observe("agentic.krb.accounts", [$host=c$id$orig_h], [$str=to_lower(msg$client_name)]);
        }
    }

event connection_state_remove(c: connection)
    {
    # Count a host only when both sides sent data (D and d in the history). A SYN scan gets a SYN-ACK from an
    # open port and a connect scan completes the handshake, but neither goes on to speak SMB or WinRM.
    if ( c$id$resp_p in fan_out_ports && "D" in c$history && "d" in c$history )
        SumStats::observe("agentic.fanout.hosts", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
    }
