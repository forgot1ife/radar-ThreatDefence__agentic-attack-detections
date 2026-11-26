##! Servers resolving out-of-band testing domains (general hunt 05)
##!
##! Agents confirm blind injection, SSRF and XXE by making the target look up a unique name under a callback service.
##! Strix's sandbox ships interactsh-client and its skills use *.oast.fun; nuclei uses the same interactsh servers;
##! CyberStrikeAI operators used dnslog.cn. When one of your servers looks up one of these names, a payload ran on it.
##!
##! A testing client polls its own service for results (Burp asks for polling.oastify.com or
##! polling.burpcollaborator.net all day), so those two names are skipped. Only the exact names: a payload name can
##! carry a "polling." label in front and still reach the callback service. One notice per source per suppress_for
##! (an hour), whatever names it looks up.
##!
##! Cluster: each lookup is judged on its own, and the Notice framework shares suppression between workers.

@load base/protocols/dns
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server looked up a name under an out-of-band testing service. ATT&CK: T1190, T1071.004.
        Out_Of_Band_Lookup,
    };

    ## Callback services. A name matches when it ends with ".<service>".
    const oob_services: set[string] = {
        "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "interact.sh", "oastify.com",
        "burpcollaborator.net", "dnslog.cn", "ceye.io", "requestrepo.com",
    } &redef;

    ## Names a testing client looks up itself, not ones a payload makes a target look up.
    const oob_ignore_names: pattern = /^polling\.(oastify\.com|burpcollaborator\.net)$/ &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( ! is_server(c$id$orig_h) )
        return;
    local q = to_lower(query);
    if ( oob_ignore_names in q )
        return;
    for ( svc in oob_services )
        if ( ends_with(q, "." + svc) )
            {
            # Keyed on the source alone: one notice per source per suppress_for.
            raise(c, Out_Of_Band_Lookup, fmt("%s looked up %s (out-of-band testing service %s)", c$id$orig_h, q, svc),
                  q, cat(c$id$orig_h));
            return;
            }
    }
