##! A server calls back to the address that was probing it (general hunt 04)
##!
##! Agentic frameworks catch reverse shells and out-of-band callbacks on the machine that runs the attack. PentAGI
##! publishes two listener ports per engagement from 28000 on its host, and Cairn's guide tells its agents to call back
##! to the host's own external address. Either way, a server you own connects out to an address that was sending it
##! attack requests shortly before. Ordinary servers rarely connect to the addresses that attack them.
##!
##! A prober is an outside address that sent payload requests straight to one of your servers. Visitors are not
##! tracked, and neither are CDN edges and reverse proxies: their requests carry a forwarding header (Via,
##! X-Forwarded-For and the rest of HTTP::proxy_headers), and the address behind them is not the one connecting.
##! Add ranges that still fire to callback_ignore_nets.
##!
##! Cluster: workers report payload requests to the manager, which counts them across workers and tells every worker
##! once an address is a prober. Each worker then checks its own outbound connections against that shared list and
##! raises the notice itself. A single process runs the same events locally. The address has to be on the list when
##! the callback connects, so a callback within moments of the very first payload requests can be missed.

@load base/protocols/http
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server opened a connection to an outside address that had been sending it payload requests. ATT&CK: T1190, T1071.
        Callback_To_Prober,
    };

    ## How long an address is remembered as a prober.
    const prober_memory: interval = 1hr &redef;
    ## Payload requests from an address before it counts as a prober.
    const prober_min_requests: count = 3 &redef;
    ## Outside ranges that are never probers: CDN, uptime monitoring, partner integrations.
    const callback_ignore_nets: set[subnet] = {} &redef;
    ## Outbound ports that are normal replies to visitors (mail, DNS, NTP).
    const callback_ignore_ports: set[port] = { 25/tcp, 53/udp, 53/tcp, 123/udp } &redef;
    ## PentAGI's worker listener range.
    const pentagi_ports_low: count = 28000 &redef;
    const pentagi_ports_high: count = 29999 &redef;

    ## Worker to manager: this outside address sent a payload request to a server.
    global prober_seen: event(a: addr);
    ## Manager to workers: this address is a prober.
    global prober_known: event(a: addr);
}

# Manager (or the single process): payload requests per outside address, summed over workers.
global prober_hits: table[addr] of count &default=0 &create_expire=prober_memory;
# Every node that inspects traffic: addresses that reached prober_min_requests.
global probers: set[addr] &create_expire=prober_memory;
# Reports this node already sent per address. A scanner costs a few messages, not one per request.
global prober_reports: table[addr] of count &default=0 &create_expire=prober_memory;

event AgenticBehaviors::prober_seen(a: addr)
    {
    # Equal, not at least: one message to the workers per address and memory period.
    if ( ++prober_hits[a] != prober_min_requests )
        return;
    if ( Cluster::is_enabled() )
        Cluster::publish(Cluster::worker_topic, AgenticBehaviors::prober_known, a);
    else
        event AgenticBehaviors::prober_known(a);
    }

event AgenticBehaviors::prober_known(a: addr)
    {
    add probers[a];
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    local o = c$id$orig_h;
    if ( ! is_orig || ! c?$http || ! c$http?$uri || Site::is_local_addr(o) || ! is_server(c$id$resp_h) )
        return;
    # Relayed by a CDN or proxy, or no payload: not a probe from this address.
    if ( c$http?$proxied || o in callback_ignore_nets || payload_uri !in c$http$uri )
        return;
    if ( o in probers || prober_reports[o] >= prober_min_requests )
        return;
    ++prober_reports[o];
    if ( Cluster::is_enabled() )
        Cluster::publish(Cluster::manager_topic, AgenticBehaviors::prober_seen, o);
    else
        event AgenticBehaviors::prober_seen(o);
    }

event connection_established(c: connection)
    {
    local o = c$id$orig_h;
    local r = c$id$resp_h;

    # Outbound: one of your servers connecting to an address that had been probing your servers.
    if ( r in probers && is_server(o) && c$id$resp_p !in callback_ignore_ports )
        {
        local p = port_to_count(c$id$resp_p);
        local note = (p >= pentagi_ports_low && p <= pentagi_ports_high) ? " (PentAGI worker port range)" : "";
        raise(c, Callback_To_Prober,
              fmt("%s connected to %s:%s after payload requests from it%s", o, r, c$id$resp_p, note),
              cat(c$id$resp_p), cat(o, r, c$id$resp_p));
        }
    }
