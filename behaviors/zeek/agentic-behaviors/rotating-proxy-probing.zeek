##! One site probed through hundreds of rotating proxy addresses (general hunt 01)
##!
##! Agent operators send their tools through residential proxy services (IPRoyal, 711proxy and 1024proxy in Gambit's
##! case). Cyber Security Cloud saw one agent rotate through 326 addresses in about 40 minutes for more than 1,200
##! requests. Per-address thresholds miss this, so this counts distinct outside addresses per target host.
##!
##! A request counts as a probe when its URI carries a payload, or when it asks for a login or admin path and the
##! server refuses it (4xx or 5xx). People signing in to a working login page get 200 and 302 answers, so they are
##! counted separately and must not outnumber the probes. Exclude your CDN, uptime monitoring and partner integrations.
##!
##! Cluster: every count here is a SumStats stream, so the manager adds up what each worker saw.

@load base/frameworks/sumstats
@load base/protocols/http
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## Many outside addresses, few requests each, sent payloads or refused login and admin requests to one host. ATT&CK: T1090.002, T1595.002.
        Rotating_Proxy_Probing,
    };

    ## Distinct outside addresses sending probes per host and window before a notice.
    const proxy_min_sources: count = 50 &redef;
    ## Average probes per address at or below which the spread looks like rotation.
    const proxy_max_per_source: double = 10.0 &redef;
    ## Probes as a share of the host's payload, login and admin requests. Below this the host is a login page in
    ## normal use with some mistyped passwords.
    const proxy_min_probe_share: double = 0.5 &redef;
    const proxy_window: interval = 40min &redef;
}

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="agentic.proxy.src", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="agentic.proxy.req", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="agentic.proxy.ok", $apply=set(SumStats::SUM));
    SumStats::create([$name="agentic-rotating-proxy",
                      $epoch=proxy_window,
                      $reducers=set(r1, r2, r3),
                      # SumStats calls threshold_crossed once per host and window, so every condition has to be part
                      # of this value. It is worked out again on each request: a host that has enough addresses
                      # but too many requests per address, or too few probes, is caught when that changes.
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          local sources = result["agentic.proxy.src"]$unique + 0.0;
                          local probes = result["agentic.proxy.req"]$sum;
                          local accepted = result["agentic.proxy.ok"]$sum;
                          if ( sources == 0.0 || probes == 0.0 || probes / sources > proxy_max_per_source )
                              return 0.0;
                          if ( probes / (probes + accepted) < proxy_min_probe_share )
                              return 0.0;
                          return sources;
                          },
                      $threshold=proxy_min_sources + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=Rotating_Proxy_Probing,
                                  $msg=fmt("%s probed from %d outside addresses, %.0f requests", key$str,
                                           result["agentic.proxy.src"]$unique, result["agentic.proxy.req"]$sum),
                                  $sub=key$str, $identifier=key$str, $suppress_for=suppress_for]);
                          }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    # Runs on the answer, so the status is known. 1xx answers are not final.
    if ( code < 200 || ! c?$http || ! c$http?$uri || Site::is_local_addr(c$id$orig_h) )
        return;
    local payload = payload_uri in c$http$uri;
    if ( ! payload && sensitive_uri !in c$http$uri )
        return;
    local host = c$http?$host ? to_lower(c$http$host) : cat(c$id$resp_h);
    if ( payload || code >= 400 )
        {
        SumStats::observe("agentic.proxy.src", [$str=host], [$str=cat(c$id$orig_h)]);
        SumStats::observe("agentic.proxy.req", [$str=host], [$num=1]);
        }
    else
        SumStats::observe("agentic.proxy.ok", [$str=host], [$num=1]);
    }
