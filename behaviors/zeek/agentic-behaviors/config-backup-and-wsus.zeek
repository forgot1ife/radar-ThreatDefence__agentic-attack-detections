##! Configuration and backup file theft, and probes of WSUS administration services (general hunt 02)
##!
##! JPCERT/CC's Case E describes Cairn, CyberStrikeAI and ARTEX stealing configuration and backup files and attacking
##! internet-facing WSUS servers. Scutum saw the agents request .git/HEAD, .env, .env.bak, backup.zip and database dumps
##! across hundreds of folders, some with a Range header that returns 206. A 200 or 206 answer with a body that is
##! not a web page means the file left. Status alone is not enough: sites that answer 200 to every path send their
##! home or error page, so the body's type (sniffed from its first bytes, not the Content-Type header) and size count.
##!
##! Cluster: the sweep count is a SumStats stream; the other notices need one connection only.

@load base/frameworks/sumstats
@load base/protocols/http
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server answered 200 or 206 to an outside request for a configuration or backup file. ATT&CK: T1552.001.
        Backup_File_Served,
        ## One outside address asked for many configuration or backup paths. ATT&CK: T1595.003.
        Backup_Path_Sweep,
        ## An outside address reached a WSUS administration or sync web service. ATT&CK: T1190.
        WSUS_Admin_From_Internet,
        ## An outside address connected to a WSUS port (8530 or 8531). ATT&CK: T1595.002.
        WSUS_Port_From_Internet,
    };

    const backup_uri: pattern =
        /\/\.git\/(HEAD|config)/ | /\/\.env(\.bak|\.old|\.backup|\.local)?($|\?)/ | /\/\.hg\// | /\/\.svn\// |
        /(?i:backup\.(zip|tar|tar\.gz|sql))/ | /(?i:db_back)/ | /(?i:database\.sql)/ | /(?i:dump\.sql)/ |
        /(?i:wp-config\.php\.(bak|old|save))/ | /(?i:web\.config\.(bak|old))/ &redef;

    const wsus_admin_uri: pattern =
        /(?i:\/(ApiRemoting30\/WebService|ServerSyncWebService\/ServerSyncWebService|ReportingWebService\/ReportingWebService)\.asmx)/ &redef;

    const wsus_ports: set[port] = { 8530/tcp, 8531/tcp } &redef;

    ## Distinct backup paths from one address within backup_sweep_window before a sweep notice.
    const backup_sweep_paths: count = 5 &redef;
    const backup_sweep_window: interval = 1hr &redef;

    ## Body types that are a web page or an API answer, not a configuration or backup file.
    const backup_page_types: pattern = /^(text\/html|application\/xhtml\+xml|text\/json|application\/json)/ &redef;
    ## Paths that must come back as an archive, so a text body is not the file either.
    const backup_archive_uri: pattern = /(?i:\.(zip|tar|gz|tgz|bz2|7z|rar)($|\?))/ &redef;
    ## Smallest body that can be a real file. A .git/HEAD is 21 bytes or more.
    const backup_min_bytes: count = 16 &redef;
}

## True when the body sent for a backup path can be the file and not a catch-all page.
function backup_body_plausible(uri: string, mime: string, size: count): bool
    {
    if ( size < backup_min_bytes || backup_page_types in mime )
        return F;
    return ! ( backup_archive_uri in uri && /^text\// in mime );
    }

event zeek_init()
    {
    local r = SumStats::Reducer($stream="agentic.backup.paths", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="agentic-backup-sweep",
                      $epoch=backup_sweep_window,
                      $reducers=set(r),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          { return result["agentic.backup.paths"]$unique + 0.0; },
                      $threshold=backup_sweep_paths + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=Backup_Path_Sweep,
                                  $msg=fmt("%s asked for %d configuration or backup paths", key$host, result["agentic.backup.paths"]$unique),
                                  $src=key$host, $identifier=cat(key$host), $suppress_for=suppress_for]);
                          }]);
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( Site::is_local_addr(c$id$orig_h) )
        return;
    if ( wsus_admin_uri in original_URI )
        raise(c, WSUS_Admin_From_Internet, fmt("%s requested a WSUS admin or sync service", c$id$orig_h),
              original_URI, cat(c$id$orig_h, c$id$resp_h, "wsus-admin"));
    if ( backup_uri in original_URI )
        SumStats::observe("agentic.backup.paths", [$host=c$id$orig_h], [$str=original_URI]);
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    # Runs at the end of the answer, when its status, body size and sniffed type are all known.
    if ( is_orig || Site::is_local_addr(c$id$orig_h) || ! c?$http || ! c$http?$uri || ! c$http?$status_code )
        return;
    local code = c$http$status_code;
    if ( (code != 200 && code != 206) || backup_uri !in c$http$uri )
        return;
    local mime = (c$http?$resp_mime_types && |c$http$resp_mime_types| > 0) ? c$http$resp_mime_types[0] : "";
    if ( backup_body_plausible(c$http$uri, mime, stat$body_length) )
        raise(c, Backup_File_Served,
              fmt("%s served %s to %s (%d, %d bytes)", c$id$resp_h, c$http$uri, c$id$orig_h, code, stat$body_length),
              c$http$uri, cat(c$id$orig_h, c$id$resp_h, c$http$uri));
    }

event connection_established(c: connection)
    {
    if ( c$id$resp_p in wsus_ports && ! Site::is_local_addr(c$id$orig_h) && Site::is_local_addr(c$id$resp_h) )
        raise(c, WSUS_Port_From_Internet, fmt("%s connected to WSUS port %s on %s", c$id$orig_h, c$id$resp_p, c$id$resp_h),
              cat(c$id$resp_p), cat(c$id$orig_h, c$id$resp_h, "wsus-port"));
    }
