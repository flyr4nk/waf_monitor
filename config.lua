local config = {
    log_path  = "/usr/local/openresty/nginx/conf/waf_monitor/log",
    to_log    = "enable",
    __DEBUG__ = "enable",
    rule      = "a",
    str_match = string.match,
    ngx_match = ngx.re.find,
    unescape  = ngx.unescape_uri,
    
    --ngx_match_method = ngx.re.match,
}

return config
