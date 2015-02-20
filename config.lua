local config = {
    log_path = "/usr/local/openresty/nginx/conf/waf_monitor/log",
    to_log   = "enable",
    str_match_method = string.match,
    ngx_match_method = ngx.re.match
}

return config
