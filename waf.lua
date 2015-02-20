local info   = get_client_info()

local result = waf_modules_start({
        check_get_args,
        check_post_data,
        check_cookie,
        WhiteIPPass,
        --BlockIP,
        --ngx.var.http_Acunetix_Aspect
        --ngx.var.http_X_Scan_Memo
        CheckUA,
        CheckURL,
        DenyCC
    }, info) 

if result then
    post_waf_handler(result,info)
end
