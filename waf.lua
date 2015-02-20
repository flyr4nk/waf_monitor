local info   = get_client_info()

local result = waf_modules_start({
        CheckArgs,
        CheckPostData,
        WhiteIPPass,
        BlockIP,
        DenyCC,
        --ngx.var.http_Acunetix_Aspect
        --ngx.var.http_X_Scan_Memo
        CheckUA,
        CheckURL,
        CheckCookie
    }, info) 

if result then
    post_waf_handler(result,info)
end
