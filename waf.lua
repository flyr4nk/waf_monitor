local info   = get_client_info()

local result = waf_modules_start({
        check_get_args,
        CheckPostData,
        WhiteIPPass,
        BlockIP,
        --ngx.var.http_Acunetix_Aspect
        --ngx.var.http_X_Scan_Memo
        CheckUA,
        CheckURL,
        CheckCookie,
        DenyCC
    }, info) 

post_waf_handler(result,info)
