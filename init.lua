cjson  = require "cjson"
config = require "config"

local match = string.match
local ngxmatch=ngx.re.match

function saveFile(data)	

    if config.to_log then
        local fd = io.open(config.log_path,"ab")

        if fd == nil then return end

        fd:write(data)
        fd:flush()
        fd:close()

    end
end


function log(module_name, info)

    saveFile(
        string.format(
            [[%s: %s [%s] "%s %s %s" "%s" "%s"]] .. "\n", 
            module_name,
            info.client_ip,
            ngx.localtime(),
            info.request_method,
            info.request_uri,
            info.server_protocol,
            info.http_referer or "_",
            info.http_user_agent or "-"
        )
    )
end

function get_client_info ()

    return {
        client_ip       = ngx.req.get_headers()["X-Real-IP"] or ngx.var.remote_addr or "unknow",
        headers         = ngx.req.get_headers(),
        request_uri     = ngx.unescape_uri(ngx.var.request_uri),
        request_method  = ngx.var.request_method,
        server_protocol = ngx.var.server_protocol,
        http_referer    = ngx.var.http_referer,
        http_user_agent = ngx.var.http_user_agent,
    }
end


function read_rules()
end

function waf_modules_start(modules,info)
    local fail_tag = nil

    for _,handler in ipairs(modules) do
        fail_tag = handler(info)
        if fail_tag then
            return fail_tag
        end
    end

end


function post_waf_handler(result, info)
    log(result,info)
end

--- 模块内容定义
function WhiteIPPass(info)
end

function BlockIP(info)
    return { 
        msg    = "IP blocked",
        action = "redict"
    }
end
function DenyCC(info)
end
--ngx.var.http_Acunetix_Aspect
--ngx.var.http_X_Scan_Memo
function WhiteURLPass(info)
end
function CheckUA(info)
end
function CheckURL(info)
end
function CheckArgs(info)
end
function CheckCookie(info)
end
function CheckPostData(info)
end

