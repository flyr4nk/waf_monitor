cjson  = require "cjson"
config = require "config"
rules  = require "rule"

regular_rule = rules.regular_rule[config.rule] or rules.regular_rule["default"]
cc_URL_list  = rules.cc_URL_list

function debug_display(msg)
    ngx.header.content_type = "text/html"
    ngx.say(msg)
    ngx.exit(ngx.HTTP_OK)
end


function save_to_file(msg)	

    if config.to_log then
        local fd = io.open(config.log_path,"ab")

        if fd == nil then return end

        fd:write(msg)
        fd:flush()
        fd:close()

    end
end


function log(module_name, info)

    local msg = string.format(
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

	if config.__DEBUG__ then 
        debug_display(msg)
    else
        save_to_file(msg)
	end
    
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
        if fail_tag then return fail_tag end
    end

end


function post_waf_handler(result, info)
    log(result.msg,info)
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
function check_get_args(info)
    local args, _req_get = ngx.req.get_uri_args(), nil

    for _,v in pairs(args) do
        if type(v) ~= "boolean" then
            if type(v) == "table" then
                local _v,table_concat_return = pcall(function()  return table.concat(v," ")   end)
                if _v then
                    _req_get = table_concat_return
                else
                    _req_get = nil
                end
            else
                _req_get = v
            end

            -- 用正则表达式去匹配get参数规则
            if _req_get then 
                _req_get = config.unescape(_req_get)
                if config.ngx_match(_req_get,regular_rule.get,"isjo") then
                   return {
                       msg    = "Get Injection",
                       action = "redict",
                   }
                end
            end

        end
    end
end

function CheckCookie(info)
end
function CheckPostData(info)
end

