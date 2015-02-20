cjson  = require "cjson"
config = require "config"
rules  = require "rule"

regular_rule = rules.regular_rule[config.rule] or rules.regular_rule["default"]
cc_URL_list  = rules.cc_URL_list
not_allow_upload_file_extensions = rules.not_allow_upload_file_extensions

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

-- 0，空串，nil, false 都是 false 统一判决
function _False(value)
	if var == 0 or var == "" or var == nil or var == false then
		return true
	end
	return false
end

function is_in_table(_table,var)
	if type(_table) ~= "table" then return false end
	
	for _,v in pairs(_table) do 
		if v == var then 
			return true  
		end 
	end
	return false
end

function waf_explode (_str,seperator)
	local pos, arr = 0, {}
		for st, sp in function() return string.find( _str, seperator, pos, true ) end do
			table.insert( arr,string.sub( _str, pos, st-1 ))
			pos = sp + 1
		end
	table.insert( arr, string.sub( _str, pos ) )
	return arr
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

function waf_modules_start(modules,info)
    local ret = nil
    local out = ""
    for _,handler in ipairs(modules) do
        ret = handler(info)
        out = out..",".._
        if ret then return ret end
    end
--    debug_display(out)
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
--                debug_display(_req_get..":"..regular_rule.get)
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

function check_cookie(info)
    local _cookie = ngx.var.http_cookie
    if _cookie then
        for _,v in string.gmatch(_cookie,"(%w+)=([^;%s]+)") do
            local request_cookie = config.unescape(_cookie)
            if config.ngx_match(request_cookie,regular_rule.cookie,"isjo") then 
                return {
                    msg = "COOKIE_BLOCKED",
                    action = "redict",

                }
            end
        end
    end 
    
end


function check_post_data(info)
--    debug_display(info.request_method)
    if info.request_method == "POST" then
        -- 获取boundary
        local boundary = string.match(info.headers["content-type"],"boundary=(.+)")
        if boundary then  -- mutil form
            boundary = "--" .. boundary
            ngx.req.read_body()
            local allbody = ngx.req.get_body_data()
            if allbody then
                local allbodytable = waf_explode(allbody,boundary)
                for _,v in ipairs(allbodytable) do
                    if v ~= "" and v then
                        local uploadFileExtension,err = ngx.re.match(v,"Content-Disposition:\\s+form-data; name=\".+?\";\\s+filename=\".+(\\..+?)\"","ijo")

                        if not uploadFileExtension then  --不是附件字段  做过滤判断
                            local now = string.gsub(v,'Content%-Disposition: form%-data; name=".+"',"")
                            now = string.gsub(now,'\r\n\r\n',"")
                            now = config.unescape(now)

                            if config.ngx_match(now,regular_rule.post,"isjo") then 
                                return {
                                    msg    = "POST Injection",
                                    action = "redict",
                                }
                            end -- config.ngx_match
                        else --判断附件扩展名
                            if not _False(not_allow_upload_file_extensions) then
                                uploadFileExtension = uploadFileExtension[1]
                                if is_in_table(not_allow_upload_file_extensions,string.lower(uploadFileExtension)) then
                                    return {
                                        msg    = "POST Injection",
                                        action = "redict",
                                    }
                                end -- belial
                            end --if not
                        end -- if no uploadFileExtension
                    end -- if v~=
                end -- for
            else --if allbody
                --Log("nginx 's client_max_body_size and client_body_buffer_size is too small","notice")
            end --if allbody
        else --boundary
            local post_args, _req_post = ngx.req.get_post_args(), nil
            for _,v in pairs(post_args) do
                if type(v) ~= "boolean" then
                    if type(v) == "table" then
                        _req_post = table.concat(v," ")
                    else
                        _req_post = v
                    end -- if type(v) = "table"

                    if _req_post then
                        _req_post = config.unescape(_req_post)
                        if config.ngx_match(_req_post,regular_rule.post,"isjo") then
                            return {
                                msg    = "POST Injection",
                                action = "redict",
                            }
                        end -- if config.ngx_match
                    end -- if _req_post
                end -- if type(v) ~= "boolean"
            end -- for _,V
        end --boundary
    end -- if info.request_method == "POST"
end


