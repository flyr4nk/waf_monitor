--拦截规则
local regular_rule =
{
	--belial waf default rule。dont delete
	default = {
		get = "'|(and|or)\\b.+?(>|<|=|\\bin|\\blike)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|(\\.\\.\\/)+|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		
		post = "base64_decode|\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT.+?INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE).+?(TABLE|DATABASE)|\\.\\/|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		
		cookie = "\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)",

		ua = "HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|Nikto|fimap|havij|PycURL|zmeu|BabyKrokodil|netsparker|httperf|bench| SF",
	},
	
	pandora = {
		get = "(and|or)\\b.+?(>|<|=|\\bin|\\blike)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|(\\.\\.\\/)+|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		
		post = "base64_decode|\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT.+?INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE).+?(TABLE|DATABASE)|\\.\\/|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		
		cookie = "\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)",

		ua = "HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|Nikto|fimap|havij|PycURL|zmeu|BabyKrokodil|netsparker|httperf|bench| SF/",
	},
}



--cc规则
-- urlRegular,ccHackAmount
local cc_URL_list = 
{
	{"read.php\\?tid=\\d+?",120},
    {"searchthread\\.php",120},
    {"login\\.php",120},
    {"register\\.php",120},
    {"thread\\.php",120},
    {"post1\\.php",60},
	{"item\\/(.+?)\\.html",120}, --伪静态url
}

return {regular_rule=regular_rule,cc_URL_list=cc_URL_list}
