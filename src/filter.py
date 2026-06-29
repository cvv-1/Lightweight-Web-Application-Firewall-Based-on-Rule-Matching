import os
import re
import urllib.parse
import html

import config as C
import dbutils
from utils import log

'''
从数据库中初始化规则列表
@return 规则列表
'''
def init_filter():

	log("正在加载规则...",1)
	compiled_rules = []

	conn = dbutils.get_conn()
	rules = dbutils.get_rules(conn)

	rules_list = list(rules)
	log(f"总共获取到 {len(rules_list)} 条规则", 1)

	# 按action分组，BLOCK规则优先，提高匹配效率
	block_rules = []
	other_rules = []

	# 创建规则类型到用户规则ID的映射
	rule_type_to_user_rule = {}

	for rule in rules_list:
		try:
			# 提取需要的字段，根据实际表结构调整索引
			# 实际表结构：id(0), content(1), description(2), action(3), created_at(4), updated_at(5), rule_type(6)
			uid = rule[0]  # id字段
			regexp = rule[1]  # content字段
			description = rule[2]  # description字段
			action = rule[3] if len(rule) > 3 else None  # action字段（索引3）
			rule_type = rule[6] if len(rule) > 6 else None  # rule_type字段（索引6）

			# 验证action字段
			if action is None or action not in ['BLOCK', 'PASS', 'LOG']:
				log(f"  - 规则ID={uid}无效的action字段: {action}，跳过", 2)
				continue

			# 不区分大小写比较action
			action_upper = action.upper()
			if action_upper == "BLOCK":
				action_code = C.ACTION_BLOCK
			elif action_upper == "PASS":
				action_code = C.ACTION_PASS
			elif action_upper == "LOG":
				action_code = C.ACTION_LOG
			else:
				log(f"  - 规则ID={uid}未知动作: {action}，跳过", 2)
				continue

			# 编译时设置标志，避免每次匹配都传递
			# 保存规则ID和描述，以便在匹配时返回
			compiled_rule = (re.compile(regexp, re.IGNORECASE | re.DOTALL), action_code, uid, description)
			# 按action分组，BLOCK规则优先
			if action_code == C.ACTION_BLOCK:
				block_rules.append(compiled_rule)
			else:
				other_rules.append(compiled_rule)

			# 记录规则类型到用户规则ID的映射（用于内置规则的替换）
			if rule_type and action_code == C.ACTION_BLOCK:
				if rule_type not in rule_type_to_user_rule:
					rule_type_to_user_rule[rule_type] = uid
		except re.error as e:
			log(f"正则表达式编译错误，规则ID={rule[0] if rule else 'unknown'}, 错误: {str(e)}", 2)
			log(f"  错误的规则内容: {str(rule)}", 2)
		except Exception as e:
			log(f"编译出错，出错的条目为: {str(rule)}, 错误: {str(e)}", 2)
			import traceback
			log(f"  详细错误: {traceback.format_exc()}", 2)

	# 内置高危规则（XXE / 反序列化），确保即使未在DB中配置也能拦截
	# 注意：这些规则只在 has_suspicious_chars 为 True 时才参与匹配，避免拖慢正常请求
	# 优化：使用更精确的正则表达式，避免在大文件上的性能问题
	# 使用更简单的模式，避免复杂的回溯
	builtin_rules = [
		# 任意 DOCTYPE 中包含 ENTITY 定义（优化：简化正则，避免回溯）
		# 使用更简单的模式：DOCTYPE后跟任意字符（限制长度），然后ENTITY
		(-9001, r'<!DOCTYPE[^<]{0,2000}<!ENTITY', "XXE 实体定义", "XXE"),
		# 显式外部实体（带 SYSTEM + 协议前缀）- 优化：更精确的匹配
		(-9002, r'<!ENTITY\s+[^>]{1,200}\s+SYSTEM\s+["\'](?:file|https?|ftp|gopher|dict)://', "XXE 外部实体注入", "XXE"),
		# 反序列化入口 / 载荷（这些规则本身已经很快，不需要优化）
		(-9003, r'unserialize\s*\(', "反序列化入口 (PHP)", "DESER"),
		(-9004, r'O:\d+:"[^"]{1,200}":\d+:\{', "PHP 序列化对象载荷", "DESER"),
		(-9005, r'(?:java\.io\.ObjectInputStream|readObject\s*\()', "Java 反序列化入口", "DESER"),
	]
	for rid, pattern, desc, rule_type in builtin_rules:
		try:
			# 对于XXE规则，不使用DOTALL，因为XML通常不会跨多行
			# 对于反序列化规则，可以使用IGNORECASE
			if rid in [-9001, -9002]:
				# XXE规则：不使用DOTALL，使用更简单的模式
				compiled = re.compile(pattern, re.IGNORECASE)
			else:
				# 反序列化规则：可以使用IGNORECASE
				compiled = re.compile(pattern, re.IGNORECASE)

			# 如果存在用户定义的同类型规则，使用用户规则ID；否则使用内置规则ID
			actual_rule_id = rule_type_to_user_rule.get(rule_type, rid)
			block_rules.append((compiled, C.ACTION_BLOCK, actual_rule_id, desc))
		except re.error as e:
			log(f"内置规则编译错误(ID={rid}): {str(e)}", 2)

	# 合并规则列表：BLOCK规则在前，其他规则在后
	compiled_rules = block_rules + other_rules
	log(f"规则加载完毕，成功加载 {len(compiled_rules)} 条规则（BLOCK: {len(block_rules)}, 其他: {len(other_rules)}）。",1)
	# 返回分组后的规则列表，避免每次请求都重新分组
	return (compiled_rules, block_rules, other_rules)

def init_blacklist():
	log("正在加载黑名单...",1)
	blacklist = []

	conn = dbutils.get_conn()
	lists = dbutils.get_blacklists(conn)

	for item in lists:
		try:
			uid,url,ip = item
			listitem = (url,ip)
			blacklist.append(listitem)
		except:
			log("加载出错，出错的条目为",2)
			log(str(item),2)
			
	return blacklist

def init_whitelist():
	log("正在加载白名单...",1)
	whitelist = []

	conn = dbutils.get_conn()
	lists = dbutils.get_whitelists(conn)

	for item in lists:
		try:
			uid,url,ip = item
			listitem = (url,ip)
			whitelist.append(listitem)
		except:
			log("加载出错，出错的条目为",2)
			log(str(item),2)
	return whitelist
	
'''
判断请求，返回动作代码
其中分为很多部分
'''
def do_filter(client_req,ip,compiled_rules,blacklists,whitelists,block_rules=None,other_rules=None):
	action = None

	# 重建chunked编码请求
	client_req = rebuild_chunked_encoding(client_req)

	# 黑名单判断
	blacklist_action = do_filter_blacklist(client_req,ip,blacklists)
	if blacklist_action is not None:
		return (blacklist_action, None, "黑名单拦截")

	# 白名单判断
	whitelist_action = do_filter_whitelist(client_req,ip,whitelists)
	if whitelist_action is not None:
		return (whitelist_action, None, "白名单放行")

	# 规则判断（包含解码后的内容检测）
	result = do_filter_rule_list(client_req,compiled_rules,block_rules,other_rules)
	
	# 返回格式：(action, rule_id, reason)
	return result

'''
还原ChunkedEncoding消息，防止bypass
'''
def rebuild_chunked_encoding(msg):
	# 快速检查是否包含chunked编码，避免不必要的处理
	if "transfer-encoding: chunked" not in msg.lower():
		return msg
	
	# 使用更高效的方法处理chunked编码
	try:
		# 尝试两种分隔符
		if "\r\n\r\n" in msg:
			headers, body = msg.split("\r\n\r\n", 1)
		else:
			headers, body = msg.split("\n\n", 1)
		
		# 使用更高效的正则表达式和字符串处理
		new_body = re.sub(r"[0-9a-fA-F]+(;[^\r\n]*)?\r\n", "", body)
		new_body = new_body.replace("\r\n", "").replace("\n", "").replace("\r", "")
		return headers + "\r\n\r\n" + new_body
	except:
		# 如果处理失败，直接返回原始消息
		return msg

'''
快速预检：检查是否包含可疑字符，如果没有则直接放行
这样可以避免对正常请求进行昂贵的解码和规则匹配
优化版本：使用更快的检查方法，同时检测XSS和SQL注入
'''
def has_suspicious_chars(content):
	"""快速检查是否包含可疑字符（XSS、SQL注入、CSRF、RCE、SSRF、XXE、反序列化和路径遍历相关）"""
	# 转换为小写进行关键词检查
	content_lower = content.lower()
	
	# 首先进行简单的字符检查（最快）
	# 检查XSS相关字符：< > （不单独检查 & 和 %，因为它们太常见）
	xss_chars = '<' in content or '>' in content
	
	# XSS相关关键词
	xss_keywords = ['script', 'javascript', 'onerror', 'onclick', 
	                'onload', 'eval', 'expression', 'vbscript', 'data:', 'iframe']
	
	# SQL注入相关关键词（注意：空格很重要，避免误匹配单词的一部分）
	# 只检查SQL注入模式的组合，而不是单独的SQL关键词，以避免误判正常URL路径（如 /api/update）
	# 检查SQL注入常见的组合模式
	sqli_patterns_context = [
		' or ', ' and ',  # OR/AND注入（注意空格，避免匹配单词的一部分）
		"' or", "' and",  # 单引号后的SQL关键字
		'" or', '" and',  # 双引号后的SQL关键字
		'or=', 'and=',    # OR/AND注入（URL参数形式）
		'--', '/*', '*/',  # SQL注释符
		'; select', '; insert', '; drop', '; update', '; delete',  # 堆叠查询
		"1=1", "1='1'", "'1'='1'",  # 常见的注入模式
		'union select',  # UNION注入
	]
	
	# 检查SQL注入相关的危险关键词（只在特定上下文中检查）
	# 这些关键词单独出现时不应该被标记为可疑（如 /api/update 是正常的URL）
	sqli_keywords = []  # 不再单独检查SQL关键词，只检查SQL注入模式
	
	# RCE（命令执行）相关关键词
	rce_keywords = ['cmd', 'command', 'exec', 'system', 'shell_exec', 'passthru',
	                'proc_open', 'popen', 'pcntl_exec', 'xp_cmdshell', 'sp_oacreate',
	                'wscript', 'cscript', 'mshta', 'powershell', 'cmd.exe',
	                'eval(', 'assert(', 'call_user_func', 'create_function',
	                '/bin/', '/usr/bin/', '/etc/',  # 系统路径
	                'whoami', 'cat ', 'ls ', 'pwd', 'id ', 'uname']  # 系统命令
	
	# CSRF相关关键词（HTTP头）- 注意：不检查 referer: 和 origin:，因为这些是正常的HTTP头
	# 真正的CSRF检测应该检查缺失Referer或可疑的Referer，而不是检查是否存在这些头
	# 所以这里不设置csrf_keywords，避免误判正常请求
	csrf_keywords = []  # 暂时不在这里检查CSRF，由LOG规则处理
	
	# SSRF相关关键词（仅伪协议）
	ssrf_keywords = ['file://', 'gopher://', 'dict://', 'ldap://', 'ldaps://',
	                 'sftp://', 'tftp://']
	
	# XXE相关关键词（同时出现时更可疑）
	xxe_keywords = ['<!doctype', '<!entity', '<?xml', 'system "', "system '", 'file://']
	
	# 反序列化相关关键词
	deser_keywords = [
		'unserialize(',            # PHP
		'php://filter',            # 常配合反序列化利用
		'java.io.objectinputstream',
		'readobject(',
		'serialversionuid',
		'rO0AB',                   # Java 序列化魔数的base64前缀
	]
	
	# 路径遍历相关关键词
	path_traversal_keywords = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c', '%252e%252e',
	                          '/etc/passwd', '/etc/shadow', 'boot.ini', 'win.ini',
	                          '/etc/', '/var/', '/usr/', 'c:\\', 'd:\\', 'e:\\']
	
	# 文件上传相关关键词（只检查真正可疑的文件上传特征）
	# 注意：不包含 'content-type:' 和 'multipart/form-data'，因为这些是正常的HTTP头
	# 真正的文件上传检测应该检查文件扩展名和内容，而不是检查是否存在multipart/form-data
	upload_keywords = []  # 文件上传检测由 check_file_upload 函数处理，这里不预检查
	
	# 检查是否包含任何可疑关键词
	has_xss_keyword = any(keyword in content_lower for keyword in xss_keywords)
	# has_sqli_keyword已移除，不再单独检查SQL关键词（如update、select等），只检查SQL注入模式
	has_rce_keyword = any(keyword in content_lower for keyword in rce_keywords)
	has_csrf_keyword = any(keyword in content_lower for keyword in csrf_keywords)
	has_ssrf_keyword = any(keyword in content_lower for keyword in ssrf_keywords)
	has_xxe_keyword = any(keyword in content_lower for keyword in xxe_keywords)
	has_deser_keyword = any(keyword in content_lower for keyword in deser_keywords)
	has_path_traversal_keyword = any(keyword in content_lower for keyword in path_traversal_keywords)
	has_upload_keyword = any(keyword in content_lower for keyword in upload_keywords)
	
	# 检查SQL注入相关的字符模式（使用sqli_patterns_context，已定义在上面）
	
	# 检查RCE相关的字符模式（注意：这些需要直接检测，不转小写）
	# 不包含 '&'，因为它太常见（URL参数分隔符），会误判正常请求
	rce_char_patterns = [';', '|', '`', '$(']  # 命令注入字符（不包含&）
	rce_char_patterns_encoded = ['%3b', '%7c', '%60', '%24', '%3B', '%7C', '%60']  # URL编码的命令注入字符（不包含%26即&）
	rce_path_patterns = ['/bin/', '/usr/bin/', '/etc/passwd', '/etc/shadow', '/proc/', '/sys/']  # 系统路径
	
	has_sqli_pattern = any(pattern.lower() in content_lower for pattern in sqli_patterns_context)
	# 注意：不单独检查 rce_char_patterns，因为它们可能出现在正常请求中
	# 只在命令注入模式的上下文中检查（见下面的 command_injection）
	has_rce_char_encoded = any(pattern in content_lower for pattern in rce_char_patterns_encoded)
	has_rce_path = any(pattern in content_lower for pattern in rce_path_patterns)
	
	# 检查命令注入字符后跟命令（包括URL编码的情况）
	# 这是更精确的检查，只有在命令注入字符后跟命令时才认为是可疑的
	command_injection = re.search(r'[;&|`]\s*(cat|ls|pwd|whoami|id|uname|curl|wget|nc|rm|mv|cp)', content_lower)
	# 检查URL编码后的命令注入
	command_injection_encoded = re.search(r'%7[Cc]\s*%?20?(whoami|cat|ls|pwd|id|uname)', content_lower)
	
	# 检查Windows命令
	windows_cmd = re.search(r'\b(cmd\.exe|powershell|wscript|cscript|mshta)\b', content_lower)
	
	# 如果包含任何可疑关键词或模式，返回True
	if has_xss_keyword or has_rce_keyword or has_csrf_keyword or has_ssrf_keyword or has_xxe_keyword or has_deser_keyword or has_path_traversal_keyword or has_upload_keyword:
		return True
	
	# RCE模式检测（包括URL编码的情况）
	# 注意：不检查 has_rce_char，因为它会误判包含 ; | ` $( 的正常请求
	# 只在命令注入模式（command_injection）或其他明确的RCE特征时才标记为可疑
	if has_rce_char_encoded or has_rce_path or command_injection or command_injection_encoded or windows_cmd:
		return True
	
	if has_sqli_pattern:
		return True
	
	# 如果包含XSS字符（< >），仍然检查（可能是编码的）
	# 但不单独检查 & 和 %，因为它们太常见（URL参数分隔符和编码前缀）
	if xss_chars:
		return True
	
	# 检查是否有URL编码的可疑内容（%后面跟十六进制数字，可能是编码的攻击载荷）
	# 这里只检查常见的可疑编码模式，而不是所有%字符
	# 注意：不检查 %26（&），因为它在URL编码中很常见（虽然通常不会被编码）
	if '%' in content:
		# 检查是否包含可疑的URL编码模式（如 %3c, %3e, %27等）
		# 排除 %26（&）和常见的URL编码字符（如 %20 空格）
		suspicious_encoded_chars = ['%3c', '%3e', '%27', '%22', '%3b', '%7c', '%60', '%24', '%00']  # 不包含 %26
		if any(enc in content_lower for enc in suspicious_encoded_chars):
			return True
	
	return False

'''
检测文件上传中的危险文件
'''
def check_file_upload(msg):
	"""检测multipart/form-data中的危险文件上传"""
	msg_lower = msg.lower()
	
	# 检查是否为multipart/form-data请求
	if 'multipart/form-data' not in msg_lower:
		return None
	
	# 危险的文件扩展名（可执行文件、脚本文件等）
	dangerous_extensions = [
		'.php', '.php3', '.php4', '.php5', '.phtml', '.phps',
		'.jsp', '.jspx', '.jspf', '.jsf',
		'.asp', '.aspx', '.asa', '.asax', '.ashx', '.asmx',
		'.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.vbe',
		'.sh', '.bash', '.csh', '.ksh', '.zsh',
		'.py', '.pyc', '.pyo', '.pyd', '.pyw',
		'.pl', '.pm', '.cgi',
		'.rb', '.rbw',
		'.jar', '.war', '.ear',
		'.dll', '.so', '.dylib',
		'.ps1', '.psm1', '.psd1',
		'.htaccess', '.htpasswd',
		'.sql', '.sqlite', '.sqlite3',
		'.action', '.do', '.struts'
	]
	
	# 检查filename字段
	filename_pattern = re.compile(r'filename\s*=\s*["\']?([^"\'\r\n]+)', re.IGNORECASE)
	filenames = filename_pattern.findall(msg)
	
	for filename in filenames:
		filename_lower = filename.lower().strip()
		
		# 检查危险扩展名
		for ext in dangerous_extensions:
			if filename_lower.endswith(ext):
				return True
		
		# 检查双扩展名绕过（如 .php.jpg, .jsp.png）
		for ext in dangerous_extensions:
			if ext + '.' in filename_lower or '.' + ext.replace('.', '') + '.' in filename_lower:
				return True
	
	# 检查文件内容中是否包含可执行代码（PHP、JSP、ASP等）
	if 'multipart/form-data' in msg_lower:
		# 检查PHP代码标记
		php_patterns = [
			r'<\?php',
			r'<\?=',
			r'<\?',
			r'<%',
			r'<%='  # ASP标记
		]
		for pattern in php_patterns:
			if re.search(pattern, msg, re.IGNORECASE):
				return True
		
		# 检查JSP标记
		if re.search(r'<%[@!]', msg, re.IGNORECASE):
			return True
		
		# 检查脚本标记
		script_patterns = [
			r'<script[^>]*>.*?</script>',
			r'javascript:',
			r'vbscript:',
			r'eval\s*\(',
			r'exec\s*\(',
			r'system\s*\('
		]
		for pattern in script_patterns:
			if re.search(pattern, msg, re.IGNORECASE | re.DOTALL):
				return True
	
	return False

'''
解码URL编码和HTML实体编码，用于检测编码后的XSS攻击
采用延迟解码策略：只在检测到可疑内容时才解码
'''
def decode_content_optimized(content):
	"""优化的解码函数，只在必要时解码一层"""
	decoded_list = []
	
	# 快速检查是否需要解码（包含%或&符号）
	needs_url_decode = '%' in content
	needs_html_decode = '&' in content
	
	if not needs_url_decode and not needs_html_decode:
		return []  # 无需解码
	
	try:
		# URL解码（只解码一次，避免过度解码）
		if needs_url_decode:
			try:
				# 使用unquote_plus来处理+号作为空格的情况
				url_decoded = urllib.parse.unquote_plus(content)
				if url_decoded != content:
					decoded_list.append(url_decoded)
				# 同时也尝试unquote（有些情况下需要）
				url_decoded2 = urllib.parse.unquote(content)
				if url_decoded2 != content and url_decoded2 != url_decoded:
					decoded_list.append(url_decoded2)
			except:
				pass
	except:
		pass
	
	try:
		# HTML实体解码
		if needs_html_decode:
			html_decoded = html.unescape(content)
			if html_decoded != content and html_decoded not in decoded_list:
				decoded_list.append(html_decoded)
	except:
		pass
	
	return decoded_list

'''
从数据库中的规则列表匹配
默认放行
优化版本：快速预检 + 延迟解码 + 预分组规则
'''
def do_filter_rule_list(msg,compiled_rules,block_rules=None,other_rules=None):
	# 提前编译并缓存的静态资源正则表达式
	static_resource_pattern = re.compile(r'\.(js|css|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)($|\?)', re.IGNORECASE)
	
	# 快速获取请求行
	line_end = msg.find("\n")
	if line_end == -1:
		line = msg
	else:
		line = msg[:line_end]
	
	# 特殊处理静态资源文件，直接放行
	if static_resource_pattern.search(line):
		return (C.ACTION_PASS, None, None)
	
	# 快速预检：如果请求不包含可疑字符，直接放行（避免昂贵的规则匹配）
	if not has_suspicious_chars(msg):
		return (C.ACTION_PASS, None, None)
	
	# 如果没有预分组规则，则动态分组（兼容旧代码）
	if block_rules is None or other_rules is None:
		block_rules = []
		other_rules = []
		# 安全检查：确保 compiled_rules 是一个列表或可迭代对象
		if isinstance(compiled_rules, tuple) and len(compiled_rules) == 3:
			# 如果 compiled_rules 实际上是一个三元组，解包它
			compiled_rules, block_rules, other_rules = compiled_rules
			# 确保解包后的 compiled_rules 是列表
			if not isinstance(compiled_rules, list):
				compiled_rules = list(compiled_rules) if compiled_rules else []
		else:
			# 正常遍历规则列表
			try:
				# 确保 compiled_rules 是可迭代的
				if not hasattr(compiled_rules, '__iter__'):
					log(f"compiled_rules 不可迭代，类型: {type(compiled_rules)}", 2)
					return (C.ACTION_PASS, None, None)
				
				for rule_item in compiled_rules:
					# 确保规则项是四元组
					if isinstance(rule_item, tuple):
						if len(rule_item) == 4:
							rule, action, rule_id, description = rule_item
							if action == C.ACTION_BLOCK:
								block_rules.append((rule, action, rule_id, description))
							else:
								other_rules.append((rule, action, rule_id, description))
						else:
							log(f"规则项长度不正确: {len(rule_item)}, 规则项: {rule_item[:2] if len(rule_item) >= 2 else rule_item}", 2)
					else:
						log(f"规则项不是元组，类型: {type(rule_item)}", 2)
			except (ValueError, TypeError) as e:
				log(f"规则遍历错误: {str(e)}, compiled_rules类型: {type(compiled_rules)}", 2)
				import traceback
				log(f"详细错误: {traceback.format_exc()}", 2)
				# 如果出错，返回放行
				return (C.ACTION_PASS, None, None)
	
	# 检查文件上传（在规则匹配之前，因为这是常见攻击向量）
	upload_check = check_file_upload(msg)
	if upload_check is True:
		# 文件上传检测到危险文件，需要进一步检查规则
		# 先检查是否有专门的文件上传BLOCK规则
		for rule, action, rule_id, description in block_rules:
			if 'upload' in str(rule.pattern).lower():
				if rule.search(msg):
					return (action, rule_id, description)
		# 如果没有匹配到专门的规则，继续执行后续规则检查
	
	# 优化：对于大文件，限制XXE和反序列化规则的匹配范围
	# 这些攻击载荷通常在请求的前面部分，不需要检查整个文件
	MAX_CHECK_LENGTH = 100000  # 最多检查前100KB
	check_content = msg[:MAX_CHECK_LENGTH] if len(msg) > MAX_CHECK_LENGTH else msg
	
	# 优先检查BLOCK规则（安全优先）
	# 对于XXE和反序列化规则（ID为负数），使用限制长度的内容
	for rule, action, rule_id, description in block_rules:
		# 内置规则（ID为负数）使用限制长度的内容，避免在大文件上卡顿
		if rule_id < 0:
			if rule.search(check_content):
				return (action, rule_id, description)
		else:
			# 其他规则使用完整内容
			if rule.search(msg):
				return (action, rule_id, description)
	
	# 如果原始消息没有匹配BLOCK规则，检查是否需要解码
	# 如果请求包含编码字符（%），先解码再检查，因为编码后可能匹配BLOCK规则
	needs_decode = '%' in msg or '&' in msg
	decoded_versions = None
	
	# 先检查解码后的BLOCK规则（优先）
	if needs_decode:
		decoded_versions = decode_content_optimized(msg)
		if decoded_versions:
			for decoded in decoded_versions:
				# 对于解码后的内容，也限制XXE和反序列化规则的检查范围
				decoded_check = decoded[:MAX_CHECK_LENGTH] if len(decoded) > MAX_CHECK_LENGTH else decoded
				for rule, action, rule_id, description in block_rules:
					# 内置规则（ID为负数）使用限制长度的内容
					if rule_id < 0:
						if rule.search(decoded_check):
							return (action, rule_id, description)
					else:
						# 其他规则使用完整解码内容
						if rule.search(decoded):
							return (action, rule_id, description)
	
	# 再检查原始消息的其他规则（LOG、PASS等）
	# 注意：由于has_suspicious_chars已经过滤了正常请求，这里只会匹配到真正可疑的请求
	for rule, action, rule_id, description in other_rules:
		if rule.search(msg):
			return (action, rule_id, description)
	
	# 最后检查解码后的其他规则
	if needs_decode and decoded_versions:
		for decoded in decoded_versions:
			for rule, action, rule_id, description in other_rules:
				if rule.search(decoded):
					return (action, rule_id, description)
			
	return (C.ACTION_PASS, None, None)

'''
快速提取HTTP请求中的URL
'''
def extract_url_from_request(msg):
	"""从HTTP请求中快速提取URL"""
	line_end = msg.find('\n')
	if line_end == -1:
		line = msg
	else:
		line = msg[:line_end]
		
	space_pos = line.find(' ')
	if space_pos == -1 or space_pos >= len(line) - 1:
		return None
		
	space_pos2 = line.find(' ', space_pos + 1)
	if space_pos2 == -1:
		return line[space_pos + 1:]
	else:
		return line[space_pos + 1:space_pos2]

'''
从黑名单匹配
优化版本：快速URL提取和匹配
'''
def do_filter_blacklist(msg,ip,blacklists):
	# 如果黑名单为空，直接返回
	if not blacklists:
		return None
	
	# 快速获取URL
	url = extract_url_from_request(msg)
	if url is None:
		return None

	# 优化循环逻辑
	for item in blacklists:
		url_match = (item[0] == "*" or url.startswith(item[0]))
		ip_match = (item[1] == "*" or ip == item[1])
		if url_match and ip_match:
			return C.ACTION_BLOCK
	
	return None


'''
从白名单匹配
优化版本：快速URL提取和匹配
'''
def do_filter_whitelist(msg,ip,whitelists):
	# 如果白名单为空，直接返回
	if not whitelists:
		return None
	
	# 快速获取URL
	url = extract_url_from_request(msg)
	if url is None:
		return None

	# 优化循环逻辑
	for item in whitelists:
		url_match = (item[0] == "*" or url.startswith(item[0]))
		ip_match = (item[1] == "*" or ip == item[1])
		if url_match and ip_match:
			return C.ACTION_PASS
	
	return None
