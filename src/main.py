import socket,sqlite3

from threading import Thread,Lock
from importlib import reload

from filter import do_filter
from response import do_response
from log import do_log
import config as C
from utils import log
import dbutils

import common

# 全局变量，代理主socket和连接池
proxy_server_socket = None
proxy_conn_pool = []
site_server_sockets = []

# 全局变量，数据库连接
db_conn = None

# 互斥锁
lock = Lock()

'''
处理请求（按站点配置）
'''
# 全局缓存规则，避免每次请求都重新加载
cached_rules = None
cached_rules_timestamp = 0
rules_reload_lock = Lock()  # 规则重新加载锁，防止多个线程同时重新加载
is_reloading = False  # 标记是否正在重新加载规则

import time
def handle_socket(client_conn, site=None):
    # 减少日志记录
    # log("开始处理客户端请求", 0)
    
    # 增大缓冲区以减少网络调用次数
    BUF_SIZE = 16384  # 缓冲区大小增大到16KB，进一步减少网络调用
    client_req = ''
    client_conn.settimeout(C.CLIENT_SOCKET_TIMEOUT)
    try:
        # 缓冲区不满说明读取完毕，否则还应继续读取
        while True:
            buf = client_conn.recv(BUF_SIZE).decode('utf-8', errors='ignore')  # 添加错误处理
            if not buf:
                # log("接收到空数据，结束接收", 0)
                break
            # log(f"接收到数据块，长度: {len(buf)} 字符", 0)
            client_req += buf
            if len(buf) < BUF_SIZE:
                break
        # log("接收到请求:\n------\n" + client_req + '\n------',1)
        # log(f"完整请求数据长度: {len(client_req)} 字符", 0)

    except Exception as e:
        # 替换print为log函数，减少I/O
        log(f"请求接收超时: {str(e)}", 2)
        return
    
    if not client_req:
        # log("出现空请求，丢弃",1)
        return

    ip = client_conn.getpeername()[0]
    # log("请求ip:"+ip,1)

    # 使用缓存的规则（只在启动时初始化，之后通过控制命令手动刷新）
    global cached_rules, cached_rules_timestamp
    
    # 如果规则未初始化，立即加载（只在启动时执行一次）
    if cached_rules is None:
        with rules_reload_lock:
            # 双重检查，避免多个线程同时初始化
            if cached_rules is None:
                try:
                    log("首次加载规则", 1)
                    cached_rules = common.reload_rules()
                    cached_rules_timestamp = time.time()
                except Exception as e:
                    log(f"首次加载规则失败: {str(e)}", 2)
                    # 如果加载失败，使用空规则（会导致所有请求被放行）
                    import filter
                    cached_rules = (([], [], []), [], [])
                    cached_rules_timestamp = time.time()
    
    rules_data, blacklists, whitelists = cached_rules
    # 兼容新旧格式
    if isinstance(rules_data, tuple) and len(rules_data) == 3:
        compiled_rules, block_rules, other_rules = rules_data
        # 确保 compiled_rules 是一个列表
        if not isinstance(compiled_rules, list):
            compiled_rules = list(compiled_rules) if compiled_rules else []
        if not isinstance(block_rules, list):
            block_rules = list(block_rules) if block_rules else []
        if not isinstance(other_rules, list):
            other_rules = list(other_rules) if other_rules else []
    else:
        # 如果 rules_data 不是三元组，检查它是否是规则列表
        if isinstance(rules_data, list):
            compiled_rules = rules_data
        else:
            compiled_rules = []
        block_rules = []
        other_rules = []
    # log(f"可用规则数量: {len(compiled_rules)}, 黑名单数量: {len(blacklists)}, 白名单数量: {len(whitelists)}", 0)
    
    result = do_filter(client_req, ip, compiled_rules, blacklists, whitelists, block_rules, other_rules)
    # log(f"过滤动作结果: {result}", 1)
    do_response(client_conn, client_req, result, site)
    # log("-----------请求处理完毕。---------",1)

'''
WAF核心模块控制连接，用于异步更新、确认存活等
'''
def handle_controller():

	log("已经开启控制连接",1)

	# 初始化 server socket
	controller_server_socket = socket.socket()
	controller_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	controller_server_socket.bind(("0.0.0.0", C.CONTROLLER_PORT))
	controller_server_socket.listen(1024)

	while True:
		conn,addr = controller_server_socket.accept()

		log("建立控制连接",1)
		log(str(conn.getpeername())+"-->"+str(conn.getsockname()),1)

		thread = Thread(target = handle_ctlmsg, args=(conn,))
		thread.setDaemon(True)
		thread.start()

	log("控制连接出错",2)

'''
处理控制信息
'''
def handle_ctlmsg(conn):
	msg = ''
	BUF_SIZE = 4096  # 增大缓冲区
	try:
		# 缓冲区不满说明读取完毕，否则还应继续读取
		while True:
			buf = conn.recv(BUF_SIZE).decode('utf-8', errors='ignore')
			msg += buf
			if len(buf) < BUF_SIZE:
				break
		log("接收到控制信息: " + msg, 1)
	except Exception as e:
		# 替换print为log函数
		log(f"控制信息接收错误: {str(e)}", 2)
		try:
			conn.close()
		except:
			pass
		return

	if not msg:
		# log("出现空请求，丢弃", 1)
		try:
			conn.close()
		except:
			pass
		return

	msg = msg.strip()

	if msg == C.CONTROL_UPDATE:
		import common
		reload(common)
		# 手动刷新规则缓存
		global cached_rules, cached_rules_timestamp, is_reloading
		with rules_reload_lock:
			if not is_reloading:
				is_reloading = True
				try:
					log("收到控制命令，重新加载规则", 1)
					cached_rules = common.reload_rules()
					cached_rules_timestamp = time.time()
					log(f"规则重新加载完成，规则数量: {len(cached_rules[0][0]) if cached_rules and cached_rules[0] else 0}", 1)
				except Exception as e:
					log(f"重新加载规则失败: {str(e)}", 2)
					import traceback
					log(f"详细错误: {traceback.format_exc()}", 2)
				finally:
					is_reloading = False
		conn.sendall("FINISHED".encode())
		conn.close()
		log("规则已更新", 1)
	elif msg == C.CONTROL_CONFIRM:
		conn.sendall(C.CONTROL_CONFIRM.encode())
		conn.close()
		log("心跳包，确认存活", 0)
	elif msg == C.CONTROL_RELOAD_SITES:
		log("处理站点重载命令", 1)
		reload_sites()
		conn.sendall("FINISHED".encode())
		conn.close()
		log("完成站点重载", 1)
	else:
		conn.sendall("INVALID COMMAND".encode())
		conn.close()
		log("非法信息！", 2)


'''
初始化工作、代理主循环
将连接放入连接池，并创建新线程处理
TODO:与管理端的交互，热更新规则
'''
def start_site_listener(site_conf):
	site_name = site_conf.get("name", "未知站点")
	bind_host = site_conf.get("proxy_host", "0.0.0.0")
	bind_port = site_conf.get("proxy_port", C.PROXY_PORT)
	real_host = site_conf.get("real_host", C.REAL_HOST)
	real_port = site_conf.get("real_port", C.REAL_PORT)
	
	try:
		# 先检查端口是否已被占用
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.settimeout(1)
			if s.connect_ex((bind_host, bind_port)) == 0:
				log(f"端口 {bind_host}:{bind_port} 已被占用，无法启动站点 {site_name}", 2)
				return
		
		# 初始化 serversocket for a specific site
		server_socket = socket.socket()
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_socket.bind((bind_host, bind_port))
		server_socket.listen(1024)
		site_server_sockets.append(server_socket)

		log("站点 [{}] 监听已启动: {}:{} -> {}:{}".format(
			site_name,
			bind_host,
			bind_port,
			real_host,
			real_port
		),1)

		while True:
			try:
				client_conn, addr = server_socket.accept()
			except Exception as e:
				log(f"站点 [{site_name}] 接受连接失败: {str(e)}", 2)
				try:
					server_socket.close()
				except:
					pass
				# 从活动监听器列表中移除
				if server_socket in site_server_sockets:
					site_server_sockets.remove(server_socket)
				break
			proxy_conn_pool.append(client_conn)
			log(f"站点 [{site_name}] 建立连接",1)
			log(str(client_conn.getpeername())+"-->"+str(client_conn.getsockname()),1)
			thread = Thread(target = handle_socket, args=(client_conn, site_conf))
			thread.setDaemon(True)
			thread.start()
	except Exception as e:
		log(f"站点 [{site_name}] 启动监听失败: {str(e)}", 2)
		# 清理可能添加的socket
		if 'server_socket' in locals() and server_socket in site_server_sockets:
			site_server_sockets.remove(server_socket)

def load_sites_from_db_or_config():
	loaded_sites = []
	has_site_records = False
	conn = None
	
	try:
		conn = dbutils.get_conn()
		rows = list(dbutils.get_sites(conn))
		
		# 检查数据库中是否有站点记录
		if rows:
			has_site_records = True
			log("数据库中发现站点记录，数量: " + str(len(rows)), 2)
			
			for row in rows:
				try:
					# 确保正确解析数据库记录
					if len(row) >= 7:
						_, name, proxy_host, proxy_port, real_host, real_port, enabled = row
						log("检查站点: " + str(name) + ", 启用状态: " + str(enabled), 2)
						
						# 处理SQLite中布尔值的不同表示
						is_enabled = False
						if isinstance(enabled, bool):
							is_enabled = enabled
						elif isinstance(enabled, int):
							is_enabled = (enabled == 1)
						elif isinstance(enabled, str):
							is_enabled = (enabled.lower() in ['true', '1', 'yes'])
						
						if is_enabled:
							loaded_sites.append({
								"name": name,
								"proxy_host": proxy_host,
								"proxy_port": int(proxy_port),
								"real_host": real_host,
								"real_port": int(real_port)
							})
							log("已加载启用的站点: " + str(name), 1)
				except Exception as e:
					log("站点记录解析失败: " + str(e) + ", 记录内容: " + str(row), 2)
		
		# 重要：如果数据库中有站点记录但都被禁用，则不加载任何配置
		if has_site_records:
			if loaded_sites:
				log("数据库中有" + str(len(loaded_sites)) + "个启用的站点", 1)
			else:
				log("数据库中有站点记录但全部被禁用，不加载任何站点配置", 1)
				return []
	finally:
		if conn:
			try:
				conn.close()
			except Exception:
				pass

	# 只有在数据库中没有任何站点记录时，才考虑使用配置文件或默认配置
	if not has_site_records:
		log("数据库中没有站点记录", 1)
		if hasattr(C, "SITES") and C.SITES:
			loaded_sites = C.SITES
			log("从配置文件加载" + str(len(loaded_sites)) + "个站点", 1)
		else:
			# 加载默认配置
			loaded_sites = [{"name": "默认站点", "proxy_host": C.PROXY_HOST, "proxy_port": C.PROXY_PORT, "real_host": C.REAL_HOST, "real_port": C.REAL_PORT}]
			log("加载默认站点配置", 1)

	return loaded_sites

def reload_sites():
	log("开始重新加载站点配置", 1)
	# 关闭现有监听
	global site_server_sockets
	for s in site_server_sockets:
		try:
			s.close()
			log("已停止站点监听器", 2)
		except Exception as e:
			log(f"停止站点监听器失败: {str(e)}", 2)
	site_server_sockets = []

	# 加载站点配置
	sites = load_sites_from_db_or_config()
	log(f"重载后站点数量: {len(sites)}", 1)
	
	# 如果有启用的站点，启动新监听
	if sites:
		for site in sites:
			try:
				listener_thread = Thread(target = start_site_listener, args=(site,))
				listener_thread.setDaemon(True)
				listener_thread.start()
			except Exception as e:
				log(f"启动站点监听器失败: {str(e)}", 2)
	else:
		log("所有站点均已禁用，不会启动任何监听器", 1)

	log(f"站点重载完成，当前活动监听器数量: {len(site_server_sockets)}", 1)

def proxy_main_loop():
	log("WAF服务启动", 1)
	
	# 初始化规则（在启动时加载一次）
	global cached_rules, cached_rules_timestamp
	if cached_rules is None:
		try:
			log("启动时加载规则", 1)
			cached_rules = common.reload_rules()
			cached_rules_timestamp = time.time()
		except Exception as e:
			log(f"启动时加载规则失败: {str(e)}", 2)
			# 如果加载失败，使用空规则
			import filter
			cached_rules = (([], [], []), [], [])
			cached_rules_timestamp = time.time()
	
	# 开启控制线程
	control_thread = Thread(target = handle_controller)
	control_thread.setDaemon(True)
	control_thread.start()

	# 初次装载站点并监听
	reload_sites()

	# 阻塞保持主线程存活
	while True:
		pass

def __main__():
	proxy_main_loop()

if __name__ == "__main__":
	__main__()