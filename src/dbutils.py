'''
数据库相关接口
优化版本：使用连接池和单例模式，提高性能
'''

import config as C
import sqlite3
import threading

# 线程本地存储，每个线程使用独立的数据库连接
_thread_local = threading.local()

def get_conn():
	"""获取数据库连接，使用线程本地存储，每个线程复用连接"""
	if not hasattr(_thread_local, 'conn') or _thread_local.conn is None:
		_thread_local.conn = sqlite3.connect(C.DATABASE_PATH, check_same_thread=False)
		# 优化SQLite性能
		_thread_local.conn.execute('PRAGMA journal_mode=WAL')  # Write-Ahead Logging，提高并发性能
		_thread_local.conn.execute('PRAGMA synchronous=NORMAL')  # 平衡性能和安全性
		_thread_local.conn.execute('PRAGMA cache_size=-64000')  # 64MB缓存
		_thread_local.conn.execute('PRAGMA temp_store=MEMORY')  # 临时表存储在内存中
	return _thread_local.conn

def execute(conn,sql):
	return conn.cursor().execute(sql)

def get_logs(conn):
	sql = "select * from {};".format(C.DB_NAME_LOGS)
	return execute(conn,sql)

def add_log(conn,time,ip,url,action,content=None,rule_id=None,reason=None):
	
	tables = C.DB_TABLE_LOGS
	args = {"time":time,"ip":ip,"url":url,"action":action,"rule_id":rule_id,"reason":reason or ""}
	conn.cursor().execute('INSERT INTO {} {} VALUES (:time, :ip ,:url, :action, :rule_id, :reason)'.format(C.DB_NAME_LOGS,tables),args)

	# 写入完整记录 - 修改为保存所有动作的完整请求内容
	if content:
		last_insert_rowid = execute(conn,'select last_insert_rowid() from {}'.format(C.DB_NAME_LOGS))
		log_id = last_insert_rowid.__next__()[0]

		tables = C.DB_TABLE_FULL_LOG
		args = {"log_id":log_id,"content":content}
		conn.cursor().execute('INSERT INTO {} {} VALUES (:log_id, :content)'.format(C.DB_NAME_FULL_LOG,tables),args)
	conn.commit()

def get_rules(conn):
	sql = "select * from {};".format(C.DB_NAME_RULES)
	return execute(conn,sql)

def add_rule(conn,action,content,description=''):
	tables = C.DB_TABLE_RULES
	# 防止注入
	args = {"action":action,"content":content,"description":description}
	conn.cursor().execute('INSERT INTO {} {} VALUES (:action, :content, :description)'.format(C.DB_NAME_RULES,tables),args)
	conn.commit()

def delete_rule(conn,uid):
	# id是保留字
	sql = 'DELETE FROM {} WHERE id={}'.format(C.DB_NAME_RULES,uid)
	conn.execute(sql)
	conn.commit()

def get_whitelists(conn):
	sql = "select * from {};".format(C.DB_NAME_WHITELIST)
	return execute(conn,sql)

def add_whitelist(conn,url,ip):
	tables = C.DB_TABLE_WHITELIST
	# 防止注入
	args = {"url":url,"ip":ip,}
	conn.cursor().execute('INSERT INTO {} {} VALUES (:url, :ip)'.format(C.DB_NAME_WHITELIST,tables),args)
	conn.commit()

def delete_whitelist(conn,uid):
	sql = 'DELETE FROM {} WHERE id={}'.format(C.DB_NAME_WHITELIST,uid)
	conn.execute(sql)
	conn.commit()

def get_blacklists(conn):
	sql = "select * from {};".format(C.DB_NAME_BLACKLIST)
	return execute(conn,sql)

def add_blacklist(conn,url,ip):
	tables = C.DB_TABLE_WHITELIST
	# 防止注入
	args = {"url":url,"ip":ip,}
	conn.cursor().execute('INSERT INTO {} {} VALUES (:url, :ip)'.format(C.DB_NAME_BLACKLIST,tables),args)
	conn.commit()

def delete_blacklist(conn,uid):
	sql = 'DELETE FROM {} WHERE id={}'.format(C.DB_NAME_BLACKLIST,uid)
	conn.execute(sql)
	conn.commit()

def get_sites(conn):
    sql = "select * from {};".format(C.DB_NAME_SITES)
    return execute(conn,sql)

def test():
	c = get_conn()
	# add_log(c,"2021-02-27","127.0.0.1","/src?id=123","PASS")
	# add_log(c,"2021-02-27","127.0.0.1","/src?id=evil","BLOCK","hello\n123\nthis\n\n123123")
	add_rule(c,"PASS",".*safe.*","test1")
	add_rule(c,"BLOCK",".*id=evil.*","test2")
	add_rule(c,"BLOCK",".*id=ev[0-9].*il.*","test3")
	add_rule(c,"LOG",".*id=evil[0-9].*","test4")
	add_rule(c,"LOG",".*id=.*evil.*","test5")
	add_rule(c,"LOG","\'\"\\1adhello","error compile test")

#test()