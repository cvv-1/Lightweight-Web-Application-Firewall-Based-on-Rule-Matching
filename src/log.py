import dbutils
from utils import log
import datetime
import pytz
import queue
import threading

# 异步日志队列，避免阻塞请求处理
_log_queue = queue.Queue(maxsize=10000)  # 队列最大10000条，防止内存溢出
_log_thread = None
_log_thread_lock = threading.Lock()

def _log_worker():
	"""后台日志写入线程，异步处理日志队列"""
	conn = None
	batch_size = 10  # 批量写入，减少数据库操作
	batch = []
	
	while True:
		try:
			# 从队列获取日志项，设置超时以便定期批量写入
			try:
				log_item = _log_queue.get(timeout=1.0)
			except queue.Empty:
				# 超时，如果有待写入的批次，先写入
				if batch:
					_write_log_batch(batch)
					batch = []
				continue
			
			batch.append(log_item)
			
			# 批量写入，提高性能
			if len(batch) >= batch_size:
				_write_log_batch(batch)
				batch = []
			
			_log_queue.task_done()
		except Exception as e:
			log(f"日志写入线程错误: {str(e)}", 2)
			# 清空批次，避免错误累积
			batch = []

def _write_log_batch(batch):
	"""批量写入日志到数据库"""
	if not batch:
		return
	
	conn = None
	try:
		conn = dbutils.get_conn()
		timestr = datetime.datetime.now(pytz.timezone('PRC')).strftime("%Y-%m-%d %H:%M:%S")
		
		# 批量插入日志记录
		for item in batch:
			req, ip, action, full, rule_id, reason = item
			try:
				line = req.split('\n')[0]
				url = line.split(" ")[1] if len(line.split(" ")) > 1 else ""
			except:
				url = ""
			
			# 直接插入日志记录，不调用 add_log（避免多次提交）
			import config as C
			args = {
				"time": timestr,
				"ip": ip,
				"url": url,
				"action": action,
				"rule_id": rule_id,
				"reason": reason or ""
			}
			cursor = conn.cursor()
			cursor.execute(
				'INSERT INTO {} {} VALUES (:time, :ip, :url, :action, :rule_id, :reason)'.format(
					C.DB_NAME_LOGS, C.DB_TABLE_LOGS
				),
				args
			)
			
			# 如果需要保存完整请求内容
			if full and req:
				log_id = cursor.lastrowid
				
				args_full = {"log_id": log_id, "content": req}
				cursor.execute(
					'INSERT INTO {} {} VALUES (:log_id, :content)'.format(
						C.DB_NAME_FULL_LOG, C.DB_TABLE_FULL_LOG
					),
					args_full
				)
		
		# 批量提交，提高性能
		conn.commit()
	except Exception as e:
		log(f"批量写入日志错误: {str(e)}", 2)
		import traceback
		log(f"详细错误: {traceback.format_exc()}", 2)
		if conn:
			try:
				conn.rollback()
			except Exception as rollback_error:
				log(f"回滚失败: {str(rollback_error)}", 2)
	# 注意：不关闭连接，因为使用线程本地存储，连接会在线程结束时自动关闭
	# 手动关闭可能导致其他操作失败

def _start_log_thread():
	"""启动日志后台线程（线程安全）"""
	global _log_thread
	with _log_thread_lock:
		if _log_thread is None or not _log_thread.is_alive():
			_log_thread = threading.Thread(target=_log_worker, daemon=True)
			_log_thread.start()
			log("异步日志线程已启动", 1)

'''
记录日志，根据full参数决定是否记录整个请求
优化版本：使用异步队列，不阻塞请求处理
'''
def do_log(req,ip,action,full=False,rule_id=None,reason=None):
	# 确保日志线程已启动
	_start_log_thread()
	
	# 快速检查队列是否已满，如果满了则丢弃日志（避免阻塞）
	try:
		_log_queue.put_nowait((req, ip, action, full, rule_id, reason))
	except queue.Full:
		# 队列满时，记录警告但不阻塞请求
		log("日志队列已满，丢弃日志", 2)