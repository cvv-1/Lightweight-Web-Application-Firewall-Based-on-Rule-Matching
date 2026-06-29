from django.apps import AppConfig


class WafConfig(AppConfig):
	name = 'waf'

	def ready(self):
		"""应用启动时自动初始化系统权限"""
		from django.db import connection
		from django.db.utils import OperationalError

		try:
			# 检查数据库连接是否可用
			with connection.cursor() as cursor:
				cursor.execute("SELECT 1")
		except (OperationalError, Exception):
			# 数据库不可用，跳过初始化
			return

		try:
			from .models import Permission

			permissions_data = [
				{'code': 'manage_sites', 'name': '管理站点', 'description': '可以添加、编辑、删除站点配置', 'category': '站点管理'},
				{'code': 'view_sites', 'name': '查看站点', 'description': '可以查看站点列表', 'category': '站点管理'},
				{'code': 'manage_rules', 'name': '管理规则', 'description': '可以添加、编辑、删除WAF规则', 'category': '规则管理'},
				{'code': 'view_rules', 'name': '查看规则', 'description': '可以查看规则列表', 'category': '规则管理'},
				{'code': 'manage_whitelist', 'name': '管理白名单', 'description': '可以添加、编辑、删除白名单', 'category': '名单管理'},
				{'code': 'view_whitelist', 'name': '查看白名单', 'description': '可以查看白名单', 'category': '名单管理'},
				{'code': 'manage_blacklist', 'name': '管理黑名单', 'description': '可以添加、编辑、删除黑名单', 'category': '名单管理'},
				{'code': 'view_blacklist', 'name': '查看黑名单', 'description': '可以查看黑名单', 'category': '名单管理'},
				{'code': 'view_logs', 'name': '查看日志', 'description': '可以查看WAF日志', 'category': '日志管理'},
				{'code': 'delete_logs', 'name': '删除日志', 'description': '可以删除WAF日志', 'category': '日志管理'},
				{'code': 'export_logs', 'name': '导出日志', 'description': '可以导出日志为CSV文件', 'category': '日志管理'},
			]

			for perm_data in permissions_data:
				Permission.objects.get_or_create(
					code=perm_data['code'],
					defaults={
						'name': perm_data['name'],
						'description': perm_data['description'],
						'category': perm_data['category']
					}
				)
		except Exception:
			# 如果初始化失败，静默处理，不影响系统启动
			pass
