
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone


class Rule(models.Model):
	id = models.AutoField('id', primary_key=True, unique=True)
	# 规则类型
	RULE_TYPE_CHOICES = (
		('SQLI', 'SQL注入'),
		('XSS', 'XSS跨站'),
		('CSRF', 'CSRF'),
		('RCE', '命令执行'),
		('SSRF', 'SSRF'),
		('XXE', 'XXE'),
		('DESER', '反序列化'),
		('PTR', '路径遍历'),
		('UPLOAD', '文件上传'),
		('OTHER', '其他规则'),
	)
	rule_type = models.CharField('规则类型', max_length=10, choices=RULE_TYPE_CHOICES, default='OTHER')
	# 规则内容
	content = models.TextField('content', default='')
	# 规则描述
	description = models.TextField('description', default='')
	# 动作类型
	ACTION_CHOICES = (
		('BLOCK', '拦截'),
		('LOG', '记录'),
		('PASS', '放行'),
	)
	action = models.CharField('动作', max_length=10, choices=ACTION_CHOICES, default='BLOCK')
	# 创建时间
	created_at = models.DateTimeField('创建时间', default=timezone.now)
	updated_at = models.DateTimeField('更新时间', default=timezone.now)

class Log(models.Model):
	id = models.AutoField("id", primary_key=True, unique=True)
	time = models.TextField(default='')
	ip = models.TextField(default='')
	url = models.TextField(default='')
	action = models.TextField(default='')
	rule_id = models.IntegerField('规则ID', null=True, blank=True, default=None)
	reason = models.TextField('触发原因', default='', blank=True)

class Fulllog(models.Model):
	id = models.AutoField('id', primary_key=True, unique=True)
	log = models.ForeignKey(on_delete=models.CASCADE, to='Log')
	content = models.TextField('content', default='')

class Whitelist(models.Model):
	# 使用*作为通配
	id = models.AutoField('id', primary_key=True, unique=True)
	url = models.TextField(default='',blank=False)
	ip = models.TextField(default='',blank=False)

class Blacklist(models.Model):
	# 使用*作为通配
	id = models.AutoField('id', primary_key=True, unique=True)
	url = models.TextField(default='',blank=False)
	ip = models.TextField(default='',blank=False)

class Site(models.Model):
	id = models.AutoField('id', primary_key=True, unique=True)
	name = models.TextField(default='', blank=False)
	proxy_host = models.TextField(default='0.0.0.0', blank=False)
	proxy_port = models.IntegerField(default=8080)
	real_host = models.TextField(default='127.0.0.1', blank=False)
	real_port = models.IntegerField(default=80)
	enabled = models.BooleanField(default=True)

# 自定义用户管理器
class CustomUserManager(BaseUserManager):
    def create_user(self, username, email=None, password=None, **extra_fields):
        if not username:
            raise ValueError('用户名必须设置')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('user_type', 'ADMIN')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('超级用户必须设置is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('超级用户必须设置is_superuser=True')
        
        return self.create_user(username, email, password, **extra_fields)

class CustomUser(AbstractUser):
	# 用户类型常量
	ADMIN = 'ADMIN'
	NORMAL = 'NORMAL'
	# 用户类型选项
	USER_TYPE_CHOICES = (
		(ADMIN, '管理员'),
		(NORMAL, '普通用户'),
	)
	# 添加用户类型字段
	user_type = models.CharField(
		max_length=10,
		choices=USER_TYPE_CHOICES,
		default=NORMAL,
		verbose_name='用户类型'
	)
	# 添加头像字段
	avatar = models.ImageField(
		upload_to='avatars/',
		default='avatars/default.svg',
		null=True,
		blank=True,
		verbose_name='头像'
	)

	objects = CustomUserManager()

	def __str__(self):
		return self.username

	def has_permission(self, permission_code):
		"""检查用户是否有特定权限"""
		if self.user_type == self.ADMIN:
			return True
		return UserPermission.objects.filter(user=self, permission__code=permission_code).exists()

class Permission(models.Model):
	"""权限定义表"""
	id = models.AutoField('id', primary_key=True, unique=True)
	code = models.CharField('权限代码', max_length=50, unique=True)
	name = models.CharField('权限名称', max_length=100)
	description = models.TextField('权限描述', default='', blank=True)
	category = models.CharField('权限分类', max_length=50, default='其他')

	class Meta:
		verbose_name = '权限'
		verbose_name_plural = '权限'

	def __str__(self):
		return self.name

class UserPermission(models.Model):
	"""用户权限关联表"""
	id = models.AutoField('id', primary_key=True, unique=True)
	user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='permissions')
	permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
	granted_at = models.DateTimeField('授权时间', default=timezone.now)
	granted_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='granted_permissions')

	class Meta:
		verbose_name = '用户权限'
		verbose_name_plural = '用户权限'
		unique_together = ('user', 'permission')

	def __str__(self):
		return f"{self.user.username} - {self.permission.name}"

class LoginLog(models.Model):
	"""登录日志"""
	id = models.AutoField('id', primary_key=True, unique=True)
	user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='login_logs')
	login_time = models.DateTimeField('登录时间', default=timezone.now)
	ip_address = models.CharField('IP地址', max_length=50, default='')
	user_agent = models.TextField('用户代理', default='', blank=True)
	status = models.CharField('登录状态', max_length=20, choices=[('SUCCESS', '成功'), ('FAILED', '失败')], default='SUCCESS')
	remark = models.TextField('备注', default='', blank=True)

	class Meta:
		verbose_name = '登录日志'
		verbose_name_plural = '登录日志'
		ordering = ['-login_time']

	def __str__(self):
		return f"{self.user.username} - {self.login_time}"

class OperationLog(models.Model):
	"""操作日志"""
	OPERATION_CHOICES = [
		('CREATE', '创建'),
		('UPDATE', '修改'),
		('DELETE', '删除'),
		('LOGIN', '登录'),
		('LOGOUT', '登出'),
		('OTHER', '其他'),
	]

	id = models.AutoField('id', primary_key=True, unique=True)
	user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='operation_logs')
	operation_type = models.CharField('操作类型', max_length=20, choices=OPERATION_CHOICES)
	module = models.CharField('操作模块', max_length=100, default='')
	object_id = models.IntegerField('对象ID', null=True, blank=True)
	object_name = models.CharField('对象名称', max_length=200, default='')
	operation_time = models.DateTimeField('操作时间', default=timezone.now)
	ip_address = models.CharField('IP地址', max_length=50, default='')
	details = models.TextField('操作详情', default='', blank=True)
	status = models.CharField('操作状态', max_length=20, choices=[('SUCCESS', '成功'), ('FAILED', '失败')], default='SUCCESS')

	class Meta:
		verbose_name = '操作日志'
		verbose_name_plural = '操作日志'
		ordering = ['-operation_time']

	def __str__(self):
		return f"{self.user.username} - {self.get_operation_type_display()} - {self.module}"