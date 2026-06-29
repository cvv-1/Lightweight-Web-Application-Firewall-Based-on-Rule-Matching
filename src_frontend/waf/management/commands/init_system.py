from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from waf.models import Permission, CustomUser
import getpass

User = get_user_model()


class Command(BaseCommand):
    help = '初始化系统：创建数据库表、超级用户和权限'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            help='管理员用户名',
        )
        parser.add_argument(
            '--email',
            type=str,
            help='管理员邮箱',
        )
        parser.add_argument(
            '--password',
            type=str,
            help='管理员密码',
        )
        parser.add_argument(
            '--no-input',
            action='store_true',
            help='不进行交互式输入',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('开始初始化系统...'))

        # 步骤1：运行数据库迁移
        self.stdout.write('步骤 1/3: 运行数据库迁移...')
        from django.core.management import call_command
        try:
            call_command('migrate', verbosity=0)
            self.stdout.write(self.style.SUCCESS('✓ 数据库迁移完成'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ 数据库迁移失败: {e}'))
            return

        # 步骤2：创建超级用户
        self.stdout.write('步骤 2/3: 创建管理员账户...')
        username = options.get('username')
        email = options.get('email')
        password = options.get('password')
        no_input = options.get('no_input')

        if no_input:
            if not username or not email or not password:
                self.stdout.write(self.style.ERROR('✗ 使用 --no-input 时必须提供 --username、--email 和 --password'))
                return
        else:
            if not username:
                username = input('请输入管理员用户名 (默认: admin): ').strip() or 'admin'
            if not email:
                email = input('请输入管理员邮箱 (默认: admin@example.com): ').strip() or 'admin@example.com'
            if not password:
                while True:
                    password = getpass.getpass('请输入管理员密码: ')
                    password_confirm = getpass.getpass('请确认管理员密码: ')
                    if password == password_confirm:
                        break
                    self.stdout.write(self.style.WARNING('两次输入的密码不一致，请重新输入'))

        # 检查用户是否已存在
        if CustomUser.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f'✓ 管理员账户 "{username}" 已存在，跳过创建'))
        else:
            try:
                admin_user = CustomUser.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password,
                    user_type=CustomUser.ADMIN
                )
                self.stdout.write(self.style.SUCCESS(f'✓ 管理员账户创建成功: {username}'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'✗ 管理员账户创建失败: {e}'))
                return

        # 步骤3：初始化权限
        self.stdout.write('步骤 3/3: 初始化系统权限...')
        permissions_data = [
            # 站点管理权限
            {'code': 'view_sites', 'name': '查看站点', 'category': '站点管理'},
            {'code': 'manage_sites', 'name': '管理站点', 'category': '站点管理'},

            # 规则管理权限
            {'code': 'view_rules', 'name': '查看规则', 'category': '规则管理'},
            {'code': 'manage_rules', 'name': '管理规则', 'category': '规则管理'},

            # 白名单管理权限
            {'code': 'view_whitelist', 'name': '查看白名单', 'category': '白名单管理'},
            {'code': 'manage_whitelist', 'name': '管理白名单', 'category': '白名单管理'},

            # 黑名单管理权限
            {'code': 'view_blacklist', 'name': '查看黑名单', 'category': '黑名单管理'},
            {'code': 'manage_blacklist', 'name': '管理黑名单', 'category': '黑名单管理'},

            # 日志管理权限
            {'code': 'view_logs', 'name': '查看日志', 'category': '日志管理'},
            {'code': 'delete_logs', 'name': '删除日志', 'category': '日志管理'},
            {'code': 'export_logs', 'name': '导出日志', 'category': '日志管理'},

            # 用户管理权限
            {'code': 'manage_users', 'name': '管理用户', 'category': '用户管理'},
        ]

        created_count = 0
        for perm_data in permissions_data:
            perm, created = Permission.objects.get_or_create(
                code=perm_data['code'],
                defaults={
                    'name': perm_data['name'],
                    'category': perm_data['category']
                }
            )
            if created:
                created_count += 1

        self.stdout.write(self.style.SUCCESS(f'✓ 权限初始化完成，共创建 {created_count} 个权限'))

        # 完成
        self.stdout.write(self.style.SUCCESS('\n' + '='*50))
        self.stdout.write(self.style.SUCCESS('系统初始化完成！'))
        self.stdout.write(self.style.SUCCESS('='*50))
        self.stdout.write(f'管理员用户名: {username}')
        self.stdout.write(f'管理员邮箱: {email}')
        self.stdout.write('请妥善保管管理员密码')
        self.stdout.write('\n现在可以运行以下命令启动开发服务器:')
        self.stdout.write(self.style.WARNING('python manage.py runserver'))
