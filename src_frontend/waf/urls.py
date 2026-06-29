from django.urls import path,re_path
from django.contrib.auth import views as auth_views

from . import views

urlpatterns = [
   #path('',views.IndexView.as_view(),name='index'),

	#path('index',views.IndexView.as_view(),name='index'),
    path('',views.index,name='index'),

	path('index',views.index,name='index'),

    path('log',views.Log_index,name='log'),
    path('log_export',views.log_export,name='log_export'),
    re_path(r'^log_del-(?P<nid>\d+)/', views.log_del, name='log_del'),
    re_path(r'^log_detail-(?P<nid>\d+)/', views.log_detail, name='log_detail'),
    path('rule',views.RuleView.as_view(),name= 'rule'),
    re_path(r'^rule_del-(?P<nid>\d+)/', views.rule_del),
    re_path(r'^rule_edit-(?P<nid>\d+)/', views.rule_edit),
    path('rule_create',views.rule_create),
    path('Whitelist',views.WhitelistView.as_view(),name= 'Whitelist'),
    re_path(r'^Whitelist_del-(?P<nid>\d+)/', views.Whitelist_del, name='Whitelist_del'),
    re_path(r'^Whitelist_edit-(?P<nid>\d+)/', views.Whitelist_edit, name='Whitelist_edit'),
    path('Whitelist_create', views.Whitelist_create, name='Whitelist_create'),
    path('Blacklist',views.BlacklistView.as_view(),name= 'Blacklist'),
    re_path(r'^Blacklist_del-(?P<nid>\d+)/', views.Blacklist_del, name='Blacklist_del'),
    re_path(r'^Blacklist_edit-(?P<nid>\d+)/', views.Blacklist_edit, name='Blacklist_edit'),
    path('Blacklist_create',views.Blacklist_create, name='Blacklist_create')
    ,
    path('Site',views.Site_list,name='Site'),
    path('Site_create',views.Site_create),
    re_path(r'^Site_edit-(?P<nid>\d+)/', views.Site_edit),
    re_path(r'^Site_del-(?P<nid>\d+)/', views.Site_del),
    path('Site_apply',views.apply_sites),
    path('apply_rules',views.apply_rules,name='apply_rules')
    ,
    re_path(r'^Site_quick_set-(?P<nid>\d+)/(?P<proxy_port>\d+)/(?P<real_port>\d+)/', views.Site_quick_set),
    
    # 登录相关URL
    path('login/', views.custom_login, name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('register/', views.register, name='register'),
    
    # 个人资料页面
    path('profile/', views.profile, name='profile'),
    
    # 用户管理相关URL - 仅管理员可见
    path('user_list/', views.user_list, name='user_list'),
    re_path(r'^user_del-(?P<user_id>\d+)/', views.user_del, name='user_del'),
    re_path(r'^user_reset_password-(?P<user_id>\d+)/', views.user_reset_password, name='user_reset_password'),
    re_path(r'^user_permissions-(?P<user_id>\d+)/', views.user_permissions, name='user_permissions'),
    path('init_permissions/', views.init_permissions, name='init_permissions'),

    # 系统日志相关URL
    path('login_log/', views.login_log_list, name='login_log'),
    path('operation_log/', views.operation_log_list, name='operation_log'),
]