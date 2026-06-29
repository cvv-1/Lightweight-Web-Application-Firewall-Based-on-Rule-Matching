from django.core import paginator
from django.http import HttpResponse,request
from django.views import generic,View
import datetime
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.core.exceptions import PermissionDenied
from django.contrib import messages
import csv
import io
from urllib.parse import quote

from .models import Log,Rule,Fulllog,Whitelist,Blacklist,Site, CustomUser, Permission, UserPermission, LoginLog, OperationLog

from django.db.models import Count, Q
from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.shortcuts import redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

import socket

# 获取客户端IP地址
def get_client_ip(request):
    """获取客户端IP地址"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# 记录操作日志
def log_operation(user, operation_type, module, object_id=None, object_name='', details='', status='SUCCESS', request=None):
    """记录用户操作日志"""
    try:
        ip_address = get_client_ip(request) if request else ''
        OperationLog.objects.create(
            user=user,
            operation_type=operation_type,
            module=module,
            object_id=object_id,
            object_name=object_name,
            ip_address=ip_address,
            details=details,
            status=status
        )
    except Exception as e:
        pass  # 日志记录失败不影响主业务

# 权限控制装饰器
def admin_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if request.user.user_type != CustomUser.ADMIN:
            raise PermissionDenied("您没有权限访问此页面")
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def permission_required(permission_code):
    """权限检查装饰器"""
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            if not request.user.has_permission(permission_code):
                return render(request, 'waf/permission_denied.html', {
                    'permission_code': permission_code,
                    'message': '您没有权限执行此操作'
                }, status=403)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
def update_rules():
    signal = "<-UPDATE->"
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", 12345))
        s.sendall(signal.encode())
    finally:
        try:
            s.close()
        except:
            pass

@admin_required
@permission_required('manage_sites')
def apply_sites(request):
    signal = "<-RELOAD_SITES->"
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", 12345))
        s.sendall(signal.encode())
        messages.success(request, "站点配置已应用到WAF服务")
    except ConnectionRefusedError:
        messages.warning(request, "WAF核心服务未运行，配置已保存但未应用到WAF")
    except Exception as e:
        messages.warning(request, f"无法连接到WAF服务: {str(e)}")
    finally:
        try:
            s.close()
        except:
            pass
    return redirect("Site")

@permission_required('manage_rules')
def apply_rules(request):
    """应用规则、白名单、黑名单配置到WAF服务"""
    signal = "<-UPDATE->"
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", 12345))
        s.sendall(signal.encode())
        # 等待响应
        response = s.recv(1024).decode('utf-8', errors='ignore')
        if response.strip() == "FINISHED":
            messages.success(request, "规则已成功应用到WAF服务")
        else:
            messages.warning(request, "规则应用完成，但未收到确认响应")
    except ConnectionRefusedError:
        messages.warning(request, "WAF核心服务未运行，规则已保存但未应用到WAF")
    except Exception as e:
        messages.warning(request, f"无法连接到WAF服务: {str(e)}")
    finally:
        try:
            s.close()
        except:
            pass

    # 根据来源页面重定向
    referer = request.META.get('HTTP_REFERER', '')
    if 'rule' in referer:
        return redirect("rule")
    elif 'Whitelist' in referer:
        return redirect("Whitelist")
    elif 'Blacklist' in referer:
        return redirect("Blacklist")
    else:
        return redirect("rule")  # 默认重定向到规则页面

@permission_required('view_sites')
def Site_list(request):
    sites = Site.objects.all()
    return render(request, 'waf/Site.html', {"Site_list": sites})

@permission_required('manage_sites')
def Site_create(request):
    if request.method=="GET":
        return render(request, 'waf/Site_create.html')
    elif request.method=="POST":
        name = request.POST.get("name")
        proxy_host = request.POST.get("proxy_host")
        proxy_port = int(request.POST.get("proxy_port"))
        real_host = request.POST.get("real_host")
        real_port = int(request.POST.get("real_port"))
        enabled = True if request.POST.get("enabled") == 'on' else False
        site = Site.objects.create(name=name, proxy_host=proxy_host, proxy_port=proxy_port, real_host=real_host, real_port=real_port, enabled=enabled)
        log_operation(
            user=request.user,
            operation_type='CREATE',
            module='站点',
            object_id=site.id,
            object_name=name,
            details=f'Created site: {name} (proxy: {proxy_host}:{proxy_port} -> {real_host}:{real_port})',
            request=request
        )
        # 调用apply_sites通知WAF服务重新加载站点配置
        apply_sites(request)
        return redirect("Site")

@permission_required('manage_sites')
def Site_edit(request,nid):
    if request.method=="GET":
        obj=Site.objects.filter(id=nid).first()
        return render(request, 'waf/Site_edit.html', {"obj": obj})
    elif request.method=="POST":
        name = request.POST.get("name")
        proxy_host = request.POST.get("proxy_host")
        proxy_port = int(request.POST.get("proxy_port"))
        real_host = request.POST.get("real_host")
        real_port = int(request.POST.get("real_port"))
        enabled = True if request.POST.get("enabled") == 'on' else False
        Site.objects.filter(id=nid).update(name=name, proxy_host=proxy_host, proxy_port=proxy_port, real_host=real_host, real_port=real_port, enabled=enabled)
        log_operation(
            user=request.user,
            operation_type='UPDATE',
            module='站点',
            object_id=nid,
            object_name=name,
            details=f'Updated site: {name} (proxy: {proxy_host}:{proxy_port} -> {real_host}:{real_port})',
            request=request
        )
        # 调用apply_sites通知WAF服务重新加载站点配置
        apply_sites(request)
        return redirect("Site")

@permission_required('manage_sites')
def Site_del(request,nid):
    site = Site.objects.filter(id=nid).first()
    if site:
        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='DELETE',
            module='站点',
            object_id=site.id,
            object_name=site.name,
            details=f'删除站点: {site.name}',
            request=request
        )
        site.delete()
    # 调用apply_sites通知WAF服务重新加载站点配置
    apply_sites(request)
    return redirect("Site")

@permission_required('manage_sites')
def Site_quick_set(request,nid,proxy_port,real_port):
    try:
        proxy_port = int(proxy_port)
        real_port = int(real_port)
    except:
        return redirect("Site")
    Site.objects.filter(id=nid).update(proxy_port=proxy_port, real_port=real_port, enabled=True)
    return apply_sites(request)


@method_decorator(permission_required('view_rules'), name='dispatch')
class RuleView(generic.ListView):
    template_name = 'waf/rule.html'
    context_object_name = 'rule_list'
    paginate_by = 20

    def get_queryset(self):
        # 获取查询参数
        rule_type = self.request.GET.get('rule_type', '')
        if rule_type:
            return Rule.objects.filter(rule_type=rule_type).order_by('-updated_at')
        return Rule.objects.all().order_by('-updated_at')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # 添加规则类型列表用于过滤
        context['rule_types'] = Rule.RULE_TYPE_CHOICES
        # 添加当前选择的规则类型
        context['current_type'] = self.request.GET.get('rule_type', '')
        # 统计各类型规则数量
        context['type_counts'] = Rule.objects.values('rule_type').annotate(count=Count('rule_type'))
        # 添加总规则数（不受过滤影响）
        context['total_rules_count'] = Rule.objects.count()
        return context

@login_required(login_url='login')
def index(request):
    rulesum,flowsum,passrate,blockrate,lograte,sitesum = 0,0,0,0,0,0

    rulesum = Rule.objects.all().aggregate(Count('id'))['id__count']
    flowsum = Log.objects.all().aggregate(Count('id'))['id__count']
    sitesum = Site.objects.all().aggregate(Count('id'))['id__count']

    psum = Log.objects.filter(action='PASS').aggregate(Count('id'))['id__count']
    bsum = Log.objects.filter(action='BLOCK').aggregate(Count('id'))['id__count']
    lsum = Log.objects.filter(action='LOG').aggregate(Count('id'))['id__count']

    if flowsum == 0:
        passrate,blockrate,lograte = 0,0,0
    else:
        passrate = round(psum*100 / flowsum , 2)
        blockrate = round(bsum*100 / flowsum , 2)
        lograte = round(lsum*100 / flowsum , 2)
    print(rulesum,flowsum,psum,bsum,lsum)
    
    # 统计各种攻击类型（按“规则类型”分组）
    rule_type_display = dict(Rule.RULE_TYPE_CHOICES)  # 规则类型代码 -> 中文名
    attack_types = {}
    for type_code, type_name in Rule.RULE_TYPE_CHOICES:
        count = Log.objects.filter(
            action='BLOCK',
            rule_id__in=Rule.objects.filter(rule_type=type_code).values('id')
        ).count()
        attack_types[type_name] = count
    
    # 获取最近24小时每小时的按规则类型统计数据
    now = datetime.datetime.now()
    hourly_labels = []
    
    # 初始化每小时各规则类型的数据（键使用中文名，方便前端直接展示）
    hourly_attack_data = {display_name: [] for _, display_name in Rule.RULE_TYPE_CHOICES}
    
    # 预先缓存各规则类型对应的规则 ID 列表，减少重复查询
    rule_ids_by_type = {
        type_code: list(Rule.objects.filter(rule_type=type_code).values_list('id', flat=True))
        for type_code, _ in Rule.RULE_TYPE_CHOICES
    }
    
    # 生成最近24小时的数据
    for i in range(23, -1, -1):
        hour_start = now - datetime.timedelta(hours=i)
        hour_end = hour_start + datetime.timedelta(hours=1)
        
        # 格式化时间标签
        hour_label = hour_start.strftime('%H:00')
        hourly_labels.append(hour_label)
        
        # 统计每种规则类型在此小时内的拦截数量
        for type_code, type_name in Rule.RULE_TYPE_CHOICES:
            rule_ids = rule_ids_by_type.get(type_code, [])
            if not rule_ids:
                hourly_attack_data[type_name].append(0)
                continue
            
            try:
                # time 如果是可比较格式，按时间区间统计
                count = Log.objects.filter(
                    action='BLOCK',
                    rule_id__in=rule_ids,
                    time__gte=hour_start.strftime('%Y-%m-%d %H:%M:%S'),
                    time__lt=hour_end.strftime('%Y-%m-%d %H:%M:%S')
                ).count()
            except Exception:
                # 如果 time 不是标准时间格式，则退回到前缀匹配
                hour_pattern = hour_start.strftime('%Y-%m-%d %H')
                count = Log.objects.filter(
                    action='BLOCK',
                    rule_id__in=rule_ids,
                    time__startswith=hour_pattern
                ).count()
            
            hourly_attack_data[type_name].append(count)

    # 获取当前时间
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 获取最近的拦截记录（动作为BLOCK的日志），限制5条
    recent_block_logs = Log.objects.filter(action='BLOCK').order_by('-time')[:5]
    
    # 计算监控时长
    monitor_duration = "0h"
    first_log = Log.objects.order_by('time').first()
    if first_log and first_log.time:
        try:
            # 尝试解析日志时间
            log_time_str = first_log.time
            # 处理不同的时间格式
            time_formats = ['%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y/%m/%d %H:%M']
            log_time = None
            
            for fmt in time_formats:
                try:
                    log_time = datetime.datetime.strptime(log_time_str, fmt)
                    break
                except ValueError:
                    continue
            
            if log_time:
                # 计算时间差
                now = datetime.datetime.now()
                duration = now - log_time
                total_hours = duration.total_seconds() / 3600
                
                if total_hours >= 24:
                    days = int(total_hours / 24)
                    remaining_hours = int(total_hours % 24)
                    if remaining_hours > 0:
                        monitor_duration = f"{days}d{remaining_hours}h"
                    else:
                        monitor_duration = f"{days}d"
                else:
                    monitor_duration = f"{int(total_hours)}h"
        except Exception as e:
            print(f"计算监控时长错误: {e}")
            # 如果计算失败，使用默认值
            monitor_duration = "0h"
    
    params = {"rulesum":rulesum,"flowsum":flowsum,"passrate":passrate,"blockrate":blockrate,"lograte":lograte,"sitesum":sitesum,
              "current_time":current_time, "recent_block_logs": recent_block_logs, "monitor_duration": monitor_duration,
              "attack_types": attack_types, "hourly_labels": hourly_labels, "hourly_attack_data": hourly_attack_data}

    return render(request, 'waf/index.html', params)

@method_decorator(permission_required('view_whitelist'), name='dispatch')
class WhitelistView(generic.ListView):
    template_name = 'waf/Whitelist.html'
    context_object_name = 'Whitelist_list'

    def get_queryset(self):
        return Whitelist.objects.all()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # 添加白名单规则数量到上下文
        context['Whitelist_count'] = Whitelist.objects.count()
        return context

@method_decorator(permission_required('view_blacklist'), name='dispatch')
class BlacklistView(generic.ListView):
    template_name = 'waf/Blacklist.html'
    context_object_name = 'Blacklist_list'

    def get_queryset(self):
        return Blacklist.objects.all()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # 添加黑名单规则数量到上下文
        context['Blacklist_count'] = Blacklist.objects.count()
        return context

@permission_required('manage_rules')
def rule_del(request,nid):  #删除
    rule = Rule.objects.filter(id=nid).first()
    if rule:
        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='DELETE',
            module='规则',
            object_id=rule.id,
            object_name=rule.description,
            details=f'删除规则: {rule.description}',
            request=request
        )
        rule.delete()
    # 不再自动刷新规则，需要手动点击应用按钮
    return redirect("rule")

@permission_required('manage_rules')
def rule_edit(request, nid):  #修改
    obj = Rule.objects.filter(id=nid).first()
    if not obj:
        return redirect('rule')

    if request.method == 'GET':
        return render(request, 'waf/rule_edit.html', {
            'obj': obj,
            'rule_types': Rule.RULE_TYPE_CHOICES,
            'action_choices': Rule.ACTION_CHOICES
        })
    elif request.method == 'POST':
        rule_type = request.POST.get('rule_type', obj.rule_type)
        content = request.POST.get('content')
        description = request.POST.get('description')
        action = request.POST.get('action', obj.action)

        Rule.objects.filter(id=nid).update(
            rule_type=rule_type,
            content=content,
            description=description,
            action=action
        )

        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='UPDATE',
            module='规则',
            object_id=obj.id,
            object_name=description,
            details=f'修改规则: {description}',
            request=request
        )

        # 不再自动刷新规则，需要手动点击应用按钮
        return redirect('rule')

@permission_required('manage_rules')
def rule_create(request):
    if request.method == 'GET':
        # 显示创建规则表单
        return render(request, 'waf/rule_create.html', {
            'rule_types': Rule.RULE_TYPE_CHOICES,
            'action_choices': Rule.ACTION_CHOICES
        })
    elif request.method == 'POST':
        # 获取表单数据
        rule_type = request.POST.get('rule_type', 'OTHER')
        content = request.POST.get('content')
        description = request.POST.get('description')
        action = request.POST.get('action', 'BLOCK')

        # 创建规则
        obj = Rule.objects.create(
            rule_type=rule_type,
            content=content,
            description=description,
            action=action
        )

        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='CREATE',
            module='规则',
            object_id=obj.id,
            object_name=description,
            details=f'创建规则: {description}',
            request=request
        )

        # 不再自动刷新规则，需要手动点击应用按钮
        return redirect('rule')

@login_required(login_url='login')
def log_detail(request,nid):
    logGet = Log.objects.filter(id=nid).first()
    FulllogGet = Fulllog.objects.filter(log = logGet).first()
    return render(request, 'waf/log_detail.html', {"log": logGet,'Fulllog':FulllogGet})

@permission_required('delete_logs')
def log_del(request,nid):  #删除
    # 获取当前页面参数和其他查询参数
    current_page = request.GET.get('page', '1')
    ip_search = request.GET.get('ip', '')
    time_search = request.GET.get('time', '')
    action_search = request.GET.get('action', '')

    log_obj = Log.objects.filter(id=nid).first()
    Log.objects.filter(id=nid).delete()

    # 记录删除操作
    if log_obj:
        log_operation(
            user=request.user,
            operation_type='DELETE',
            module='日志',
            object_id=nid,
            object_name=f'Log #{nid}',
            details=f'Deleted log entry: IP={log_obj.ip}, URL={log_obj.url}, Action={log_obj.action}',
            request=request
        )

    # 删除后重定向到日志列表页面，保持搜索条件
    # 正确构建查询参数字典
    query_params = {'page': current_page}
    if ip_search:
        query_params['ip'] = ip_search
    if time_search:
        query_params['time'] = time_search
    if action_search:
        query_params['action'] = action_search

    # 使用redirect()的HttpResponseRedirect方式，确保查询参数正确传递
    from django.http import HttpResponseRedirect
    from django.urls import reverse
    return HttpResponseRedirect(reverse('log') + '?' + '&'.join([f"{k}={v}" for k, v in query_params.items()]))

# 不再需要单独的批量删除视图函数，已合并到Log_index中处理
#Whitelist
@permission_required('manage_whitelist')
def Whitelist_del(request,nid):  #删除
    whitelist = Whitelist.objects.filter(id=nid).first()
    if whitelist:
        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='DELETE',
            module='白名单',
            object_id=whitelist.id,
            object_name=f"URL: {whitelist.url}, IP: {whitelist.ip}",
            details=f'删除白名单: URL={whitelist.url}, IP={whitelist.ip}',
            request=request
        )
        whitelist.delete()
    # 不再自动刷新规则，需要手动点击应用按钮
    return redirect("Whitelist")

@permission_required('manage_whitelist')
def Whitelist_edit(request,nid):  #修改
    if request.method=="GET":
        obj=Whitelist.objects.filter(id=nid).first()
        return render(request, 'waf/Whitelist_edit.html', {"obj": obj})
    elif request.method=="POST":      #拿到提交的数据
        urlGet=request.POST.get("url")
        ipGet = request.POST.get("ip")
        obj = Whitelist.objects.filter(id=nid).first()
        Whitelist.objects.filter(id=nid).update(url = urlGet, ip = ipGet)

        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='UPDATE',
            module='白名单',
            object_id=obj.id,
            object_name=f"URL: {urlGet}, IP: {ipGet}",
            details=f'修改白名单: URL={urlGet}, IP={ipGet}',
            request=request
        )

        # 不再自动刷新规则，需要手动点击应用按钮
        return redirect("Whitelist")

@permission_required('manage_whitelist')
def Whitelist_create(request):
    if request.method=="GET":
        return render(request, 'waf/Whitelist_create.html')
    elif request.method=="POST":
        urlGet=request.POST.get("url")
        ipGet = request.POST.get("ip")
        obj = Whitelist.objects.create(url = urlGet, ip = ipGet)

        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='CREATE',
            module='白名单',
            object_id=obj.id,
            object_name=f"URL: {urlGet}, IP: {ipGet}",
            details=f'创建白名单: URL={urlGet}, IP={ipGet}',
            request=request
        )

        # 不再自动刷新规则，需要手动点击应用按钮
        return redirect("Whitelist")
#Blacklist
@permission_required('manage_blacklist')
def Blacklist_del(request,nid):  #删除
    blacklist = Blacklist.objects.filter(id=nid).first()
    if blacklist:
        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='DELETE',
            module='黑名单',
            object_id=blacklist.id,
            object_name=f"URL: {blacklist.url}, IP: {blacklist.ip}",
            details=f'删除黑名单: URL={blacklist.url}, IP={blacklist.ip}',
            request=request
        )
        blacklist.delete()
    # 不再自动刷新规则，需要手动点击应用按钮
    return redirect("Blacklist")

@permission_required('manage_blacklist')
def Blacklist_edit(request,nid):  #修改
    if request.method=="GET":
        obj=Blacklist.objects.filter(id=nid).first()
        return render(request, 'waf/Blacklist_edit.html', {"obj": obj})
    elif request.method=="POST":      #拿到提交的数据
        urlGet=request.POST.get("url")
        ipGet = request.POST.get("ip")
        obj = Blacklist.objects.filter(id=nid).first()
        Blacklist.objects.filter(id=nid).update(url = urlGet, ip = ipGet)

        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='UPDATE',
            module='黑名单',
            object_id=obj.id,
            object_name=f"URL: {urlGet}, IP: {ipGet}",
            details=f'修改黑名单: URL={urlGet}, IP={ipGet}',
            request=request
        )

        # 不再自动刷新规则，需要手动点击应用按钮
        return redirect("Blacklist")

@permission_required('manage_blacklist')
def Blacklist_create(request):
    if request.method=="GET":
        return render(request, 'waf/Blacklist_create.html')
    elif request.method=="POST":
        urlGet=request.POST.get("url")
        ipGet = request.POST.get("ip")
        obj = Blacklist.objects.create(url = urlGet, ip = ipGet)

        # 记录操作日志
        log_operation(
            user=request.user,
            operation_type='CREATE',
            module='黑名单',
            object_id=obj.id,
            object_name=f"URL: {urlGet}, IP: {ipGet}",
            details=f'创建黑名单: URL={urlGet}, IP={ipGet}',
            request=request
        )

        # 不再自动刷新规则，需要手动点击应用按钮
        return redirect("Blacklist")

@permission_required('view_logs')
def Log_index(request):
    # 处理批量删除请求
    if request.method == "POST" and request.user.is_superuser:
        # 获取选中的日志ID列表
        log_ids = request.POST.getlist("log_ids")
        if log_ids:
            # 删除选中的日志
            Log.objects.filter(id__in=log_ids).delete()
            # 记录批量删除操作
            log_operation(
                user=request.user,
                operation_type='DELETE',
                module='日志',
                object_name='Batch Delete Logs',
                details=f'Batch deleted {len(log_ids)} log entries',
                request=request
            )

        # 构建重定向URL，保持搜索条件
        from django.http import HttpResponseRedirect
        from django.urls import reverse

        # 从POST数据中获取搜索参数（这些是通过JavaScript动态添加的）
        current_page = request.POST.get('page', '1')
        ip_search = request.POST.get('ip', '')
        time_search = request.POST.get('time', '')
        action_search = request.POST.get('action', '')

        # 构建查询参数字典
        query_params = {'page': current_page}
        if ip_search:
            query_params['ip'] = ip_search
        if time_search:
            query_params['time'] = time_search
        if action_search:
            query_params['action'] = action_search

        # 重定向到日志列表页面，保持搜索条件
        return HttpResponseRedirect(reverse('log') + '?' + '&'.join([f"{k}={v}" for k, v in query_params.items()]))

    # 获取搜索参数（GET请求时）
    ip_search = request.GET.get('ip', '')
    time_search = request.GET.get('time', '')
    action_search = request.GET.get('action', '')

    # 记录查询操作（仅当有搜索条件时）
    if ip_search or time_search or action_search:
        log_operation(
            user=request.user,
            operation_type='CREATE',
            module='日志',
            object_name='Log Query',
            details=f'Queried logs (IP: {ip_search or "all"}, Time: {time_search or "all"}, Action: {action_search or "all"})',
            request=request
        )

    # 构建查询
    log_list = Log.objects.all()

    # 按IP搜索
    if ip_search:
        log_list = log_list.filter(ip__icontains=ip_search)

    # 按时间搜索
    if time_search:
        log_list = log_list.filter(time__icontains=time_search)

    # 按动作搜索（阻断事件等）
    if action_search:
        log_list = log_list.filter(action=action_search)

    # 按时间降序排序
    log_list = log_list.order_by('-time')

    # 分页
    data = split_page(log_list, request)
    data.update({
        'latest_log_list': data['page'].object_list,
        'ip_search': ip_search,
        'time_search': time_search,
        'action_search': action_search,
        'action_choices': [('BLOCK', '阻断'), ('LOG', '记录'), ('PASS', '放行')]
    })

    # 强制使用log.html模板，不再依赖template参数
    return render(request, 'waf/log.html', data)

@permission_required('export_logs')
def log_export(request):
    """导出日志为CSV格式，支持根据IP、时间、动作等条件过滤，以及导出选中的日志"""
    # 获取搜索参数
    ip_search = request.GET.get('ip', '') or request.POST.get('ip', '')
    time_search = request.GET.get('time', '') or request.POST.get('time', '')
    action_search = request.GET.get('action', '') or request.POST.get('action', '')

    # 构建查询（与Log_index相同的逻辑）
    log_list = Log.objects.all()

    # 如果有选中的日志ID，只导出选中的日志
    selected_log_ids = request.POST.getlist('log_ids')
    if selected_log_ids:
        log_list = log_list.filter(id__in=selected_log_ids)
    else:
        # 按IP搜索
        if ip_search:
            log_list = log_list.filter(ip__icontains=ip_search)

        # 按时间搜索
        if time_search:
            log_list = log_list.filter(time__icontains=time_search)

        # 按动作搜索
        if action_search:
            log_list = log_list.filter(action=action_search)

    # 按时间降序排序
    log_list = log_list.order_by('-time')

    # 先将QuerySet转换为列表，避免重复查询
    log_list = list(log_list)

    # 记录导出操作
    if selected_log_ids:
        log_operation(
            user=request.user,
            operation_type='CREATE',
            module='日志',
            object_name='Log Export',
            details=f'Exported {len(log_list)} selected log entries',
            request=request
        )
    else:
        log_operation(
            user=request.user,
            operation_type='CREATE',
            module='日志',
            object_name='Log Export',
            details=f'Exported {len(log_list)} log entries (IP: {ip_search or "all"}, Time: {time_search or "all"}, Action: {action_search or "all"})',
            request=request
        )

    # 预加载Fulllog数据，提高查询效率（批量查询）
    log_ids = [log.id for log in log_list]
    fulllog_dict = {}
    if log_ids:
        for fulllog in Fulllog.objects.filter(log_id__in=log_ids):
            fulllog_dict[fulllog.log_id] = fulllog.content

    # 创建CSV响应
    response = HttpResponse(content_type='text/csv; charset=utf-8-sig')

    # 生成文件名（包含时间戳和过滤条件）
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename_parts = ['日志导出', timestamp]
    if selected_log_ids:
        filename_parts.append(f'选中_{len(selected_log_ids)}条')
    else:
        if ip_search:
            filename_parts.append(f'IP_{ip_search}')
        if time_search:
            filename_parts.append(f'时间_{time_search}')
        if action_search:
            filename_parts.append(f'动作_{action_search}')
    filename = '_'.join(filename_parts) + '.csv'

    # 设置响应头，支持中文文件名（使用URL编码）
    encoded_filename = quote(filename.encode('utf-8'))
    response['Content-Disposition'] = f'attachment; filename*=UTF-8\'\'{encoded_filename}'

    # 创建CSV写入器
    writer = csv.writer(response)

    # 写入表头（BOM标记，确保Excel正确显示中文）
    response.write('\ufeff')
    writer.writerow(['ID', '时间', 'IP地址', 'URL', '动作', '规则ID', '触发原因', '请求详情'])

    # 写入日志数据
    for log in log_list:
        # 将动作转换为中文
        action_display = {
            'BLOCK': '阻断',
            'LOG': '记录',
            'PASS': '放行'
        }.get(log.action, log.action)

        # 获取请求详情（从预加载的字典中获取）
        request_detail = fulllog_dict.get(log.id, '')

        writer.writerow([
            log.id,
            log.time,
            log.ip,
            log.url,
            action_display,
            log.rule_id or '',
            log.reason or '',
            request_detail
        ])
    
    return response

def split_page(object_list, request, per_page=20):
    paginator = Paginator(object_list, per_page)
    # 取出当前需要展示的页码, 默认为1
    page_num = request.GET.get('page', default='1')
    # 根据页码从分页器中取出对应页的数据
    try:
        page = paginator.page(page_num)
    except PageNotAnInteger as e:
        # 不是整数返回第一页数据
        page = paginator.page('1')
        page_num = 1
    except EmptyPage as e:
        # 当参数页码大于或小于页码范围时,会触发该异常
        print('EmptyPage:{}'.format(e))
        if int(page_num) > paginator.num_pages:
            # 大于 获取最后一页数据返回
            page = paginator.page(paginator.num_pages)
        else:
            # 小于 获取第一页
            page = paginator.page(1)

    # 这部分是为了再有大量数据时，仍然保证所显示的页码数量不超过10，
    page_num = int(page_num)
    if page_num < 6:
        if paginator.num_pages <= 10:
            dis_range = range(1, paginator.num_pages + 1)
        else:
            dis_range = range(1, 11)
    elif (page_num >= 6) and (page_num <= paginator.num_pages - 5):
        dis_range = range(page_num - 5, page_num + 5)
    else:
        dis_range = range(paginator.num_pages - 9, paginator.num_pages + 1)

    data = {'page': page, 'paginator': paginator, 'dis_range': dis_range }
    return data

# 注册视图函数
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # 验证密码是否一致
        if password != confirm_password:
            return render(request, 'waf/register.html', {'error': '两次输入的密码不一致'})

        # 检查用户名是否已存在
        if CustomUser.objects.filter(username=username).exists():
            return render(request, 'waf/register.html', {'error': '用户名已存在'})

        # 创建新用户（默认为普通用户）
        user = CustomUser.objects.create_user(
            username=username,
            password=password,
            user_type=CustomUser.NORMAL
        )

        # 记录操作日志
        log_operation(
            user=user,
            operation_type='CREATE',
            module='用户管理',
            object_id=user.id,
            object_name=username,
            details='用户自行注册',
            request=request
        )

        # 自动登录新用户
        login(request, user)

        # 记录登录日志
        LoginLog.objects.create(
            user=user,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            status='SUCCESS',
            remark='用户注册后自动登录'
        )

        return redirect('index')

    return render(request, 'waf/register.html')

def custom_login(request):
    """自定义登录视图，用于记录登录日志"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            # 记录登录日志
            LoginLog.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status='SUCCESS'
            )

            return redirect('index')
        else:
            # 记录失败的登录尝试
            try:
                user_obj = CustomUser.objects.get(username=username)
                LoginLog.objects.create(
                    user=user_obj,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    status='FAILED',
                    remark='密码错误'
                )
            except CustomUser.DoesNotExist:
                pass

            return render(request, 'waf/login.html', {'error': '用户名或密码错误'})

    return render(request, 'waf/login.html')

# 权限不足错误处理视图
def permission_denied(request, exception=None):
    return render(request, 'waf/permission_denied.html', status=403)

# 用户管理功能 - 仅管理员可见
@admin_required
def user_list(request):
    """用户列表页面"""
    users = CustomUser.objects.all()
    return render(request, 'waf/user_list.html', {'users': users})

@admin_required
def user_del(request, user_id):
    """删除用户"""
    # 不允许删除最后一个管理员用户
    admin_count = CustomUser.objects.filter(user_type=CustomUser.ADMIN).count()
    user = CustomUser.objects.get(id=user_id)

    if user.user_type == CustomUser.ADMIN and admin_count <= 1:
        return redirect('user_list')

    # 记录操作日志
    log_operation(
        user=request.user,
        operation_type='DELETE',
        module='用户管理',
        object_id=user.id,
        object_name=user.username,
        details=f'删除用户: {user.username}',
        request=request
    )

    user.delete()
    return redirect('user_list')

# 个人资料页面
@login_required(login_url='login')
def profile(request):
    # 获取管理员邮箱（获取第一个管理员用户的邮箱）
    admin_email = ''
    admin_user = CustomUser.objects.filter(user_type=CustomUser.ADMIN).first()
    if admin_user and admin_user.email:
        admin_email = admin_user.email
    
    if request.method == 'POST':
        # 获取并更新用户名
        username = request.POST.get('username', '')
        if username and username != request.user.username:
            # 检查用户名是否已存在
            if CustomUser.objects.filter(username=username).exists():
                # 通过URL参数传递错误信息
                from django.urls import reverse
                return redirect(f'{reverse("profile")}?error=username_exists')
            request.user.username = username
        
        # 更新用户邮箱
        email = request.POST.get('email', '')
        request.user.email = email
        
        # 处理头像上传
        if 'avatar' in request.FILES:
            # 检查文件类型
            avatar_file = request.FILES['avatar']
            allowed_types = ['image/jpeg', 'image/png', 'image/gif']
            if avatar_file.content_type not in allowed_types:
                from django.urls import reverse
                return redirect(f'{reverse("profile")}?error=invalid_image')
            # 检查文件大小（限制为2MB）
            if avatar_file.size > 2 * 1024 * 1024:
                from django.urls import reverse
                return redirect(f'{reverse("profile")}?error=image_too_large')
            # 保存头像
            request.user.avatar = avatar_file
        
        request.user.save()
        # 通过URL参数传递成功信息
        from django.urls import reverse
        return redirect(f'{reverse("profile")}?success=profile_updated')
    
    return render(request, 'waf/profile.html', {'admin_email': admin_email, 'user': request.user})

@admin_required
def user_reset_password(request, user_id):
    """重置用户密码"""
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not new_password or new_password != confirm_password:
            return render(request, 'waf/user_reset_password.html', {
                'user_id': user_id,
                'error': '密码不能为空且两次输入必须一致'
            })

        user = CustomUser.objects.get(id=user_id)
        user.set_password(new_password)
        user.save()
        log_operation(
            user=request.user,
            operation_type='UPDATE',
            module='用户',
            object_id=user.id,
            object_name=user.username,
            details=f'Reset password for user: {user.username}',
            request=request
        )
        return redirect('user_list')

    return render(request, 'waf/user_reset_password.html', {'user_id': user_id})

@admin_required
def user_permissions(request, user_id):
    """管理用户权限"""
    user = CustomUser.objects.get(id=user_id)

    # 管理员拥有所有权限，不需要单独分配
    if user.user_type == CustomUser.ADMIN:
        return redirect('user_list')

    # 获取所有权限，按分类分组
    all_permissions = Permission.objects.all().order_by('category', 'name')
    permissions_by_category = {}
    for perm in all_permissions:
        if perm.category not in permissions_by_category:
            permissions_by_category[perm.category] = []
        permissions_by_category[perm.category].append(perm)

    # 获取用户已有的权限
    user_permission_ids = UserPermission.objects.filter(user=user).values_list('permission_id', flat=True)

    if request.method == 'POST':
        # 获取选中的权限ID列表
        selected_permissions = request.POST.getlist('permissions')
        selected_permissions = [int(p) for p in selected_permissions]

        # 权限依赖关系：管理权限包含查看权限
        permission_dependencies = {
            'manage_sites': 'view_sites',
            'manage_rules': 'view_rules',
            'manage_whitelist': 'view_whitelist',
            'manage_blacklist': 'view_blacklist',
            'delete_logs': 'view_logs',
            'export_logs': 'view_logs',
        }

        # 获取所有权限的code到id的映射
        perm_code_to_id = {}
        for perm in all_permissions:
            for perm_list in permissions_by_category.values():
                for p in perm_list:
                    perm_code_to_id[p.code] = p.id

        # 自动添加依赖权限
        final_permissions = set(selected_permissions)
        for perm_id in selected_permissions:
            # 查找该权限的code
            perm = Permission.objects.filter(id=perm_id).first()
            if perm and perm.code in permission_dependencies:
                # 添加依赖的权限
                dep_code = permission_dependencies[perm.code]
                dep_id = perm_code_to_id.get(dep_code)
                if dep_id:
                    final_permissions.add(dep_id)

        # 删除未选中的权限
        UserPermission.objects.filter(user=user).exclude(permission_id__in=final_permissions).delete()

        # 添加新选中的权限
        for perm_id in final_permissions:
            UserPermission.objects.get_or_create(
                user=user,
                permission_id=perm_id,
                defaults={'granted_by': request.user}
            )

        # 获取权限名称用于日志记录
        assigned_perms = Permission.objects.filter(id__in=final_permissions).values_list('name', flat=True)
        log_operation(
            user=request.user,
            operation_type='UPDATE',
            module='用户',
            object_id=user.id,
            object_name=user.username,
            details=f'Updated permissions for user {user.username}: {", ".join(assigned_perms)}',
            request=request
        )

        messages.success(request, f'已成功更新用户 {user.username} 的权限')
        return redirect('user_list')

    return render(request, 'waf/user_permissions.html', {
        'target_user': user,
        'permissions_by_category': permissions_by_category,
        'user_permission_ids': list(user_permission_ids)
    })

@admin_required
def init_permissions(request):
    """初始化系统权限（仅在首次使用时调用）"""
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

    created_count = 0
    for perm_data in permissions_data:
        perm, created = Permission.objects.get_or_create(
            code=perm_data['code'],
            defaults={
                'name': perm_data['name'],
                'description': perm_data['description'],
                'category': perm_data['category']
            }
        )
        if created:
            created_count += 1

    messages.success(request, f'权限初始化完成，共创建 {created_count} 个权限')
    return redirect('user_list')

@admin_required
def login_log_list(request):
    """登录日志列表"""
    # 获取搜索参数
    username_search = request.GET.get('username', '')
    ip_search = request.GET.get('ip', '')
    status_search = request.GET.get('status', '')

    # 构建查询
    logs = LoginLog.objects.all()

    # 按用户名搜索
    if username_search:
        logs = logs.filter(user__username__icontains=username_search)

    # 按IP搜索
    if ip_search:
        logs = logs.filter(ip_address__icontains=ip_search)

    # 按状态搜索
    if status_search:
        logs = logs.filter(status=status_search)

    # 按时间降序排序
    logs = logs.order_by('-login_time')

    # 分页
    data = split_page(logs, request)
    data.update({
        'latest_log_list': data['page'].object_list,
        'username_search': username_search,
        'ip_search': ip_search,
        'status_search': status_search,
        'status_choices': [('SUCCESS', '成功'), ('FAILED', '失败')]
    })

    return render(request, 'waf/login_log.html', data)

@admin_required
def operation_log_list(request):
    """操作日志列表"""
    # 获取搜索参数
    username_search = request.GET.get('username', '')
    module_search = request.GET.get('module', '')
    operation_type_search = request.GET.get('operation_type', '')

    # 构建查询
    logs = OperationLog.objects.all()

    # 按用户名搜索
    if username_search:
        logs = logs.filter(user__username__icontains=username_search)

    # 按模块搜索
    if module_search:
        logs = logs.filter(module__icontains=module_search)

    # 按操作类型搜索
    if operation_type_search:
        logs = logs.filter(operation_type=operation_type_search)

    # 按时间降序排序
    logs = logs.order_by('-operation_time')

    # 分页
    data = split_page(logs, request)
    data.update({
        'latest_log_list': data['page'].object_list,
        'username_search': username_search,
        'module_search': module_search,
        'operation_type_search': operation_type_search,
        'operation_type_choices': [('CREATE', '创建'), ('UPDATE', '修改'), ('DELETE', '删除')]
    })

    return render(request, 'waf/operation_log.html', data)
