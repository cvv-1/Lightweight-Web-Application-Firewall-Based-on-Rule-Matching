from .models import UserPermission

def user_permissions(request):
    """
    上下文处理器：为模板提供用户权限信息
    """
    if request.user.is_authenticated:
        # 获取用户的所有权限代码
        user_perms = UserPermission.objects.filter(
            user=request.user
        ).values_list('permission__code', flat=True)

        return {
            'user_permissions': set(user_perms),
            'has_permission': lambda perm_code: perm_code in user_perms,
        }

    return {
        'user_permissions': set(),
        'has_permission': lambda perm_code: False,
    }
