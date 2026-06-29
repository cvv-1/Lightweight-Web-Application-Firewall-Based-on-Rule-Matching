import filter
import importlib

# 初始化规则（返回分组后的规则列表）
try:
    rules_result = filter.init_filter()
    if isinstance(rules_result, tuple) and len(rules_result) == 3:
        compiled_rules, block_rules, other_rules = rules_result
        # 确保 compiled_rules 是一个列表
        if not isinstance(compiled_rules, list):
            compiled_rules = list(compiled_rules) if compiled_rules else []
    else:
        # 兼容旧格式
        compiled_rules = rules_result if isinstance(rules_result, list) else []
        block_rules = []
        other_rules = []
except Exception as e:
    import sys
    sys.stderr.write(f"初始化规则失败: {str(e)}\n")
    compiled_rules = []
    block_rules = []
    other_rules = []

blacklists = filter.init_blacklist()
whitelists = filter.init_whitelist()

def reload_rules():
    """
    重新加载所有规则、黑名单和白名单
    优化版本：避免不必要的模块重新导入，只重新读取数据库
    """
    global compiled_rules, blacklists, whitelists, block_rules, other_rules
    # 注意：不再重新导入filter模块，因为filter模块的代码通常不会在运行时改变
    # 如果确实需要重新加载filter模块，可以通过控制命令触发
    # importlib.reload(filter)  # 注释掉，避免不必要的重新导入
    
    # 重新初始化规则（从数据库读取）
    try:
        rules_result = filter.init_filter()
        if isinstance(rules_result, tuple) and len(rules_result) == 3:
            compiled_rules, block_rules, other_rules = rules_result
            # 确保 compiled_rules 是一个列表
            if not isinstance(compiled_rules, list):
                compiled_rules = list(compiled_rules) if compiled_rules else []
        else:
            # 兼容旧格式
            compiled_rules = rules_result if isinstance(rules_result, list) else []
            block_rules = []
            other_rules = []
    except Exception as e:
        import sys
        sys.stderr.write(f"重新加载规则失败: {str(e)}\n")
        import traceback
        sys.stderr.write(f"详细错误: {traceback.format_exc()}\n")
        # 如果重新加载失败，抛出异常，让调用者决定如何处理
        raise
    
    # 重新加载黑名单和白名单
    try:
        blacklists = filter.init_blacklist()
        whitelists = filter.init_whitelist()
    except Exception as e:
        import sys
        sys.stderr.write(f"重新加载黑名单/白名单失败: {str(e)}\n")
        import traceback
        sys.stderr.write(f"详细错误: {traceback.format_exc()}\n")
        # 如果重新加载失败，抛出异常
        raise
    
    return ((compiled_rules, block_rules, other_rules), blacklists, whitelists)
