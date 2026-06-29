'''一些常用的小工具，包括日志
'''

import config as C
import sys

# 预先编译颜色代码，避免每次调用都重建
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[1;32m"
COLOR_RED = "\033[1;31m"

# 缓存DEBUG_LEVEL值，避免每次都访问模块属性
DEBUG_LEVEL_CACHE = C.DEBUG_LEVEL

'''
一个日志输出工具，可以指定级别。
0:正常白色输出 1:debug级别绿色 2:warning级别红色
设置全局选项DEBUG_LEVEL，可以决定日志显示的类别
'''
def log(message, level=0):
    # 快速检查日志级别，不符合直接返回
    if level < DEBUG_LEVEL_CACHE:
        return
    
    # 避免不必要的字符串格式化和异常处理
    try:
        if level == 0:
            # 普通日志，直接输出
            print(str(message))
        elif level == 1:
            # 调试日志，绿色
            sys.stdout.write(f"{COLOR_GREEN}[+] {message}{COLOR_RESET}\n")
            sys.stdout.flush()  # 立即刷新，减少缓冲
        elif level == 2:
            # 警告日志，红色
            sys.stderr.write(f"{COLOR_RED}[!] {message}{COLOR_RESET}\n")
            sys.stderr.flush()  # 立即刷新错误输出
    except Exception:
        # 确保日志函数本身不会抛异常导致主程序崩溃
        try:
            print(f"日志输出错误: {str(message)}")
        except:
            pass
