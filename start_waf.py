#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import time
import platform
import threading

def print_separator(title=""):
    """打印分隔线"""
    if title:
        print(f"\n{'=' * 60}")
        print(f"  {title}")
        print(f"{'=' * 60}\n")
    else:
        print(f"\n{'=' * 60}\n")

def run_service(name, python_exe, cwd, script_name, args=None):
    """在后台运行服务"""
    try:
        print(f"[*] 正在启动 {name}...")

        # 创建日志文件
        log_file = os.path.join(cwd, f"{script_name.replace('.py', '')}.log")

        # 构建命令
        cmd = [python_exe, script_name]
        if args:
            cmd.extend(args)

        # 启动进程，不创建新窗口，输出到日志文件
        with open(log_file, "w", encoding="utf-8") as log:
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )

        print(f"[完成] {name} 已启动 (PID: {process.pid})")
        print(f"[信息] 日志文件: {log_file}")

        return process
    except Exception as e:
        print(f"[错误] 启动 {name} 失败: {e}")
        return None

def main():
    """启动WAF完整服务（Django + WAF核心）"""
    print()
    print_separator("WAF 一键启动脚本")

    # 获取项目根目录
    project_root = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(project_root, "src")
    src_frontend_dir = os.path.join(project_root, "src_frontend")
    venv_dir = os.path.join(project_root, ".venv")

    # 检查目录是否存在
    if not os.path.exists(src_dir):
        print("[错误] src 目录不存在")
        return 1

    if not os.path.exists(src_frontend_dir):
        print("[错误] src_frontend 目录不存在")
        return 1

    if not os.path.exists(venv_dir):
        print("[错误] 虚拟环境不存在")
        return 1

    # 获取虚拟环境中的Python
    if platform.system() == "Windows":
        python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        python_exe = os.path.join(venv_dir, "bin", "python")

    if not os.path.exists(python_exe):
        print("[错误] 虚拟环境Python不存在")
        return 1

    try:
        processes = []

        # 启动Django前端
        print("[信息] 正在启动 Django 前端服务...")
        django_process = run_service(
            "Django前端",
            python_exe,
            src_frontend_dir,
            "manage.py",
            ["runserver", "0.0.0.0:8000"]
        )
        if django_process:
            processes.append(("Django前端", django_process))
        else:
            return 1

        # 等待Django启动
        print("[*] 等待Django启动...")
        time.sleep(3)

        # 启动WAF核心
        print("\n[信息] 正在启动 WAF 核心服务...")
        waf_process = run_service(
            "WAF核心",
            python_exe,
            src_dir,
            "main.py"
        )
        if waf_process:
            processes.append(("WAF核心", waf_process))
        else:
            return 1

        # 打印启动完成信息
        print_separator("WAF 完整服务启动完成!")

        print("服务状态:")
        for name, process in processes:
            status = "运行中" if process.poll() is None else "已停止"
            print(f"  ✓ {name}: {status} (PID: {process.pid})")

        print()
        print("访问地址:")
        print("  - Web管理界面: http://127.0.0.1:8000")

        print()
        print("查看日志:")
        print(f"  - Django日志: {os.path.join(src_frontend_dir, 'manage.log')}")
        print(f"  - WAF核心日志: {os.path.join(src_dir, 'main.log')}")

        print()
        print("查看运行的进程:")
        if platform.system() == "Windows":
            print("  - tasklist | findstr python")
        else:
            print("  - ps aux | grep python")

        print()
        print("停止服务:")
        print("  - 按 Ctrl+C 停止所有服务")
        print()

        # 等待用户中断
        while True:
            time.sleep(1)
            # 检查进程是否还在运行
            for name, process in processes:
                if process.poll() is not None:
                    print(f"[警告] {name} 已停止")

    except KeyboardInterrupt:
        print()
        print_separator("正在停止所有服务...")

        # 停止所有进程
        for name, process in processes:
            try:
                print(f"[*] 正在停止 {name}...")
                process.terminate()
                process.wait(timeout=5)
                print(f"[完成] {name} 已停止")
            except subprocess.TimeoutExpired:
                print(f"[警告] {name} 未响应，强制杀死...")
                process.kill()
            except Exception as e:
                print(f"[错误] 停止 {name} 失败: {e}")

        print()
        print("[信息] 所有服务已停止")
        return 0

    except Exception as e:
        print()
        print(f"[错误] 启动失败: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
