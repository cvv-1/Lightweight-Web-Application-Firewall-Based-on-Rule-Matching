@echo off
chcp 65001 >nul
title WAF一键启动
setlocal enabledelayedexpansion

echo ============================================================
echo WAF 一键启动脚本
echo ============================================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到Python，请先安装Python 3.6或更高版本
    pause
    exit /b 1
)

echo [信息] 正在启动WAF服务...
echo.

REM 启动Python脚本
python start_waf.py

if errorlevel 1 (
    echo.
    echo [错误] 启动失败
    pause
    exit /b 1
)

pause


















