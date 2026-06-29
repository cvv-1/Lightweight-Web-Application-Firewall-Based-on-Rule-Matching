#!/bin/bash
# WAF项目启动脚本 (Ubuntu)

# 切换到脚本所在目录
cd "$(dirname "$0")"

echo "===================================="
echo "WAF 项目启动脚本 (Ubuntu)"
echo "===================================="

# 检查Python版本
echo "检查Python版本..."
python3 --version
if [ $? -ne 0 ]; then
    echo "错误: Python3 未安装"
    exit 1
fi

# 检查依赖
echo "检查依赖..."
required_packages=("django" "pytz")
for pkg in "${required_packages[@]}"; do
    python3 -c "import $pkg" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "警告: 缺少依赖 $pkg"
        echo "建议运行: pip3 install -r requirements.txt"
    fi
done

# 启动Django前端
echo "启动Django前端服务..."
cd src_frontend
nohup python3 manage.py runserver 0.0.0.0:8000 > django.log 2>&1 &
DJANGO_PID=$!
cd ..
echo "Django前端已启动 (PID: $DJANGO_PID)"
echo "Web管理界面: http://$(hostname -I | awk '{print $1}'):8000"

# 等待Django启动
sleep 3

# 启动WAF核心
echo "启动WAF核心服务..."
cd src
nohup python3 main.py > waf_core.log 2>&1 &
WAF_PID=$!
cd ..
echo "WAF核心已启动 (PID: $WAF_PID)"

echo "===================================="
echo "WAF服务启动完成!"
echo "===================================="
echo "服务状态:"
echo "- Django前端: 运行中 (PID: $DJANGO_PID)"
echo "- WAF核心: 运行中 (PID: $WAF_PID)"
echo ""
echo "查看日志:"
echo "- Django日志: tail -f src_frontend/django.log"
echo "- WAF核心日志: tail -f src/waf_core.log"
echo ""
echo "停止服务:"
echo "kill $DJANGO_PID $WAF_PID"