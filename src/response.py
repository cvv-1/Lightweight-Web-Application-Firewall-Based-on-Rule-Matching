import socket

import config as C
from utils import log
from log import do_log


def _extract_client_ip(client_conn, client_req):
    """
    优先从请求头中获取真实客户端 IP（例如经过反向代理时），
    如果没有相关头部，则回退到与 WAF 建立 TCP 连接的一端 IP。
    """
    try:
        # 只解析首部区
        headers_part = client_req.split('\\r\\n\\r\\n', 1)[0]
        lines = headers_part.split('\\r\\n')[1:]  # 跳过请求行
        headers = {}
        for line in lines:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        # 1) 优先 X-Forwarded-For（可能有多个IP，逗号分隔，取第一个）
        xff = headers.get('x-forwarded-for')
        if xff:
            return xff.split(',')[0].strip()

        # 2) 其次 X-Real-IP
        real_ip = headers.get('x-real-ip')
        if real_ip:
            return real_ip.strip()
    except Exception:
        pass

    # 默认：直接使用连接对端 IP
    return client_conn.getpeername()[0]


'''
根据动作代码决定处理方法（支持按站点配置转发）
action参数可以是字符串（旧格式）或元组(action, rule_id, reason)（新格式）
'''
def do_response(client_conn,proxy_req,action,site=None):
    # 兼容旧格式和新格式
    if isinstance(action, tuple):
        action_code, rule_id, reason = action
    else:
        action_code = action
        rule_id = None
        reason = None
    
    if action_code == C.ACTION_PASS:
        do_response_pass(client_conn,proxy_req,site, rule_id, reason)
    elif action_code == C.ACTION_BLOCK:
        do_response_block(client_conn,proxy_req, rule_id, reason)
    elif action_code == C.ACTION_LOG:
        log("log it",1)
        do_response_log(client_conn,proxy_req,site, rule_id, reason)
    else:
        log("action not supported!",2)

'''
辅助函数：转发请求到后端服务器并获取响应
'''
def _forward_request(client_req, site=None):
    """转发请求到后端服务器，返回响应数据"""
    proxy_host = (site.get("proxy_host") if site else C.PROXY_HOST)
    proxy_port = (site.get("proxy_port") if site else C.PROXY_PORT)
    real_host = (site.get("real_host") if site else C.REAL_HOST)
    real_port = (site.get("real_port") if site else C.REAL_PORT)

    proxy_addr = str(proxy_host)+':'+str(proxy_port)
    real_addr = str(real_host)+':'+str(real_port)

    # 优化字符串替换：只替换必要的部分，减少不必要的操作
    proxy_req = client_req.replace(proxy_addr, real_addr)
    if 'keep-alive' in proxy_req.lower():
        proxy_req = proxy_req.replace('keep-alive', 'close')
    if 'gzip' in proxy_req.lower():
        proxy_req = proxy_req.replace('gzip', '')

    proxy_client_socket = socket.socket()
    proxy_client_socket.settimeout(30)  # 设置超时，避免长时间阻塞
    try:
        proxy_client_socket.connect((real_host, real_port))
        proxy_client_socket.sendall(proxy_req.encode())
    except socket.timeout:
        log("连接后端服务器超时", 2)
        return None, None, None
    except Exception as e:
        log(f"连接后端服务器失败: {str(e)}", 2)
        return None, None, None

    target_resp = b''
    BUF_SIZE = 8192  # 增大缓冲区，减少recv调用次数
    try:
        while True:
            try:
                buf = proxy_client_socket.recv(BUF_SIZE)
            except socket.timeout:
                break

            if not buf:
                break
            target_resp += buf
            
            # 如果接收的数据小于缓冲区，说明已经接收完毕
            if len(buf) < BUF_SIZE:
                break
    except Exception as e:
        log(f"接收后端响应错误: {str(e)}", 2)
    finally:
        try:
            proxy_client_socket.close()
        except:
            pass
    
    # 优化字符串替换：只在需要时替换
    proxy_resp = target_resp
    if b'Content-Encoding: gzip\r\n' in proxy_resp:
        proxy_resp = proxy_resp.replace(b'Content-Encoding: gzip\r\n', b'')
    if real_addr.encode() in proxy_resp:
        proxy_resp = proxy_resp.replace(real_addr.encode(), proxy_addr.encode())
    
    return proxy_resp, proxy_addr, real_addr

'''
动作是PASS，放行
'''
def do_response_pass(client_conn,client_req,site=None,rule_id=None,reason=None):

    ip = _extract_client_ip(client_conn, client_req)

    proxy_resp, _, _ = _forward_request(client_req, site)
    if proxy_resp is None:
        client_conn.close()
        return

    client_conn.sendall(proxy_resp)
    client_conn.close()

    # 记录放行的请求（异步，不阻塞）
    do_log(client_req,ip,C.ACTION_PASS,full=True,rule_id=rule_id,reason=reason)

'''
动作是LOG
'''
def do_response_log(client_conn,client_req,site=None,rule_id=None,reason=None):

    ip = _extract_client_ip(client_conn, client_req)

    proxy_resp, _, _ = _forward_request(client_req, site)
    if proxy_resp is None:
        client_conn.close()
        return

    client_conn.sendall(proxy_resp)
    client_conn.close()
    
    # 记录日志（异步，不阻塞）
    do_log(client_req,ip,C.ACTION_LOG,full=True,rule_id=rule_id,reason=reason)

'''
动作是BLOCK，拦截
这里直接返回一个写死的简洁拦截页面，不再依赖 blocked_page.html。
'''
def do_response_block(client_conn,client_req,rule_id=None,reason=None):
    import datetime
    
    ip = _extract_client_ip(client_conn, client_req)
    
    # 写死一个简单的拦截页面（无滚动条，内容较少，保证一屏显示）
    html_content = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>访问被拦截 - 简单WAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }
        .container {
            background: rgba(255, 255, 255, 0.96);
            border-radius: 18px;
            box-shadow: 0 16px 40px rgba(0,0,0,0.25);
            max-width: 480px;
            width: 100%;
            padding: 24px 26px;
            text-align: center;
        }
        .icon {
            width: 60px;
            height: 60px;
            margin: 0 auto 10px;
            border-radius: 50%;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-size: 32px;
            box-shadow: 0 10px 25px rgba(238,90,36,0.45);
        }
        h1 {
            font-size: 22px;
            color: #2c3e50;
            margin-bottom: 4px;
        }
        p.subtitle {
            font-size: 13px;
            color: #7f8c8d;
            margin-bottom: 10px;
        }
        p.tip {
            font-size: 12px;
            color: #95a5a6;
        }
        .actions {
            margin-top: 16px;
            display: flex;
            justify-content: center;
            gap: 10px;
        }
        .btn {
            border: none;
            border-radius: 18px;
            padding: 8px 20px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all .2s ease;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
        }
        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 18px rgba(102,126,234,0.5);
        }
        .btn-secondary {
            background: #ecf0f1;
            color: #2c3e50;
        }
        .btn-secondary:hover {
            background: #d5dbdb;
        }
        .footer {
            margin-top: 10px;
            font-size: 11px;
            color: #bdc3c7;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>访问请求已被拦截</h1>
        <p class="subtitle">您的请求触发了 Web 应用防火墙（WAF）的安全规则。</p>
        <p class="tip">如果您认为这是误拦截，请联系网站管理员。</p>
        <div class="actions">
            <button class="btn btn-primary" onclick="history.back()">返回上一页</button>
            <button class="btn btn-secondary" onclick="location.reload()">刷新页面</button>
        </div>
        <div class="footer">简单WAF · 保护您的网站安全</div>
    </div>
</body>
</html>'''
    
    # 构建HTTP响应头
    current_time = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    response_headers = f'''HTTP/1.1 403 Forbidden\r
Server: WAF/1.0\r
Date: {current_time}\r
Content-Type: text/html; charset=UTF-8\r
Content-Length: {len(html_content.encode('utf-8'))}\r
Connection: close\r
X-Frame-Options: DENY\r
X-Content-Type-Options: nosniff\r
\r
'''
    
    block_message = (response_headers + html_content).encode("utf-8")
    
    client_conn.sendall(block_message)
    client_conn.close()
    
    log("waf blocked",1)
    do_log(client_req,ip,C.ACTION_BLOCK,full=True,rule_id=rule_id,reason=reason)
