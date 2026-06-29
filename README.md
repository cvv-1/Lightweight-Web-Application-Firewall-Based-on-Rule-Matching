# Lightweight-Web-Application-Firewall-Based-on-Rule-Matching
 - 基于规则匹配的轻量级Web应用防火墙

一个基于 **反向代理** 架构的轻量级 Web 应用防火墙（WAF）演示项目，使用纯 Python Socket 编程实现请求拦截与过滤引擎，并搭配 Django 管理后台提供可视化配置能力。

---

## 目录

- [项目介绍](#项目介绍)
- [核心特性](#核心特性)
- [系统架构](#系统架构)
- [攻击检测能力](#攻击检测能力)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [使用说明](#使用说明)
- [技术栈](#技术栈)

---

## 项目介绍

本项目实现了一个完整的 Web 应用防火墙原型系统，通过**反向代理模式**部署在用户与后端服务器之间，对所有 HTTP 请求进行安全检测与过滤。核心检测引擎基于正则表达式和语义分析实现，覆盖 OWASP Top 10 中的多种攻击类型。

适用于以下场景：
- 网络安全课程教学与实验
- WAF 原理学习与研究
- 小型 Web 应用的安全防护
- 安全产品原型开发参考

---

## 核心特性

### 代理引擎
- **反向代理模式**：透明地代理客户端请求到后端服务器
- **多站点支持**：支持同时代理多个不同的后端服务
- **连接池管理**：高性能的 TCP 连接处理

### 检测能力
- **多层检测**：支持原始请求检测 + URL 解码检测 + HTML 实体解码检测
- **快速预检机制**：通过可疑字符快速预检，正常请求低延迟放行
- **静态资源加速**：对 JS/CSS/图片等静态资源自动放行
- **分块编码还原**：防止 Chunked Encoding 绕过攻击

### 管理功能
- **可视化规则管理**：通过 Django 后台添加、编辑、删除规则
- **黑白名单机制**：支持按 URL 和 IP 组合的黑白名单
- **规则热加载**：通过控制通道实时更新规则，无需重启服务
- **请求日志**：记录所有被拦截或放行的请求详情
- **多站点管理**：动态添加和配置需要保护的站点

### 内置防御
- 内置 XXE 检测规则（即使数据库中未配置也能拦截）
- 内置反序列化攻击检测规则（PHP/Java）
- 文件上传安全检查（危险扩展名 + 恶意代码检测）

---

## 系统架构

```
┌────────────────────┐         ┌────────────────────────────────────┐         ┌─────────────────┐
│     客户端         │ HTTP请求 │        WAF 代理核心模块 (src/)      │合法流量转发│   后端业务服务器 │
│  (浏览器 / API端)  │ ──────▶ │  ├─ 请求拦截、流量过滤              │ ──────▶ │   (真实业务服务) │
└────────────────────┘         │  ├─ 自定义规则匹配 & 防御动作执行   │         └─────────────────┘
                               │  └─ 网络连接管控（监听端口 12345） │
                               └───────────┬────────────────────────┘
                                           │ 配置/日志交互指令
                                           ▼
                         ┌────────────────────────────────────┐
                         │    Django 可视化管理后台           │
                         │      (src_frontend/)              │
                         │  ├─ 安全防护规则管理               │
                         │  ├─ IP黑白名单配置                │
                         │  ├─ 攻击日志查询与导出            │
                         │  └─ 防护站点集群管理              │
                         └────────────────────────────────────┘
```

**通信流程：**
1. 客户端请求 → WAF 代理端口（默认 8081）
2. WAF 对请求进行解码、规则匹配、黑白名单检查
3. 匹配到 BLOCK 规则 → 返回 403 拦截页面
4. 匹配到 PASS 规则 → 转发请求到后端服务器（默认 8082）
5. 请求详情记录到 SQLite 数据库
6. Django 管理后台读取数据库用于展示和配置

---

## 攻击检测能力

| 攻击类型 | 检测方法 | 说明 |
|---------|---------|------|
| **SQL 注入** | 正则匹配 | UNION、OR/AND、堆叠查询、注释符绕过等 |
| **XSS** | 正则匹配 + 编码检测 | Script 标签、事件处理器、编码绕过 |
| **命令注入 (RCE)** | 模式检测 | Shell 命令、系统函数、危险协议 |
| **XXE** | 正则匹配 | DOCTYPE + ENTITY 定义、外部实体 |
| **反序列化攻击** | 正则匹配 | PHP serialize、Java ObjectInputStream |
| **SSRF** | 关键词检测 | file://、gopher://、dict:// 等伪协议 |
| **路径遍历** | 关键词检测 | ../、..\\、编码绕过 |
| **文件上传攻击** | 扩展名 + 内容检测 | 危险扩展名、PHP/JSP/ASP 代码标记 |
| **编码绕过** | 双层解码检测 | URL 编码、HTML 实体编码、双重编码 |
| **Chunked Bypass** | 请求重建 | Transfer-Encoding: chunked 还原 |

---

## 快速开始

### 环境要求

- Python 3.6+
- Django 3.1+
- Windows / Linux / macOS

### 安装与启动

```bash
# 1. 克隆项目
git clone https://github.com/cvv-1/Simple-WAF-Demo.git
cd Simple-WAF-Demo.git

# 2. 创建虚拟环境（推荐）
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 初始化 Django 数据库
cd src_frontend
python manage.py migrate
cd ..

# 5. 一键启动（WAF 核心 + Django 后台）
python start_waf.py
```

启动后：
- WAF 代理监听端口：**8081**
- 后端服务器地址：**127.0.0.1:8082**
- 管理后台地址：**http://127.0.0.1:8000/admin**
- 控制连接端口：**12345**

### 手动启动（分开启动）

```bash
# 终端 1：启动 Django 管理后台
cd src_frontend
python manage.py runserver 0.0.0.0:8000

# 终端 2：启动 WAF 核心
cd src
python main.py
```

---

## 项目结构

```
Simple-WAF-Demo/
├── src/                          # WAF 核心引擎
│   ├── main.py                   # 代理主入口、多线程连接管理
│   ├── filter.py                 # 攻击检测引擎（核心过滤逻辑）
│   ├── response.py               # 响应处理（放行/拦截/日志）
│   ├── config.py                 # 配置信息（端口、数据库路径等）
│   ├── common.py                 # 通用工具（规则重载等）
│   ├── dbutils.py                # 数据库操作工具
│   ├── log.py                    # 日志记录模块
│   └── utils.py                  # 辅助函数
├── src_frontend/                 # Django 管理后台
│   ├── manage.py                 # Django 管理入口
│   ├── waf/                      # WAF 应用
│   │   ├── views.py              # 视图函数
│   │   ├── models.py             # 数据模型
│   │   ├── urls.py               # URL 路由
│   │   ├── admin.py              # 后台管理注册
│   │   ├── apps.py               # 应用配置
│   │   ├── templates/            # 前端模板
│   │   └── static/               # 静态资源
│   └── wafmanager/               # Django 项目配置
├── start_waf.py                  # 一键启动脚本
├── start_waf.sh                  # Linux 启动脚本
├── start_waf.bat                 # Windows 启动脚本
├── requirements.txt              # Python 依赖
```

---

## 使用说明

### 规则管理

1. 访问 `http://127.0.0.1:8000/admin` 登录 Django 后台
2. 在 Rules 模块中添加安全规则：
   - **Content**：正则表达式（如 `(union.*select)`）
   - **Action**：`BLOCK`（拦截）、`PASS`（放行）、`LOG`（仅记录）
   - **Description**：规则描述
3. 保存后通过控制命令热加载（参见下方）

### 热加载规则

```bash
# 使用 Python socket 发送更新命令
python -c "
import socket
s = socket.socket()
s.connect(('127.0.0.1', 12345))
s.sendall(b'<-UPDATE->')
print(s.recv(4096).decode())
s.close()
"
```

### 黑白名单配置

- **黑名单**：配置后匹配到的请求直接被拦截
- **白名单**：配置后匹配到的请求直接放行（跳过规则检测）
- 支持 `*` 通配符匹配所有 URL 或 IP

### 站点管理

通过 Django 后台的 Sites 模块，可以动态添加/启用/禁用需要保护的站点，支持为不同站点配置不同的代理端口和后端地址。

---

## 技术栈

| 组件 | 技术 |
|------|------|
| 代理引擎 | Python Socket（原生） |
| 管理后台 | Django 3.1 |
| 数据库 | SQLite |
| 前端 UI | Bootstrap + jQuery + Layui |
| 图表库 | Chart.js + Morris.js |
| 并发处理 | 多线程 (threading) |

---

## 许可证

本项目仅供学习和研究使用。


