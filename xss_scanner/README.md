# XSS Scanner Agent

一个功能强大的 Web 应用 XSS 漏洞扫描工具，支持多种认证方式，适用于渗透测试和安全评估。

## 功能特性

- **动态爬取**：自动爬取网站页面，识别所有输入点
- **XSS 检测**：支持反射型、DOM 型、存储型 XSS 检测
- **多种认证**：Cookie、 Bearer Token、登录表单认证
- **自动登录**：支持表单登录，自动处理 CSRF Token
- **HTML 报告**：生成美观的可视化漏洞报告
- **异步并发**：基于 asyncio 的异步架构，扫描效率高
- **丰富 Payload**：内置 21+ 种 XSS 检测 payload

## 安装

### 环境要求

- Python 3.8+
- pip

### 安装依赖

```bash
cd xss_scanner
pip install -r requirements.txt
```

## 快速开始

### 基本用法

```bash
python main.py -u https://example.com
```

### 扫描并生成报告

```bash
python main.py -u https://example.com -o ./reports -d 3
```

## 认证方式

### 1. Cookie 认证

适用于已登录状态的目标网站：

```bash
python main.py -u https://example.com \
  --cookie "PHPSESSID=abc123; user_token=xyz789"
```

### 2. Bearer Token 认证

适用于 API Token 认证的系统：

```bash
python main.py -u https://example.com \
  --bearer "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 3. 登录表单认证

适用于需要用户名密码登录的系统：

```bash
python main.py -u https://example.com \
  --login-url https://example.com/login \
  --username admin \
  --password your_password
```

### 4. 自定义表单字段

如果登录表单的字段名不是默认的 `username` 和 `password`：

```bash
python main.py -u https://example.com \
  --login-url https://example.com/login \
  --username admin \
  --password your_password \
  --username-field email \
  --password-field passwd
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-u, --url` | 目标网站 URL | 必需 |
| `-o, --output` | 报告输出目录 | `./reports` |
| `-d, --depth` | 爬取深度 | `3` |
| `-t, --timeout` | 请求超时秒数 | `30` |
| `--cookie` | Cookie 认证 | - |
| `--bearer` | Bearer Token 认证 | - |
| `--login-url` | 登录页面 URL | - |
| `--username` | 登录用户名 | - |
| `--password` | 登录密码 | - |
| `--username-field` | 用户名表单字段名 | `username` |
| `--password-field` | 密码表单字段名 | `password` |

## 使用示例

### 示例 1：扫描公开网站

```bash
python main.py -u https://example.com -o ./reports
```

### 示例 2：扫描需要登录的系统

```bash
python main.py -u https://internal.example.com/dashboard \
  --login-url https://internal.example.com/login \
  --username admin \
  --password P@ssw0rd \
  -o ./reports
```

### 示例 3：使用已有 Cookie 扫描

```bash
# 从浏览器开发者工具获取 Cookie
python main.py -u https://example.com \
  --cookie "session=abc123; security=high" \
  -o ./reports
```

### 示例 4：深层扫描

```bash
python main.py -u https://example.com -d 5 -t 60 -o ./reports
```

## 输出报告

扫描完成后，会在指定目录生成 HTML 格式的报告，包含：

- **概览统计**：漏洞总数、高危/中危/低危数量
- **漏洞列表**：每个漏洞的详细信息
  - 漏洞 URL
  - 危险参数
  - 漏洞类型
  - Payload
  - 危害等级
- **修复建议**：针对每个漏洞的修复方案

## 项目结构

```
xss_scanner/
├── main.py              # 命令行入口
├── requirements.txt     # 依赖列表
├── scanner/
│   ├── crawler.py       # 网页爬取模块
│   ├── detector.py      # XSS 检测模块
│   ├── payload.py       # Payload 管理
│   └── reporter.py      # 报告生成
├── core/
│   └── engine.py        # 扫描引擎
├── utils/
│   └── helpers.py       # 工具函数
└── templates/
    └── report.html      # 报告模板
```

## 免责声明

本工具仅用于授权的安全测试和渗透测试。使用本工具扫描未授权的网站是违法行为。使用者需自行承担使用本工具的风险和责任。

## 许可证

MIT License
