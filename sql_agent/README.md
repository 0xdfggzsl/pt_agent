# SQL Scanner Agent

一个功能强大的 Web 应用 SQL 注入漏洞扫描工具，支持多种认证方式，适用于渗透测试和安全评估。

## 功能特性

- **多种注入检测**：支持错误型注入、UNION 注入、布尔盲注、时间盲注、堆叠查询
- **智能爬取**：自动爬取网站页面，识别所有可注入参数
- **多种认证**：Cookie、Bearer Token、登录表单认证
- **HTML 报告**：生成美观的可视化漏洞报告
- **丰富 Payload**：内置 50+ 种 SQL 注入 payload
- **异步并发**：基于 asyncio 的异步架构，扫描效率高

## 安装

```bash
cd sql_agent
pip install -r requirements.txt
```

## 快速开始

```bash
python main.py -u https://example.com
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

## SQL 注入类型

| 类型 | 说明 | 危害 |
|------|------|------|
| Error-based | 错误信息注入 | 高 |
| Union-based | UNION 注入 | 高 |
| Boolean-based Blind | 布尔盲注 | 中 |
| Time-based Blind | 时间盲注 | 高 |
| Stacked Queries | 堆叠查询 | 高 |
| Encoded | 编码绕过 | 中 |

## 使用示例

```bash
# 基本扫描
python main.py -u https://example.com

# 扫描需要登录的系统
python main.py -u https://example.com \
  --login-url https://example.com/login \
  --username admin \
  --password secret

# 使用 Cookie
python main.py -u https://example.com \
  --cookie "PHPSESSID=abc123"
```

## 输出报告

扫描完成后生成 HTML 报告，包含：
- 漏洞统计概览
- 漏洞详情（URL、参数、类型、Payload）
- 修复建议

## 项目结构

```
sql_agent/
├── main.py              # 命令行入口
├── requirements.txt     # 依赖
├── scanner/
│   ├── crawler.py       # 网页爬取
│   ├── detector.py      # SQL 检测
│   └── reporter.py      # 报告生成
├── core/
│   └── engine.py        # 扫描引擎
├── config/
│   └── models.json      # 模型配置
├── templates/
│   └── sql_report.html  # 报告模板
└── data/                # 数据存储
```

## 免责声明

本工具仅用于授权的安全测试。使用本工具扫描未授权的网站是违法行为。

## 许可证

MIT License
