# XSS Scanner Agent - 技术设计规格

## 1. 项目概述

- **项目名称**: XSS Scanner Agent
- **项目类型**: 动态Web安全扫描工具
- **核心功能**: 自动爬取网站，检测网页输入点，发送XSS payload测试，生成可视化HTML报告
- **目标用户**: 安全工程师、Web开发者、渗透测试人员

## 2. 技术架构

### 2.1 技术栈

- **语言**: Python 3.x
- **HTTP客户端**: httpx (支持异步)
- **HTML解析**: BeautifulSoup4
- **报告生成**: Jinja2
- **并发处理**: asyncio

### 2.2 核心模块

```
xss_scanner/
├── scanner/
│   ├── __init__.py
│   ├── crawler.py       # 网页爬取模块
│   ├── detector.py      # XSS检测模块
│   ├── payload.py       # Payload管理
│   └── reporter.py      # 报告生成
├── core/
│   ├── __init__.py
│   └── engine.py        # 扫描引擎
├── utils/
│   ├── __init__.py
│   └── helpers.py
└── main.py              # 入口文件
```

## 3. 功能需求

### 3.1 核心功能

1. **网页爬取**
   - 支持递归爬取网站页面
   - 识别HTML表单和输入点
   - 处理cookies和session
   - 设置爬取深度限制

2. **XSS检测**
   - 自动识别输入点（GET/POST参数、表单输入）
   - 内置多种XSS payload库
   - 检测反射型XSS
   - 检测存储型XSS（需要二次访问）
   - DOM型XSS基础检测

3. **报告生成**
   - 生成HTML格式可视化报告
   - 显示漏洞详情、位置、危害等级
   - 包含修复建议

### 3.2 Payload分类

| 类型 | 描述 |
|------|------|
| 反射型 | `<script>alert(1)</script>` |
| 存储型 | 检测数据持久化 |
| DOM型 | `<img src=x onerror=alert(1)>` |
| 编码绕过 | HTML编码、URL编码 |

### 3.3 报告结构

- 概览统计（扫描时间、发现漏洞数、风险等级）
- 漏洞列表（类型、位置、URL、参数、危害等级）
- 修复建议

## 4. 输入输出

### 4.1 命令行接口

```bash
python main.py -u <target_url> [-o <output_dir>] [--depth <depth>]
```

### 4.2 参数说明

| 参数 | 说明 |
|------|------|
| `-u, --url` | 目标网站URL（必需） |
| `-o, --output` | 报告输出目录（默认: ./reports） |
| `-d, --depth` | 爬取深度（默认: 3） |
| `-t, --timeout` | 请求超时秒数（默认: 30） |

### 4.3 输出

- `report_<timestamp>.html` - HTML可视化报告

## 5. 风险等级定义

| 等级 | 说明 |
|------|------|
| 高危 | 可执行任意JS代码，获取敏感信息 |
| 中危 | 可触发弹窗，可能用于钓鱼 |
| 低危 | 可能存在潜在风险，需手动确认 |

## 6. 验收标准

- [ ] 支持指定URL的爬取和扫描
- [ ] 能识别HTML表单和输入参数
- [ ] 内置不少于10种XSS payload
- [ ] 生成HTML格式漏洞报告
- [ ] 支持命令行参数配置
- [ ] 单元测试覆盖核心模块
