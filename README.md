# Security Scanner Agent Platform

安全扫描 Agent 平台，支持多种 Web 漏洞检测能力。

## 项目结构

```
security-scanner/
├── README.md                    # 本文件 - 项目索引
├── xss_agent/               # XSS 检测 Agent (AI版)
├── sql_agent/                 # SQL 注入检测 Agent (AI版)
├── unified_agent/             # 统一安全扫描 Agent (推荐)
├── xss_scanner/               # XSS 检测工具 (基础版)
├── reports/                   # 扫描报告输出
└── tests/                    # 测试文件
```

## Agent 列表

### 1. 统一 Agent (推荐)

**路径**: `unified_agent/`

通过自然语言交互，自动选择合适的扫描工具，支持 9 种漏洞检测。

**启动**:
```bash
cd unified_agent
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."
python main.py
```

**支持漏洞**:
| 漏洞类型 | 命令关键词 | 严重程度 |
|----------|------------|----------|
| XSS | `xss` | 高/中 |
| SQL 注入 | `sql`, `注入` | 高 |
| SSRF | `ssrf` | 高 |
| 命令注入 | `命令`, `command` | 高 |
| 路径遍历 | `路径`, `traversal` | 中 |
| XXE | `xxe` | 高 |
| 敏感信息泄露 | `敏感`, `sensitive` | 中 |
| CSRF | `csrf` | 中 |
| 开放重定向 | `重定向`, `redirect` | 低 |

---

### 2. XSS Agent (AI版)

**路径**: `xss_agent/`

专注于 XSS 漏洞检测的 AI Agent，支持自然语言交互。

**启动**:
```bash
cd xss_agent
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."
python main.py
```

**特点**:
- 21+ 内置 Payload
- 支持 Cookie / Token / 登录表单认证
- 自然语言交互
- HTML 报告

---

### 3. SQL Agent (AI版)

**路径**: `sql_agent/`

专注于 SQL 注入漏洞检测的 AI Agent，支持自然语言交互。

**启动**:
```bash
cd sql_agent
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."
python main.py
```

**支持的注入类型**:
| 类型 | 说明 |
|------|------|
| Error-based | 错误信息注入 |
| UNION-based | UNION 联合查询 |
| Boolean Blind | 布尔盲注 |
| Time-based Blind | 时间盲注 |
| Stacked Queries | 堆叠查询 |

---

### 4. XSS Scanner (基础版)

**路径**: `xss_scanner/`

命令行版本的 XSS 检测工具，无 AI 功能。

**启动**:
```bash
cd xss_scanner
pip install -r requirements.txt
python main.py -u https://example.com
```

---

## 快速开始

### 方式一：使用统一 Agent (推荐)

一次交互，扫描所有漏洞：

```bash
cd unified_agent
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."
python main.py

# 在交互界面输入:
> 全面检测 https://example.com
```

### 方式二：使用独立 Agent

针对特定漏洞进行扫描：

```bash
# XSS 检测
cd xss_agent
pip install -r requirements.txt
python main.py

# SQL 注入检测
cd sql_agent
pip install -r requirements.txt
python main.py
```

---

## Agent 对比

| 特性 | 统一 Agent | XSS Agent | SQL Agent | XSS Scanner |
|------|------------|-----------|-----------|-------------|
| 交互方式 | 自然语言 | 自然语言 | 自然语言 | 命令行 |
| 漏洞检测 | 9 种 | XSS | SQL | XSS |
| LLM 验证 | 自动 | 自动 | 自动 | 无 |
| 报告格式 | 3 种 | HTML | HTML | HTML |
| 适用场景 | 全面扫描 | 专注 XSS | 专注 SQL | 快速 CLI |

---

## 环境要求

- Python 3.8+
- LLM API 密钥 (OpenAI / Anthropic / 阿里云)

---

## 许可证

MIT License
