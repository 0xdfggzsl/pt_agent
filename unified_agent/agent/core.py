import os
import sys
import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Intent:
    action: str
    url: Optional[str]
    scan_types: List[str]
    auth_info: Dict
    confidence: float
    raw_query: str
    needs_auth_info: bool = False

class IntentParser:
    SYSTEM_PROMPT = """你是一个网络安全扫描助手，负责解析用户的扫描意图。

分析用户输入，返回 JSON 格式的意图：
- action: 动作 (scan, help, history, setting, explain)
- url: 目标 URL (如果有)
- scan_types: 扫描类型列表，可选值：
  ["xss", "sql", "ssrf", "command_injection", "path_traversal", "xxe", "sensitive_info", "csrf", "open_redirect", "all"]
  空列表或["all"]表示让助手自动选择所有扫描器
- auth_info: 认证信息 {type: "none/cookie/bearer/login", login_url, username, password, cookie, token}
- confidence: 置信度 0-1
- needs_auth_info: 是否需要认证信息
- report_format: 报告格式 ["html", "json", "markdown", "pdf"]
- raw_query: 原始查询

示例：
"扫描 example.com，生成 Markdown 报告" -> {"action": "scan", "url": "https://example.com", "scan_types": ["all"], "auth_info": {"type": "none"}, "confidence": 0.95, "needs_auth_info": false, "report_format": "markdown"}
"全面检测网站" -> {"action": "scan", "url": null, "scan_types": ["all"], ...}
"只检测 XSS 和 SQL" -> {"action": "scan", "scan_types": ["xss", "sql"], ...}
"检测 SSRF" -> {"action": "scan", "scan_types": ["ssrf"], ...}
"""
    
    def __init__(self, llm):
        self.llm = llm
    
    async def parse(self, user_input: str) -> Intent:
        if not self.llm.api_key:
            return self._fallback_parse(user_input)
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": user_input}
        ]
        
        try:
            response = await self.llm.chat(messages)
            data = self._extract_json(response)
            if data:
                return Intent(
                    action=data.get('action', 'other'),
                    url=data.get('url'),
                    scan_types=data.get('scan_types', []),
                    auth_info=data.get('auth_info', {'type': 'none'}),
                    confidence=data.get('confidence', 0.5),
                    raw_query=user_input,
                    needs_auth_info=data.get('needs_auth_info', False)
                )
        except Exception:
            pass
        
        return self._fallback_parse(user_input)
    
    def _extract_json(self, text: str) -> Optional[Dict]:
        try:
            match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception:
            pass
        return None
    
    def _fallback_parse(self, user_input: str) -> Intent:
        url_match = re.search(r'https?://[^\s]+', user_input)
        url = url_match.group() if url_match else None
        
        scan_types = []
        if 'xss' in user_input.lower():
            scan_types.append('xss')
        if 'sql' in user_input.lower() or '注入' in user_input:
            scan_types.append('sql')
        if 'ssrf' in user_input.lower():
            scan_types.append('ssrf')
        if '命令' in user_input or 'command' in user_input.lower():
            scan_types.append('command_injection')
        if '路径' in user_input or 'traversal' in user_input.lower() or '遍历' in user_input:
            scan_types.append('path_traversal')
        if 'xxe' in user_input.lower():
            scan_types.append('xxe')
        if '敏感' in user_input or 'sensitive' in user_input.lower() or '信息泄露' in user_input:
            scan_types.append('sensitive_info')
        if 'csrf' in user_input.lower():
            scan_types.append('csrf')
        if '重定向' in user_input or 'redirect' in user_input.lower():
            scan_types.append('open_redirect')
        if '路径参数' in user_input or 'path_param' in user_input.lower():
            scan_types.append('path_parameter')
        if 'header' in user_input.lower() or '头部' in user_input or 'Header' in user_input:
            scan_types.append('header_injection')
        if '全面' in user_input or 'all' in user_input.lower():
            scan_types = ['all']
        if not scan_types:
            scan_types = ['xss', 'sql']
        
        report_format = 'html'
        for fmt in ['markdown', 'json', 'pdf', 'html']:
            if fmt in user_input.lower():
                report_format = fmt
                break
        
        needs_auth = False
        auth_type = 'none'
        
        if any(kw in user_input for kw in ['登录', 'login', 'cookie', 'token', '认证']):
            if 'cookie' in user_input.lower():
                auth_type = 'cookie'
            elif 'token' in user_input.lower() or 'bearer' in user_input.lower():
                auth_type = 'bearer'
            elif any(kw in user_input for kw in ['登录', 'login', '用户名', 'password']):
                auth_type = 'login'
                if not any(kw in user_input for kw in ['url', 'username', 'user', '密码', 'password']):
                    needs_auth = True
        
        if any(kw in user_input for kw in ['扫描', '检测', 'test', 'scan', 'check']):
            action = 'scan'
        elif any(kw in user_input for kw in ['历史', 'history']):
            action = 'history'
        elif any(kw in user_input for kw in ['帮助', 'help']):
            action = 'help'
        else:
            action = 'other'
        
        return Intent(
            action=action,
            url=url,
            scan_types=scan_types,
            auth_info={'type': auth_type, 'report_format': report_format},
            confidence=0.7 if scan_types else 0.6,
            raw_query=user_input,
            needs_auth_info=needs_auth
        )

class FalsePositiveFilter:
    SYSTEM_PROMPT = """你是一个专业的安全工程师，负责分析扫描结果，判断是否存在误报。

给定一个漏洞发现列表，你需要：
1. 分析每个漏洞是否可能是误报
2. 考虑以下因素：
   - 响应内容是否真的包含恶意 payload
   - 是否有 WAF 或安全设备拦截
   - 应用是否有额外的输入验证
   - 漏洞是否确实可利用

返回 JSON 格式：
{
  "verified_findings": [
    {
      "original": {...},
      "is_false_positive": false,
      "reason": "验证说明"
    }
  ],
  "summary": "总体评估"
}

如果 is_false_positive 为 true，说明这个发现是误报。
"""
    
    def __init__(self, llm):
        self.llm = llm
    
    async def filter(self, findings: List[Dict], scan_type: str) -> Dict:
        if not findings:
            return {
                'verified_findings': [],
                'summary': '无漏洞发现'
            }
        
        if not self.llm.api_key:
            return {
                'verified_findings': [{'original': f, 'is_false_positive': False, 'reason': '未启用LLM验证'} for f in findings],
                'summary': f'发现 {len(findings)} 个潜在漏洞（未经 LLM 验证）'
            }
        
        context = f"扫描类型: {scan_type.upper()}\n"
        context += f"漏洞数量: {len(findings)}\n\n"
        context += "漏洞详情：\n"
        for i, f in enumerate(findings, 1):
            context += f"\n{i}. URL: {f.get('url', 'N/A')}\n"
            context += f"   参数: {f.get('param', 'N/A')}\n"
            context += f"   Payload: {f.get('payload', 'N/A')}\n"
            context += f"   类型: {f.get('type', 'N/A')}\n"
            context += f"   严重程度: {f.get('severity', 'N/A')}\n"
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": context}
        ]
        
        try:
            response = await self.llm.chat(messages)
            data = self._extract_json(response)
            if data:
                return data
        except Exception:
            pass
        
        return {
            'verified_findings': [{'original': f, 'is_false_positive': False, 'reason': '验证超时'} for f in findings],
            'summary': f'发现 {len(findings)} 个潜在漏洞'
        }
    
    def _extract_json(self, text: str) -> Optional[Dict]:
        try:
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception:
            pass
        return None

class ReportGenerator:
    def __init__(self):
        self.formats = ['html', 'json', 'markdown']
    
    def generate(self, findings: List[Dict], format: str = 'html', **kwargs) -> str:
        if format == 'json':
            return self._generate_json(findings, **kwargs)
        elif format == 'markdown':
            return self._generate_markdown(findings, **kwargs)
        else:
            return self._generate_html(findings, **kwargs)
    
    def _generate_html(self, findings: List[Dict], **kwargs) -> str:
        target_url = kwargs.get('target_url', 'N/A')
        scan_type = kwargs.get('scan_type', 'N/A')
        scan_time = kwargs.get('scan_time', 'N/A')
        verified = kwargs.get('verified', False)
        
        high = len([f for f in findings if f.get('severity') == 'high'])
        medium = len([f for f in findings if f.get('severity') == 'medium'])
        low = len([f for f in findings if f.get('severity') == 'low'])
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>安全扫描报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .meta {{ color: #666; margin-bottom: 20px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #f8f9fa; padding: 15px 25px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 28px; font-weight: bold; color: #333; }}
        .stat-label {{ color: #666; font-size: 14px; }}
        .finding {{ border-left: 4px solid #dc3545; padding: 15px; margin: 15px 0; background: #fff5f5; border-radius: 4px; }}
        .finding.false-positive {{ border-color: #28a745; background: #f5fff5; }}
        .finding-header {{ display: flex; justify-content: space-between; margin-bottom: 10px; }}
        .url {{ font-family: monospace; color: #333; word-break: break-all; }}
        .badge {{ padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge.high {{ background: #dc3545; color: white; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        .badge.low {{ background: #17a2b8; color: white; }}
        .badge.verified {{ background: #28a745; color: white; }}
        .badge.false {{ background: #6c757d; color: white; }}
        .payload {{ background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; word-break: break-all; }}
        .reason {{ color: #666; font-style: italic; margin-top: 10px; }}
        .no-findings {{ text-align: center; padding: 40px; color: #28a745; font-size: 18px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>安全扫描报告</h1>
        <div class="meta">
            <p><strong>目标:</strong> {target_url}</p>
            <p><strong>扫描类型:</strong> {scan_type}</p>
            <p><strong>扫描时间:</strong> {scan_time}</p>
            <p><strong>LLM验证:</strong> {'已启用' if verified else '未启用'}</p>
        </div>
        <div class="summary">
            <div class="stat"><div class="stat-value">{len(findings)}</div><div class="stat-label">总漏洞</div></div>
            <div class="stat"><div class="stat-value">{high}</div><div class="stat-label">高危</div></div>
            <div class="stat"><div class="stat-value">{medium}</div><div class="stat-label">中危</div></div>
            <div class="stat"><div class="stat-value">{low}</div><div class="stat-label">低危</div></div>
        </div>
"""
        
        if not findings:
            html += '<div class="no-findings">未发现安全漏洞</div>'
        else:
            html += '<h2>漏洞详情</h2>'
            for f in findings:
                is_fp = f.get('is_false_positive', False)
                orig = f.get('original', f)
                html += f'<div class="finding {"false-positive" if is_fp else ""}">'
                html += f'<div class="finding-header">'
                html += f'<span class="url">{orig.get("url", "N/A")}</span>'
                badge_class = orig.get('severity', 'low')
                html += f'<span class="badge {badge_class}">{orig.get("severity", "N/A").upper()}</span>'
                html += '</div>'
                html += f'<div><strong>参数:</strong> {orig.get("param", "N/A")}</div>'
                html += f'<div><strong>类型:</strong> {orig.get("type", "N/A")}</div>'
                html += f'<div><strong>Payload:</strong></div>'
                html += f'<div class="payload">{orig.get("payload", "N/A")}</div>'
                if is_fp:
                    html += f'<div class="reason">⚠️ 误报标记: {f.get("reason", "LLM判定为误报")}</div>'
                else:
                    html += f'<div class="reason">✓ 已验证: {f.get("reason", "LLM验证为真实漏洞")}</div>'
                html += '</div>'
        
        html += """
    </div>
</body>
</html>"""
        return html
    
    def _generate_json(self, findings: List[Dict], **kwargs) -> str:
        verified_list = []
        for f in findings:
            orig = f.get('original', f)
            verified_list.append({
                'url': orig.get('url'),
                'param': orig.get('param'),
                'payload': orig.get('payload'),
                'type': orig.get('type'),
                'severity': orig.get('severity'),
                'is_false_positive': f.get('is_false_positive', False),
                'reason': f.get('reason', '')
            })
        
        report = {
            'metadata': {
                'target_url': kwargs.get('target_url', 'N/A'),
                'scan_type': kwargs.get('scan_type', 'N/A'),
                'scan_time': kwargs.get('scan_time', 'N/A'),
                'llm_verified': kwargs.get('verified', False)
            },
            'summary': {
                'total': len(findings),
                'high': len([f for f in findings if f.get('original', {}).get('severity') == 'high']),
                'medium': len([f for f in findings if f.get('original', {}).get('severity') == 'medium']),
                'low': len([f for f in findings if f.get('original', {}).get('severity') == 'low']),
                'verified': len([f for f in findings if not f.get('is_false_positive', False)]),
                'false_positives': len([f for f in findings if f.get('is_false_positive', False)])
            },
            'findings': verified_list
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def _generate_markdown(self, findings: List[Dict], **kwargs) -> str:
        target_url = kwargs.get('target_url', 'N/A')
        scan_type = kwargs.get('scan_type', 'N/A')
        scan_time = kwargs.get('scan_time', 'N/A')
        verified = kwargs.get('verified', False)
        
        md = f"""# 安全扫描报告

## 基本信息

| 项目 | 内容 |
|------|------|
| 目标 URL | {target_url} |
| 扫描类型 | {scan_type} |
| 扫描时间 | {scan_time} |
| LLM 验证 | {'已启用' if verified else '未启用'} |

## 漏洞统计

- **总计**: {len(findings)} 个
- **高危**: {len([f for f in findings if f.get('original', {}).get('severity') == 'high'])} 个
- **中危**: {len([f for f in findings if f.get('original', {}).get('severity') == 'medium'])} 个
- **低危**: {len([f for f in findings if f.get('original', {}).get('severity') == 'low'])} 个
- **已验证**: {len([f for f in findings if not f.get('is_false_positive', False)])} 个
- **误报**: {len([f for f in findings if f.get('is_false_positive', False)])} 个

"""
        
        if not findings:
            md += '## 结论\n\n✅ 未发现安全漏洞\n'
        else:
            md += '## 漏洞详情\n\n'
            for i, f in enumerate(findings, 1):
                orig = f.get('original', f)
                is_fp = f.get('is_false_positive', False)
                status = '⚠️ 误报' if is_fp else '✓ 真实漏洞'
                md += f"""### {i}. {orig.get('type', 'N/A').upper()} - {orig.get('severity', 'N/A').upper()}

**URL**: `{orig.get('url', 'N/A')}`

**参数**: {orig.get('param', 'N/A')}

**Payload**: 
```
{orig.get('payload', 'N/A')}
```

**状态**: {status}

**原因**: {f.get('reason', 'N/A')}

---

"""
        
        return md
    
    def save(self, content: str, output_path: str):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return output_path
    
    def generate_and_save(self, findings: List[Dict], format: str, **kwargs) -> str:
        content = self.generate(findings, format, **kwargs)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_type = kwargs.get('scan_type', 'scan').upper()
        ext = 'md' if format == 'markdown' else format
        filename = f'{scan_type.lower()}_report_{timestamp}.{ext}'
        output_dir = kwargs.get('output_dir', './reports')
        output_path = os.path.join(output_dir, filename)
        return self.save(content, output_path)

class Agent:
    def __init__(self, model_name: str = None, api_key: str = None, log_dir: str = './logs'):
        from agent.llm import LLMFactory
        from agent.memory import MemoryStore
        from agent.tools import get_registry
        
        self.memory = MemoryStore()
        self.model_name = model_name or self.memory.get_preference('default_model', 'gpt-4')
        self.llm = LLMFactory.create(self.model_name, api_key)
        
        if not self.llm.api_key:
            for env_var in ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'DASHSCOPE_API_KEY']:
                key = os.environ.get(env_var)
                if key:
                    self.llm.set_api_key(key)
                    break
        
        self.tool_registry = get_registry()
        self.parser = IntentParser(self.llm)
        self.false_positive_filter = FalsePositiveFilter(self.llm)
        self.report_generator = ReportGenerator()
        self.pending_auth = {}
        self.scan_logger = None
        
        self.system_prompt = """你是一个专业的网络安全扫描 AI 助手。

你的职责：
1. 理解用户的安全扫描需求
2. 智能选择合适的扫描工具
3. 使用 LLM 验证扫描结果，排除误报
4. 提供专业的漏洞解释和修复建议
5. 生成多种格式的报告

当用户提到需要登录的网站时，请询问：
1. 登录页面 URL
2. 用户名
3. 密码

可用工具：
- xss_scanner: XSS 跨站脚本漏洞扫描
- sql_scanner: SQL 注入漏洞扫描

认证方式：
1. Cookie 认证：用户提供登录后的 Cookie 值
2. Bearer Token：用户提供 API Token
3. 用户名密码：提供登录页面 URL 和用户名密码

报告格式：
- HTML: 生成美观的网页报告
- JSON: 生成结构化数据报告
- Markdown: 生成 Markdown 格式报告

保持专业、客观的态度，只扫描用户授权的目标。"""
    
    async def chat(self, user_input: str) -> str:
        if not user_input.strip():
            return "请输入你的需求"
        
        if user_input.lower() in ['exit', 'quit', 'q']:
            return "再见!"
        
        if user_input.lower() in ['取消', 'cancel']:
            self.pending_auth = {}
            return "已取消认证信息输入"
        
        self.memory.add_entry('user', user_input)
        
        if self.pending_auth:
            return await self._handle_auth_input(user_input)
        
        intent = await self.parser.parse(user_input)
        
        if intent.action == 'help':
            return self._get_help()
        
        if intent.action == 'history':
            return self._get_history()
        
        if intent.action == 'scan':
            if intent.needs_auth_info or intent.auth_info.get('type') == 'login':
                return await self._request_auth_info(intent)
            return await self._handle_scan(intent)
        
        return await self._general_chat(user_input)
    
    async def _request_auth_info(self, intent: Intent) -> str:
        self.pending_auth = {
            'intent': intent,
            'step': 'login_url'
        }
        
        return """请提供登录信息：

**方式1: 用户名密码登录**
  - 登录页面 URL
  - 用户名
  - 密码

**方式2: Cookie 认证**
  - 提供完整的 Cookie 字符串

**方式3: Bearer Token**
  - 提供 Token 值

输入 `取消` 终止操作"""
    
    async def _handle_auth_input(self, user_input: str) -> str:
        pending = self.pending_auth
        intent = pending.get('intent')
        step = pending.get('step', '')
        
        if step == 'login_url':
            if user_input.startswith(('http://', 'https://')):
                pending['login_url'] = user_input
                pending['step'] = 'username'
                return "请输入用户名："
            else:
                pending['auth_type'] = 'cookie'
                pending['cookie'] = user_input
                self.pending_auth = {}
                intent.auth_info = {
                    'type': 'cookie',
                    'cookie': pending['cookie']
                }
                return await self._handle_scan(intent)
        
        elif step == 'username':
            pending['username'] = user_input
            pending['step'] = 'password'
            return "请输入密码："
        
        elif step == 'password':
            pending['password'] = user_input
            self.pending_auth = {}
            
            if 'login_url' in pending:
                intent.auth_info = {
                    'type': 'login',
                    'login_url': pending.get('login_url'),
                    'username': pending.get('username'),
                    'password': pending.get('password')
                }
            else:
                intent.auth_info = {
                    'type': 'cookie',
                    'cookie': user_input
                }
            
            return await self._handle_scan(intent)
        
        return "认证信息输入取消"
    
    async def _handle_scan(self, intent: Intent) -> str:
        if not intent.url:
            return "请提供要扫描的目标 URL，例如：扫描 example.com"
        
        if not intent.url.startswith(('http://', 'https://')):
            intent.url = 'https://' + intent.url
        
        scan_types = intent.scan_types if intent.scan_types else ['xss', 'sql']
        
        if 'all' in scan_types:
            scan_types = self.tool_registry.get_all_names()
        
        from agent.logger import ScanLogger
        self.scan_logger = ScanLogger()
        self.scan_logger.log_scan_start(intent.url, scan_types)
        self.scan_logger.log_intent({
            'action': intent.action,
            'url': intent.url,
            'scan_types': scan_types,
            'auth_info': intent.auth_info
        })
        self.scan_logger.log_auth(intent.auth_info.get('type', 'none'), intent.needs_auth_info)
        
        report_format = intent.auth_info.get('report_format', 'html')
        
        results = []
        total_findings = {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        self.scan_logger.info("=" * 60)
        self.scan_logger.info("阶段1: 执行所有扫描器...")
        
        all_raw_findings = []
        scanner_results = {}
        
        for scan_type in scan_types:
            self.scan_logger.log_scanner_start(scan_type)
            
            tool = self.tool_registry.get(f'{scan_type}_scanner')
            if not tool:
                results.append(f"[!] {scan_type}扫描器不可用")
                self.scan_logger.warning(f"{scan_type}扫描器不可用")
                continue
            
            try:
                auth_info = self._parse_auth_info(intent.auth_info)
                scan_result = await tool.scan(intent.url, **auth_info)
                
                if scan_result.success:
                    findings = scan_result.data.get('findings', [])
                    scanner_results[scan_type] = findings
                    all_raw_findings.extend(findings)
                    self.scan_logger.log_scanner_result(scan_type, len(findings), len(findings), 0)
                    results.append(f"[+] {scan_type.upper()}扫描完成，发现 {len(findings)} 个潜在漏洞")
                else:
                    results.append(f"[!] {scan_type}扫描失败: {scan_result.error}")
                    self.scan_logger.log_error(scan_type, scan_result.error)
            except Exception as e:
                results.append(f"[!] {scan_type}扫描异常: {str(e)}")
                self.scan_logger.log_exception(scan_type, e)
        
        if not all_raw_findings:
            self.scan_logger.log_scan_complete(total_findings)
            response = '\n\n'.join(results) + "\n\n未发现任何漏洞"
            self.memory.add_entry('assistant', response)
            return response
        
        self.scan_logger.info("=" * 60)
        self.scan_logger.info(f"阶段2: 批量 LLM 验证...")
        self.scan_logger.info(f"待验证漏洞总数: {len(all_raw_findings)}")
        
        verified_all = await self.false_positive_filter.filter(all_raw_findings, 'all')
        verified_findings = verified_all.get('verified_findings', [])
        
        verified_count = len([f for f in verified_findings if not f.get('is_false_positive', False)])
        fp_count = len([f for f in verified_findings if f.get('is_false_positive', False)])
        
        self.scan_logger.info(f"LLM 验证完成: {verified_count} 个真实漏洞, {fp_count} 个误报")
        
        self.scan_logger.info("=" * 60)
        self.scan_logger.info("阶段3: 生成报告...")
        
        for f in verified_findings:
            if not f.get('is_false_positive', False):
                sev = f.get('original', {}).get('severity', 'low')
                if sev == 'high':
                    total_findings['high'] += 1
                elif sev == 'medium':
                    total_findings['medium'] += 1
                else:
                    total_findings['low'] += 1
        total_findings['total'] = verified_count
        
        report_path = self.report_generator.generate_and_save(
            verified_findings,
            format=report_format,
            target_url=intent.url,
            scan_type='all',
            scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            verified=True,
            output_dir='./reports'
        )
        self.scan_logger.log_report(report_path, report_format)
        
        self.scan_logger.log_scan_complete(total_findings)
        
        results_summary = [
            f"\n[+] 扫描完成!",
            f"    总潜在漏洞: {len(all_raw_findings)}",
            f"    真实漏洞: {verified_count}",
            f"    误报数量: {fp_count}",
            f"    高危: {total_findings['high']} | 中危: {total_findings['medium']} | 低危: {total_findings['low']}",
            f"    报告: {report_path}",
        ]
        
        if verified_all.get('summary'):
            results_summary.append(f"    验证摘要: {verified_all['summary']}")
        
        response = '\n\n'.join(results)
        response += '\n\n' + '\n'.join(results_summary)
        
        self._save_scan_history(intent.url, 'all', verified_findings, intent.auth_info.get('type', 'none'))
        self.memory.add_entry('assistant', response)
        return response
    
    def _parse_auth_info(self, auth_info: Dict) -> Dict:
        result = {
            'depth': 3,
            'timeout': 30,
            'cookies': None,
            'bearer_token': None,
            'login_url': None,
            'username': None,
            'password': None
        }
        
        auth_type = auth_info.get('type', 'none')
        
        if auth_type == 'cookie' and 'cookie' in auth_info:
            result['cookies'] = auth_info['cookie']
        elif auth_type == 'bearer' and 'token' in auth_info:
            result['bearer_token'] = auth_info['token']
        elif auth_type == 'login':
            result['login_url'] = auth_info.get('login_url')
            result['username'] = auth_info.get('username')
            result['password'] = auth_info.get('password')
        
        return result
    
    def _save_scan_history(self, url: str, scan_type: str, findings: List[Dict], auth_type: str):
        from agent.memory import ScanHistory
        summary = {
            'total': len(findings),
            'high': len([f for f in findings if f.get('original', {}).get('severity') == 'high']),
            'medium': len([f for f in findings if f.get('original', {}).get('severity') == 'medium']),
            'low': len([f for f in findings if f.get('original', {}).get('severity') == 'low']),
        }
        record = ScanHistory(
            url=url,
            scan_types=[scan_type],
            results=summary,
            auth_type=auth_type,
            duration=0.0,
            model_used=self.model_name
        )
        self.memory.add_scan_history(record)
    
    async def _general_chat(self, user_input: str) -> str:
        if not self.llm.api_key:
            return "未设置 API 密钥，无法进行智能对话。请设置 OPENAI_API_KEY 等环境变量。"
        
        context = self.memory.get_context()
        messages = [
            {"role": "system", "content": self.system_prompt}
        ]
        messages.extend(context)
        
        try:
            response = await self.llm.chat(messages)
            self.memory.add_entry('assistant', response)
            return response
        except Exception as e:
            return f"抱歉，发生了错误: {str(e)}"
    
    def _get_help(self) -> str:
        return """
安全扫描助手 - 帮助信息

可用命令：
1. 扫描网站（自动选择工具）：
   "扫描 example.com"
   "全面检测网站"

2. 指定扫描类型：
   "只扫 XSS"
   "只检测 SQL 注入"

3. 生成不同格式报告：
   "扫描 example.com，生成 JSON 报告"
   "扫描 example.com，生成 Markdown 报告"

4. 需要认证：
   "扫描需要登录的网站"

5. 历史记录：
   "查看扫描历史"

6. 退出：
   "exit" 或 "quit"

支持的扫描类型：
- XSS (跨站脚本)
- SQL 注入

报告格式：
- HTML: 美观网页报告（默认）
- JSON: 结构化数据
- Markdown: Markdown 格式

认证方式：
- Cookie: 提供登录后的 Cookie
- Bearer Token: 提供 API Token
- 用户名密码: 提供登录页面 URL 和凭据

环境变量：
- OPENAI_API_KEY
- ANTHROPIC_API_KEY
- DASHSCOPE_API_KEY
"""
    
    def _get_history(self) -> str:
        history = self.memory.get_scan_history(10)
        if not history:
            return "暂无扫描历史"
        
        lines = ["\n扫描历史："]
        for i, record in enumerate(history, 1):
            lines.append(f"{i}. {record.url}")
            lines.append(f"   时间: {record.timestamp.strftime('%Y-%m-%d %H:%M')}")
            lines.append(f"   类型: {', '.join(record.scan_types)}")
            lines.append(f"   结果: 高危{record.results.get('high', 0)} 中危{record.results.get('medium', 0)} 低危{record.results.get('low', 0)}")
            lines.append("")
        
        return '\n'.join(lines)
