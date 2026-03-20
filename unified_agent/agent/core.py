import os
import sys
import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

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
- scan_types: 扫描类型列表 ["xss", "sql"]，空列表表示让助手自动选择
- auth_info: 认证信息 {type: "none/cookie/bearer/login", login_url, username, password, cookie, token}
- confidence: 置信度 0-1
- needs_auth_info: 是否需要认证信息（如果用户提到登录但未提供详细信息，则为 true）
- raw_query: 原始查询

认证类型：
- none: 不需要认证
- cookie: 使用 Cookie 认证
- bearer: 使用 Bearer Token 认证
- login: 使用用户名密码登录（需要 login_url, username, password）

示例：
"扫描 example.com" -> {"action": "scan", "url": "https://example.com", "scan_types": [], "auth_info": {"type": "none"}, "confidence": 0.95, "needs_auth_info": false}
"扫描需要登录的网站" -> {"action": "scan", "url": null, "scan_types": [], "auth_info": {"type": "login"}, "confidence": 0.8, "needs_auth_info": true}
"用 Cookie 扫描" -> {"action": "scan", "url": null, "scan_types": [], "auth_info": {"type": "cookie"}, "confidence": 0.8, "needs_auth_info": false}
"只扫 XSS" -> {"action": "scan", "url": null, "scan_types": ["xss"], "auth_info": {"type": "none"}, "confidence": 0.8, "needs_auth_info": false}
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
            auth_info={'type': auth_type},
            confidence=0.7 if scan_types else 0.6,
            raw_query=user_input,
            needs_auth_info=needs_auth
        )

class Agent:
    def __init__(self, model_name: str = None, api_key: str = None):
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
        self.pending_auth: Dict = {}
        
        self.system_prompt = """你是一个专业的网络安全扫描 AI 助手。

你的职责：
1. 理解用户的安全扫描需求
2. 智能选择合适的扫描工具
3. 提供专业的漏洞解释和修复建议
4. 生成清晰的扫描报告

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
        
        self.memory.add_entry('assistant', """请提供登录信息：

方式1: 用户名密码登录
  - 登录页面 URL
  - 用户名
  - 密码

方式2: Cookie 认证
  - 请提供完整的 Cookie 字符串

方式3: Bearer Token
  - 请提供 Token 值

输入 "取消" 终止操作""")
        
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
        
        results = []
        for scan_type in scan_types:
            print(f"\n[*] 开始 {scan_type.upper()} 扫描: {intent.url}")
            
            tool = self.tool_registry.get(f'{scan_type}_scanner')
            if not tool:
                results.append(f"[!] {scan_type} 扫描器不可用")
                continue
            
            try:
                auth_info = self._parse_auth_info(intent.auth_info)
                result = await tool.scan(intent.url, **auth_info)
                
                if result.success:
                    summary = result.data['summary']
                    results.append(
                        f"[+] {scan_type.upper()} 扫描完成!\n"
                        f"    漏洞总数: {summary['total']}\n"
                        f"    高危: {summary['high']} | 中危: {summary['medium']} | 低危: {summary['low']}\n"
                        f"    报告: {result.report_path}"
                    )
                    
                    self._save_scan_history(intent.url, scan_type, result.data, intent.auth_info.get('type', 'none'))
                else:
                    results.append(f"[!] {scan_type} 扫描失败: {result.error}")
            except Exception as e:
                results.append(f"[!] {scan_type} 扫描异常: {str(e)}")
        
        response = '\n\n'.join(results)
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
    
    def _save_scan_history(self, url: str, scan_type: str, data: Dict, auth_type: str):
        from agent.memory import ScanHistory
        summary = data.get('summary', {})
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

3. 需要认证：
   "扫描需要登录的网站"
   （会提示输入登录信息）

4. 历史记录：
   "查看扫描历史"

5. 退出：
   "exit" 或 "quit"

支持的扫描类型：
- XSS (跨站脚本)
- SQL 注入

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
