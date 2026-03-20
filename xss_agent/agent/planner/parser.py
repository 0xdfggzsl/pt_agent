import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class Intent:
    action: str
    entities: Dict
    confidence: float
    raw_query: str

class IntentParser:
    SYSTEM_PROMPT = """你是一个安全测试助手，负责解析用户意图。

分析用户的输入，返回 JSON 格式的意图：
- action: 主要动作 (scan, crawl, report, explain, help, history, setting, other)
- entities: 提取的实体信息 (url, depth, auth_info 等)
- confidence: 置信度 (0-1)

可用工具：
- xss_scanner: 扫描网站 XSS 漏洞
- web_crawler: 爬取网页内容

认证类型：
- cookie: 使用 Cookie 认证
- bearer: 使用 Bearer Token 认证  
- login: 使用用户名密码登录

用户输入示例：
"扫描 example.com" -> {"action": "scan", "entities": {"url": "https://example.com"}, "confidence": 0.95}
"帮我扫描需要登录的网站" -> {"action": "scan", "entities": {"url": null, "auth_type": "login"}, "confidence": 0.8}
"查看扫描历史" -> {"action": "history", "entities": {}, "confidence": 0.95}
"切换到 GPT 模型" -> {"action": "setting", "entities": {"model": "gpt-4"}, "confidence": 0.9}
"""
    
    def __init__(self, llm):
        self.llm = llm
    
    async def parse(self, user_input: str) -> Intent:
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": user_input}
        ]
        
        try:
            response = await self.llm.chat(messages)
            
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return Intent(
                    action=data.get('action', 'other'),
                    entities=data.get('entities', {}),
                    confidence=data.get('confidence', 0.5),
                    raw_query=user_input
                )
        except Exception:
            pass
        
        return self._fallback_parse(user_input)
    
    def _fallback_parse(self, user_input: str) -> Intent:
        url_match = re.search(r'https?://[^\s]+', user_input)
        url = url_match.group() if url_match else None
        
        if any(kw in user_input for kw in ['扫描', 'scan', '检测']):
            auth_type = 'none'
            if '登录' in user_input or 'login' in user_input.lower():
                auth_type = 'login'
            return Intent('scan', {'url': url, 'auth_type': auth_type}, 0.8, user_input)
        
        if any(kw in user_input for kw in ['历史', 'history']):
            return Intent('history', {}, 0.9, user_input)
        
        if any(kw in user_input for kw in ['帮助', 'help']):
            return Intent('help', {}, 0.9, user_input)
        
        if any(kw in user_input for kw in ['设置', 'model', '模型']):
            return Intent('setting', {}, 0.7, user_input)
        
        return Intent('other', {}, 0.5, user_input)
