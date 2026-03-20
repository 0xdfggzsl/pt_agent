import asyncio
import json
from typing import Dict, List, Any
from .parser import IntentParser, Intent

class TaskStep:
    def __init__(self, step_type: str, tool: str, params: Dict, description: str):
        self.step_type = step_type
        self.tool = tool
        self.params = params
        self.description = description
        self.result: Any = None
        self.error: str = None

class TaskPlanner:
    SYSTEM_PROMPT = """你是一个任务规划专家，负责将复杂任务分解为可执行的步骤。

根据意图和可用工具，规划执行步骤：
- tool_calls: 需要调用的工具及参数
- response: 初始响应消息

可用工具：
- xss_scanner: 扫描网站 XSS 漏洞，参数：url, depth, timeout, auth_type, auth_info
- web_crawler: 爬取网页，参数：url, depth

返回 JSON 格式：
{
  "tool_calls": [
    {"tool": "xss_scanner", "params": {"url": "https://example.com"}, "description": "扫描 example.com"}
  ],
  "response": "好的，我来帮你扫描 https://example.com 的 XSS 漏洞..."
}
"""
    
    def __init__(self, llm, tool_registry):
        self.llm = llm
        self.tool_registry = tool_registry
        self.parser = IntentParser(llm)
    
    async def plan(self, user_input: str) -> tuple[Intent, List[TaskStep], str]:
        intent = await self.parser.parse(user_input)
        
        if intent.action in ['help', 'history', 'setting']:
            return intent, [], ""
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"用户意图: {json.dumps(intent.__dict__, ensure_ascii=False)}\n可用工具: {json.dumps(self.tool_registry.list_tools(), ensure_ascii=False)}"}
        ]
        
        try:
            response = await self.llm.chat(messages)
            
            json_match = None
            import re
            json_match = re.search(r'\{[^{}]*"tool_calls"[^{}]*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                steps = []
                for call in data.get('tool_calls', []):
                    step = TaskStep(
                        step_type='tool',
                        tool=call.get('tool', ''),
                        params=call.get('params', {}),
                        description=call.get('description', '')
                    )
                    steps.append(step)
                return intent, steps, data.get('response', response)
        except Exception:
            pass
        
        if intent.action == 'scan' and intent.entities.get('url'):
            steps = [TaskStep(
                step_type='tool',
                tool='xss_scanner',
                params={'url': intent.entities['url'], 'depth': 3},
                description=f"扫描 {intent.entities['url']} 的 XSS 漏洞"
            )]
            return intent, steps, f"好的，我来扫描 {intent.entities['url']} 的 XSS 漏洞..."
        
        return intent, [], "抱歉，我无法理解你的请求。请告诉我你想做什么？"
    
    async def execute_steps(self, steps: List[TaskStep]) -> List[TaskStep]:
        for step in steps:
            if step.step_type == 'tool':
                tool = self.tool_registry.get(step.tool)
                if tool:
                    try:
                        result = await tool.execute(**step.params)
                        step.result = result
                    except Exception as e:
                        step.error = str(e)
        return steps
    
    async def execute_with_fallback(self, steps: List[TaskStep], user_input: str) -> List[TaskStep]:
        executed_steps = await self.execute_steps(steps)
        
        for step in executed_steps:
            if step.error:
                print(f"[!] 工具执行失败: {step.error}")
                print(f"[*] 尝试使用 LLM 直接分析...")
                
                messages = [
                    {"role": "system", "content": "你是一个安全专家。用户遇到了扫描问题，请提供帮助。"},
                    {"role": "user", "content": f"用户请求: {user_input}\n错误: {step.error}"}
                ]
                try:
                    response = await self.llm.chat(messages)
                    step.result = response
                    step.error = None
                except Exception as e:
                    step.error = str(e)
        
        return executed_steps
