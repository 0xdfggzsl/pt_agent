import asyncio
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from agent.llm import LLMFactory
from agent.memory import MemoryStore
from agent.tools import register_tools, get_registry
from agent.planner import TaskPlanner, Intent

class Agent:
    def __init__(self, model_name: str = None, api_key: str = None):
        self.memory = MemoryStore()
        self.model_name = model_name or self.memory.get_preference('default_model', 'gpt-4')
        
        self.llm = LLMFactory.create(self.model_name, api_key)
        if not self.llm.api_key:
            env_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('ANTHROPIC_API_KEY') or os.environ.get('DASHSCOPE_API_KEY')
            if env_key:
                self.llm.set_api_key(env_key)
        
        register_tools()
        self.tool_registry = get_registry()
        self.planner = TaskPlanner(self.llm, self.tool_registry)
        
        self.system_prompt = """你是一个专业、友好的 XSS 安全测试 AI 助手。

你的职责：
1. 理解和执行用户的安全扫描需求
2. 通过自然语言与用户交流
3. 调用工具完成扫描任务
4. 解释漏洞原因和修复方法

能力：
- 扫描网站 XSS 漏洞
- 生成专业的安全报告
- 解释安全漏洞的技术细节

请始终保持专业、客观的态度。"""
    
    async def chat(self, user_input: str) -> str:
        if not self.llm.api_key:
            return "错误：未设置 API 密钥。请设置 OPENAI_API_KEY、ANTHROPIC_API_KEY 或 DASHSCOPE_API_KEY 环境变量。"
        
        self.memory.add_entry('user', user_input)
        
        context = self.memory.get_session_context()
        
        messages = [
            {"role": "system", "content": self.system_prompt}
        ]
        messages.extend(context)
        
        intent, steps, response = await self.planner.plan(user_input)
        
        if intent.action == 'help':
            return self._get_help()
        elif intent.action == 'history':
            return await self._get_history()
        elif intent.action == 'setting':
            return await self._handle_setting(intent)
        elif intent.action == 'scan':
            if response:
                await self._stream(response)
            if steps:
                await self._stream(f"\n[*] 执行任务: {steps[0].description}")
                executed_steps = await self.planner.execute_with_fallback(steps, user_input)
                return await self._format_results(executed_steps)
            return response
        elif steps:
            if response:
                await self._stream(response)
            executed_steps = await self.planner.execute_with_fallback(steps, user_input)
            return await self._format_results(executed_steps)
        
        messages.append({"role": "user", "content": user_input})
        llm_response = await self.llm.chat(messages)
        
        self.memory.add_entry('assistant', llm_response)
        
        return llm_response
    
    async def _stream(self, text: str):
        print(text, end='', flush=True)
    
    async def _format_results(self, steps) -> str:
        results = []
        for step in steps:
            if step.result:
                if hasattr(step.result, 'success'):
                    if step.result.success:
                        results.append(f"[+] {step.tool} 执行成功")
                        if isinstance(step.result.data, dict):
                            if 'summary' in step.result.data:
                                s = step.result.data['summary']
                                results.append(f"    漏洞总数: {s['total']}, 高危: {s['high']}, 中危: {s['medium']}, 低危: {s['low']}")
                            if 'report_path' in step.result.data:
                                results.append(f"    报告: {step.result.data['report_path']}")
                    else:
                        results.append(f"[!] {step.tool} 执行失败: {step.result.error}")
                elif isinstance(step.result, str):
                    results.append(step.result)
        return '\n'.join(results) if results else "任务完成"
    
    def _get_help(self) -> str:
        return """
XSS Scanner AI Agent - 帮助信息

可用命令：
1. 扫描网站：帮我扫描 example.com
2. 查看历史：查看我的扫描历史
3. 切换模型：切换到 GPT-4
4. 获取帮助：help

认证选项：
- Cookie: 提供 session cookie
- Bearer Token: 提供 API token  
- 登录表单: 提供用户名密码

环境变量：
- OPENAI_API_KEY: OpenAI API 密钥
- ANTHROPIC_API_KEY: Anthropic API 密钥
- DASHSCOPE_API_KEY: 阿里云 API 密钥
"""
    
    async def _get_history(self) -> str:
        history = self.memory.get_scan_history(5)
        if not history:
            return "暂无扫描历史"
        
        lines = ["\n扫描历史："]
        for i, record in enumerate(history, 1):
            lines.append(f"{i}. {record.url}")
            lines.append(f"   时间: {record.timestamp.strftime('%Y-%m-%d %H:%M')}")
            lines.append(f"   漏洞: {len(record.findings)} 个")
            lines.append(f"   耗时: {record.duration:.1f}秒")
            lines.append(f"   模型: {record.model_used}")
            lines.append("")
        
        return '\n'.join(lines)
    
    async def _handle_setting(self, intent: Intent) -> str:
        if 'model' in intent.entities:
            new_model = intent.entities['model']
            self.memory.set_preference('default_model', new_model)
            self.model_name = new_model
            return f"已切换到 {new_model} 模型"
        return "设置命令不完整"

async def main():
    print("=" * 50)
    print("XSS Scanner AI Agent")
    print("=" * 50)
    print("\n输入你的问题或命令，输入 'exit' 退出\n")
    
    api_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('ANTHROPIC_API_KEY')
    agent = Agent(api_key=api_key)
    
    if not agent.llm.api_key:
        print("[!] 警告：未设置 API 密钥，功能可能受限")
        print("[*] 请设置 OPENAI_API_KEY 或 ANTHROPIC_API_KEY 环境变量\n")
    
    while True:
        try:
            user_input = input("\n> ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ['exit', 'quit', 'q']:
                print("再见!")
                break
            
            print()
            response = await agent.chat(user_input)
            print(response)
            
        except KeyboardInterrupt:
            print("\n\n再见!")
            break
        except Exception as e:
            print(f"\n错误: {e}")

if __name__ == '__main__':
    asyncio.run(main())
