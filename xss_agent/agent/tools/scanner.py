import sys
import os
import asyncio
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'xss_scanner'))

from agent.tools.base import Tool, ToolResult, register_tool
from agent.memory import ScanRecord

class XSSScannerTool(Tool):
    name = "xss_scanner"
    description = "扫描网站的 XSS 漏洞，接受 URL 和认证信息，返回发现的漏洞列表"
    parameters = [
        {"name": "url", "type": "string", "required": True, "description": "目标网站 URL"},
        {"name": "depth", "type": "integer", "required": False, "description": "爬取深度，默认 3"},
        {"name": "timeout", "type": "integer", "required": False, "description": "超时秒数，默认 30"},
        {"name": "auth_type", "type": "string", "required": False, "description": "认证类型: none/cookie/bearer/login"},
        {"name": "auth_info", "type": "object", "required": False, "description": "认证信息"}
    ]
    
    async def execute(self, **kwargs) -> ToolResult:
        try:
            url = kwargs.get('url')
            depth = kwargs.get('depth', 3)
            timeout = kwargs.get('timeout', 30)
            auth_type = kwargs.get('auth_type', 'none')
            auth_info = kwargs.get('auth_info', {})
            
            from core.engine import ScanEngine
            
            engine = ScanEngine(
                target_url=url,
                depth=depth,
                timeout=timeout,
                cookies=auth_info.get('cookie'),
                bearer_token=auth_info.get('bearer'),
                login_url=auth_info.get('login_url'),
                username=auth_info.get('username'),
                password=auth_info.get('password')
            )
            
            result = await engine.run()
            summary = engine.get_summary()
            report_path = engine.generate_report()
            
            return ToolResult(
                success=True,
                data={
                    'summary': summary,
                    'findings': result['findings'],
                    'duration': result['duration'],
                    'report_path': report_path
                },
                tool_name=self.name
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data=None,
                error=str(e),
                tool_name=self.name
            )

class WebCrawlerTool(Tool):
    name = "web_crawler"
    description = "爬取网页内容，提取链接和表单信息"
    parameters = [
        {"name": "url", "type": "string", "required": True, "description": "目标 URL"},
        {"name": "depth", "type": "integer", "required": False, "description": "爬取深度"}
    ]
    
    async def execute(self, **kwargs) -> ToolResult:
        try:
            url = kwargs.get('url')
            depth = kwargs.get('depth', 1)
            
            from scanner.crawler import WebCrawler
            
            crawler = WebCrawler(url, depth)
            await crawler.init_client()
            
            result = await crawler.crawl(url, current_depth=0)
            
            await crawler.close()
            
            return ToolResult(
                success=True,
                data={
                    'forms': result['forms'],
                    'links': result['links'][:20]
                },
                tool_name=self.name
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data=None,
                error=str(e),
                tool_name=self.name
            )

def register_tools():
    register_tool(XSSScannerTool())
    register_tool(WebCrawlerTool())
