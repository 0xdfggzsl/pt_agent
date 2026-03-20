from abc import ABC, abstractmethod
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

class ScanType(Enum):
    XSS = "xss"
    SQL = "sql"
    BOTH = "both"

@dataclass
class ScanResult:
    success: bool
    scan_type: str
    data: Any
    error: str = ""
    report_path: str = ""

class ScannerTool(ABC):
    name: str = ""
    description: str = ""
    
    @abstractmethod
    async def scan(self, url: str, **kwargs) -> ScanResult:
        pass
    
    def get_info(self) -> Dict:
        return {
            'name': self.name,
            'description': self.description
        }

class XSSTool(ScannerTool):
    name = "xss_scanner"
    description = "XSS 跨站脚本漏洞扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from xss_scanner.core.engine import ScanEngine
            
            engine = ScanEngine(
                target_url=url,
                depth=kwargs.get('depth', 3),
                timeout=kwargs.get('timeout', 30),
                cookies=kwargs.get('cookies'),
                bearer_token=kwargs.get('bearer_token'),
                login_url=kwargs.get('login_url'),
                username=kwargs.get('username'),
                password=kwargs.get('password')
            )
            
            result = await engine.run()
            summary = engine.get_summary()
            report_path = engine.generate_report()
            
            return ScanResult(
                success=True,
                scan_type='xss',
                data={'summary': summary, 'findings': result['findings']},
                report_path=report_path
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='xss', data=None, error=str(e))

class SQLTool(ScannerTool):
    name = "sql_scanner"
    description = "SQL 注入漏洞扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from sql_agent.core.engine import ScanEngine
            
            engine = ScanEngine(
                target_url=url,
                depth=kwargs.get('depth', 3),
                timeout=kwargs.get('timeout', 30),
                cookies=kwargs.get('cookies'),
                bearer_token=kwargs.get('bearer_token'),
                login_url=kwargs.get('login_url'),
                username=kwargs.get('username'),
                password=kwargs.get('password')
            )
            
            result = await engine.run()
            summary = engine.get_summary()
            report_path = engine.generate_report()
            
            return ScanResult(
                success=True,
                scan_type='sql',
                data={'summary': summary, 'findings': result['findings']},
                report_path=report_path
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='sql', data=None, error=str(e))

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ScannerTool] = {}
        self.register_default_tools()
    
    def register_default_tools(self):
        self._tools['xss_scanner'] = XSSTool()
        self._tools['sql_scanner'] = SQLTool()
    
    def get(self, name: str) -> ScannerTool:
        return self._tools.get(name)
    
    def list_tools(self) -> List[Dict]:
        return [t.get_info() for t in self._tools.values()]
    
    def get_all_names(self) -> List[str]:
        return list(self._tools.keys())

_global_registry = ToolRegistry()

def get_registry() -> ToolRegistry:
    return _global_registry
