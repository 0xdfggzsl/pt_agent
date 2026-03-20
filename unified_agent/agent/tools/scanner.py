from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

class ScanType:
    XSS = "xss"
    SQL = "sql"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SENSITIVE_INFO = "sensitive_info"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"

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

class SSRFDetectorTool(ScannerTool):
    name = "ssrf_scanner"
    description = "服务端请求伪造漏洞扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import SSRFDetector
            
            detector = SSRFDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='ssrf',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='ssrf', data=None, error=str(e))

class CommandInjectionTool(ScannerTool):
    name = "command_injection_scanner"
    description = "命令注入漏洞扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import CommandInjectionDetector
            
            detector = CommandInjectionDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='command_injection',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='command_injection', data=None, error=str(e))

class PathTraversalTool(ScannerTool):
    name = "path_traversal_scanner"
    description = "路径遍历漏洞扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import PathTraversalDetector
            
            detector = PathTraversalDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='path_traversal',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='path_traversal', data=None, error=str(e))

class XXETool(ScannerTool):
    name = "xxe_scanner"
    description = "XXE 漏洞扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import XXEDetector
            
            detector = XXEDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='xxe',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='xxe', data=None, error=str(e))

class SensitiveInfoTool(ScannerTool):
    name = "sensitive_info_scanner"
    description = "敏感信息泄露扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import SensitiveInfoDetector
            
            detector = SensitiveInfoDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='sensitive_info',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='sensitive_info', data=None, error=str(e))

class CSRFDetectorTool(ScannerTool):
    name = "csrf_scanner"
    description = "CSRF 漏洞扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import CSRFDetector
            
            detector = CSRFDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='csrf',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='csrf', data=None, error=str(e))

class OpenRedirectTool(ScannerTool):
    name = "open_redirect_scanner"
    description = "开放重定向漏洞扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import OpenRedirectDetector
            
            detector = OpenRedirectDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='open_redirect',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='open_redirect', data=None, error=str(e))

class PathParameterTool(ScannerTool):
    name = "path_parameter_scanner"
    description = "URL路径参数注入扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import PathParameterDetector
            
            detector = PathParameterDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='path_parameter',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='path_parameter', data=None, error=str(e))

class HeaderInjectionTool(ScannerTool):
    name = "header_injection_scanner"
    description = "HTTP Header注入扫描器"
    
    async def scan(self, url: str, **kwargs) -> ScanResult:
        try:
            from unified_agent.scanner.detectors.security import HeaderInjectionDetector
            
            detector = HeaderInjectionDetector(timeout=kwargs.get('timeout', 30))
            result = await detector.scan(url)
            
            return ScanResult(
                success=True,
                scan_type='header_injection',
                data={'summary': detector.get_summary(), 'findings': result['findings']},
                report_path=''
            )
        except Exception as e:
            return ScanResult(success=False, scan_type='header_injection', data=None, error=str(e))

ALL_SCANNERS = {
    'xss': XSSTool(),
    'sql': SQLTool(),
    'ssrf': SSRFDetectorTool(),
    'command_injection': CommandInjectionTool(),
    'path_traversal': PathTraversalTool(),
    'xxe': XXETool(),
    'sensitive_info': SensitiveInfoTool(),
    'csrf': CSRFDetectorTool(),
    'open_redirect': OpenRedirectTool(),
    'path_parameter': PathParameterTool(),
    'header_injection': HeaderInjectionTool(),
}

ALL_VULN_TYPES = list(ALL_SCANNERS.keys())

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ScannerTool] = {}
        self.register_default_tools()
    
    def register_default_tools(self):
        for name, tool in ALL_SCANNERS.items():
            self._tools[name] = tool
    
    def get(self, name: str) -> ScannerTool:
        return self._tools.get(name)
    
    def list_tools(self) -> List[Dict]:
        return [t.get_info() for t in self._tools.values()]
    
    def get_all_names(self) -> List[str]:
        return list(self._tools.keys())

_global_registry = ToolRegistry()

def get_registry() -> ToolRegistry:
    return _global_registry
