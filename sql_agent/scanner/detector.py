from typing import List, Dict, Optional
import asyncio
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
from .payloads.sql_payloads import SQLPayload

class SQLDetector:
    ERROR_PATTERNS = [
        r"SQL syntax",
        r"MySQL",
        r"mysql_fetch",
        r"mysqli_",
        r"PostgreSQL",
        r"pg_exec",
        r"SQLite",
        r"sqlite3",
        r"Microsoft SQL Server",
        r"mssql_query",
        r"ODBC",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Incorrect syntax",
        r"Unclosed quotation",
        r"SQLServer",
        r"SQL error",
        r"Syntax error",
        r"Warning.*mysql",
        r"MySQL server version",
        r"valid MySQL result",
        r"mysql_num_rows",
        r"mysql_fetch_array",
        r"SQLSTATE[0-9]{5}",
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.payload_manager = SQLPayload()
        self.client: Optional[httpx.AsyncClient] = None
        self.findings: List[Dict] = []

    async def init_client(self):
        self.client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)

    async def close(self):
        if self.client:
            await self.client.aclose()

    async def test_get_parameter(self, url: str, param: str) -> Optional[Dict]:
        payloads = self.payload_manager.get_all()
        
        for payload in payloads:
            try:
                test_url = self._inject_param(url, param, payload)
                response = await self.client.get(test_url)
                
                if self._check_error(response.text):
                    return self._create_finding(
                        url=url,
                        param=param,
                        payload=payload,
                        vuln_type='error',
                        severity='high'
                    )
                
                if self._check_blind(response.text):
                    return self._create_finding(
                        url=url,
                        param=param,
                        payload=payload,
                        vuln_type='blind',
                        severity='medium'
                    )
            except Exception:
                continue
        
        return None

    async def test_post_parameter(self, url: str, param: str, form_data: Dict) -> Optional[Dict]:
        payloads = self.payload_manager.get_all()
        
        for payload in payloads:
            try:
                test_data = form_data.copy()
                test_data[param] = payload
                
                response = await self.client.post(url, data=test_data)
                
                if self._check_error(response.text):
                    return self._create_finding(
                        url=url,
                        param=param,
                        payload=payload,
                        vuln_type='error',
                        severity='high'
                    )
            except Exception:
                continue
        
        return None

    async def test_time_based(self, url: str, param: str, method: str = 'GET') -> Optional[Dict]:
        time_payloads = self.payload_manager.get_by_type('blind_time')
        
        import time
        for payload in time_payloads:
            try:
                start = time.time()
                
                if method == 'GET':
                    test_url = self._inject_param(url, param, payload)
                    response = await self.client.get(test_url)
                else:
                    response = await self.client.post(url, data={param: payload})
                
                elapsed = time.time() - start
                
                if elapsed >= 4:
                    return self._create_finding(
                        url=url,
                        param=param,
                        payload=payload,
                        vuln_type='time_blind',
                        severity='high'
                    )
            except Exception:
                continue
        
        return None

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        
        if param in query_dict:
            query_dict[param] = [payload]
        else:
            query_dict[param] = [payload]
        
        new_query = urlencode(query_dict, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def _check_error(self, content: str) -> bool:
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _check_blind(self, content: str) -> bool:
        blind_patterns = [
            r"Welcome, admin",
            r"Login successful",
            r"Authentication successful",
            r"logged in as",
            r"User ID:",
            r"Profile",
        ]
        for pattern in blind_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _create_finding(self, url: str, param: str, payload: str, vuln_type: str, severity: str) -> Dict:
        return {
            'url': url,
            'param': param,
            'payload': payload,
            'type': vuln_type,
            'severity': severity,
            'description': self._get_description(vuln_type, severity)
        }

    def _get_description(self, vuln_type: str, severity: str) -> str:
        descriptions = {
            ('error', 'high'): '发现 SQL 错误注入漏洞，数据库错误信息被泄露',
            ('union', 'high'): '发现 UNION 注入漏洞，可能导致数据泄露',
            ('blind_boolean', 'medium'): '发现布尔型盲注漏洞',
            ('time_blind', 'high'): '发现时间型盲注漏洞',
            ('stacked', 'high'): '发现堆叠查询注入漏洞',
        }
        return descriptions.get((vuln_type, severity), f'发现 {vuln_type} 类型 SQL 注入漏洞')

    async def scan(self, target_url: str, params: List[Dict], form_data: Dict = None) -> List[Dict]:
        all_findings = []
        
        for param_info in params:
            param = param_info['param']
            method = param_info.get('method', 'GET')
            location = param_info.get('location', 'query')
            
            if method == 'GET' or location == 'query':
                finding = await self.test_get_parameter(target_url, param)
                if finding:
                    all_findings.append(finding)
                    continue
                
                time_finding = await self.test_time_based(target_url, param, 'GET')
                if time_finding:
                    all_findings.append(time_finding)
            
            if method == 'POST' or location == 'body':
                finding = await self.test_post_parameter(target_url, param, form_data or {})
                if finding:
                    all_findings.append(finding)
        
        self.findings = all_findings
        return all_findings

    def get_findings(self) -> List[Dict]:
        return self.findings

    def get_summary(self) -> Dict:
        return {
            'total': len(self.findings),
            'high': len([f for f in self.findings if f['severity'] == 'high']),
            'medium': len([f for f in self.findings if f['severity'] == 'medium']),
            'low': len([f for f in self.findings if f['severity'] == 'low']),
        }
