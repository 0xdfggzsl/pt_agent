from typing import List, Dict, Optional
import asyncio
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .payload import PayloadManager

class XSSDetector:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.payload_manager = PayloadManager()
        self.client = None
        self.findings: List[Dict] = []

    async def init_client(self):
        self.client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)

    async def close(self):
        if self.client:
            await self.client.aclose()

    async def test_reflected_xss(self, url: str, param: str, method: str = 'GET') -> Optional[Dict]:
        payloads = self.payload_manager.get_all_payloads()
        
        for payload in payloads:
            try:
                if method == 'GET':
                    test_url = self._inject_param(url, param, payload)
                    response = await self.client.get(test_url)
                else:
                    response = await self.client.post(url, data={param: payload})
                
                if self._check_reflection(response.text, payload):
                    return self._create_finding(
                        url=url,
                        param=param,
                        payload=payload,
                        vuln_type='reflected',
                        severity='high'
                    )
            except Exception:
                continue
        
        return None

    async def test_form_xss(self, form: Dict) -> List[Dict]:
        findings = []
        payloads = self.payload_manager.get_all_payloads()
        
        for payload in payloads:
            for input_field in form.get('inputs', []):
                if input_field.get('type') in ['text', 'search', 'email', 'url', 'tel']:
                    try:
                        data = {input_field['name']: payload}
                        
                        if form['method'] == 'post':
                            response = await self.client.post(form['action'], data=data)
                        else:
                            response = await self.client.get(form['action'], params=data)
                        
                        if self._check_reflection(response.text, payload):
                            findings.append(self._create_finding(
                                url=form['action'],
                                param=input_field['name'],
                                payload=payload,
                                vuln_type='reflected',
                                severity='high'
                            ))
                            break
                    except Exception:
                        continue
        
        return findings

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        query_dict[param] = [payload]
        new_query = urlencode(query_dict, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def _check_reflection(self, content: str, payload: str) -> bool:
        plain_payload = payload.replace('<', '').replace('>', '')
        if plain_payload in content:
            return True
        if payload in content:
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
            ('reflected', 'high'): '发现高危反射型XSS漏洞，攻击者可利用此漏洞执行任意JavaScript代码',
            ('dom', 'high'): '发现高危DOM型XSS漏洞，可能导致客户端代码执行',
            ('stored', 'critical'): '发现存储型XSS漏洞，恶意脚本将被永久存储',
        }
        return descriptions.get((vuln_type, severity), f'发现{vuln_type}型XSS漏洞')

    async def scan(self, target_url: str, forms: List[Dict], get_params: List[Dict]) -> List[Dict]:
        all_findings = []
        
        for param_info in get_params:
            finding = await self.test_reflected_xss(
                param_info['url'],
                param_info['param'],
                param_info.get('method', 'GET')
            )
            if finding:
                all_findings.append(finding)
        
        for form in forms:
            form_findings = await self.test_form_xss(form)
            all_findings.extend(form_findings)
        
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
