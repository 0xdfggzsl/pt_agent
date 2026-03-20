from bs4 import BeautifulSoup
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse
import asyncio
import httpx

class WebCrawler:
    def __init__(self, base_url: str, depth: int = 3, timeout: int = 30,
                 cookies: Optional[str] = None,
                 bearer_token: Optional[str] = None,
                 login_url: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 username_field: Optional[str] = None,
                 password_field: Optional[str] = None):
        self.base_url = base_url
        self.max_depth = depth
        self.timeout = timeout
        self.cookies = cookies
        self.bearer_token = bearer_token
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field or 'username'
        self.password_field = password_field or 'password'
        self.visited: Set[str] = set()
        self.forms: List[Dict] = []
        self.links: List[str] = []
        self.client = None

    async def init_client(self):
        headers = {}
        if self.bearer_token:
            headers['Authorization'] = f'Bearer {self.bearer_token}'
        
        cookies_dict = {}
        if self.cookies:
            for cookie in self.cookies.split(';'):
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    cookies_dict[key] = value

        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
            cookies=cookies_dict
        )

    async def close(self):
        if self.client:
            await self.client.aclose()

    async def login(self) -> bool:
        if not self.login_url or not self.username or not self.password:
            return True

        try:
            response = await self.client.get(self.login_url)
            html = response.text
            
            csrf_token = self._extract_csrf_token(html)
            
            login_data = {
                self.username_field: self.username,
                self.password_field: self.password
            }
            if csrf_token:
                login_data['csrf_token'] = csrf_token

            login_response = await self.client.post(
                self.login_url,
                data=login_data,
                allow_redirects=True
            )
            
            if login_response.status_code == 200:
                print(f"[+] 登录成功")
                return True
            else:
                print(f"[!] 登录失败: {login_response.status_code}")
                return False
        except Exception as e:
            print(f"[!] 登录异常: {e}")
            return False

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        soup = BeautifulSoup(html, 'lxml')
        
        token_inputs = soup.find_all('input', {'name': ['csrf_token', 'csrf', '_token', 'token']})
        for inp in token_inputs:
            if inp.get('value'):
                return inp.get('value')
        
        meta = soup.find('meta', {'name': 'csrf-token'})
        if meta and meta.get('content'):
            return meta.get('content')
        
        return None

    async def crawl(self, url: str, current_depth: int = 0) -> Dict:
        if current_depth >= self.max_depth:
            return {'forms': [], 'links': []}
        
        normalized_url = self._normalize_url(url)
        if normalized_url in self.visited:
            return {'forms': [], 'links': []}
        
        self.visited.add(normalized_url)
        
        try:
            response = await self.client.get(normalized_url)
            html = response.text
            
            forms = self._extract_forms(html, normalized_url)
            links = self._extract_links(html, normalized_url)
            
            self.forms.extend(forms)
            self.links.extend(links)
            
            for link in links[:5]:
                await self.crawl(link, current_depth + 1)
            
            return {'forms': forms, 'links': links}
        except Exception as e:
            return {'forms': [], 'links': []}

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        soup = BeautifulSoup(html, 'lxml')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'tag': input_tag.name
                }
                if input_info['name']:
                    form_data['inputs'].append(input_info)
            
            forms.append(form_data)
        
        return forms

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, 'lxml')
        links = []
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('http') or href.startswith('/'):
                full_url = urljoin(base_url, href)
                if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                    if full_url not in self.visited:
                        links.append(full_url)
        
        return links

    async def get_input_params(self, url: str) -> List[Dict]:
        parsed = urlparse(url)
        params = []
        
        if parsed.query:
            query_params = parsed.query.split('&')
            for param in query_params:
                if '=' in param:
                    name, _ = param.split('=', 1)
                    params.append({
                        'url': url,
                        'param': name,
                        'method': 'GET',
                        'location': 'query'
                    })
        
        return params
