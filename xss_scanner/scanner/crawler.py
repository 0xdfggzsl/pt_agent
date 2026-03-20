from bs4 import BeautifulSoup
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
import asyncio
import httpx

class WebCrawler:
    def __init__(self, base_url: str, depth: int = 3, timeout: int = 30):
        self.base_url = base_url
        self.max_depth = depth
        self.timeout = timeout
        self.visited: Set[str] = set()
        self.forms: List[Dict] = []
        self.links: List[str] = []
        self.client = None

    async def init_client(self):
        self.client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)

    async def close(self):
        if self.client:
            await self.client.aclose()

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
