from bs4 import BeautifulSoup
from typing import List, Dict, Tuple
from urllib.parse import urlparse, parse_qs

def extract_forms(html: str, base_url: str) -> List[Dict]:
    soup = BeautifulSoup(html, 'lxml')
    forms = []
    
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            form_data['inputs'].append({
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'tag': input_tag.name
            })
        
        forms.append(form_data)
    
    return forms

def extract_links(html: str, base_url: str) -> List[str]:
    soup = BeautifulSoup(html, 'lxml')
    links = []
    
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('http') or href.startswith('/'):
            links.append(href)
    
    return links

def parse_url(url: str) -> Dict:
    parsed = urlparse(url)
    return {
        'scheme': parsed.scheme,
        'netloc': parsed.netloc,
        'path': parsed.path,
        'params': parsed.params,
        'query': parsed.query,
        'fragment': parsed.fragment
    }

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def get_query_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    return dict(parse_qs(parsed.query))
