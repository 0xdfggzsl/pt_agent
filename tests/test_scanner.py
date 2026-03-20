import pytest
from xss_scanner.scanner.payload import PayloadManager
from xss_scanner.utils.helpers import extract_forms, extract_links, parse_url, is_valid_url

class TestPayloadManager:
    def setup_method(self):
        self.pm = PayloadManager()

    def test_get_all_payloads(self):
        payloads = self.pm.get_all_payloads()
        assert len(payloads) > 10

    def test_get_payloads_by_type(self):
        reflected = self.pm.get_payloads('reflected')
        assert len(reflected) > 0
        assert '<script>alert(1)</script>' in reflected

    def test_get_payload_with_context(self):
        payloads = self.pm.get_payload_with_context()
        assert len(payloads) > 0
        assert all('payload' in p and 'type' in p and 'severity' in p for p in payloads)

    def test_get_random_payload(self):
        payload = self.pm.get_random_payload()
        assert isinstance(payload, str)
        assert len(payload) > 0

class TestHelpers:
    def test_extract_forms(self):
        html = '''
        <form action="/submit" method="post">
            <input type="text" name="username">
            <input type="password" name="password">
            <textarea name="bio"></textarea>
        </form>
        '''
        forms = extract_forms(html, 'http://example.com')
        assert len(forms) == 1
        assert forms[0]['action'] == '/submit'
        assert forms[0]['method'] == 'post'
        assert len(forms[0]['inputs']) == 3

    def test_extract_links(self):
        html = '''
        <html><body>
            <a href="http://example.com/page1">Page 1</a>
            <a href="/page2">Page 2</a>
            <a href="#section">Section</a>
        </body></html>
        '''
        links = extract_links(html, 'http://example.com')
        assert len(links) == 2

    def test_parse_url(self):
        url = 'https://example.com/path?query=value#fragment'
        parsed = parse_url(url)
        assert parsed['scheme'] == 'https'
        assert parsed['netloc'] == 'example.com'
        assert parsed['path'] == '/path'
        assert parsed['query'] == 'query=value'

    def test_is_valid_url(self):
        assert is_valid_url('https://example.com') == True
        assert is_valid_url('http://test.org/path') == True
        assert is_valid_url('invalid') == False
        assert is_valid_url('ftp://example.com') == True
