import asyncio
import time
from typing import Dict, List, Optional
from .scanner.crawler import WebCrawler
from .scanner.detector import XSSDetector
from .scanner.reporter import ReportGenerator
from urllib.parse import urlparse

class ScanEngine:
    def __init__(self, target_url: str, depth: int = 3, timeout: int = 30, output_dir: str = './reports'):
        self.target_url = target_url
        self.depth = depth
        self.timeout = timeout
        self.output_dir = output_dir
        self.crawler = WebCrawler(target_url, depth, timeout)
        self.detector = XSSDetector(timeout)
        self.reporter = ReportGenerator()
        self.findings: List[Dict] = []
        self.start_time = 0
        self.end_time = 0

    async def run(self) -> Dict:
        self.start_time = time.time()
        
        await self.crawler.init_client()
        await self.detector.init_client()
        
        try:
            crawl_result = await self.crawler.crawl(self.target_url)
            
            get_params = await self.crawler.get_input_params(self.target_url)
            
            self.findings = await self.detector.scan(
                self.target_url,
                crawl_result['forms'],
                get_params
            )
        finally:
            await self.crawler.close()
            await self.detector.close()
        
        self.end_time = time.time()
        
        return {
            'findings': self.findings,
            'duration': self.end_time - self.start_time
        }

    def generate_report(self, output_path: str = None) -> str:
        if output_path is None:
            import os
            os.makedirs(self.output_dir, exist_ok=True)
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.output_dir, f'xss_report_{timestamp}.html')
        
        return self.reporter.generate_html_report(
            self.target_url,
            self.findings,
            self.end_time - self.start_time,
            output_path
        )

    def get_summary(self) -> Dict:
        return self.detector.get_summary()
