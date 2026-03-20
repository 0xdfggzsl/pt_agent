import logging
import os
from datetime import datetime
from pathlib import Path

class ScanLogger:
    def __init__(self, log_dir: str = './logs', name: str = None):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        if name is None:
            name = f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        self.name = name
        self.log_file = os.path.join(log_dir, f'{name}.log')
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        if not self.logger.handlers:
            fh = logging.FileHandler(self.log_file, encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            fh.setFormatter(formatter)
            ch.setFormatter(formatter)
            
            self.logger.addHandler(fh)
            self.logger.addHandler(ch)
    
    def info(self, msg: str):
        self.logger.info(msg)
    
    def debug(self, msg: str):
        self.logger.debug(msg)
    
    def warning(self, msg: str):
        self.logger.warning(msg)
    
    def error(self, msg: str):
        self.logger.error(msg)
    
    def critical(self, msg: str):
        self.logger.critical(msg)
    
    def log_scan_start(self, url: str, scan_types: list):
        self.info(f"=" * 60)
        self.info(f"扫描任务开始")
        self.info(f"目标 URL: {url}")
        self.info(f"扫描类型: {', '.join(scan_types)}")
        self.info(f"=" * 60)
    
    def log_intent(self, intent: dict):
        self.debug(f"意图解析完成: action={intent.get('action')}, url={intent.get('url')}")
        self.debug(f"扫描类型: {intent.get('scan_types')}")
        self.debug(f"认证方式: {intent.get('auth_info', {}).get('type', 'none')}")
    
    def log_auth(self, auth_type: str, provided: bool):
        if auth_type == 'none':
            self.info("认证方式: 无需认证")
        elif auth_type == 'login':
            self.info(f"认证方式: 用户名密码登录")
        elif auth_type == 'cookie':
            self.info(f"认证方式: Cookie 认证")
        elif auth_type == 'bearer':
            self.info(f"认证方式: Bearer Token 认证")
    
    def log_scanner_start(self, scanner_name: str):
        self.info(f"-" * 60)
        self.info(f"开始执行扫描器: {scanner_name}")
    
    def log_scanner_result(self, scanner_name: str, findings_count: int, verified_count: int, fp_count: int):
        self.info(f"扫描器 {scanner_name} 完成:")
        self.info(f"  - 发现漏洞: {findings_count}")
        self.info(f"  - 真实漏洞: {verified_count}")
        self.info(f"  - 误报数量: {fp_count}")
    
    def log_llm_verify(self, findings_count: int):
        self.debug(f"LLM 验证开始，待验证 {findings_count} 个发现")
    
    def log_llm_result(self, verified_count: int, fp_count: int):
        self.info(f"LLM 验证完成: {verified_count} 个真实漏洞, {fp_count} 个误报")
    
    def log_report(self, report_path: str, format: str):
        self.info(f"报告已生成: {report_path} (格式: {format})")
    
    def log_scan_complete(self, total_findings: dict):
        self.info(f"=" * 60)
        self.info(f"扫描任务完成")
        self.info(f"总漏洞数: {total_findings.get('total', 0)}")
        self.info(f"  - 高危: {total_findings.get('high', 0)}")
        self.info(f"  - 中危: {total_findings.get('medium', 0)}")
        self.info(f"  - 低危: {total_findings.get('low', 0)}")
        self.info(f"=" * 60)
    
    def log_error(self, step: str, error: str):
        self.error(f"错误 [{step}]: {error}")
    
    def log_exception(self, step: str, exc: Exception):
        self.critical(f"异常 [{step}]: {str(exc)}")
    
    def get_log_path(self) -> str:
        return self.log_file
