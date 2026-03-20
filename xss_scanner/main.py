import argparse
import asyncio
import os
import sys
from core.engine import ScanEngine

def parse_args():
    parser = argparse.ArgumentParser(
        description='XSS Scanner - Web应用XSS漏洞检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--url', required=True, help='目标网站URL')
    parser.add_argument('-o', '--output', default='./reports', help='报告输出目录')
    parser.add_argument('-d', '--depth', type=int, default=3, help='爬取深度')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='请求超时秒数')
    return parser.parse_args()

async def main():
    args = parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    print(f"[*] 目标: {args.url}")
    print(f"[*] 爬取深度: {args.depth}")
    print(f"[*] 超时设置: {args.timeout}s")
    print(f"[*] 开始扫描...")
    
    engine = ScanEngine(
        target_url=args.url,
        depth=args.depth,
        timeout=args.timeout,
        output_dir=args.output
    )
    
    result = await engine.run()
    
    summary = engine.get_summary()
    
    print(f"\n[+] 扫描完成!")
    print(f"    发现漏洞总数: {summary['total']}")
    print(f"    高危: {summary['high']}")
    print(f"    中危: {summary['medium']}")
    print(f"    低危: {summary['low']}")
    print(f"    耗时: {result['duration']:.2f}秒")
    
    report_path = engine.generate_report()
    print(f"\n[+] 报告已生成: {report_path}")

if __name__ == '__main__':
    asyncio.run(main())
