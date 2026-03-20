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
    
    auth = parser.add_argument_group('认证选项 (Authentication Options)')
    auth.add_argument('--cookie', help='Cookie认证，格式: key1=value1;key2=value2')
    auth.add_argument('--bearer', help='Bearer Token认证')
    auth.add_argument('--login-url', help='登录页面URL')
    auth.add_argument('--username', help='登录用户名')
    auth.add_argument('--password', help='登录密码')
    auth.add_argument('--username-field', default='username', help='用户名表单字段名 (默认: username)')
    auth.add_argument('--password-field', default='password', help='密码表单字段名 (默认: password)')
    
    return parser.parse_args()

async def main():
    args = parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    print(f"[*] 目标: {args.url}")
    print(f"[*] 爬取深度: {args.depth}")
    print(f"[*] 超时设置: {args.timeout}s")
    
    if args.cookie:
        print(f"[*] 认证方式: Cookie")
    elif args.bearer:
        print(f"[*] 认证方式: Bearer Token")
    elif args.login_url:
        print(f"[*] 认证方式: 登录表单 ({args.login_url})")
    else:
        print(f"[*] 认证方式: 无")
    
    print(f"[*] 开始扫描...")
    
    engine = ScanEngine(
        target_url=args.url,
        depth=args.depth,
        timeout=args.timeout,
        output_dir=args.output,
        cookies=args.cookie,
        bearer_token=args.bearer,
        login_url=args.login_url,
        username=args.username,
        password=args.password
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
