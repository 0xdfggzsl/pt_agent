import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..', 'xss_scanner'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..', 'sql_agent'))

from agent.core import Agent

def main():
    print("=" * 60)
    print("安全扫描助手 - Smart Security Scanner")
    print("=" * 60)
    print("\n支持 XSS 和 SQL 注入扫描")
    print("输入你的需求，输入 'exit' 退出\n")
    
    api_key = None
    for env_var in ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'DASHSCOPE_API_KEY']:
        key = os.environ.get(env_var)
        if key:
            api_key = key
            print(f"[*] 使用 {env_var} 进行认证")
            break
    
    if not api_key:
        print("[!] 警告：未设置 API 密钥，功能可能受限")
        print("[*] 请设置 OPENAI_API_KEY、ANTHROPIC_API_KEY 或 DASHSCOPE_API_KEY 环境变量\n")
    
    try:
        agent = Agent(api_key=api_key)
    except Exception as e:
        print(f"[!] 初始化失败: {e}")
        return
    
    while True:
        try:
            user_input = input("\n> ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ['exit', 'quit', 'q']:
                print("再见!")
                break
            
            print()
            response = asyncio.run(agent.chat(user_input))
            print(response)
            
        except KeyboardInterrupt:
            print("\n\n再见!")
            break
        except Exception as e:
            print(f"\n错误: {e}")

if __name__ == '__main__':
    main()
