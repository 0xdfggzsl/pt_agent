import dashscope
from typing import List, Dict, Optional
from .base import LLMInterface

class DashScopeLLM(LLMInterface):
    def __init__(self, model_name: str = "qwen-plus"):
        super().__init__(model_name)
        self.api_key: Optional[str] = None
    
    def set_api_key(self, api_key: str) -> None:
        self.api_key = api_key
        dashscope.api_key = api_key
    
    async def chat(self, messages: List[Dict], **kwargs) -> str:
        if not self.api_key:
            raise ValueError("API key not set. Call set_api_key() first.")
        
        temperature = kwargs.get('temperature', 0.7)
        max_tokens = kwargs.get('max_tokens', 2048)
        
        response = dashscope.Generation.call(
            model=self.model_name,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        if response.status_code == 200:
            return response.output['text']
        else:
            raise Exception(f"DashScope API error: {response.message}")
    
    async def chat_stream(self, messages: List[Dict], **kwargs):
        raise NotImplementedError("DashScope does not support streaming")
