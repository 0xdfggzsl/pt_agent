import openai
from typing import List, Dict, Optional
from .base import LLMInterface

class OpenAILLM(LLMInterface):
    def __init__(self, model_name: str = "gpt-4"):
        super().__init__(model_name)
        self.client: Optional[openai.OpenAI] = None
    
    def set_api_key(self, api_key: str) -> None:
        self.api_key = api_key
        self.client = openai.OpenAI(api_key=api_key)
    
    async def chat(self, messages: List[Dict], **kwargs) -> str:
        if not self.client:
            raise ValueError("API key not set")
        
        temperature = kwargs.get('temperature', 0.7)
        max_tokens = kwargs.get('max_tokens', 4096)
        
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        return response.choices[0].message.content
