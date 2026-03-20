import anthropic
from typing import List, Dict, Optional
from .base import LLMInterface

class AnthropicLLM(LLMInterface):
    def __init__(self, model_name: str = "claude-3-opus"):
        super().__init__(model_name)
        self.client: Optional[anthropic.Anthropic] = None
    
    def set_api_key(self, api_key: str) -> None:
        self.api_key = api_key
        self.client = anthropic.Anthropic(api_key=api_key)
    
    async def chat(self, messages: List[Dict], **kwargs) -> str:
        if not self.client:
            raise ValueError("API key not set. Call set_api_key() first.")
        
        temperature = kwargs.get('temperature', 0.7)
        max_tokens = kwargs.get('max_tokens', 2048)
        
        system_message = ""
        filtered_messages = []
        for msg in messages:
            if msg.get('role') == 'system':
                system_message = msg.get('content', '')
            else:
                filtered_messages.append(msg)
        
        response = self.client.messages.create(
            model=self.model_name,
            system=system_message,
            messages=filtered_messages,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        return response.content[0].text
    
    async def chat_stream(self, messages: List[Dict], **kwargs):
        if not self.client:
            raise ValueError("API key not set. Call set_api_key() first.")
        
        temperature = kwargs.get('temperature', 0.7)
        max_tokens = kwargs.get('max_tokens', 2048)
        
        system_message = ""
        filtered_messages = []
        for msg in messages:
            if msg.get('role') == 'system':
                system_message = msg.get('content', '')
            else:
                filtered_messages.append(msg)
        
        with self.client.messages.stream(
            model=self.model_name,
            system=system_message,
            messages=filtered_messages,
            temperature=temperature,
            max_tokens=max_tokens
        ) as stream:
            for text in stream.text_stream:
                yield text
