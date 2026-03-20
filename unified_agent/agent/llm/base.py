from abc import ABC, abstractmethod
from typing import List, Dict, Optional
import os
import json

class LLMInterface(ABC):
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.api_key: Optional[str] = None
    
    @abstractmethod
    async def chat(self, messages: List[Dict], **kwargs) -> str:
        pass
    
    @abstractmethod
    def set_api_key(self, api_key: str) -> None:
        pass
    
    def get_model_name(self) -> str:
        return self.model_name

class LLMFactory:
    @classmethod
    def create(cls, model_name: str, api_key: Optional[str] = None) -> LLMInterface:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'models.json')
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        if model_name not in config['models']:
            raise ValueError(f"Unknown model: {model_name}")
        
        model_config = config['models'][model_name]
        provider = model_config['provider']
        
        if provider == 'openai':
            from .openai import OpenAILLM
            llm = OpenAILLM(model_name)
        elif provider == 'anthropic':
            from .anthropic import AnthropicLLM
            llm = AnthropicLLM(model_name)
        elif provider == 'dashscope':
            from .dashscope import DashScopeLLM
            llm = DashScopeLLM(model_name)
        else:
            raise ValueError(f"Unknown provider: {provider}")
        
        if api_key:
            llm.set_api_key(api_key)
        else:
            env_var = model_config.get('api_key_env')
            if env_var:
                key = os.environ.get(env_var)
                if key:
                    llm.set_api_key(key)
        
        return llm
