from .base import LLMInterface, LLMFactory
from .openai import OpenAILLM
from .anthropic import AnthropicLLM
from .dashscope import DashScopeLLM

LLMFactory.register('openai', OpenAILLM)
LLMFactory.register('anthropic', AnthropicLLM)
LLMFactory.register('dashscope', DashScopeLLM)

__all__ = ['LLMInterface', 'LLMFactory', 'OpenAILLM', 'AnthropicLLM', 'DashScopeLLM']
