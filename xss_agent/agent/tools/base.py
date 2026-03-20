from abc import ABC, abstractmethod
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum

class ToolType(Enum):
    SCANNER = "scanner"
    CRAWLER = "crawler"
    REPORTER = "reporter"
    OTHER = "other"

@dataclass
class ToolResult:
    success: bool
    data: Any
    error: str = ""
    tool_name: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'tool_name': self.tool_name
        }

class Tool(ABC):
    name: str = ""
    description: str = ""
    parameters: List[Dict] = []
    
    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        pass
    
    def get_schema(self) -> Dict:
        return {
            'name': self.name,
            'description': self.description,
            'parameters': self.parameters
        }

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}
    
    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool
    
    def get(self, name: str) -> Tool:
        return self._tools.get(name)
    
    def list_tools(self) -> List[Dict]:
        return [t.get_schema() for t in self._tools.values()]
    
    def get_tool_names(self) -> List[str]:
        return list(self._tools.keys())

_global_registry = ToolRegistry()

def get_registry() -> ToolRegistry:
    return _global_registry

def register_tool(tool: Tool) -> None:
    _global_registry.register(tool)
