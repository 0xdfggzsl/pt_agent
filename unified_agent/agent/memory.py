from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import os

@dataclass
class MemoryEntry:
    role: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)

@dataclass
class ScanHistory:
    url: str
    timestamp: datetime = field(default_factory=datetime.now)
    scan_types: List[str] = field(default_factory=list)
    results: Dict = field(default_factory=dict)
    auth_type: str = 'none'
    duration: float = 0.0
    model_used: str = ''

class MemoryStore:
    def __init__(self, data_dir: str = None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.memory_file = os.path.join(data_dir, 'memory.json')
        self.preferences_file = os.path.join(data_dir, 'preferences.json')
        self.history_file = os.path.join(data_dir, 'history.json')
        self._load_memory()
        self._load_preferences()
        self._load_history()
    
    def _load_memory(self):
        if os.path.exists(self.memory_file):
            with open(self.memory_file, 'r') as f:
                data = json.load(f)
                self.entries = [MemoryEntry(
                    role=e['role'],
                    content=e['content'],
                    timestamp=datetime.fromisoformat(e['timestamp']),
                    metadata=e.get('metadata', {})
                ) for e in data.get('entries', [])]
        else:
            self.entries = []
    
    def _save_memory(self):
        with open(self.memory_file, 'w') as f:
            json.dump({
                'entries': [
                    {'role': e.role, 'content': e.content, 'timestamp': e.timestamp.isoformat(), 'metadata': e.metadata}
                    for e in self.entries
                ]
            }, f, indent=2)
    
    def _load_preferences(self):
        if os.path.exists(self.preferences_file):
            with open(self.preferences_file, 'r') as f:
                self.preferences = json.load(f)
        else:
            self.preferences = {
                'default_model': 'gpt-4',
                'default_scan_type': 'both',
                'temperature': 0.7
            }
    
    def _save_preferences(self):
        with open(self.preferences_file, 'w') as f:
            json.dump(self.preferences, f, indent=2)
    
    def _load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                data = json.load(f)
                self.history = [ScanHistory(
                    url=h['url'],
                    timestamp=datetime.fromisoformat(h['timestamp']),
                    scan_types=h.get('scan_types', []),
                    results=h.get('results', {}),
                    auth_type=h.get('auth_type', 'none'),
                    duration=h.get('duration', 0.0),
                    model_used=h.get('model_used', '')
                ) for h in data.get('history', [])]
        else:
            self.history = []
    
    def _save_history(self):
        with open(self.history_file, 'w') as f:
            json.dump({
                'history': [
                    {
                        'url': h.url,
                        'timestamp': h.timestamp.isoformat(),
                        'scan_types': h.scan_types,
                        'results': h.results,
                        'auth_type': h.auth_type,
                        'duration': h.duration,
                        'model_used': h.model_used
                    }
                    for h in self.history
                ]
            }, f, indent=2)
    
    def add_entry(self, role: str, content: str, metadata: Dict = None):
        entry = MemoryEntry(role=role, content=content, metadata=metadata or {})
        self.entries.append(entry)
        self._save_memory()
    
    def get_recent(self, n: int = 20) -> List[MemoryEntry]:
        return self.entries[-n:]
    
    def get_context(self) -> List[Dict]:
        recent = self.get_recent(20)
        return [{'role': e.role, 'content': e.content} for e in recent]
    
    def add_scan_history(self, record: ScanHistory):
        self.history.append(record)
        if len(self.history) > 50:
            self.history = self.history[-50:]
        self._save_history()
    
    def get_scan_history(self, limit: int = 10) -> List[ScanHistory]:
        return self.history[-limit:]
    
    def set_preference(self, key: str, value):
        self.preferences[key] = value
        self._save_preferences()
    
    def get_preference(self, key: str, default=None):
        return self.preferences.get(key, default)
    
    def clear_memory(self):
        self.entries = []
        self._save_memory()
