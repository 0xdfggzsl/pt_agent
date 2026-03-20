from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
import json
import os

@dataclass
class MemoryEntry:
    role: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'role': self.role,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'MemoryEntry':
        return cls(
            role=data['role'],
            content=data['content'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            metadata=data.get('metadata', {})
        )

@dataclass
class ScanRecord:
    url: str
    timestamp: datetime = field(default_factory=datetime.now)
    findings: List[Dict] = field(default_factory=list)
    auth_type: str = 'none'
    duration: float = 0.0
    model_used: str = ''
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'timestamp': self.timestamp.isoformat(),
            'findings': self.findings,
            'auth_type': self.auth_type,
            'duration': self.duration,
            'model_used': self.model_used
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanRecord':
        return cls(
            url=data['url'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            findings=data.get('findings', []),
            auth_type=data.get('auth_type', 'none'),
            duration=data.get('duration', 0.0),
            model_used=data.get('model_used', '')
        )

class MemoryStore:
    def __init__(self, data_dir: str = None):
        if data_dir is None:
            data_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'data'
            )
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.memory_file = os.path.join(data_dir, 'memory.json')
        self.preferences_file = os.path.join(data_dir, 'preferences.json')
        self.history_dir = os.path.join(data_dir, 'history')
        os.makedirs(self.history_dir, exist_ok=True)
        
        self._load_memory()
        self._load_preferences()
    
    def _load_memory(self):
        if os.path.exists(self.memory_file):
            with open(self.memory_file, 'r') as f:
                data = json.load(f)
                self.entries = [MemoryEntry.from_dict(e) for e in data.get('entries', [])]
        else:
            self.entries = []
    
    def _save_memory(self):
        with open(self.memory_file, 'w') as f:
            json.dump({
                'entries': [e.to_dict() for e in self.entries]
            }, f, indent=2)
    
    def _load_preferences(self):
        if os.path.exists(self.preferences_file):
            with open(self.preferences_file, 'r') as f:
                self.preferences = json.load(f)
        else:
            self.preferences = {
                'default_model': 'gpt-4',
                'temperature': 0.7,
                'max_tokens': 2048
            }
    
    def _save_preferences(self):
        with open(self.preferences_file, 'w') as f:
            json.dump(self.preferences, f, indent=2)
    
    def add_entry(self, role: str, content: str, metadata: Dict = None):
        entry = MemoryEntry(role=role, content=content, metadata=metadata or {})
        self.entries.append(entry)
        self._save_memory()
    
    def get_recent(self, n: int = 10) -> List[MemoryEntry]:
        return self.entries[-n:]
    
    def get_session_context(self, max_entries: int = 20) -> List[Dict]:
        recent = self.get_recent(max_entries)
        return [{'role': e.role, 'content': e.content} for e in recent]
    
    def save_scan_record(self, record: ScanRecord):
        filename = f"{record.timestamp.strftime('%Y-%m-%d_%H%M%S')}_{record.url.replace('://', '_').replace('/', '_')[:50]}.json"
        filepath = os.path.join(self.history_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(record.to_dict(), f, indent=2)
    
    def get_scan_history(self, limit: int = 10) -> List[ScanRecord]:
        files = sorted(os.listdir(self.history_dir), reverse=True)[:limit]
        records = []
        for f in files:
            with open(os.path.join(self.history_dir, f), 'r') as fp:
                records.append(ScanRecord.from_dict(json.load(fp)))
        return records
    
    def set_preference(self, key: str, value):
        self.preferences[key] = value
        self._save_preferences()
    
    def get_preference(self, key: str, default=None):
        return self.preferences.get(key, default)
    
    def clear_memory(self):
        self.entries = []
        self._save_memory()
