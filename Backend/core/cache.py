import hashlib
import json
import os
from typing import Dict, Any, Optional

class CacheManager:
    def __init__(self, cache_dir: str = ".sastify_cache"):
        self.cache_dir = cache_dir
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

    def _get_file_hash(self, content: str) -> str:
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def get_cached_result(self, file_path: str, content: str) -> Optional[Dict[str, Any]]:
        file_hash = self._get_file_hash(content)
        cache_path = os.path.join(self.cache_dir, f"{file_hash}.json")
        
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except:
                return None
        return None

    def cache_result(self, file_path: str, content: str, result: Dict[str, Any]):
        file_hash = self._get_file_hash(content)
        cache_path = os.path.join(self.cache_dir, f"{file_hash}.json")
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(result, f)
        except Exception as e:
            print(f"Failed to cache result: {e}")
