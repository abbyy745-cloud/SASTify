import yaml
import os
from typing import List, Dict, Any

class RuleLoader:
    def __init__(self, rules_dir: str = "Backend/rules"):
        self.rules_dir = rules_dir
        self.rules = {
            'sources': {},
            'sinks': {},
            'sanitizers': {},
            'patterns': []
        }

    def load_rules(self):
        if not os.path.exists(self.rules_dir):
            return self.rules

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(('.yaml', '.yml')):
                path = os.path.join(self.rules_dir, filename)
                try:
                    with open(path, 'r') as f:
                        data = yaml.safe_load(f)
                        self._merge_rules(data)
                except Exception as e:
                    print(f"Error loading rule file {filename}: {e}")
        return self.rules

    def _merge_rules(self, data: Dict):
        if 'sources' in data:
            for lang, sources in data['sources'].items():
                if lang not in self.rules['sources']:
                    self.rules['sources'][lang] = []
                self.rules['sources'][lang].extend(sources)
        
        if 'sinks' in data:
            for lang, sinks in data['sinks'].items():
                if lang not in self.rules['sinks']:
                    self.rules['sinks'][lang] = {}
                for vuln_type, func_names in sinks.items():
                    if vuln_type not in self.rules['sinks'][lang]:
                        self.rules['sinks'][lang][vuln_type] = []
                    self.rules['sinks'][lang][vuln_type].extend(func_names)

        if 'sanitizers' in data:
            for lang, sanitizers in data['sanitizers'].items():
                if lang not in self.rules['sanitizers']:
                    self.rules['sanitizers'][lang] = []
                self.rules['sanitizers'][lang].extend(sanitizers)

        if 'patterns' in data:
            self.rules['patterns'].extend(data['patterns'])
