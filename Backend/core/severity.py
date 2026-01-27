from enum import Enum, auto
from dataclasses import dataclass

class SeverityLevel(Enum):
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 2
    INFO = 0

@dataclass
class Severity:
    level: SeverityLevel
    score: float # 0.0 to 10.0
    vector: str = "" # CVSS-like vector string

    def __str__(self):
        return self.level.name

class VulnerabilityType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RCE = "remote_code_execution"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_SECRET = "hardcoded_secret"
    # ... add more

def calculate_severity(vuln_type: str, confidence: float, impact: str = "high") -> Severity:
    # Basic logic to map type/confidence to severity
    base_score = 0
    if vuln_type in ['sql_injection', 'remote_code_execution', 'command_injection']:
        base_score = 9.0
    elif vuln_type in ['xss', 'path_traversal', 'hardcoded_secret']:
        base_score = 7.0
    else:
        base_score = 4.0
        
    final_score = base_score * confidence
    
    if final_score >= 9.0:
        level = SeverityLevel.CRITICAL
    elif final_score >= 7.0:
        level = SeverityLevel.HIGH
    elif final_score >= 4.0:
        level = SeverityLevel.MEDIUM
    else:
        level = SeverityLevel.LOW
        
    return Severity(level, final_score)
