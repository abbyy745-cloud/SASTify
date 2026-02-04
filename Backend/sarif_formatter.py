"""
SARIF Formatter - Static Analysis Results Interchange Format

Outputs scan results in SARIF 2.1.0 format for integration with:
- GitHub Security tab
- Azure DevOps
- VS Code SARIF Viewer
- Other CI/CD tools
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


# SARIF 2.1.0 Schema version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


@dataclass
class SarifRule:
    """A SARIF rule definition"""
    id: str
    name: str
    short_description: str
    full_description: str
    help_uri: str
    severity: str  # error, warning, note, none
    security_severity: str  # 0.0-10.0
    tags: List[str]
    cwe_id: Optional[str] = None


class SarifFormatter:
    """
    Formats SASTify scan results as SARIF 2.1.0.
    
    SARIF is the industry standard for static analysis results,
    enabling integration with GitHub Security, Azure DevOps, and more.
    """
    
    SEVERITY_MAP = {
        'critical': ('error', '9.0'),
        'high': ('error', '7.0'),
        'medium': ('warning', '5.0'),
        'low': ('note', '3.0'),
        'info': ('note', '1.0')
    }
    
    # EdTech-specific rules with CWE mappings
    RULE_DEFINITIONS = {
        'sql_injection': SarifRule(
            id='SAST001',
            name='SQL Injection',
            short_description='SQL injection vulnerability detected',
            full_description='User-controlled input is used in SQL query without proper sanitization, allowing attackers to execute arbitrary SQL commands.',
            help_uri='https://owasp.org/www-community/attacks/SQL_Injection',
            severity='error',
            security_severity='9.0',
            tags=['security', 'injection', 'owasp-a03'],
            cwe_id='CWE-89'
        ),
        'xss': SarifRule(
            id='SAST002',
            name='Cross-Site Scripting (XSS)',
            short_description='XSS vulnerability detected',
            full_description='User-controlled input is rendered in HTML without proper escaping, allowing attackers to inject malicious scripts.',
            help_uri='https://owasp.org/www-community/attacks/xss/',
            severity='error',
            security_severity='7.0',
            tags=['security', 'xss', 'owasp-a03'],
            cwe_id='CWE-79'
        ),
        'code_injection': SarifRule(
            id='SAST003',
            name='Code Injection',
            short_description='Code injection vulnerability detected',
            full_description='User-controlled input is passed to code execution functions like eval() or exec().',
            help_uri='https://owasp.org/www-community/attacks/Code_Injection',
            severity='error',
            security_severity='9.5',
            tags=['security', 'injection', 'owasp-a03'],
            cwe_id='CWE-94'
        ),
        'shell_injection': SarifRule(
            id='SAST004',
            name='Shell/Command Injection',
            short_description='Command injection vulnerability detected',
            full_description='User-controlled input is used in shell commands without proper sanitization.',
            help_uri='https://owasp.org/www-community/attacks/Command_Injection',
            severity='error',
            security_severity='9.5',
            tags=['security', 'injection', 'owasp-a03'],
            cwe_id='CWE-78'
        ),
        'path_traversal': SarifRule(
            id='SAST005',
            name='Path Traversal',
            short_description='Path traversal vulnerability detected',
            full_description='User-controlled input is used in file paths without validation, allowing access to arbitrary files.',
            help_uri='https://owasp.org/www-community/attacks/Path_Traversal',
            severity='error',
            security_severity='7.0',
            tags=['security', 'file-access', 'owasp-a01'],
            cwe_id='CWE-22'
        ),
        'hardcoded_secret': SarifRule(
            id='SAST006',
            name='Hardcoded Secret',
            short_description='Hardcoded credential or secret detected',
            full_description='Sensitive credentials, API keys, or secrets are hardcoded in the source code.',
            help_uri='https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
            severity='error',
            security_severity='8.0',
            tags=['security', 'secrets', 'owasp-a07'],
            cwe_id='CWE-798'
        ),
        'insecure_randomness': SarifRule(
            id='SAST007',
            name='Insecure Randomness',
            short_description='Insecure random number generation',
            full_description='Weak random number generators are used for security-sensitive operations.',
            help_uri='https://owasp.org/www-community/vulnerabilities/Insecure_Randomness',
            severity='warning',
            security_severity='5.0',
            tags=['security', 'crypto', 'owasp-a02'],
            cwe_id='CWE-330'
        ),
        'missing_authentication': SarifRule(
            id='SAST008',
            name='Missing Authentication',
            short_description='Endpoint lacks authentication',
            full_description='Security-sensitive endpoint does not enforce authentication.',
            help_uri='https://owasp.org/www-project-web-security-testing-guide/',
            severity='error',
            security_severity='8.0',
            tags=['security', 'authentication', 'owasp-a07'],
            cwe_id='CWE-306'
        ),
        # EdTech-specific rules
        'student_pii_exposure': SarifRule(
            id='EDTECH001',
            name='Student PII Exposure',
            short_description='Student personally identifiable information may be exposed',
            full_description='Student data such as names, IDs, or grades are logged or exposed in an insecure manner. This may violate FERPA.',
            help_uri='https://studentprivacy.ed.gov/faq/what-ferpa',
            severity='error',
            security_severity='8.0',
            tags=['security', 'privacy', 'ferpa', 'edtech'],
            cwe_id='CWE-359'
        ),
        'exam_answer_exposure': SarifRule(
            id='EDTECH002',
            name='Exam Answer Exposure',
            short_description='Exam answers may be exposed to students',
            full_description='Correct exam answers are present in client-side code or API responses visible to students.',
            help_uri='https://www.proctorio.com/blog/academic-integrity-best-practices',
            severity='error',
            security_severity='9.0',
            tags=['security', 'academic-integrity', 'edtech'],
            cwe_id='CWE-200'
        ),
        'prompt_injection': SarifRule(
            id='EDTECH003',
            name='AI Prompt Injection',
            short_description='User input passed unsanitized to AI/LLM',
            full_description='Student input is concatenated directly into AI prompts without sanitization, allowing prompt injection attacks.',
            help_uri='https://owasp.org/www-project-top-10-for-large-language-model-applications/',
            severity='error',
            security_severity='7.0',
            tags=['security', 'ai', 'llm', 'edtech'],
            cwe_id='CWE-74'
        ),
        # Mobile-specific rules
        'insecure_storage': SarifRule(
            id='MOBILE001',
            name='Insecure Data Storage',
            short_description='Sensitive data stored insecurely',
            full_description='Sensitive data is stored in plaintext in SharedPreferences, UserDefaults, or local storage.',
            help_uri='https://owasp.org/www-project-mobile-top-10/',
            severity='error',
            security_severity='7.0',
            tags=['security', 'mobile', 'storage'],
            cwe_id='CWE-922'
        ),
        'insecure_communication': SarifRule(
            id='MOBILE002',
            name='Insecure Communication',
            short_description='Unencrypted network communication',
            full_description='Application uses HTTP or disables certificate validation, exposing data in transit.',
            help_uri='https://owasp.org/www-project-mobile-top-10/',
            severity='error',
            security_severity='7.0',
            tags=['security', 'mobile', 'network'],
            cwe_id='CWE-319'
        ),
    }
    
    def __init__(self, tool_name: str = "SASTify", tool_version: str = "1.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
    
    def format(self, scan_results: Dict, filename: str = None) -> Dict:
        """
        Convert SASTify scan results to SARIF format.
        
        Args:
            scan_results: Dictionary with 'vulnerabilities' list
            filename: Optional filename for the scanned file
            
        Returns:
            SARIF 2.1.0 compliant dictionary
        """
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Collect unique rules used
        rules_used = set()
        for vuln in vulnerabilities:
            vuln_type = self._normalize_vuln_type(vuln.get('type', 'unknown'))
            rules_used.add(vuln_type)
        
        # Build SARIF document
        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": self._build_tool_section(rules_used),
                "results": self._build_results(vulnerabilities, filename),
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                }]
            }]
        }
        
        return sarif
    
    def format_to_string(self, scan_results: Dict, filename: str = None, 
                         indent: int = 2) -> str:
        """Format results as SARIF JSON string"""
        sarif = self.format(scan_results, filename)
        return json.dumps(sarif, indent=indent)
    
    def _build_tool_section(self, rules_used: set) -> Dict:
        """Build the tool section with rule definitions"""
        rules = []
        
        for rule_type in rules_used:
            rule_def = self.RULE_DEFINITIONS.get(rule_type)
            if rule_def:
                rule = {
                    "id": rule_def.id,
                    "name": rule_def.name,
                    "shortDescription": {"text": rule_def.short_description},
                    "fullDescription": {"text": rule_def.full_description},
                    "helpUri": rule_def.help_uri,
                    "properties": {
                        "security-severity": rule_def.security_severity,
                        "tags": rule_def.tags
                    }
                }
                
                if rule_def.cwe_id:
                    rule["relationships"] = [{
                        "target": {
                            "id": rule_def.cwe_id,
                            "guid": self._cwe_to_guid(rule_def.cwe_id),
                            "toolComponent": {"name": "CWE"}
                        },
                        "kinds": ["superset"]
                    }]
                
                rules.append(rule)
            else:
                # Unknown rule type - create generic entry
                rules.append({
                    "id": f"SAST-{hashlib.md5(rule_type.encode()).hexdigest()[:6].upper()}",
                    "name": rule_type.replace('_', ' ').title(),
                    "shortDescription": {"text": f"Potential {rule_type} vulnerability"},
                    "properties": {"tags": ["security"]}
                })
        
        return {
            "driver": {
                "name": self.tool_name,
                "version": self.tool_version,
                "informationUri": "https://github.com/yourusername/sastify",
                "rules": rules,
                "supportedTaxonomies": [{
                    "name": "CWE",
                    "guid": "a0caf6c8-9b95-4e91-8721-91a7b0b8d0f7"
                }]
            }
        }
    
    def _build_results(self, vulnerabilities: List[Dict], filename: str) -> List[Dict]:
        """Build the results array"""
        results = []
        
        for i, vuln in enumerate(vulnerabilities):
            vuln_type = self._normalize_vuln_type(vuln.get('type', 'unknown'))
            rule_def = self.RULE_DEFINITIONS.get(vuln_type)
            
            severity = vuln.get('severity', 'medium').lower()
            sarif_level, _ = self.SEVERITY_MAP.get(severity, ('warning', '5.0'))
            
            # Build message text - include AI explanation if available
            message_text = vuln.get('description', f"Potential {vuln_type} vulnerability")
            if vuln.get('ai_analyzed') and vuln.get('ai_explanation'):
                message_text += f"\n\nAI Analysis: {vuln['ai_explanation']}"
                if vuln.get('ai_is_false_positive'):
                    message_text += f"\n⚠️ AI suggests this may be a false positive: {vuln.get('ai_false_positive_reason', 'See AI analysis')}"
            
            result = {
                "ruleId": rule_def.id if rule_def else f"SAST-{i:03d}",
                "level": sarif_level,
                "message": {
                    "text": message_text
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": filename or vuln.get('file', 'unknown'),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": vuln.get('line', 1),
                            "startColumn": vuln.get('column', 1),
                            "snippet": {
                                "text": vuln.get('snippet', '')
                            }
                        }
                    }
                }],
                "fingerprints": {
                    "primary": self._generate_fingerprint(vuln)
                },
                "properties": {
                    "confidence": vuln.get('confidence', 0.8),
                    "scanner": vuln.get('scanner', 'ast_analysis')
                }
            }
            
            # Add AI analysis to properties if available
            if vuln.get('ai_analyzed'):
                result["properties"]["ai_analyzed"] = True
                result["properties"]["ai_confidence"] = vuln.get('ai_confidence', 0.5)
                result["properties"]["ai_is_false_positive"] = vuln.get('ai_is_false_positive', False)
                if vuln.get('ai_risk_level'):
                    result["properties"]["ai_risk_level"] = vuln['ai_risk_level']
                if vuln.get('ai_test_suggestions'):
                    result["properties"]["ai_suggested_tests"] = vuln['ai_test_suggestions']
            
            # Add fix suggestions - prioritize AI fix if available
            # Note: SARIF fixes must include artifactChanges, so we add as properties instead
            fix_suggestions = []
            if vuln.get('ai_fix_suggestion'):
                fix_suggestions.append(f"AI Suggested Fix: {vuln['ai_fix_suggestion']}")
            
            remediation = vuln.get('remediation')
            if remediation:
                fix_suggestions.append(remediation)
            
            if fix_suggestions:
                result["properties"]["fix_suggestions"] = fix_suggestions
            
            # Add related locations for cross-file vulnerabilities
            if vuln.get('source_file') and vuln.get('sink_file'):
                result["relatedLocations"] = [
                    {
                        "id": 0,
                        "physicalLocation": {
                            "artifactLocation": {"uri": vuln['source_file']},
                            "region": {"startLine": vuln.get('source_line', 1)}
                        },
                        "message": {"text": "Taint source"}
                    },
                    {
                        "id": 1,
                        "physicalLocation": {
                            "artifactLocation": {"uri": vuln['sink_file']},
                            "region": {"startLine": vuln.get('sink_line', 1)}
                        },
                        "message": {"text": "Vulnerable sink"}
                    }
                ]
            
            results.append(result)
        
        return results
    
    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type names"""
        vuln_type = vuln_type.lower().replace(' ', '_').replace('-', '_')
        
        # Map common variations
        mappings = {
            'sqli': 'sql_injection',
            'sql': 'sql_injection',
            'cross_site_scripting': 'xss',
            'command_injection': 'shell_injection',
            'os_command': 'shell_injection',
            'rce': 'code_injection',
            'remote_code_execution': 'code_injection',
            'lfi': 'path_traversal',
            'directory_traversal': 'path_traversal',
            'hardcoded_password': 'hardcoded_secret',
            'hardcoded_credentials': 'hardcoded_secret',
            'pii_exposure': 'student_pii_exposure',
            'student_data': 'student_pii_exposure',
        }
        
        return mappings.get(vuln_type, vuln_type)
    
    def _generate_fingerprint(self, vuln: Dict) -> str:
        """Generate a stable fingerprint for a vulnerability"""
        fp_data = f"{vuln.get('type', '')}-{vuln.get('line', 0)}-{vuln.get('snippet', '')[:100]}"
        return hashlib.sha256(fp_data.encode()).hexdigest()[:32]
    
    def _cwe_to_guid(self, cwe_id: str) -> str:
        """Convert CWE ID to a deterministic GUID in valid UUID v4 format"""
        # Generate a deterministic hash from the CWE ID
        hash_hex = hashlib.md5(cwe_id.encode()).hexdigest()
        # Format as UUID with proper version (4) and variant (8/9/a/b) bits
        # UUID format: xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx
        # M = version (4 for random), N = variant (8, 9, a, or b)
        guid = f"{hash_hex[0:8]}-{hash_hex[8:12]}-4{hash_hex[13:16]}-a{hash_hex[17:20]}-{hash_hex[20:32]}"
        return guid


def to_sarif(scan_results: Dict, filename: str = None) -> str:
    """Convenience function to convert results to SARIF string"""
    formatter = SarifFormatter()
    return formatter.format_to_string(scan_results, filename)


def validate_sarif(sarif_doc: Dict) -> bool:
    """Basic validation of SARIF structure"""
    required_fields = ['$schema', 'version', 'runs']
    
    if not all(field in sarif_doc for field in required_fields):
        return False
    
    if sarif_doc.get('version') != SARIF_VERSION:
        return False
    
    runs = sarif_doc.get('runs', [])
    if not runs or not isinstance(runs, list):
        return False
    
    for run in runs:
        if 'tool' not in run or 'results' not in run:
            return False
    
    return True
