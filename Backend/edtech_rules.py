"""
EdTech Security Rules - Comprehensive Ruleset

This module contains 50+ EdTech-specific security rules covering:
1. Student Data Protection (FERPA/COPPA compliance)
2. Exam & Assessment Integrity
3. AI/LLM Security in Education
4. LMS Integration Security
5. Proctoring System Security
6. Academic Integrity
7. Parent/Guardian Data Access
8. Grading System Security
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum
import re


class RuleCategory(Enum):
    STUDENT_DATA = "student_data_protection"
    EXAM_INTEGRITY = "exam_integrity"
    AI_SECURITY = "ai_security"
    LMS_SECURITY = "lms_security"
    PROCTORING = "proctoring"
    ACADEMIC_INTEGRITY = "academic_integrity"
    GRADING = "grading_security"
    AUTHENTICATION = "authentication"
    ACCESS_CONTROL = "access_control"


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class EdTechRule:
    """A single EdTech-specific security rule"""
    id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    pattern: str  # Regex pattern
    languages: List[str]
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    ferpa_relevant: bool = False
    coppa_relevant: bool = False
    examples: List[str] = field(default_factory=list)
    false_positive_hints: List[str] = field(default_factory=list)


class EdTechRuleEngine:
    """
    Comprehensive EdTech Security Rule Engine
    
    Contains 50+ rules specifically designed for educational platforms.
    """
    
    def __init__(self):
        self.rules: Dict[str, EdTechRule] = {}
        self._register_all_rules()
    
    def _register_all_rules(self):
        """Register all 50+ EdTech rules"""
        
        # ============================================
        # CATEGORY 1: STUDENT DATA PROTECTION (15 rules)
        # ============================================
        
        self._register(EdTechRule(
            id="EDTECH-001",
            name="Student PII in Logs",
            description="Detects logging of student personally identifiable information",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.HIGH,
            pattern=r"(console\.log|print|logger\.(info|debug|error)|logging\.(info|debug|error))\s*\([^)]*\b(student_?id|student_?name|cnic|ssn|date_?of_?birth|dob|parent_?email|guardian|address)\b",
            languages=["python", "javascript", "typescript"],
            remediation="Remove PII from logs or use structured logging with PII redaction",
            cwe_id="CWE-532",
            ferpa_relevant=True,
            coppa_relevant=True,
            examples=["console.log('Student:', studentName, studentDOB)"]
        ))
        
        self._register(EdTechRule(
            id="EDTECH-002",
            name="Student Data in URL Parameters",
            description="Student data passed in URL query strings (visible in logs/history)",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.HIGH,
            pattern=r"(redirect|navigate|href|location\.href|window\.location)\s*[=+]\s*.*\?(.*&)?(student_?id|grade|score|cnic|email)=",
            languages=["python", "javascript", "typescript"],
            remediation="Use POST requests or encrypted tokens instead of query parameters",
            cwe_id="CWE-598",
            ferpa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-003",
            name="Unencrypted Student Data Storage",
            description="Student data stored without encryption",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.CRITICAL,
            pattern=r"(localStorage|sessionStorage)\.(setItem|set)\s*\([^,]+,\s*[^)]*\b(student|grade|score|cnic|ssn|dob)\b",
            languages=["javascript", "typescript"],
            remediation="Encrypt sensitive data before storing in browser storage",
            cwe_id="CWE-312",
            ferpa_relevant=True,
            coppa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-004",
            name="Student Data in Comments",
            description="Real student data hardcoded in comments (potential data leak)",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.MEDIUM,
            pattern=r"(//|#|/\*|\"\"\").*\b(student.*:\s*\w+@|cnic.*:\s*\d{5}|ssn.*:\s*\d{3})",
            languages=["python", "javascript", "typescript"],
            remediation="Remove real student data from comments, use placeholders",
            cwe_id="CWE-615",
            ferpa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-005",
            name="Bulk Student Data Export Without Authorization",
            description="Exporting all student records without authorization check",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.CRITICAL,
            pattern=r"(Student|User)\.find\(\s*\{\s*\}\s*\)|SELECT\s+\*\s+FROM\s+(students|users)\s*(WHERE\s+1\s*=\s*1)?|\.findAll\(\s*\)",
            languages=["python", "javascript", "typescript"],
            remediation="Add proper authorization checks and pagination for data exports",
            cwe_id="CWE-285",
            ferpa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-006",
            name="Student Email Exposure in API Response",
            description="Student emails returned in API without need-to-know basis",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.MEDIUM,
            pattern=r"(res\.json|jsonify|return)\s*\([^)]*\b(student|user).*\.(email|parent_?email|guardian_?email)",
            languages=["python", "javascript", "typescript"],
            remediation="Only return email when specifically needed, hide by default",
            ferpa_relevant=True,
            coppa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-007",
            name="Student Photo/Avatar Without Consent Check",
            description="Displaying student photos without checking consent status",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.MEDIUM,
            pattern=r"(img|Image|avatar).*src\s*=.*\b(student|user)\.(photo|avatar|picture|image)",
            languages=["python", "javascript", "typescript"],
            remediation="Check consent status before displaying student images",
            coppa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-008",
            name="Cross-Student Data Access",
            description="One student accessing another student's data",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.CRITICAL,
            pattern=r"(Student|Submission|Grade)\.find.*\(\s*\{\s*_?id\s*:\s*(req\.(params|query|body)|params|query)",
            languages=["python", "javascript", "typescript"],
            remediation="Verify requesting user owns the resource or has explicit permission",
            cwe_id="CWE-639",
            ferpa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-009",
            name="Minor Student Age Data Exposure",
            description="Age or date of birth of minors exposed",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.HIGH,
            pattern=r"(return|res\.(json|send)|jsonify).*\b(age|date_?of_?birth|dob|birth_?date)\b",
            languages=["python", "javascript", "typescript"],
            remediation="Only expose age data when legally required, never for minors publicly",
            coppa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-010",
            name="Student Location Tracking",
            description="Tracking student geolocation without clear consent",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.HIGH,
            pattern=r"(geolocation|navigator\.geolocation|getCurrentPosition|watchPosition).*student",
            languages=["javascript", "typescript"],
            remediation="Obtain explicit consent before tracking student location",
            coppa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-011",
            name="Student Data Retention Violation",
            description="No data retention policy implemented for student data",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.MEDIUM,
            pattern=r"(Student|User)\.(create|save|insert)(?!.*expir|.*retention|.*delete_?after)",
            languages=["python", "javascript", "typescript"],
            remediation="Implement data retention policies with automatic deletion",
            ferpa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-012",
            name="Parent Contact Info Without Verification",
            description="Using parent contact information without verification",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.MEDIUM,
            pattern=r"(send_?email|sendEmail|send_?sms|sendSMS)\s*\([^)]*parent[^)]*\)(?!.*verif)",
            languages=["python", "javascript", "typescript"],
            remediation="Verify parent contact information before sending communications",
            coppa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-013",
            name="Student Health Data Exposure",
            description="Student health information (IEP, 504, allergies) exposed",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.CRITICAL,
            pattern=r"\b(iep|504_?plan|allerg|disabil|medication|health_?record|medical)\b.*\b(student|user)\b",
            languages=["python", "javascript", "typescript"],
            remediation="Health data requires additional encryption and access controls",
            ferpa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-014",
            name="Student SSN/Tax ID Processing",
            description="Social security or tax ID numbers being processed",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.CRITICAL,
            pattern=r"\b(ssn|social_?security|tax_?id|taxpayer)\b\s*[=:]",
            languages=["python", "javascript", "typescript"],
            remediation="SSNs should never be stored in EdTech platforms",
            ferpa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-015",
            name="Third-Party Student Data Sharing",
            description="Student data sent to third-party services without DPA",
            category=RuleCategory.STUDENT_DATA,
            severity=Severity.HIGH,
            pattern=r"(axios|fetch|request)\.(post|put)\s*\([^,]+,.*\b(student|user|grade)\b",
            languages=["python", "javascript", "typescript"],
            remediation="Ensure Data Processing Agreements exist before sharing student data",
            ferpa_relevant=True
        ))
        
        # ============================================
        # CATEGORY 2: EXAM & ASSESSMENT INTEGRITY (12 rules)
        # ============================================
        
        self._register(EdTechRule(
            id="EDTECH-016",
            name="Exam Answers in Client-Side Code",
            description="Correct answers or answer keys exposed in frontend code",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.CRITICAL,
            pattern=r"(correct_?answer|answer_?key|right_?answer|solution)\s*[=:]\s*['\"`\[]",
            languages=["javascript", "typescript"],
            remediation="Never send correct answers to client, validate on server only",
            examples=["const correctAnswer = 'B'"]
        ))
        
        self._register(EdTechRule(
            id="EDTECH-017",
            name="Exam Timer Manipulation Vulnerability",
            description="Exam timer can be manipulated client-side",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.HIGH,
            pattern=r"(setInterval|setTimeout)\s*\([^,]+,\s*(time_?remaining|exam_?duration|timer)",
            languages=["javascript", "typescript"],
            remediation="Track exam time server-side, client timer is display only",
            examples=["setInterval(() => timeRemaining--, 1000)"]
        ))
        
        self._register(EdTechRule(
            id="EDTECH-018",
            name="Direct Grade Update Without Validation",
            description="Grades can be updated with arbitrary values",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.CRITICAL,
            pattern=r"(Grade|Score|Mark|Result)\.(update|save|set)\s*\([^)]*\b(req\.(body|params)|body\.|params\.)",
            languages=["python", "javascript", "typescript"],
            remediation="Validate grades against possible values, check permissions",
            cwe_id="CWE-20"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-019",
            name="Exam Submission After Deadline",
            description="Submissions accepted without deadline validation",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.HIGH,
            pattern=r"(Submission|Answer|Assignment)\.create\s*\((?!.*deadline|.*due_?date|.*expires)",
            languages=["python", "javascript", "typescript"],
            remediation="Always validate submission time against exam deadline server-side"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-020",
            name="Multiple Exam Submissions Allowed",
            description="Student can submit multiple times without restriction",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.MEDIUM,
            pattern=r"(Submission|Answer)\.create\s*\((?!.*exists|.*find|.*count|.*unique)",
            languages=["python", "javascript", "typescript"],
            remediation="Check for existing submissions before accepting new ones"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-021",
            name="Exam Question Order Predictable",
            description="Question order is predictable (not randomized)",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.MEDIUM,
            pattern=r"questions\.(forEach|map|sort)\s*\((?!.*random|.*shuffle)",
            languages=["javascript", "typescript"],
            remediation="Randomize question order to prevent answer sharing"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-022",
            name="Answer Choice Order Not Randomized",
            description="Multiple choice options in predictable order",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.LOW,
            pattern=r"(options|choices|answers)\s*[=:]\s*\[\s*['\"`]",
            languages=["javascript", "typescript"],
            remediation="Randomize answer choice order per student"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-023",
            name="Exam Access Without Enrollment Check",
            description="Exam accessible without verifying student enrollment",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.HIGH,
            pattern=r"(getExam|loadExam|startExam)\s*\((?!.*enroll|.*course|.*class)",
            languages=["python", "javascript", "typescript"],
            remediation="Verify student is enrolled in course before granting exam access"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-024",
            name="Exam Score Calculation Client-Side",
            description="Exam scoring performed in browser instead of server",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.CRITICAL,
            pattern=r"(score|grade|marks)\s*[+\-]=.*\b(correct|right|match)\b",
            languages=["javascript", "typescript"],
            remediation="Calculate all scores server-side, never trust client calculations"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-025",
            name="Question Bank Exposed to Client",
            description="Full question bank sent to client at once",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.HIGH,
            pattern=r"(res\.(json|send)|return)\s*\(.*all_?questions|question_?bank|questions\s*:",
            languages=["python", "javascript", "typescript"],
            remediation="Only send current question, not the entire bank"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-026",
            name="Exam Session Hijacking Possible",
            description="Exam session can be taken over by another user",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.CRITICAL,
            pattern=r"(exam_?session|session_?id)\s*=\s*(req\.(query|params|body)|localStorage)",
            languages=["python", "javascript", "typescript"],
            remediation="Bind exam session to authenticated user, validate on each request"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-027",
            name="Exam Content Cacheable",
            description="Exam questions can be cached and shared",
            category=RuleCategory.EXAM_INTEGRITY,
            severity=Severity.MEDIUM,
            pattern=r"(Cache-Control|cache)\s*[=:]\s*['\"]?(public|max-age).*exam",
            languages=["python", "javascript", "typescript"],
            remediation="Set Cache-Control: no-store for exam content"
        ))
        
        # ============================================
        # CATEGORY 3: AI/LLM SECURITY (10 rules)
        # ============================================
        
        self._register(EdTechRule(
            id="EDTECH-028",
            name="Student Input in AI Prompt Without Sanitization",
            description="Direct student input used in LLM prompts",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.CRITICAL,
            pattern=r"(prompt|message|content)\s*[=:+]\s*.*\b(student_?input|user_?input|answer|submission|query|question)\b",
            languages=["python", "javascript", "typescript"],
            remediation="Sanitize and escape student input before including in prompts"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-029",
            name="AI Grading Without Human Review",
            description="AI-generated grades applied without human verification",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.HIGH,
            pattern=r"(grade|score|marks)\s*=.*\b(ai_?response|gpt_?response|llm_?output|completion)",
            languages=["python", "javascript", "typescript"],
            remediation="Require human review for AI-generated grades above certain thresholds"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-030",
            name="AI Tutoring Answer Leakage",
            description="AI tutor might reveal exam answers through hints",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.HIGH,
            pattern=r"(get_?hint|explain|help)\s*\(.*\b(exam|test|quiz|assessment)",
            languages=["python", "javascript", "typescript"],
            remediation="Implement guardrails to prevent AI from revealing answers"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-031",
            name="AI System Prompt Exposed",
            description="AI system prompt or instructions visible to users",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.MEDIUM,
            pattern=r"(system_?prompt|system_?message|instruction)\s*[=:].*\b(res\.(json|send)|return|console\.log)",
            languages=["python", "javascript", "typescript"],
            remediation="Never expose system prompts to end users"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-032",
            name="AI Response Without Content Filter",
            description="AI responses sent to students without content filtering",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.MEDIUM,
            pattern=r"(res\.(json|send))\s*\(.*\b(ai_?response|completion|generated)\b(?!.*filter|.*moderate|.*sanitize)",
            languages=["python", "javascript", "typescript"],
            remediation="Filter AI responses for inappropriate content before showing to students"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-033",
            name="AI Model Confusion Attack",
            description="User input designed to confuse AI about its role",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.HIGH,
            pattern=r"(user|student).*\b(ignore|forget|disregard)\s+(previous|above|all)\s+(instructions?|rules?|prompt)",
            languages=["python", "javascript", "typescript"],
            remediation="Detect and block prompt injection patterns"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-034",
            name="AI Training Data Leakage",
            description="Potential exposure of other students' data via AI",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.CRITICAL,
            pattern=r"(fine_?tune|train|fit)\s*\(.*\b(student|submission|answer)",
            languages=["python", "javascript", "typescript"],
            remediation="Never train models on identifiable student data without consent"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-035",
            name="AI Plagiarism Helper",
            description="AI used to generate or rephrase student work",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.MEDIUM,
            pattern=r"(rephrase|rewrite|paraphrase|improve)\s*\(.*\b(essay|assignment|homework|paper)",
            languages=["python", "javascript", "typescript"],
            remediation="Log AI assistance usage for academic integrity purposes"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-036",
            name="Hardcoded AI API Key",
            description="AI service API key exposed in code",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.CRITICAL,
            pattern=r"(openai|anthropic|deepseek|cohere)\s*(api)?_?key\s*[=:]\s*['\"`](sk-|api-)[a-zA-Z0-9]{20,}",
            languages=["python", "javascript", "typescript"],
            remediation="Use environment variables for API keys"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-037",
            name="AI Rate Limiting Missing",
            description="No rate limiting on AI endpoints (cost attack)",
            category=RuleCategory.AI_SECURITY,
            severity=Severity.MEDIUM,
            pattern=r"(app\.(post|get)|router\.(post|get))\s*\(['\"`](/api)?/(ai|chat|complete|generate)(?!.*rate|.*limit)",
            languages=["python", "javascript", "typescript"],
            remediation="Implement rate limiting on AI endpoints"
        ))
        
        # ============================================
        # CATEGORY 4: LMS/LTI SECURITY (8 rules)
        # ============================================
        
        self._register(EdTechRule(
            id="EDTECH-038",
            name="LTI Secret in Code",
            description="LTI consumer secret hardcoded",
            category=RuleCategory.LMS_SECURITY,
            severity=Severity.CRITICAL,
            pattern=r"(lti_?secret|consumer_?secret|shared_?secret)\s*[=:]\s*['\"`][a-zA-Z0-9]{8,}",
            languages=["python", "javascript", "typescript"],
            remediation="Store LTI secrets in environment variables"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-039",
            name="LTI Signature Not Verified",
            description="LTI OAuth signature not being validated",
            category=RuleCategory.LMS_SECURITY,
            severity=Severity.CRITICAL,
            pattern=r"(lti|launch)\s*\((?!.*verify|.*validate|.*signature)",
            languages=["python", "javascript", "typescript"],
            remediation="Always verify LTI OAuth signature before processing launch"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-040",
            name="LTI Nonce Replay Attack",
            description="LTI nonce not being tracked for replay prevention",
            category=RuleCategory.LMS_SECURITY,
            severity=Severity.HIGH,
            pattern=r"oauth_nonce(?!.*store|.*save|.*cache|.*check)",
            languages=["python", "javascript", "typescript"],
            remediation="Store and validate nonces to prevent replay attacks"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-041",
            name="SCORM Data Tampering",
            description="SCORM completion data modifiable by client",
            category=RuleCategory.LMS_SECURITY,
            severity=Severity.HIGH,
            pattern=r"(cmi\.|scorm\.).*[=]\s*(true|complete|passed|100)",
            languages=["javascript", "typescript"],
            remediation="Validate SCORM data server-side, don't trust client values"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-042",
            name="xAPI Statement Forgery",
            description="xAPI statements created without authentication",
            category=RuleCategory.LMS_SECURITY,
            severity=Severity.HIGH,
            pattern=r"xapi.*statement.*\{(?!.*auth|.*token|.*verify)",
            languages=["python", "javascript", "typescript"],
            remediation="Authenticate all xAPI statement submissions"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-043",
            name="Canvas API Token Exposed",
            description="Canvas LMS API token in code",
            category=RuleCategory.LMS_SECURITY,
            severity=Severity.CRITICAL,
            pattern=r"(canvas_?token|canvas_?api|instructure)\s*(token|key)?\s*[=:]\s*['\"`]\d{4}~[a-zA-Z0-9]{64}",
            languages=["python", "javascript", "typescript"],
            remediation="Use environment variables for Canvas API tokens"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-044",
            name="LMS Webhook Not Verified",
            description="LMS webhooks processed without origin verification",
            category=RuleCategory.LMS_SECURITY,
            severity=Severity.HIGH,
            pattern=r"(webhook|callback)\s*\((?!.*verify|.*signature|.*hmac)",
            languages=["python", "javascript", "typescript"],
            remediation="Verify webhook signatures before processing"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-045",
            name="Grade Passback Without SSL",
            description="LTI grade passback over insecure connection",
            category=RuleCategory.LMS_SECURITY,
            severity=Severity.HIGH,
            pattern=r"(outcome|grade|score).*url.*http://(?!localhost)",
            languages=["python", "javascript", "typescript"],
            remediation="Always use HTTPS for grade passback URLs"
        ))
        
        # ============================================
        # CATEGORY 5: PROCTORING SECURITY (7 rules)
        # ============================================
        
        self._register(EdTechRule(
            id="EDTECH-046",
            name="Proctoring Bypass Detection",
            description="Code that detects or evades proctoring software",
            category=RuleCategory.PROCTORING,
            severity=Severity.HIGH,
            pattern=r"(navigator\.webdriver|window\.Cypress|__SELENIUM|puppeteer)",
            languages=["javascript", "typescript"],
            remediation="Flag attempts to detect automation tools"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-047",
            name="Tab Visibility Override",
            description="Attempt to override document visibility detection",
            category=RuleCategory.PROCTORING,
            severity=Severity.HIGH,
            pattern=r"(visibilitychange|document\.hidden|document\.visibilityState).*prevent|override|stop",
            languages=["javascript", "typescript"],
            remediation="Log visibility override attempts"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-048",
            name="Screenshot/Recording Blocking",
            description="Attempt to block proctoring screenshots",
            category=RuleCategory.PROCTORING,
            severity=Severity.MEDIUM,
            pattern=r"(getDisplayMedia|mediaDevices|screen.*capture).*error|block|prevent",
            languages=["javascript", "typescript"],
            remediation="Flag screenshot blocking attempts"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-049",
            name="Virtual Machine Detection Bypass",
            description="Code to hide VM indicators from proctoring",
            category=RuleCategory.PROCTORING,
            severity=Severity.HIGH,
            pattern=r"(vmware|virtualbox|qemu|hyperv).*hide|spoof|mask",
            languages=["javascript", "typescript"],
            remediation="Flag VM spoofing attempts"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-050",
            name="Webcam Spoofing",
            description="Attempt to use virtual/fake webcam",
            category=RuleCategory.PROCTORING,
            severity=Severity.HIGH,
            pattern=r"(OBS|virtual.*cam|fake.*video|video.*loop)",
            languages=["javascript", "typescript"],
            remediation="Implement liveness detection for proctoring"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-051",
            name="Copy-Paste Detection Bypass",
            description="Circumventing copy-paste restrictions",
            category=RuleCategory.PROCTORING,
            severity=Severity.MEDIUM,
            pattern=r"(oncopy|onpaste|oncut).*return\s*(true|!1|void)",
            languages=["javascript", "typescript"],
            remediation="Implement server-side paste detection"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-052",
            name="Browser Extension Detection Bypass",
            description="Hiding browser extensions from proctoring",
            category=RuleCategory.PROCTORING,
            severity=Severity.MEDIUM,
            pattern=r"chrome\.runtime|browser\.runtime|extension.*hide",
            languages=["javascript", "typescript"],
            remediation="Flag extension hiding attempts"
        ))
        
        # ============================================
        # CATEGORY 6: AUTHENTICATION/ACCESS CONTROL (5 rules)
        # ============================================
        
        self._register(EdTechRule(
            id="EDTECH-053",
            name="Teacher Impersonation Possible",
            description="Role can be changed to teacher without verification",
            category=RuleCategory.ACCESS_CONTROL,
            severity=Severity.CRITICAL,
            pattern=r"(role|user_?type)\s*=\s*(req\.(body|params|query)|body\.|params\.)",
            languages=["python", "javascript", "typescript"],
            remediation="Never allow client to set their own role"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-054",
            name="Course Admin Access Without Verification",
            description="Admin actions without course ownership check",
            category=RuleCategory.ACCESS_CONTROL,
            severity=Severity.HIGH,
            pattern=r"(deleteCourse|updateCourse|addTeacher)\s*\((?!.*owner|.*admin|.*auth)",
            languages=["python", "javascript", "typescript"],
            remediation="Verify course ownership before admin actions"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-055",
            name="Parent Access to Wrong Child",
            description="Parent can access any child's data, not just their own",
            category=RuleCategory.ACCESS_CONTROL,
            severity=Severity.HIGH,
            pattern=r"(parent|guardian).*\b(child|student).*id\s*[=:]\s*(req|params|query)",
            languages=["python", "javascript", "typescript"],
            remediation="Verify parent-child relationship before showing data",
            coppa_relevant=True
        ))
        
        self._register(EdTechRule(
            id="EDTECH-056",
            name="Student Accessing Teacher-Only Endpoint",
            description="Missing role check on teacher endpoints",
            category=RuleCategory.ACCESS_CONTROL,
            severity=Severity.HIGH,
            pattern=r"(app\.(post|get)|router\.(post|get))\s*\(['\"`]/teacher/(?!.*role|.*auth|.*check)",
            languages=["python", "javascript", "typescript"],
            remediation="Add role verification middleware to teacher routes"
        ))
        
        self._register(EdTechRule(
            id="EDTECH-057",
            name="Class Enrollment Bypass",
            description="Student can enroll in any class without approval",
            category=RuleCategory.ACCESS_CONTROL,
            severity=Severity.MEDIUM,
            pattern=r"(enroll|join|add.*class)\s*\((?!.*approv|.*invite|.*code|.*verify)",
            languages=["python", "javascript", "typescript"],
            remediation="Require approval or enrollment codes for class joining"
        ))
        
    def _register(self, rule: EdTechRule):
        """Register a rule"""
        self.rules[rule.id] = rule
    
    def get_rules_by_category(self, category: RuleCategory) -> List[EdTechRule]:
        """Get all rules in a category"""
        return [r for r in self.rules.values() if r.category == category]
    
    def get_rules_for_language(self, language: str) -> List[EdTechRule]:
        """Get all rules applicable to a language"""
        return [r for r in self.rules.values() if language in r.languages]
    
    def get_ferpa_rules(self) -> List[EdTechRule]:
        """Get all FERPA-relevant rules"""
        return [r for r in self.rules.values() if r.ferpa_relevant]
    
    def get_coppa_rules(self) -> List[EdTechRule]:
        """Get all COPPA-relevant rules"""
        return [r for r in self.rules.values() if r.coppa_relevant]
    
    def scan_code(self, code: str, language: str, filename: str = "") -> List[Dict]:
        """Scan code against all applicable EdTech rules"""
        issues = []
        applicable_rules = self.get_rules_for_language(language)
        
        lines = code.split('\n')
        
        for rule in applicable_rules:
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                
                for i, line in enumerate(lines, 1):
                    if pattern.search(line):
                        issues.append({
                            'rule_id': rule.id,
                            'type': rule.name,
                            'description': rule.description,
                            'category': rule.category.value,
                            'severity': rule.severity.value,
                            'line': i,
                            'snippet': line.strip(),
                            'remediation': rule.remediation,
                            'cwe_id': rule.cwe_id,
                            'ferpa_relevant': rule.ferpa_relevant,
                            'coppa_relevant': rule.coppa_relevant,
                            'confidence': 0.85,
                            'scanner': 'edtech_rules'
                        })
            except re.error as e:
                print(f"Regex error in rule {rule.id}: {e}")
        
        return issues
    
    def get_statistics(self) -> Dict:
        """Get rule statistics"""
        return {
            'total_rules': len(self.rules),
            'by_category': {
                cat.value: len(self.get_rules_by_category(cat))
                for cat in RuleCategory
            },
            'by_severity': {
                sev.value: len([r for r in self.rules.values() if r.severity == sev])
                for sev in Severity
            },
            'ferpa_rules': len(self.get_ferpa_rules()),
            'coppa_rules': len(self.get_coppa_rules()),
            'languages': {
                'python': len(self.get_rules_for_language('python')),
                'javascript': len(self.get_rules_for_language('javascript')),
                'typescript': len(self.get_rules_for_language('typescript')),
            }
        }


# Convenience function
def scan_edtech_vulnerabilities(code: str, language: str, filename: str = "") -> List[Dict]:
    """Scan code for EdTech-specific vulnerabilities"""
    engine = EdTechRuleEngine()
    return engine.scan_code(code, language, filename)
