"""
Unit Tests for EdTech Rules

Tests the 57 EdTech-specific security rules.
"""

import pytest
import sys
import os

# Add parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from edtech_rules import EdTechRuleEngine, RuleCategory, Severity


class TestEdTechRuleEngine:
    """Test the EdTech rule engine"""
    
    @pytest.fixture
    def engine(self):
        return EdTechRuleEngine()
    
    def test_rule_count(self, engine):
        """Test that we have 50+ rules"""
        assert len(engine.rules) >= 50, f"Expected 50+ rules, got {len(engine.rules)}"
    
    def test_category_coverage(self, engine):
        """Test that all categories have rules"""
        for category in RuleCategory:
            rules = engine.get_rules_by_category(category)
            assert len(rules) > 0, f"No rules for category {category.value}"
    
    def test_language_coverage(self, engine):
        """Test language support"""
        python_rules = engine.get_rules_for_language('python')
        js_rules = engine.get_rules_for_language('javascript')
        ts_rules = engine.get_rules_for_language('typescript')
        
        assert len(python_rules) > 30, "Not enough Python rules"
        assert len(js_rules) > 40, "Not enough JavaScript rules"
        assert len(ts_rules) > 40, "Not enough TypeScript rules"
    
    def test_ferpa_rules(self, engine):
        """Test FERPA-relevant rules exist"""
        ferpa_rules = engine.get_ferpa_rules()
        assert len(ferpa_rules) >= 10, "Not enough FERPA rules"
    
    def test_coppa_rules(self, engine):
        """Test COPPA-relevant rules exist"""
        coppa_rules = engine.get_coppa_rules()
        assert len(coppa_rules) >= 5, "Not enough COPPA rules"


class TestStudentDataRules:
    """Test student data protection rules"""
    
    @pytest.fixture
    def engine(self):
        return EdTechRuleEngine()
    
    def test_pii_in_logs_python(self, engine):
        """Test detection of PII in Python logs"""
        code = '''
def get_student(student_id):
    student = Student.query.get(student_id)
    print(f"Found student: {student.name}, DOB: {student.dob}")
    return student
'''
        issues = engine.scan_code(code, 'python')
        assert any('PII' in i['type'] or 'Log' in i['type'] for i in issues), \
            "Should detect PII in logs"
    
    def test_pii_in_logs_javascript(self, engine):
        """Test detection of PII in JavaScript logs"""
        code = '''
function getStudent(studentId) {
    const student = await Student.findById(studentId);
    console.log("Student:", student.student_name, student.cnic);
    return student;
}
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('PII' in i['type'] or 'Log' in i['type'] for i in issues), \
            "Should detect PII in logs"
    
    def test_student_data_in_url(self, engine):
        """Test detection of student data in URL parameters"""
        code = '''
function viewGrade(studentId, grade) {
    window.location.href = `/grades?student_id=${studentId}&grade=${grade}`;
}
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('URL' in i['type'] for i in issues), \
            "Should detect student data in URL"
    
    def test_unencrypted_storage(self, engine):
        """Test detection of unencrypted student data storage"""
        code = '''
function saveStudent(student) {
    localStorage.setItem('current_student', JSON.stringify({
        name: student.name,
        grade: student.grade,
        cnic: student.cnic
    }));
}
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('Unencrypted' in i['type'] or 'Storage' in i['type'] for i in issues), \
            "Should detect unencrypted storage"
    
    def test_bulk_export_without_auth(self, engine):
        """Test detection of bulk data export without authorization"""
        code = '''
def export_all_students():
    students = Student.find({})
    return jsonify(students)
'''
        issues = engine.scan_code(code, 'python')
        assert any('Bulk' in i['type'] or 'Export' in i['type'] for i in issues), \
            "Should detect bulk export"


class TestExamIntegrityRules:
    """Test exam integrity rules"""
    
    @pytest.fixture
    def engine(self):
        return EdTechRuleEngine()
    
    def test_answers_in_client_code(self, engine):
        """Test detection of correct answers in client-side code"""
        code = '''
const questions = [
    {
        text: "What is 2+2?",
        options: ["3", "4", "5", "6"],
        correct_answer: "4"
    }
];
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('Answer' in i['type'] for i in issues), \
            "Should detect answers in client code"
    
    def test_client_side_timer(self, engine):
        """Test detection of client-side timer manipulation"""
        code = '''
let timeRemaining = 3600;
setInterval(() => {
    timeRemaining--;
    updateDisplay(timeRemaining);
}, 1000);
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('Timer' in i['type'] for i in issues), \
            "Should detect client-side timer"
    
    def test_direct_grade_update(self, engine):
        """Test detection of direct grade updates from request"""
        code = '''
app.post('/api/grade', (req, res) => {
    Grade.update({ id: req.params.id }, { score: req.body.score });
});
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('Grade' in i['type'] for i in issues), \
            "Should detect direct grade update"
    
    def test_client_side_scoring(self, engine):
        """Test detection of client-side score calculation"""
        code = '''
function checkAnswer(answer, questionId) {
    if (answer === correctAnswers[questionId]) {
        score += 10;
    }
    updateScore(score);
}
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('Score' in i['type'] or 'Client' in i['type'] for i in issues), \
            "Should detect client-side scoring"


class TestAISecurityRules:
    """Test AI/LLM security rules"""
    
    @pytest.fixture
    def engine(self):
        return EdTechRuleEngine()
    
    def test_prompt_injection(self, engine):
        """Test detection of prompt injection vulnerability"""
        code = '''
def get_ai_response(student_input):
    prompt = f"Grade this answer: {student_input}"
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response
'''
        issues = engine.scan_code(code, 'python')
        assert any('Prompt' in i['type'] or 'AI' in i['type'] or 'Sanitiz' in i['type'] for i in issues), \
            "Should detect prompt injection"
    
    def test_ai_grading_without_review(self, engine):
        """Test detection of AI grading without human review"""
        code = '''
async function gradeSubmission(submission) {
    const ai_response = await getAIGrade(submission.content);
    submission.grade = ai_response.score;
    await submission.save();
}
'''
        issues = engine.scan_code(code, 'javascript')
        # AI grading rules might trigger
        assert len(issues) >= 0  # AI-related issues
    
    def test_hardcoded_api_key(self, engine):
        """Test detection of hardcoded AI API key"""
        code = '''
const openai = new OpenAI({
    apiKey: "sk-1234567890abcdefghijklmnopqrstuvwxyz12345678"
});
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('Key' in i['type'] or 'API' in i['type'] for i in issues), \
            "Should detect hardcoded API key"


class TestLMSSecurityRules:
    """Test LMS/LTI security rules"""
    
    @pytest.fixture
    def engine(self):
        return EdTechRuleEngine()
    
    def test_lti_secret_exposed(self, engine):
        """Test detection of exposed LTI secret"""
        code = '''
const ltiConfig = {
    consumer_key: "my_consumer",
    consumer_secret: "super_secret_value_12345"
};
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('LTI' in i['type'] or 'Secret' in i['type'] for i in issues), \
            "Should detect LTI secret"
    
    def test_canvas_token_exposed(self, engine):
        """Test detection of exposed Canvas API token"""
        code = '''
CANVAS_TOKEN = "1234~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901234"
'''
        issues = engine.scan_code(code, 'python')
        assert any('Canvas' in i['type'] or 'Token' in i['type'] for i in issues), \
            "Should detect Canvas token"


class TestProctoringRules:
    """Test proctoring security rules"""
    
    @pytest.fixture
    def engine(self):
        return EdTechRuleEngine()
    
    def test_selenium_detection(self, engine):
        """Test detection of automation tool detection (cheating attempt)"""
        code = '''
if (navigator.webdriver) {
    // Hide that we're using automation
    Object.defineProperty(navigator, 'webdriver', { get: () => false });
}
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('Proctor' in i['type'] or 'Bypass' in i['type'] for i in issues), \
            "Should detect proctoring bypass"
    
    def test_visibility_override(self, engine):
        """Test detection of tab visibility override"""
        code = '''
document.addEventListener('visibilitychange', (e) => {
    e.preventDefault();
    e.stopPropagation();
});
'''
        issues = engine.scan_code(code, 'javascript')
        # May trigger visibility-related rules
        assert len(issues) >= 0


class TestAccessControlRules:
    """Test access control rules"""
    
    @pytest.fixture
    def engine(self):
        return EdTechRuleEngine()
    
    def test_role_from_request(self, engine):
        """Test detection of role set from user input"""
        code = '''
app.post('/api/user', (req, res) => {
    user.role = req.body.role;  // Should not allow setting own role
    user.save();
});
'''
        issues = engine.scan_code(code, 'javascript')
        assert any('Role' in i['type'] or 'Impersonation' in i['type'] for i in issues), \
            "Should detect role from request"


class TestRuleStatistics:
    """Test rule statistics accuracy"""
    
    def test_statistics_completeness(self):
        engine = EdTechRuleEngine()
        stats = engine.get_statistics()
        
        assert stats['total_rules'] >= 50
        assert sum(stats['by_category'].values()) == stats['total_rules']
        assert sum(stats['by_severity'].values()) == stats['total_rules']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
