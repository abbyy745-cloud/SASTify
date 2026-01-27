"""
AI/LLM Library Model - EdTech Specific

Describes the taint behavior of AI/LLM libraries for detecting
prompt injection and AI-related vulnerabilities.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class TaintSource:
    function: str
    returns_tainted: bool = True
    tainted_return_type: str = "ai_output"
    description: str = ""


@dataclass
class TaintSink:
    function: str
    dangerous_params: List[int]
    vuln_type: str
    severity: str = "High"
    description: str = ""
    param_names: List[str] = None  # For named params like 'messages'


@dataclass
class Sanitizer:
    function: str
    sanitizes: List[str]
    description: str = ""


class AIModel:
    """
    Model of AI/LLM libraries' security-relevant behavior.
    
    Critical for EdTech platforms that use:
    - AI tutoring systems
    - Automated grading
    - Content generation
    - Plagiarism detection
    """
    
    def __init__(self):
        self.sources = self._define_sources()
        self.sinks = self._define_sinks()
        self.sanitizers = self._define_sanitizers()
    
    def _define_sources(self) -> Dict[str, TaintSource]:
        """Define AI sources (AI-generated content that may need validation)"""
        return {
            # OpenAI responses
            'openai.ChatCompletion.create': TaintSource(
                function='openai.ChatCompletion.create',
                tainted_return_type='ai_generated_content',
                description='ChatGPT response - may contain hallucinations'
            ),
            'openai.Completion.create': TaintSource(
                function='openai.Completion.create',
                tainted_return_type='ai_generated_content',
                description='GPT completion response'
            ),
            # LangChain
            'langchain.LLMChain.run': TaintSource(
                function='LLMChain.run',
                tainted_return_type='ai_generated_content',
                description='LangChain LLM response'
            ),
            'langchain.Agent.run': TaintSource(
                function='Agent.run',
                tainted_return_type='ai_agent_output',
                description='LangChain agent output - high risk'
            ),
            # Anthropic
            'anthropic.complete': TaintSource(
                function='anthropic.complete',
                tainted_return_type='ai_generated_content',
                description='Claude response'
            ),
            # Local/Other models
            'transformers.pipeline': TaintSource(
                function='pipeline',
                tainted_return_type='ai_generated_content',
                description='HuggingFace model output'
            ),
        }
    
    def _define_sinks(self) -> Dict[str, TaintSink]:
        """Define AI sinks (prompt injection points)"""
        return {
            # OpenAI - Python
            'openai.ChatCompletion.create': TaintSink(
                function='openai.ChatCompletion.create',
                dangerous_params=[-1],  # Named param
                param_names=['messages'],
                vuln_type='prompt_injection',
                severity='Critical',
                description='ChatGPT API - messages param susceptible to injection'
            ),
            'openai.Completion.create': TaintSink(
                function='openai.Completion.create',
                dangerous_params=[0],
                param_names=['prompt'],
                vuln_type='prompt_injection',
                severity='Critical',
                description='GPT completion API - prompt param'
            ),
            # OpenAI - JavaScript
            'openai.createChatCompletion': TaintSink(
                function='openai.createChatCompletion',
                dangerous_params=[-1],
                param_names=['messages'],
                vuln_type='prompt_injection',
                severity='Critical',
                description='OpenAI JS SDK chat completion'
            ),
            'openai.createCompletion': TaintSink(
                function='openai.createCompletion',
                dangerous_params=[-1],
                param_names=['prompt'],
                vuln_type='prompt_injection',
                severity='Critical',
                description='OpenAI JS SDK completion'
            ),
            # LangChain
            'langchain.LLMChain.run': TaintSink(
                function='LLMChain.run',
                dangerous_params=[0],
                vuln_type='prompt_injection',
                severity='Critical',
                description='LangChain LLM chain - input flows to prompt'
            ),
            'langchain.LLMChain.invoke': TaintSink(
                function='LLMChain.invoke',
                dangerous_params=[0],
                vuln_type='prompt_injection',
                severity='Critical',
                description='LangChain invoke'
            ),
            'langchain.Agent.run': TaintSink(
                function='Agent.run',
                dangerous_params=[0],
                vuln_type='prompt_injection',
                severity='Critical',
                description='LangChain agent - can execute arbitrary actions'
            ),
            'langchain.PromptTemplate.format': TaintSink(
                function='PromptTemplate.format',
                dangerous_params=[-1],  # All kwargs
                vuln_type='prompt_injection',
                severity='High',
                description='Prompt template formatting'
            ),
            # Anthropic
            'anthropic.Anthropic.messages.create': TaintSink(
                function='messages.create',
                dangerous_params=[-1],
                param_names=['messages'],
                vuln_type='prompt_injection',
                severity='Critical',
                description='Claude messages API'
            ),
            # EdTech-specific: AI Grading
            'grade_with_ai': TaintSink(
                function='grade_with_ai',
                dangerous_params=[0, 1],  # student_answer, rubric
                vuln_type='ai_grading_manipulation',
                severity='Critical',
                description='AI-based grading - student can inject in answer'
            ),
            'evaluate_submission': TaintSink(
                function='evaluate_submission',
                dangerous_params=[0],
                vuln_type='ai_grading_manipulation',
                severity='Critical',
                description='AI submission evaluation'
            ),
            # EdTech-specific: AI Tutoring
            'get_ai_hint': TaintSink(
                function='get_ai_hint',
                dangerous_params=[0],
                vuln_type='prompt_injection',
                severity='High',
                description='AI tutoring hint - could leak answers'
            ),
            'explain_solution': TaintSink(
                function='explain_solution',
                dangerous_params=[0],
                vuln_type='prompt_injection',
                severity='High',
                description='AI solution explanation'
            ),
        }
    
    def _define_sanitizers(self) -> Dict[str, Sanitizer]:
        """Define AI input sanitizers"""
        return {
            # Custom sanitizers that should be implemented
            'sanitize_prompt': Sanitizer(
                function='sanitize_prompt',
                sanitizes=['prompt_injection'],
                description='Custom prompt sanitization'
            ),
            'escape_user_content': Sanitizer(
                function='escape_user_content',
                sanitizes=['prompt_injection'],
                description='Escape user content before including in prompt'
            ),
            # Content filtering
            'filter_injection_patterns': Sanitizer(
                function='filter_injection_patterns',
                sanitizes=['prompt_injection'],
                description='Filter known injection patterns'
            ),
            # Rate limiting / detection (not really sanitizers but mitigations)
            'detect_prompt_injection': Sanitizer(
                function='detect_prompt_injection',
                sanitizes=['prompt_injection'],
                description='Detect and reject injection attempts'
            ),
        }
    
    def is_source(self, func_name: str) -> bool:
        for source_name in self.sources:
            if source_name in func_name:
                return True
        return False
    
    def is_sink(self, func_name: str) -> Optional[TaintSink]:
        for sink_name, sink in self.sinks.items():
            if sink_name in func_name:
                return sink
        return None
    
    def is_sanitizer(self, func_name: str) -> Optional[Sanitizer]:
        for san_name, san in self.sanitizers.items():
            if san_name in func_name:
                return san
        return None
    
    def get_edtech_ai_risks(self) -> List[str]:
        """Get EdTech-specific AI security risks"""
        return [
            "Prompt Injection: Students injecting commands in AI tutoring/grading systems",
            "Answer Leakage: AI accidentally revealing exam answers through hints",
            "Grade Manipulation: Injecting prompts to influence AI grading",
            "Content Generation Abuse: Using AI to generate inappropriate content",
            "Jailbreaking: Breaking AI safety guardrails in educational contexts",
            "Data Exfiltration: Using AI to extract training data or other students' work",
        ]
