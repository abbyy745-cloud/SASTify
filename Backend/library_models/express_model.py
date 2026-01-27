"""
Express.js Framework Model

Describes the taint behavior of Express.js framework functions.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class TaintSource:
    function: str
    returns_tainted: bool = True
    tainted_return_type: str = "user_input"
    description: str = ""


@dataclass
class TaintSink:
    function: str
    dangerous_params: List[int]
    vuln_type: str
    severity: str = "High"
    description: str = ""


@dataclass
class Sanitizer:
    function: str
    sanitizes: List[str]
    description: str = ""


class ExpressModel:
    """Model of Express.js framework's security-relevant behavior"""
    
    def __init__(self):
        self.sources = self._define_sources()
        self.sinks = self._define_sinks()
        self.sanitizers = self._define_sanitizers()
        self.route_methods = self._define_route_methods()
    
    def _define_sources(self) -> Dict[str, TaintSource]:
        """Define Express sources (user input entry points)"""
        return {
            # Request body
            'req.body': TaintSource(
                function='req.body',
                tainted_return_type='request_body',
                description='Parsed request body (requires body-parser)'
            ),
            # Query string
            'req.query': TaintSource(
                function='req.query',
                tainted_return_type='query_string',
                description='URL query parameters'
            ),
            # URL parameters
            'req.params': TaintSource(
                function='req.params',
                tainted_return_type='url_params',
                description='Route parameters (/user/:id)'
            ),
            # Cookies
            'req.cookies': TaintSource(
                function='req.cookies',
                tainted_return_type='cookie',
                description='Request cookies'
            ),
            'req.signedCookies': TaintSource(
                function='req.signedCookies',
                tainted_return_type='cookie',
                description='Signed cookies'
            ),
            # Headers
            'req.headers': TaintSource(
                function='req.headers',
                tainted_return_type='header',
                description='Request headers'
            ),
            'req.get': TaintSource(
                function='req.get',
                tainted_return_type='header',
                description='Get specific header'
            ),
            # URL
            'req.url': TaintSource(
                function='req.url',
                tainted_return_type='url',
                description='Request URL'
            ),
            'req.path': TaintSource(
                function='req.path',
                tainted_return_type='url_path',
                description='Request path'
            ),
            'req.originalUrl': TaintSource(
                function='req.originalUrl',
                tainted_return_type='url',
                description='Original request URL'
            ),
            # File uploads
            'req.file': TaintSource(
                function='req.file',
                tainted_return_type='file_upload',
                description='Uploaded file (multer single)'
            ),
            'req.files': TaintSource(
                function='req.files',
                tainted_return_type='file_upload',
                description='Uploaded files (multer array)'
            ),
            # EdTech: Student data
            'Student.findById': TaintSource(
                function='Student.findById',
                tainted_return_type='pii_data',
                description='Student record from MongoDB'
            ),
            'User.findById': TaintSource(
                function='User.findById',
                tainted_return_type='pii_data',
                description='User record from database'
            ),
        }
    
    def _define_sinks(self) -> Dict[str, TaintSink]:
        """Define Express sinks"""
        return {
            # Response - XSS
            'res.send': TaintSink(
                function='res.send',
                dangerous_params=[0],
                vuln_type='xss',
                severity='High',
                description='Send response - if HTML, XSS risk'
            ),
            'res.write': TaintSink(
                function='res.write',
                dangerous_params=[0],
                vuln_type='xss',
                severity='High',
                description='Write to response'
            ),
            # Redirect - Open Redirect
            'res.redirect': TaintSink(
                function='res.redirect',
                dangerous_params=[0],
                vuln_type='open_redirect',
                severity='Medium',
                description='HTTP redirect'
            ),
            # File operations - Path Traversal
            'res.sendFile': TaintSink(
                function='res.sendFile',
                dangerous_params=[0],
                vuln_type='path_traversal',
                severity='High',
                description='Send file to client'
            ),
            'res.download': TaintSink(
                function='res.download',
                dangerous_params=[0],
                vuln_type='path_traversal',
                severity='High',
                description='Download file'
            ),
            # Child process - Command Injection
            'child_process.exec': TaintSink(
                function='exec',
                dangerous_params=[0],
                vuln_type='shell_injection',
                severity='Critical',
                description='Execute shell command'
            ),
            'child_process.execSync': TaintSink(
                function='execSync',
                dangerous_params=[0],
                vuln_type='shell_injection',
                severity='Critical',
                description='Synchronous shell execution'
            ),
            'child_process.spawn': TaintSink(
                function='spawn',
                dangerous_params=[0, 1],
                vuln_type='shell_injection',
                severity='Critical',
                description='Spawn process'
            ),
            # Code execution
            'eval': TaintSink(
                function='eval',
                dangerous_params=[0],
                vuln_type='code_injection',
                severity='Critical',
                description='Evaluate JavaScript code'
            ),
            'Function': TaintSink(
                function='new Function',
                dangerous_params=[0],
                vuln_type='code_injection',
                severity='Critical',
                description='Create function from string'
            ),
            'setTimeout': TaintSink(
                function='setTimeout',
                dangerous_params=[0],
                vuln_type='code_injection',
                severity='High',
                description='If string passed, executes as code'
            ),
            'setInterval': TaintSink(
                function='setInterval',
                dangerous_params=[0],
                vuln_type='code_injection',
                severity='High',
                description='If string passed, executes as code'
            ),
            # SSRF
            'axios': TaintSink(
                function='axios',
                dangerous_params=[0],
                vuln_type='ssrf',
                severity='High',
                description='HTTP request with user-controlled URL'
            ),
            'fetch': TaintSink(
                function='fetch',
                dangerous_params=[0],
                vuln_type='ssrf',
                severity='High',
                description='Fetch with user-controlled URL'
            ),
            'http.request': TaintSink(
                function='http.request',
                dangerous_params=[0],
                vuln_type='ssrf',
                severity='High',
                description='HTTP request'
            ),
            # EdTech: Grade manipulation
            'Grade.updateOne': TaintSink(
                function='Grade.updateOne',
                dangerous_params=[1],  # The update object
                vuln_type='grade_manipulation',
                severity='Critical',
                description='Direct grade update - requires validation'
            ),
            'Score.save': TaintSink(
                function='Score.save',
                dangerous_params=[0],
                vuln_type='score_tampering',
                severity='Critical',
                description='Score save without validation'
            ),
        }
    
    def _define_sanitizers(self) -> Dict[str, Sanitizer]:
        """Define Express sanitizers"""
        return {
            # DOMPurify
            'DOMPurify.sanitize': Sanitizer(
                function='DOMPurify.sanitize',
                sanitizes=['xss'],
                description='Sanitize HTML'
            ),
            # xss library
            'xss': Sanitizer(
                function='xss',
                sanitizes=['xss'],
                description='XSS filter library'
            ),
            # Encoding
            'encodeURIComponent': Sanitizer(
                function='encodeURIComponent',
                sanitizes=['xss', 'open_redirect'],
                description='URL encode'
            ),
            'encodeURI': Sanitizer(
                function='encodeURI',
                sanitizes=['xss', 'open_redirect'],
                description='URL encode'
            ),
            # express-validator
            'sanitize': Sanitizer(
                function='sanitize',
                sanitizes=['xss', 'sql_injection'],
                description='express-validator sanitize'
            ),
            'escape': Sanitizer(
                function='escape',
                sanitizes=['xss'],
                description='Escape HTML entities'
            ),
            # Path sanitization
            'path.basename': Sanitizer(
                function='path.basename',
                sanitizes=['path_traversal'],
                description='Get base filename'
            ),
            'path.normalize': Sanitizer(
                function='path.normalize',
                sanitizes=['path_traversal'],
                description='Normalize path'
            ),
        }
    
    def _define_route_methods(self) -> Set[str]:
        """Methods that define routes (entry points)"""
        return {
            'app.get',
            'app.post',
            'app.put',
            'app.delete',
            'app.patch',
            'app.all',
            'app.use',
            'router.get',
            'router.post',
            'router.put',
            'router.delete',
            'router.patch',
            'router.all',
            'router.use',
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
    
    def is_route_definition(self, func_name: str) -> bool:
        """Check if this is a route definition"""
        return any(route in func_name for route in self.route_methods)
