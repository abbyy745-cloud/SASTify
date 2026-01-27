"""
Flask Framework Model

Describes the taint behavior of Flask framework functions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class TaintSource:
    """A function that returns tainted (user-controlled) data"""
    function: str
    returns_tainted: bool = True
    tainted_return_type: str = "user_input"
    description: str = ""


@dataclass
class TaintSink:
    """A function that is dangerous if passed tainted data"""
    function: str
    dangerous_params: List[int]  # Indices of dangerous parameters
    vuln_type: str
    severity: str = "High"
    description: str = ""


@dataclass  
class Sanitizer:
    """A function that sanitizes/cleans tainted data"""
    function: str
    sanitizes: List[str]  # Types of vulnerabilities it prevents
    description: str = ""


class FlaskModel:
    """Model of Flask framework's security-relevant behavior"""
    
    def __init__(self):
        self.sources = self._define_sources()
        self.sinks = self._define_sinks()
        self.sanitizers = self._define_sanitizers()
        self.route_decorators = self._define_route_decorators()
    
    def _define_sources(self) -> Dict[str, TaintSource]:
        """Define Flask sources (user input entry points)"""
        return {
            # Request object - main source of user input
            'request.args': TaintSource(
                function='request.args',
                tainted_return_type='query_string',
                description='URL query parameters'
            ),
            'request.args.get': TaintSource(
                function='request.args.get',
                tainted_return_type='query_string',
                description='Get specific query parameter'
            ),
            'request.form': TaintSource(
                function='request.form',
                tainted_return_type='form_data',
                description='Form POST data'
            ),
            'request.form.get': TaintSource(
                function='request.form.get',
                tainted_return_type='form_data',
                description='Get specific form field'
            ),
            'request.json': TaintSource(
                function='request.json',
                tainted_return_type='json_body',
                description='Parsed JSON request body'
            ),
            'request.data': TaintSource(
                function='request.data',
                tainted_return_type='raw_body',
                description='Raw request body bytes'
            ),
            'request.values': TaintSource(
                function='request.values',
                tainted_return_type='user_input',
                description='Combined args and form'
            ),
            'request.cookies': TaintSource(
                function='request.cookies',
                tainted_return_type='cookie',
                description='Request cookies'
            ),
            'request.cookies.get': TaintSource(
                function='request.cookies.get',
                tainted_return_type='cookie',
                description='Get specific cookie'
            ),
            'request.headers': TaintSource(
                function='request.headers',
                tainted_return_type='header',
                description='Request headers'
            ),
            'request.headers.get': TaintSource(
                function='request.headers.get',
                tainted_return_type='header',
                description='Get specific header'
            ),
            'request.files': TaintSource(
                function='request.files',
                tainted_return_type='file_upload',
                description='Uploaded files'
            ),
            'request.url': TaintSource(
                function='request.url',
                tainted_return_type='url',
                description='Full request URL'
            ),
            'request.path': TaintSource(
                function='request.path',
                tainted_return_type='url_path',
                description='Request path'
            ),
        }
    
    def _define_sinks(self) -> Dict[str, TaintSink]:
        """Define Flask sinks (dangerous functions)"""
        return {
            # Template rendering - XSS
            'render_template_string': TaintSink(
                function='render_template_string',
                dangerous_params=[0],
                vuln_type='xss',
                severity='High',
                description='Renders string as Jinja2 template'
            ),
            'Markup': TaintSink(
                function='Markup',
                dangerous_params=[0],
                vuln_type='xss',
                severity='High',
                description='Marks string as safe HTML'
            ),
            # File operations - Path Traversal
            'send_file': TaintSink(
                function='send_file',
                dangerous_params=[0],
                vuln_type='path_traversal',
                severity='High',
                description='Sends file to client'
            ),
            'send_from_directory': TaintSink(
                function='send_from_directory',
                dangerous_params=[1],  # filename param
                vuln_type='path_traversal',
                severity='High',
                description='Sends file from directory'
            ),
            # Redirect - Open Redirect
            'redirect': TaintSink(
                function='redirect',
                dangerous_params=[0],
                vuln_type='open_redirect',
                severity='Medium',
                description='HTTP redirect'
            ),
        }
    
    def _define_sanitizers(self) -> Dict[str, Sanitizer]:
        """Define Flask sanitizers"""
        return {
            'escape': Sanitizer(
                function='markupsafe.escape',
                sanitizes=['xss'],
                description='Escapes HTML entities'
            ),
            'secure_filename': Sanitizer(
                function='werkzeug.utils.secure_filename',
                sanitizes=['path_traversal'],
                description='Sanitizes filename'
            ),
        }
    
    def _define_route_decorators(self) -> Set[str]:
        """Decorators that mark a function as a route (entry point)"""
        return {
            'app.route',
            'blueprint.route',
            'app.get',
            'app.post',
            'app.put',
            'app.delete',
            'app.patch',
        }
    
    def is_source(self, func_name: str) -> bool:
        """Check if a function is a known source"""
        for source_name in self.sources:
            if source_name in func_name:
                return True
        return False
    
    def is_sink(self, func_name: str) -> Optional[TaintSink]:
        """Check if a function is a known sink"""
        for sink_name, sink in self.sinks.items():
            if sink_name in func_name:
                return sink
        return None
    
    def is_sanitizer(self, func_name: str) -> Optional[Sanitizer]:
        """Check if a function is a known sanitizer"""
        for san_name, san in self.sanitizers.items():
            if san_name in func_name:
                return san
        return None
