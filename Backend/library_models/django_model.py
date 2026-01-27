"""
Django Framework Model

Describes the taint behavior of Django framework functions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


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


class DjangoModel:
    """Model of Django framework's security-relevant behavior"""
    
    def __init__(self):
        self.sources = self._define_sources()
        self.sinks = self._define_sinks()
        self.sanitizers = self._define_sanitizers()
    
    def _define_sources(self) -> Dict[str, TaintSource]:
        """Define Django sources"""
        return {
            # Request object
            'request.GET': TaintSource(
                function='request.GET',
                tainted_return_type='query_string',
                description='Query parameters (QueryDict)'
            ),
            'request.GET.get': TaintSource(
                function='request.GET.get',
                tainted_return_type='query_string',
                description='Get specific query param'
            ),
            'request.POST': TaintSource(
                function='request.POST',
                tainted_return_type='form_data',
                description='POST form data'
            ),
            'request.POST.get': TaintSource(
                function='request.POST.get',
                tainted_return_type='form_data',
                description='Get specific POST field'
            ),
            'request.body': TaintSource(
                function='request.body',
                tainted_return_type='raw_body',
                description='Raw request body'
            ),
            'request.COOKIES': TaintSource(
                function='request.COOKIES',
                tainted_return_type='cookie',
                description='Request cookies'
            ),
            'request.META': TaintSource(
                function='request.META',
                tainted_return_type='header',
                description='Request metadata/headers'
            ),
            'request.FILES': TaintSource(
                function='request.FILES',
                tainted_return_type='file_upload',
                description='Uploaded files'
            ),
            'request.path': TaintSource(
                function='request.path',
                tainted_return_type='url_path',
                description='Request path'
            ),
            # EdTech: Student data from ORM
            'Student.objects.get': TaintSource(
                function='Student.objects.get',
                tainted_return_type='pii_data',
                description='Student record from database'
            ),
            'User.objects.get': TaintSource(
                function='User.objects.get',
                tainted_return_type='pii_data',
                description='User record from database'
            ),
        }
    
    def _define_sinks(self) -> Dict[str, TaintSink]:
        """Define Django sinks"""
        return {
            # Raw SQL
            'Model.objects.raw': TaintSink(
                function='Model.objects.raw',
                dangerous_params=[0],
                vuln_type='sql_injection',
                severity='Critical',
                description='Raw SQL query'
            ),
            'cursor.execute': TaintSink(
                function='cursor.execute',
                dangerous_params=[0],
                vuln_type='sql_injection',
                severity='Critical',
                description='Raw SQL execution'
            ),
            'connection.execute': TaintSink(
                function='connection.execute',
                dangerous_params=[0],
                vuln_type='sql_injection',
                severity='Critical',
                description='Database connection execute'
            ),
            # Extra/RawSQL
            'RawSQL': TaintSink(
                function='RawSQL',
                dangerous_params=[0],
                vuln_type='sql_injection',
                severity='Critical',
                description='Raw SQL expression'
            ),
            'extra': TaintSink(
                function='extra',
                dangerous_params=[0, 1],  # where, params
                vuln_type='sql_injection',
                severity='Critical',
                description='QuerySet.extra()'
            ),
            # Template - XSS
            'mark_safe': TaintSink(
                function='mark_safe',
                dangerous_params=[0],
                vuln_type='xss',
                severity='High',
                description='Marks string as safe HTML'
            ),
            'Template': TaintSink(
                function='django.template.Template',
                dangerous_params=[0],
                vuln_type='xss',
                severity='High',
                description='Template from string'
            ),
            # File handling - Path Traversal
            'FileResponse': TaintSink(
                function='FileResponse',
                dangerous_params=[0],
                vuln_type='path_traversal',
                severity='High',
                description='Serves file to client'
            ),
            # Redirect - Open Redirect
            'HttpResponseRedirect': TaintSink(
                function='HttpResponseRedirect',
                dangerous_params=[0],
                vuln_type='open_redirect',
                severity='Medium',
                description='HTTP redirect'
            ),
            'redirect': TaintSink(
                function='redirect',
                dangerous_params=[0],
                vuln_type='open_redirect',
                severity='Medium',
                description='Redirect shortcut'
            ),
        }
    
    def _define_sanitizers(self) -> Dict[str, Sanitizer]:
        """Define Django sanitizers"""
        return {
            'escape': Sanitizer(
                function='django.utils.html.escape',
                sanitizes=['xss'],
                description='Escapes HTML entities'
            ),
            'format_html': Sanitizer(
                function='django.utils.html.format_html',
                sanitizes=['xss'],
                description='Safe HTML formatting with escaping'
            ),
            'strip_tags': Sanitizer(
                function='django.utils.html.strip_tags',
                sanitizes=['xss'],
                description='Removes HTML tags'
            ),
            # Parameterized queries
            'filter': Sanitizer(
                function='QuerySet.filter',
                sanitizes=['sql_injection'],
                description='Parameterized ORM filter'
            ),
            'get': Sanitizer(
                function='QuerySet.get',
                sanitizes=['sql_injection'],
                description='Parameterized ORM get'
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
