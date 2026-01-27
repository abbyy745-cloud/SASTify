"""
Database Library Model

Describes the taint behavior of common database libraries.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class TaintSink:
    function: str
    dangerous_params: List[int]
    vuln_type: str
    severity: str = "Critical"
    description: str = ""


@dataclass
class Sanitizer:
    function: str
    sanitizes: List[str]
    description: str = ""


class DatabaseModel:
    """Model of database libraries' security-relevant behavior"""
    
    def __init__(self):
        self.sinks = self._define_sinks()
        self.sanitizers = self._define_sanitizers()
    
    def _define_sinks(self) -> Dict[str, TaintSink]:
        """Define database sinks (SQL injection points)"""
        return {
            # Python - sqlite3
            'sqlite3.cursor.execute': TaintSink(
                function='cursor.execute',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='SQLite cursor execute'
            ),
            'sqlite3.connection.execute': TaintSink(
                function='connection.execute',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='SQLite connection execute'
            ),
            # Python - psycopg2 (PostgreSQL)
            'psycopg2.cursor.execute': TaintSink(
                function='cursor.execute',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='PostgreSQL cursor execute'
            ),
            # Python - mysql-connector
            'mysql.cursor.execute': TaintSink(
                function='cursor.execute',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='MySQL cursor execute'
            ),
            # Python - SQLAlchemy
            'sqlalchemy.text': TaintSink(
                function='text',
                dangerous_params=[0],
                vuln_type='sql_injection',
                severity='High',  # text() can be parameterized
                description='SQLAlchemy raw text'
            ),
            'sqlalchemy.execute': TaintSink(
                function='session.execute',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='SQLAlchemy session execute'
            ),
            'sqlalchemy.engine.execute': TaintSink(
                function='engine.execute',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='SQLAlchemy engine execute'
            ),
            # JavaScript - mysql/mysql2
            'mysql.query': TaintSink(
                function='connection.query',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='MySQL query'
            ),
            'mysql2.query': TaintSink(
                function='connection.query',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='MySQL2 query'
            ),
            'pool.query': TaintSink(
                function='pool.query',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='Connection pool query'
            ),
            # JavaScript - pg (PostgreSQL)
            'pg.query': TaintSink(
                function='client.query',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='PostgreSQL query'
            ),
            # JavaScript - Sequelize
            'sequelize.query': TaintSink(
                function='sequelize.query',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='Sequelize raw query'
            ),
            # JavaScript - Knex
            'knex.raw': TaintSink(
                function='knex.raw',
                dangerous_params=[0],
                vuln_type='sql_injection',
                description='Knex raw SQL'
            ),
            # JavaScript - MongoDB (NoSQL Injection)
            'mongodb.find': TaintSink(
                function='collection.find',
                dangerous_params=[0],
                vuln_type='nosql_injection',
                severity='High',
                description='MongoDB find query'
            ),
            'mongodb.findOne': TaintSink(
                function='collection.findOne',
                dangerous_params=[0],
                vuln_type='nosql_injection',
                severity='High',
                description='MongoDB findOne query'
            ),
            'mongoose.find': TaintSink(
                function='Model.find',
                dangerous_params=[0],
                vuln_type='nosql_injection',
                severity='High',
                description='Mongoose find query'
            ),
            '$where': TaintSink(
                function='$where',
                dangerous_params=[0],
                vuln_type='nosql_injection',
                severity='Critical',
                description='MongoDB $where operator (code execution)'
            ),
        }
    
    def _define_sanitizers(self) -> Dict[str, Sanitizer]:
        """Define database sanitizers (parameterized queries)"""
        return {
            # Python - psycopg2
            'psycopg2.sql.SQL': Sanitizer(
                function='sql.SQL',
                sanitizes=['sql_injection'],
                description='Parameterized SQL builder'
            ),
            'psycopg2.sql.Identifier': Sanitizer(
                function='sql.Identifier',
                sanitizes=['sql_injection'],
                description='Safe identifier quoting'
            ),
            'psycopg2.sql.Literal': Sanitizer(
                function='sql.Literal',
                sanitizes=['sql_injection'],
                description='Safe literal quoting'
            ),
            # SQLAlchemy
            'sqlalchemy.bindparam': Sanitizer(
                function='bindparam',
                sanitizes=['sql_injection'],
                description='Bind parameter'
            ),
            # JavaScript - mysql
            'mysql.escape': Sanitizer(
                function='mysql.escape',
                sanitizes=['sql_injection'],
                description='MySQL string escaping'
            ),
            'mysql.escapeId': Sanitizer(
                function='mysql.escapeId',
                sanitizes=['sql_injection'],
                description='MySQL identifier escaping'
            ),
            # Mongoose
            'mongoose.sanitize': Sanitizer(
                function='sanitize',
                sanitizes=['nosql_injection'],
                description='Mongoose query sanitization'
            ),
        }
    
    def is_sink(self, func_name: str) -> Optional[TaintSink]:
        for sink_name, sink in self.sinks.items():
            if sink_name in func_name or func_name.endswith(sink_name.split('.')[-1]):
                return sink
        return None
    
    def is_sanitizer(self, func_name: str) -> Optional[Sanitizer]:
        for san_name, san in self.sanitizers.items():
            if san_name in func_name:
                return san
        return None
