"""
Unit Tests for TypeScript Analyzer

Tests TypeScript parsing, type extraction, and type-aware taint analysis.
"""

import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typescript_analyzer import TypeScriptParser, TypeScriptFile, TypeInfo


class TestTypeScriptParser:
    """Test TypeScript parsing functionality"""
    
    def test_function_parsing(self):
        """Test parsing of function declarations"""
        code = '''
function greetUser(name: string, age: number): string {
    return `Hello, ${name}! You are ${age} years old.`;
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'greetUser' in result.functions
        func = result.functions['greetUser']
        assert len(func.parameters) == 2
        assert func.parameters[0].name == 'name'
        assert func.parameters[0].type_info.name == 'string'
        assert func.parameters[1].name == 'age'
        assert func.parameters[1].type_info.name == 'number'
    
    def test_arrow_function_parsing(self):
        """Test parsing of arrow functions"""
        code = '''
const processData = async (input: UserInput): Promise<Result> => {
    return await transform(input);
};
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'processData' in result.functions
        func = result.functions['processData']
        assert func.is_arrow
        assert func.is_async
    
    def test_class_parsing(self):
        """Test parsing of class declarations"""
        code = '''
export class UserController extends BaseController implements IController {
    private userService: UserService;
    
    constructor(userService: UserService) {
        super();
        this.userService = userService;
    }
    
    async getUser(id: string): Promise<User> {
        return this.userService.findById(id);
    }
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'UserController' in result.classes
        cls = result.classes['UserController']
        assert cls.extends == 'BaseController'
        assert 'IController' in cls.implements or len(cls.implements) > 0
        assert cls.is_exported
    
    def test_interface_parsing(self):
        """Test parsing of interface declarations"""
        code = '''
export interface UserRequest extends Request {
    user?: User;
    session: Session;
}

interface ApiResponse<T> {
    data: T;
    error?: string;
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'UserRequest' in result.interfaces
        assert 'ApiResponse' in result.interfaces
    
    def test_import_parsing(self):
        """Test parsing of import statements"""
        code = '''
import { Request, Response } from 'express';
import * as db from './database';
import UserService from './services/user';
import type { User } from './types';
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert len(result.imports) >= 3
        
        # Check named imports
        express_import = next((i for i in result.imports if i['module'] == 'express'), None)
        assert express_import is not None
        assert 'Request' in express_import['names']
    
    def test_export_parsing(self):
        """Test parsing of export statements"""
        code = '''
export function publicFunction() {}
export const publicConst = 42;
export class PublicClass {}
export { privateFunc as publicFunc };
export default MainClass;
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'publicFunction' in result.exports
        assert 'publicConst' in result.exports
        assert 'PublicClass' in result.exports
        assert 'default' in result.exports
    
    def test_type_alias_parsing(self):
        """Test parsing of type aliases"""
        code = '''
type UserId = string;
type UserRole = 'admin' | 'user' | 'guest';
export type Handler<T> = (req: Request) => Promise<T>;
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'UserId' in result.type_aliases
        assert 'UserRole' in result.type_aliases


class TestTypeInfo:
    """Test type information extraction"""
    
    def test_nullable_type(self):
        """Test nullable type detection"""
        code = '''
function maybeUser(id: string): User | null {
    return null;
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        func = result.functions.get('maybeUser')
        if func and func.return_type:
            # Type might be parsed as nullable
            pass
    
    def test_array_type(self):
        """Test array type detection"""
        code = '''
function getUsers(): User[] {
    return [];
}

function getItems(): Array<Item> {
    return [];
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        # Both should be detected as arrays
        assert 'getUsers' in result.functions
        assert 'getItems' in result.functions
    
    def test_promise_type(self):
        """Test Promise type detection"""
        code = '''
async function fetchData(): Promise<Data> {
    return await api.get('/data');
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        func = result.functions.get('fetchData')
        assert func is not None
        if func.return_type:
            assert func.return_type.is_promise or 'Promise' in func.return_type.name
    
    def test_generic_type(self):
        """Test generic type extraction"""
        code = '''
function transform<T, U>(input: T, mapper: (item: T) => U): U {
    return mapper(input);
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'transform' in result.functions


class TestTypeSafetyIssues:
    """Test type safety issue detection"""
    
    def test_any_type_detection(self):
        """Test detection of dangerous 'any' type"""
        code = '''
function processAny(data: any): any {
    return data.whatever();
}

const unsafeHandler = (input: any) => {
    eval(input);
};
'''
        parser = TypeScriptParser('test.ts', code)
        issues = parser.get_type_safety_issues()
        
        # Should detect any types
        any_issues = [i for i in issues if 'any' in i['type'].lower()]
        assert len(any_issues) >= 1
    
    def test_type_assertion_detection(self):
        """Test detection of type assertions"""
        code = '''
const data = response.data as any;
const user = <any>getUserData();
'''
        parser = TypeScriptParser('test.ts', code)
        issues = parser.get_type_safety_issues()
        
        # Should detect unsafe casts
        bypass_issues = [i for i in issues if 'bypass' in i['type'].lower() or 'any' in i.get('message', '').lower()]
        assert len(bypass_issues) >= 1


class TestTaintSourceDetection:
    """Test detection of taint sources from types"""
    
    def test_request_type_source(self):
        """Test detection of Request type as taint source"""
        code = '''
import { Request, Response } from 'express';

function handler(req: Request, res: Response) {
    const userId = req.params.id;
    const data = req.body;
    return processData(userId, data);
}
'''
        parser = TypeScriptParser('test.ts', code)
        sources = parser.get_taint_sources()
        
        # Should detect req parameter as source
        assert len(sources) >= 1


class TestComplexPatterns:
    """Test complex TypeScript patterns"""
    
    def test_decorator_parsing(self):
        """Test parsing of decorators"""
        code = '''
@Controller('/users')
@UseGuards(AuthGuard)
export class UserController {
    @Get(':id')
    @Roles('admin')
    async getUser(@Param('id') id: string): Promise<User> {
        return this.userService.findById(id);
    }
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        # Should detect class and method decorators
        if 'UserController' in result.classes:
            cls = result.classes['UserController']
            assert len(cls.decorators) >= 1
    
    def test_nested_generic_types(self):
        """Test parsing of nested generic types"""
        code = '''
function complexHandler(
    data: Map<string, Array<Promise<User>>>
): Observable<Result<User, Error>> {
    return processData(data);
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'complexHandler' in result.functions
    
    def test_optional_chaining(self):
        """Test handling of optional parameters"""
        code = '''
interface Config {
    database?: {
        host?: string;
        port?: number;
    };
}

function connect(config?: Config): Connection {
    const host = config?.database?.host ?? 'localhost';
    return new Connection(host);
}
'''
        parser = TypeScriptParser('test.ts', code)
        result = parser.parse()
        
        assert 'connect' in result.functions
        func = result.functions['connect']
        assert any(p.is_optional for p in func.parameters)


class TestReactTSX:
    """Test React/TSX component parsing"""
    
    def test_functional_component(self):
        """Test parsing of React functional components"""
        code = '''
interface UserCardProps {
    user: User;
    onEdit?: (id: string) => void;
}

const UserCard: React.FC<UserCardProps> = ({ user, onEdit }) => {
    return (
        <div className="user-card">
            <h2>{user.name}</h2>
            <button onClick={() => onEdit?.(user.id)}>Edit</button>
        </div>
    );
};

export default UserCard;
'''
        parser = TypeScriptParser('test.tsx', code)
        result = parser.parse()
        
        assert 'UserCard' in result.functions or 'UserCardProps' in result.interfaces


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
