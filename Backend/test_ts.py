"""Quick test for TypeScript analyzer"""
from typescript_analyzer import TypeScriptParser

test_code = '''
import { Request, Response } from 'express';

interface StudentData {
    id: string;
    name: string;
    grade: number;
}

// Function with Request type (taint source)
function handleRequest(req: Request, res: Response): Promise<void> {
    const userId: any = req.params.id;  // Using any - dangerous!
    const data = req.body as any;  // Type bypass
    return processData(userId);
}

// Arrow function with any return
const processStudent = async (input: any): Promise<any> => {
    return await fetchStudent(input);
};

// Class with methods
export class StudentController {
    private db: any;  // Any type for property
    
    async getStudent(id: string): Promise<StudentData> {
        const result = this.db.query!.execute(id);  // Non-null assertion
        return result;
    }
}
'''

print("=" * 50)
print("TypeScript Analyzer Test")
print("=" * 50)

parser = TypeScriptParser('test.ts', test_code)
result = parser.parse()

print(f"\nParsed TypeScript file:")
print(f"  Functions: {list(result.functions.keys())}")
print(f"  Classes: {list(result.classes.keys())}")
print(f"  Interfaces: {list(result.interfaces.keys())}")
print(f"  Imports: {len(result.imports)} imports")
print(f"  Exports: {result.exports}")

# Get type safety issues
issues = parser.get_type_safety_issues()
print(f"\nType Safety Issues Found: {len(issues)}")
for issue in issues:
    print(f"  [{issue.get('severity', 'Unknown')}] Line {issue['line']}: {issue['type']}")
    if 'snippet' in issue:
        print(f"      Code: {issue['snippet'][:50]}...")

# Get taint sources
sources = parser.get_taint_sources()
print(f"\nPotential Taint Sources: {len(sources)}")
for func, param_idx, reason in sources:
    print(f"  {func}[param {param_idx}]: {reason}")
