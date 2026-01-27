const fs = require('fs');
const babelParser = require('@babel/parser');
const vueParser = require('vue-eslint-parser');
// const angularParser = require('@angular-eslint/template-parser'); // Note: Angular parser often requires more setup, keeping simple for now

const filePath = process.argv[2];
const fileType = process.argv[3]; // 'react', 'vue', 'angular'

if (!filePath || !fileType) {
    console.error("Usage: node parse_frontend.js <file_path> <file_type>");
    process.exit(1);
}

try {
    const code = fs.readFileSync(filePath, 'utf-8');
    let ast = null;

    if (fileType === 'react') {
        ast = babelParser.parse(code, {
            sourceType: 'module',
            plugins: ['jsx', 'typescript', 'classProperties', 'decorators-legacy']
        });
    } else if (fileType === 'vue') {
        // Vue parser expects the whole file content
        ast = vueParser.parse(code, {
            sourceType: 'module',
            ecmaVersion: 2020,
            parser: {
                // Use babel parser for script tags
                js: 'espree',
                ts: 'espree'
            }
        });
    } else if (fileType === 'angular') {
        const angularParser = require('@angular-eslint/template-parser');
        const result = angularParser.parseForESLint(code, {
            filePath: filePath
        });
        ast = result.ast;
    }

    const replacer = (key, value) => {
        if (key === 'parent' || key === 'tokens' || key === 'comments') {
            return undefined;
        }
        return value;
    };

    console.log(JSON.stringify(ast, replacer));

} catch (error) {
    console.error(`Error parsing ${filePath}: ${error.message}`);
    process.exit(1);
}
