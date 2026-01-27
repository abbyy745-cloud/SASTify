const angularParser = require('@angular-eslint/template-parser');
const fs = require('fs');

const code = `<div [innerHTML]="userContent"></div>`;

try {
    const ast = angularParser.parseForESLint(code, {
        filePath: 'test.html'
    });
    console.log("Success!");
    console.log(Object.keys(ast.ast));
    console.log(JSON.stringify(ast.ast, (k, v) => k == 'parent' ? undefined : v, 2).slice(0, 500));
} catch (e) {
    console.error("Error:", e.message);
}
