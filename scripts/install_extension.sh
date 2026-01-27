#!/bin/bash

echo "🔌 Installing SASTify VSCode Extension..."

cd frontend/vscode-extension

echo "📦 Installing dependencies..."
npm install

echo "🔨 Compiling TypeScript..."
npm run compile

# Check if vsce is installed
if ! command -v vsce &> /dev/null; then
    echo "📦 Installing vsce..."
    npm install -g vsce
fi

echo "📦 Packaging extension..."
vsce package

echo "🚀 Installing extension..."
code --install-extension sastify-security-1.0.0.vsix

echo "✅ Installation complete!"
echo ""
echo "🎯 Next steps:"
echo "1. Reload VSCode (Ctrl+Shift+P → 'Developer: Reload Window')"
echo "2. Open a JavaScript or Python file"
echo "3. Right-click → 'SASTify: Scan Current File'"
echo "4. Make sure backend is running: cd backend && python app.py"