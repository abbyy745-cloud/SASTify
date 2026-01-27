#!/bin/bash

echo "🚀 Setting up SASTify..."

# Create directories
mkdir -p backend frontend/vscode-extension/src/webview frontend/web-dashboard/src/components frontend/web-dashboard/src/styles scripts

echo "📦 Installing backend dependencies..."
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Create .env file
if [ ! -f .env ]; then
    echo "DEEPSEEK_API_KEY=your_deepseek_api_key_here" > .env
    echo "FLASK_ENV=development" >> .env
    echo "FLASK_DEBUG=True" >> .env
    echo "⚠️  Please edit backend/.env with your DeepSeek API key"
fi

cd ..

echo "🔌 Setting up VSCode extension..."
cd frontend/vscode-extension
npm install
cd ../..

echo "📊 Setting up web dashboard..."
cd frontend/web-dashboard
npm install
cd ../..

echo "✅ Setup complete!"
echo ""
echo "🎯 To run SASTify:"
echo "1. Backend: cd backend && source venv/bin/activate && python app.py"
echo "2. Dashboard: cd frontend/web-dashboard && npm run dev"
echo "3. VSCode Extension: cd frontend/vscode-extension && npm run compile"
echo ""
echo "🔑 Don't forget to add your DeepSeek API key to backend/.env"