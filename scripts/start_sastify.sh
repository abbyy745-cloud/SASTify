#!/bin/bash

echo "🚀 Starting SASTify..."

# Terminal 1 - Backend
gnome-terminal --tab --title="SASTify Backend" -- bash -c "cd backend && source venv/bin/activate && python app.py; exec bash"

# Wait for backend to start
sleep 3

# Terminal 2 - Dashboard  
gnome-terminal --tab --title="SASTify Dashboard" -- bash -c "cd frontend/web-dashboard && npm run dev; exec bash"

# Terminal 3 - Extension (compile)
gnome-terminal --tab --title="SASTify Extension" -- bash -c "cd frontend/vscode-extension && npm install && npm run compile; echo 'Extension compiled! Now open VSCode in this directory and press F5'; exec bash"

echo "✅ All services starting..."
echo "📊 Dashboard: http://localhost:3000"
echo "🔧 Backend: http://localhost:5000"
echo "🔌 Extension: Open frontend/vscode-extension in VSCode and press F5"