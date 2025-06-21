#!/bin/bash

echo "🔄 Restarting Resume Optimizer Server..."

# Kill existing processes
echo "🛑 Stopping existing server..."
lsof -ti:8080 | xargs kill -9 2>/dev/null || true
pkill -f "python.*app_enhanced" 2>/dev/null || true
pkill -f "python.*start_optimized" 2>/dev/null || true

# Wait a moment
sleep 2

# Start optimized server
echo "🚀 Starting optimized server..."
python3 start_optimized.py &

# Wait and check
sleep 3
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ | grep -q "200"; then
    echo "✅ Server restarted successfully!"
    echo "🌐 Access your app at: http://localhost:8080"
    echo "👤 Login: bhavithakula / bhavith123"
else
    echo "❌ Server failed to start properly"
fi 