#!/usr/bin/env python3
"""
Optimized Resume Optimizer Startup Script
Improved performance with minimal debug overhead
"""

import os
import sys
from app_enhanced import app, init_enhanced_database

def optimize_app_performance():
    """Configure Flask for better performance"""
    
    # Disable unnecessary features for better performance
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year cache for static files
    app.config['TEMPLATES_AUTO_RELOAD'] = False  # Disable template auto-reload
    app.config['EXPLAIN_TEMPLATE_LOADING'] = False
    
    # Optimize JSON handling
    app.config['JSON_SORT_KEYS'] = False
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
    
    # Database optimization
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Session optimization
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    
    print("⚡ Performance optimizations applied!")

def start_server():
    """Start the optimized server"""
    
    print("🚀 Resume Optimizer - OPTIMIZED & STYLE-AWARE!")
    print("✅ 100% ATS Optimization with Original Style Preservation")
    print("✅ Enhanced Performance Configuration")
    print("✅ Professional Document Generation")
    print("✅ Interactive Status Tracking")
    print("✅ Comprehensive Settings & Security")
    print("-" * 60)
    
    # Initialize database
    try:
        init_enhanced_database()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"⚠️  Database warning: {e}")
    
    # Apply performance optimizations
    optimize_app_performance()
    
    # Start server with optimized settings
    try:
        app.run(
            debug=False,  # Disable debug for better performance
            host='0.0.0.0',
            port=8080,
            threaded=True,  # Enable threading for better concurrent handling
            use_reloader=False,  # Disable auto-reloader for performance
            use_debugger=False  # Disable debugger for performance
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped gracefully")
    except Exception as e:
        print(f"❌ Server error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    start_server() 