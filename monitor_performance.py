#!/usr/bin/env python3
"""
Resume Optimizer Performance Monitor
Quick performance check and optimization tips
"""

import time
import sqlite3
import os
import psutil
import requests

def check_database_performance():
    """Check database performance metrics"""
    print("📊 Database Performance Check")
    print("-" * 40)
    
    try:
        # Check database file size
        db_size = os.path.getsize('ResumeOptimizerDB.sqlite') / (1024 * 1024)  # MB
        print(f"Database size: {db_size:.2f} MB")
        
        # Check database connection speed
        start_time = time.time()
        conn = sqlite3.connect('ResumeOptimizerDB.sqlite', timeout=30.0)
        conn.execute("SELECT COUNT(*) FROM users")
        conn.close()
        db_time = (time.time() - start_time) * 1000
        print(f"Database query time: {db_time:.2f} ms")
        
        if db_time > 100:
            print("⚠️  Database is slow. Consider optimizing.")
        else:
            print("✅ Database performance is good")
            
    except Exception as e:
        print(f"❌ Database error: {e}")

def check_server_performance():
    """Check server response performance"""
    print("\n🌐 Server Performance Check")
    print("-" * 40)
    
    try:
        start_time = time.time()
        response = requests.get('http://localhost:8080/', timeout=10)
        response_time = (time.time() - start_time) * 1000
        
        print(f"Server response time: {response_time:.2f} ms")
        print(f"HTTP status: {response.status_code}")
        
        if response_time > 1000:
            print("⚠️  Server is slow. Consider restarting.")
        elif response_time > 500:
            print("⚠️  Server response is moderate.")
        else:
            print("✅ Server performance is good")
            
    except Exception as e:
        print(f"❌ Server error: {e}")

def check_system_resources():
    """Check system resource usage"""
    print("\n💻 System Resources")
    print("-" * 40)
    
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        print(f"CPU usage: {cpu_percent}%")
        
        # Memory usage
        memory = psutil.virtual_memory()
        print(f"Memory usage: {memory.percent}% ({memory.used / (1024**3):.1f}GB used)")
        
        # Disk usage
        disk = psutil.disk_usage('.')
        print(f"Disk usage: {disk.percent}% ({disk.free / (1024**3):.1f}GB free)")
        
        # Check for issues
        if cpu_percent > 80:
            print("⚠️  High CPU usage detected")
        if memory.percent > 80:
            print("⚠️  High memory usage detected")
        if disk.percent > 90:
            print("⚠️  Low disk space")
            
        if cpu_percent < 80 and memory.percent < 80:
            print("✅ System resources are healthy")
            
    except Exception as e:
        print(f"❌ System check error: {e}")

def optimization_tips():
    """Display optimization tips"""
    print("\n💡 Performance Optimization Tips")
    print("-" * 40)
    print("1. Use the optimized startup script: python3 start_optimized.py")
    print("2. Clear browser cache if pages load slowly")
    print("3. Restart server if memory usage is high")
    print("4. Check for large files in uploads/ directory")
    print("5. Monitor database size - vacuum if > 100MB")
    print("6. Use Chrome/Firefox for best performance")

def main():
    """Run all performance checks"""
    print("🚀 Resume Optimizer Performance Monitor")
    print("=" * 50)
    
    check_database_performance()
    check_server_performance()
    check_system_resources()
    optimization_tips()
    
    print("\n" + "=" * 50)
    print("Performance check complete!")

if __name__ == '__main__':
    main() 