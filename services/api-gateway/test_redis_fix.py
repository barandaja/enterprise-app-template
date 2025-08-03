#!/usr/bin/env python3
"""
Test script to validate Redis RecursionError fix.
"""
import asyncio
import sys
import os
import time

# Set required environment variables for testing
os.environ['JWT_SECRET_KEY'] = 'test_secret_key_for_redis_validation_only_32_chars_minimum'
os.environ['REDIS_URL'] = 'redis://localhost:6379'

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.core.redis import init_redis, redis_manager, close_redis, is_redis_initialized
from src.core.config import get_settings

async def test_redis_connection():
    """Test Redis connection and health checks without recursion."""
    print("Testing Redis connection fix...")
    
    try:
        # Initialize settings
        settings = get_settings()
        print(f"Redis URL: {settings.redis_url}")
        
        # Test initialization
        print("1. Testing Redis initialization...")
        await init_redis()
        
        if not is_redis_initialized():
            print("❌ Redis failed to initialize")
            return False
        
        print("✅ Redis initialized successfully")
        
        # Test health check multiple times to ensure no recursion
        print("2. Testing health checks (recursion prevention)...")
        for i in range(5):
            start_time = time.time()
            healthy = await redis_manager.health_check()
            duration = time.time() - start_time
            
            if duration > 5.0:  # If it takes more than 5 seconds, might be hanging
                print(f"❌ Health check {i+1} took too long: {duration:.2f}s")
                return False
            
            print(f"  Health check {i+1}: {'✅ healthy' if healthy else '❌ unhealthy'} ({duration:.3f}s)")
            
            if not healthy:
                print("❌ Health check failed")
                return False
        
        # Test basic Redis operations
        print("3. Testing Redis operations...")
        
        # Test set/get
        success = await redis_manager.set_json("test_key", {"message": "test"}, ttl=60)
        if not success:
            print("❌ Failed to set test data")
            return False
        
        data = await redis_manager.get_json("test_key")
        if data != {"message": "test"}:
            print("❌ Failed to retrieve test data")
            return False
        
        print("✅ Basic Redis operations working")
        
        # Test cleanup
        print("4. Testing Redis cleanup...")
        await close_redis()
        
        if is_redis_initialized():
            print("❌ Redis cleanup failed")
            return False
        
        print("✅ Redis cleanup successful")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_concurrent_health_checks():
    """Test concurrent health checks to ensure no race conditions."""
    print("\nTesting concurrent health checks...")
    
    try:
        # Reinitialize for concurrent test
        await init_redis()
        
        async def health_check_task(task_id):
            results = []
            for i in range(3):
                start_time = time.time()
                healthy = await redis_manager.health_check()
                duration = time.time() - start_time
                results.append((healthy, duration))
                await asyncio.sleep(0.1)  # Small delay between checks
            return task_id, results
        
        # Run multiple concurrent health check tasks
        tasks = [health_check_task(i) for i in range(5)]
        results = await asyncio.gather(*tasks)
        
        all_successful = True
        for task_id, task_results in results:
            for healthy, duration in task_results:
                if not healthy or duration > 2.0:
                    print(f"❌ Task {task_id} health check failed or too slow: {healthy}, {duration:.3f}s")
                    all_successful = False
        
        if all_successful:
            print("✅ Concurrent health checks successful")
        
        await close_redis()
        return all_successful
        
    except Exception as e:
        print(f"❌ Concurrent test failed: {e}")
        return False

async def main():
    """Main test function."""
    print("Redis RecursionError Fix Validation")
    print("=" * 40)
    
    # Test basic connection and health checks
    basic_test = await test_redis_connection()
    
    # Test concurrent access
    concurrent_test = await test_concurrent_health_checks()
    
    print("\n" + "=" * 40)
    print("Test Results:")
    print(f"Basic Redis Test: {'✅ PASSED' if basic_test else '❌ FAILED'}")
    print(f"Concurrent Test: {'✅ PASSED' if concurrent_test else '❌ FAILED'}")
    
    if basic_test and concurrent_test:
        print("\n🎉 All tests passed! Redis RecursionError has been fixed.")
        return 0
    else:
        print("\n❌ Some tests failed. Please check the Redis configuration.")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)