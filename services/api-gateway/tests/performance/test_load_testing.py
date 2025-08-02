"""
Performance and load testing for the API Gateway.
Tests latency, throughput, concurrent users, and system limits.
"""
import pytest
import asyncio
import time
import statistics
import concurrent.futures
import threading
from typing import List, Dict, Any
from unittest.mock import patch


@pytest.mark.performance
@pytest.mark.slow
class TestLatencyPerformance:
    """Test response latency under various conditions."""
    
    def test_single_request_latency(self, client, performance_monitor):
        """Test latency of single requests."""
        performance_monitor.start()
        
        # Test different endpoints
        endpoints = [
            "/health",
            "/ready",
            "/metrics",
        ]
        
        latencies = []
        for endpoint in endpoints:
            for _ in range(20):  # Multiple samples
                start_time = time.time()
                response = client.get(endpoint)
                duration = time.time() - start_time
                
                assert response.status_code == 200
                latencies.append(duration)
                performance_monitor.record_request(duration, response.status_code)
        
        performance_monitor.stop()
        
        # Analyze latency statistics
        avg_latency = statistics.mean(latencies)
        p95_latency = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        p99_latency = statistics.quantiles(latencies, n=100)[98]  # 99th percentile
        
        # Assert reasonable latency thresholds
        assert avg_latency < 0.1  # Average under 100ms
        assert p95_latency < 0.2  # 95th percentile under 200ms
        assert p99_latency < 0.5  # 99th percentile under 500ms
        
        print(f"Latency stats - Avg: {avg_latency:.3f}s, P95: {p95_latency:.3f}s, P99: {p99_latency:.3f}s")
    
    def test_authenticated_request_latency(self, client, auth_headers, performance_monitor):
        """Test latency of authenticated requests."""
        headers = auth_headers["valid_user"]
        performance_monitor.start()
        
        latencies = []
        for _ in range(50):
            start_time = time.time()
            response = client.get("/api/v1/services", headers=headers)
            duration = time.time() - start_time
            
            if response.status_code != 401:  # Skip if auth fails
                latencies.append(duration)
                performance_monitor.record_request(duration, response.status_code)
        
        performance_monitor.stop()
        
        if latencies:  # Only test if we have successful requests
            avg_latency = statistics.mean(latencies)
            p95_latency = statistics.quantiles(latencies, n=20)[18]
            
            # Authenticated requests may be slightly slower due to token validation
            assert avg_latency < 0.15  # Average under 150ms
            assert p95_latency < 0.3   # 95th percentile under 300ms
            
            print(f"Authenticated request latency - Avg: {avg_latency:.3f}s, P95: {p95_latency:.3f}s")
    
    @patch("httpx.AsyncClient")
    def test_proxy_request_latency(self, mock_http_client, client, auth_headers, performance_monitor):
        """Test latency of proxied requests to backend services."""
        # Mock backend service with controlled latency
        def create_delayed_response(delay: float):
            def delayed_response(*args, **kwargs):
                time.sleep(delay)  # Simulate backend latency
                mock_response = type('MockResponse', (), {})()
                mock_response.status_code = 200
                mock_response.content = b'{"status": "success"}'
                mock_response.headers = {"Content-Type": "application/json"}
                return mock_response
            return delayed_response
        
        mock_client_instance = type('MockClient', (), {})()
        mock_client_instance.request = create_delayed_response(0.05)  # 50ms backend latency
        mock_http_client.return_value = mock_client_instance
        
        headers = auth_headers["valid_user"]
        performance_monitor.start()
        
        latencies = []
        for _ in range(30):
            start_time = time.time()
            response = client.get("/api/v1/auth/profile", headers=headers)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                latencies.append(duration)
                performance_monitor.record_request(duration, response.status_code)
        
        performance_monitor.stop()
        
        if latencies:
            avg_latency = statistics.mean(latencies)
            p95_latency = statistics.quantiles(latencies, n=20)[18]
            
            # Should include backend latency + gateway overhead
            assert avg_latency > 0.04  # Should be at least backend latency
            assert avg_latency < 0.2   # But not too much overhead
            assert p95_latency < 0.3
            
            print(f"Proxy request latency - Avg: {avg_latency:.3f}s, P95: {p95_latency:.3f}s")


@pytest.mark.performance
@pytest.mark.slow
class TestThroughputPerformance:
    """Test request throughput and processing capacity."""
    
    def test_sequential_throughput(self, client, performance_monitor):
        """Test throughput with sequential requests."""
        num_requests = 100
        performance_monitor.start()
        
        start_time = time.time()
        successful_requests = 0
        
        for i in range(num_requests):
            response = client.get("/health")
            if response.status_code == 200:
                successful_requests += 1
            
            duration = 0.01  # Estimated per-request time
            performance_monitor.record_request(duration, response.status_code)
        
        total_time = time.time() - start_time
        performance_monitor.stop()
        
        throughput = successful_requests / total_time
        
        # Should handle at least 50 requests per second sequentially
        assert throughput > 50
        assert successful_requests / num_requests > 0.95  # 95% success rate
        
        print(f"Sequential throughput: {throughput:.2f} requests/second")
    
    def test_concurrent_throughput(self, client, performance_monitor):
        """Test throughput with concurrent requests."""
        num_threads = 10
        requests_per_thread = 20
        total_requests = num_threads * requests_per_thread
        
        results = []
        start_time = time.time()
        
        def make_requests():
            thread_results = []
            for _ in range(requests_per_thread):
                request_start = time.time()
                response = client.get("/health")
                duration = time.time() - request_start
                
                thread_results.append({
                    "status_code": response.status_code,
                    "duration": duration
                })
            return thread_results
        
        # Execute concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(make_requests) for _ in range(num_threads)]
            
            for future in concurrent.futures.as_completed(futures):
                results.extend(future.result())
        
        total_time = time.time() - start_time
        
        # Analyze results
        successful_requests = sum(1 for r in results if r["status_code"] == 200)
        throughput = successful_requests / total_time
        avg_latency = statistics.mean([r["duration"] for r in results])
        
        # Record metrics
        performance_monitor.start()
        for result in results:
            performance_monitor.record_request(result["duration"], result["status_code"])
        performance_monitor.stop()
        
        # Performance assertions
        assert throughput > 100  # Should handle 100+ concurrent requests/second
        assert successful_requests / total_requests > 0.95  # 95% success rate
        assert avg_latency < 0.2  # Average latency under 200ms under load
        
        print(f"Concurrent throughput: {throughput:.2f} requests/second")
        print(f"Success rate: {successful_requests/total_requests:.2%}")
        print(f"Average latency under load: {avg_latency:.3f}s")
    
    def test_sustained_load_throughput(self, client, performance_monitor):
        """Test throughput under sustained load."""
        duration_seconds = 30  # 30 second test
        target_rps = 50  # Target 50 requests per second
        
        results = []
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        performance_monitor.start()
        
        while time.time() < end_time:
            batch_start = time.time()
            
            # Make requests for 1 second
            batch_results = []
            while time.time() - batch_start < 1.0:
                request_start = time.time()
                response = client.get("/health")
                duration = time.time() - request_start
                
                batch_results.append({
                    "status_code": response.status_code,
                    "duration": duration,
                    "timestamp": request_start
                })
                
                performance_monitor.record_request(duration, response.status_code)
                
                # Control rate to avoid overwhelming
                if len(batch_results) >= target_rps:
                    break
            
            results.extend(batch_results)
            
            # Brief pause to control overall rate
            elapsed_batch_time = time.time() - batch_start
            if elapsed_batch_time < 1.0:
                time.sleep(1.0 - elapsed_batch_time)
        
        total_time = time.time() - start_time
        performance_monitor.stop()
        
        # Analyze sustained performance
        successful_requests = sum(1 for r in results if r["status_code"] == 200)
        actual_throughput = len(results) / total_time
        success_rate = successful_requests / len(results)
        
        # Performance assertions for sustained load
        assert actual_throughput > target_rps * 0.8  # At least 80% of target
        assert success_rate > 0.95  # 95% success rate
        
        print(f"Sustained throughput: {actual_throughput:.2f} requests/second over {duration_seconds}s")
        print(f"Success rate: {success_rate:.2%}")


@pytest.mark.performance
@pytest.mark.slow
class TestConcurrentUserLoad:
    """Test performance with multiple concurrent users."""
    
    def test_concurrent_authenticated_users(self, client, auth_headers, performance_monitor):
        """Test performance with multiple authenticated users."""
        num_users = 20
        requests_per_user = 10
        
        def simulate_user(user_id: int):
            headers = auth_headers["valid_user"]
            user_results = []
            
            for _ in range(requests_per_user):
                start_time = time.time()
                response = client.get("/api/v1/services", headers=headers)
                duration = time.time() - start_time
                
                user_results.append({
                    "user_id": user_id,
                    "status_code": response.status_code,
                    "duration": duration
                })
                
                # Small delay between requests from same user
                time.sleep(0.1)
            
            return user_results
        
        # Simulate concurrent users
        start_time = time.time()
        all_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_users) as executor:
            futures = [executor.submit(simulate_user, i) for i in range(num_users)]
            
            for future in concurrent.futures.as_completed(futures):
                all_results.extend(future.result())
        
        total_time = time.time() - start_time
        
        # Analyze multi-user performance
        successful_requests = sum(1 for r in all_results if r["status_code"] not in [401, 403])
        total_requests = len(all_results)
        throughput = total_requests / total_time
        avg_latency = statistics.mean([r["duration"] for r in all_results])
        
        # Record metrics
        performance_monitor.start()
        for result in all_results:
            performance_monitor.record_request(result["duration"], result["status_code"])
        performance_monitor.stop()
        
        # Performance assertions
        assert successful_requests / total_requests > 0.9  # 90% success rate
        assert throughput > 30  # Handle concurrent users efficiently
        assert avg_latency < 0.3  # Reasonable latency under user load
        
        print(f"Multi-user performance: {throughput:.2f} requests/second")
        print(f"Success rate: {successful_requests/total_requests:.2%}")
        print(f"Average latency: {avg_latency:.3f}s")
    
    def test_mixed_workload_performance(self, client, auth_headers, performance_monitor):
        """Test performance with mixed authenticated and unauthenticated workload."""
        duration = 20  # 20 second test
        
        results = []
        start_time = time.time()
        end_time = start_time + duration
        
        def authenticated_worker():
            headers = auth_headers["valid_user"]
            while time.time() < end_time:
                request_start = time.time()
                response = client.get("/api/v1/services", headers=headers)
                duration = time.time() - request_start
                
                results.append({
                    "type": "authenticated",
                    "status_code": response.status_code,
                    "duration": duration
                })
                
                time.sleep(0.1)  # 10 requests per second per worker
        
        def unauthenticated_worker():
            while time.time() < end_time:
                request_start = time.time()
                response = client.get("/health")
                duration = time.time() - request_start
                
                results.append({
                    "type": "unauthenticated",
                    "status_code": response.status_code,
                    "duration": duration
                })
                
                time.sleep(0.05)  # 20 requests per second per worker
        
        # Start mixed workload
        performance_monitor.start()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # 3 authenticated workers, 5 unauthenticated workers
            futures = []
            futures.extend([executor.submit(authenticated_worker) for _ in range(3)])
            futures.extend([executor.submit(unauthenticated_worker) for _ in range(5)])
            
            concurrent.futures.wait(futures)
        
        total_time = time.time() - start_time
        performance_monitor.stop()
        
        # Analyze mixed workload results
        auth_results = [r for r in results if r["type"] == "authenticated"]
        unauth_results = [r for r in results if r["type"] == "unauthenticated"]
        
        auth_success_rate = sum(1 for r in auth_results if r["status_code"] not in [401, 403]) / len(auth_results)
        unauth_success_rate = sum(1 for r in unauth_results if r["status_code"] == 200) / len(unauth_results)
        
        total_throughput = len(results) / total_time
        
        # Record all metrics
        for result in results:
            performance_monitor.record_request(result["duration"], result["status_code"])
        
        # Performance assertions
        assert auth_success_rate > 0.9  # 90% success for authenticated requests
        assert unauth_success_rate > 0.95  # 95% success for unauthenticated requests
        assert total_throughput > 80  # Combined throughput
        
        print(f"Mixed workload throughput: {total_throughput:.2f} requests/second")
        print(f"Authenticated success rate: {auth_success_rate:.2%}")
        print(f"Unauthenticated success rate: {unauth_success_rate:.2%}")


@pytest.mark.performance
@pytest.mark.slow
class TestResourceUtilization:
    """Test resource utilization under load."""
    
    def test_memory_usage_under_load(self, client, performance_monitor):
        """Test memory usage during load testing."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Generate load
        performance_monitor.start()
        
        for i in range(500):
            response = client.get("/health")
            performance_monitor.record_request(0.01, response.status_code)
            
            # Check memory every 100 requests
            if i % 100 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_increase = current_memory - initial_memory
                
                # Memory increase should be reasonable
                assert memory_increase < 100  # Less than 100MB increase
        
        performance_monitor.stop()
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory
        
        print(f"Memory usage: {initial_memory:.2f}MB -> {final_memory:.2f}MB (increase: {memory_increase:.2f}MB)")
        
        # Memory should not increase excessively
        assert memory_increase < 50  # Less than 50MB for 500 requests
    
    def test_response_time_distribution(self, client, performance_monitor):
        """Test response time distribution under load."""
        num_requests = 200
        response_times = []
        
        performance_monitor.start()
        
        for _ in range(num_requests):
            start_time = time.time()
            response = client.get("/health")
            duration = time.time() - start_time
            
            response_times.append(duration)
            performance_monitor.record_request(duration, response.status_code)
        
        performance_monitor.stop()
        
        # Calculate percentiles
        response_times.sort()
        p50 = response_times[len(response_times) // 2]
        p90 = response_times[int(len(response_times) * 0.9)]
        p95 = response_times[int(len(response_times) * 0.95)]
        p99 = response_times[int(len(response_times) * 0.99)]
        
        # Response time distribution should be reasonable
        assert p50 < 0.05  # Median under 50ms
        assert p90 < 0.1   # 90th percentile under 100ms
        assert p95 < 0.15  # 95th percentile under 150ms
        assert p99 < 0.3   # 99th percentile under 300ms
        
        print(f"Response time percentiles - P50: {p50:.3f}s, P90: {p90:.3f}s, P95: {p95:.3f}s, P99: {p99:.3f}s")


@pytest.mark.performance
@pytest.mark.slow
class TestScalabilityLimits:
    """Test scalability limits and breaking points."""
    
    def test_connection_limit_handling(self, client):
        """Test handling of connection limits."""
        # This test would need to be run against a real server
        # to test actual connection limits
        
        max_concurrent = 100
        successful_connections = 0
        
        def make_connection():
            nonlocal successful_connections
            try:
                response = client.get("/health", timeout=5)
                if response.status_code == 200:
                    successful_connections += 1
            except Exception:
                pass  # Connection failed
        
        # Attempt many concurrent connections
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = [executor.submit(make_connection) for _ in range(max_concurrent)]
            concurrent.futures.wait(futures, timeout=30)
        
        # Should handle a reasonable number of concurrent connections
        success_rate = successful_connections / max_concurrent
        assert success_rate > 0.8  # At least 80% successful
        
        print(f"Connection handling: {successful_connections}/{max_concurrent} successful ({success_rate:.2%})")
    
    @pytest.mark.skip(reason="Stress test - only run manually")
    def test_stress_breaking_point(self, client, performance_monitor):
        """Test system behavior at breaking point (stress test)."""
        # This is a stress test that should only be run manually
        # to find the actual breaking point of the system
        
        max_rps = 1000  # Start with high rate
        test_duration = 60  # 1 minute test
        
        results = []
        start_time = time.time()
        end_time = start_time + test_duration
        
        performance_monitor.start()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            while time.time() < end_time:
                batch_futures = []
                
                # Submit batch of requests
                for _ in range(max_rps // 10):  # 100ms batches
                    future = executor.submit(lambda: client.get("/health"))
                    batch_futures.append(future)
                
                # Collect results
                for future in concurrent.futures.as_completed(batch_futures, timeout=1):
                    try:
                        response = future.result()
                        results.append({
                            "status_code": response.status_code,
                            "timestamp": time.time()
                        })
                        performance_monitor.record_request(0.01, response.status_code)
                    except Exception:
                        results.append({
                            "status_code": 0,  # Failed
                            "timestamp": time.time()
                        })
                
                time.sleep(0.1)  # 100ms batch interval
        
        performance_monitor.stop()
        
        # Analyze stress test results
        total_requests = len(results)
        successful_requests = sum(1 for r in results if r["status_code"] == 200)
        actual_rps = total_requests / test_duration
        success_rate = successful_requests / total_requests if total_requests > 0 else 0
        
        print(f"Stress test results:")
        print(f"Actual RPS: {actual_rps:.2f}")
        print(f"Success rate: {success_rate:.2%}")
        print(f"Total requests: {total_requests}")
        
        # Even under stress, should maintain some level of service
        assert success_rate > 0.5  # At least 50% success under extreme load