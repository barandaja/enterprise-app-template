"""
Performance and load testing for auth service.
Tests response times, throughput, and system behavior under load.
"""
import pytest
import pytest_asyncio
import asyncio
import time
from unittest.mock import patch, AsyncMock
from fastapi import status
import statistics

from tests.factories import UserFactory, SessionFactory, LoadTestUserFactory


class TestPerformance:
    """Performance test suite."""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_login_endpoint_response_time(self, async_client, benchmark):
        """Test login endpoint response time under normal conditions."""
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        user = UserFactory()
        session = SessionFactory()
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (user, session, "access_token", "refresh_token")
            
            # Act & Assert
            def login_request():
                return asyncio.run(async_client.post("/api/v1/auth/login", json=login_data))
            
            result = benchmark(login_request)
            assert result.status_code == status.HTTP_200_OK
            
            # Response time should be under 200ms for single request
            assert benchmark.stats['mean'] < 0.2
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_concurrent_login_performance(self, async_client):
        """Test login performance under concurrent load."""
        # Arrange
        num_concurrent = 50
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        user = UserFactory()
        session = SessionFactory()
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (user, session, "access_token", "refresh_token")
            
            # Act
            start_time = time.time()
            
            tasks = [
                async_client.post("/api/v1/auth/login", json=login_data)
                for _ in range(num_concurrent)
            ]
            
            responses = await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Assert
            # All requests should succeed
            success_count = sum(1 for r in responses if r.status_code == status.HTTP_200_OK)
            assert success_count >= num_concurrent * 0.95  # Allow 5% failure rate
            
            # Throughput should be reasonable (>100 requests/second)
            throughput = num_concurrent / total_time
            assert throughput > 100, f"Throughput too low: {throughput} req/s"
            
            print(f"Concurrent login test: {throughput:.2f} req/s")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_database_query_performance(self, db_session, benchmark):
        """Test database query performance for user operations."""
        # Arrange - Create test users
        users = LoadTestUserFactory.create_users(100)
        for user in users:
            db_session.add(user)
        await db_session.commit()
        
        # Test user lookup performance
        from src.services.user_service import UserService
        user_service = UserService()
        
        async def lookup_user():
            return await user_service.get_user_by_id(db_session, users[0].id)
        
        # Act & Assert
        result = await benchmark(lookup_user)
        assert result is not None
        
        # Database lookup should be fast
        assert benchmark.stats['mean'] < 0.05  # 50ms
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_session_creation_performance(self, db_session, benchmark):
        """Test session creation performance."""
        # Arrange
        user = UserFactory()
        db_session.add(user)
        await db_session.commit()
        
        from src.services.session_service import SessionService
        session_service = SessionService()
        
        async def create_session():
            return await session_service.create_session(
                db=db_session,
                user=user,
                ip_address="127.0.0.1",
                user_agent="TestAgent/1.0"
            )
        
        # Act & Assert
        result = await benchmark(create_session)
        assert result is not None
        
        # Session creation should be fast
        assert benchmark.stats['mean'] < 0.1  # 100ms
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_password_hashing_performance(self, benchmark):
        """Test password hashing performance."""
        from src.core.security import SecurityService
        
        def hash_password():
            return SecurityService.get_password_hash("TestPassword123!")
        
        # Act & Assert
        result = benchmark(hash_password)
        assert result is not None
        
        # Password hashing should be reasonably fast but secure
        # bcrypt should take 100-300ms for good security
        assert 0.05 < benchmark.stats['mean'] < 0.5
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_token_generation_performance(self, benchmark):
        """Test JWT token generation performance."""
        from src.core.security import SecurityService
        
        def generate_token():
            return SecurityService.create_access_token(
                data={"sub": "1", "session_id": "test_session"}
            )
        
        # Act & Assert
        result = benchmark(generate_token)
        assert result is not None
        
        # Token generation should be very fast
        assert benchmark.stats['mean'] < 0.01  # 10ms
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_redis_cache_performance(self, redis_client, benchmark):
        """Test Redis cache performance."""
        # Arrange
        cache_key = "test_key"
        cache_value = {"user_id": 1, "data": "test_data"}
        
        from src.core.redis import get_cache_service
        cache_service = get_cache_service()
        
        async def cache_operations():
            await cache_service.set(cache_key, cache_value, ttl=300)
            result = await cache_service.get(cache_key)
            await cache_service.delete(cache_key)
            return result
        
        # Act & Assert
        result = await benchmark(cache_operations)
        assert result is not None
        
        # Cache operations should be very fast
        assert benchmark.stats['mean'] < 0.01  # 10ms
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_session_validation_performance(self, async_client):
        """Test session validation performance under load."""
        # Arrange
        num_requests = 100
        
        with patch('src.api.deps.get_current_active_user') as mock_get_user, \
             patch('src.services.session_service.SessionService.validate_session') as mock_validate:
            
            mock_get_user.return_value = UserFactory(id=1)
            mock_validate.return_value = SessionFactory()
            
            headers = {"Authorization": "Bearer test_token"}
            
            # Act
            start_time = time.time()
            
            tasks = [
                async_client.get("/api/v1/auth/sessions", headers=headers)
                for _ in range(num_requests)
            ]
            
            responses = await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Assert
            success_count = sum(1 for r in responses if r.status_code == status.HTTP_200_OK)
            assert success_count >= num_requests * 0.95
            
            throughput = num_requests / total_time
            assert throughput > 200, f"Session validation throughput too low: {throughput} req/s"
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_memory_usage_under_load(self, async_client):
        """Test memory usage during sustained load."""
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Arrange
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        user = UserFactory()
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            # Simulate load
            for batch in range(10):  # 10 batches of 20 requests
                tasks = []
                for i in range(20):
                    session = SessionFactory(session_id=f"session_{batch}_{i}")
                    mock_auth.return_value = (user, session, f"token_{batch}_{i}", f"refresh_{batch}_{i}")
                    tasks.append(async_client.post("/api/v1/auth/login", json=login_data))
                
                await asyncio.gather(*tasks)
                
                # Check memory after each batch
                current_memory = process.memory_info().rss / 1024 / 1024  # MB
                memory_increase = current_memory - initial_memory
                
                # Memory shouldn't grow excessively (allow 100MB increase)
                assert memory_increase < 100, f"Memory usage increased by {memory_increase:.2f}MB"
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_response_time_percentiles(self, async_client):
        """Test response time percentiles under load."""
        # Arrange
        num_requests = 200
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        user = UserFactory()
        session = SessionFactory()
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (user, session, "access_token", "refresh_token")
            
            # Act - Measure response times
            response_times = []
            
            for _ in range(num_requests):
                start_time = time.time()
                response = await async_client.post("/api/v1/auth/login", json=login_data)
                end_time = time.time()
                
                if response.status_code == status.HTTP_200_OK:
                    response_times.append((end_time - start_time) * 1000)  # Convert to milliseconds
            
            # Assert
            assert len(response_times) >= num_requests * 0.95  # 95% success rate
            
            # Calculate percentiles
            p50 = statistics.median(response_times)
            p95 = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
            p99 = statistics.quantiles(response_times, n=100)[98]  # 99th percentile
            
            print(f"Response time percentiles - P50: {p50:.2f}ms, P95: {p95:.2f}ms, P99: {p99:.2f}ms")
            
            # Performance assertions
            assert p50 < 100, f"P50 response time too high: {p50:.2f}ms"
            assert p95 < 300, f"P95 response time too high: {p95:.2f}ms"
            assert p99 < 500, f"P99 response time too high: {p99:.2f}ms"
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_database_connection_pool_performance(self, db_session):
        """Test database connection pool under concurrent load."""
        from src.services.user_service import UserService
        
        # Arrange
        user_service = UserService()
        users = LoadTestUserFactory.create_users(50)
        
        for user in users:
            db_session.add(user)
        await db_session.commit()
        
        # Act - Concurrent database operations
        async def db_operation(user_id):
            return await user_service.get_user_by_id(db_session, user_id)
        
        start_time = time.time()
        
        tasks = [db_operation(user.id) for user in users]
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Assert
        success_count = sum(1 for r in results if r is not None)
        assert success_count >= len(users) * 0.95
        
        throughput = len(users) / total_time
        assert throughput > 50, f"Database throughput too low: {throughput:.2f} ops/s"
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_audit_logging_performance(self, db_session):
        """Test audit logging performance impact."""
        from src.models.audit import AuditLogger, AuditEventType
        
        # Arrange
        audit_logger = AuditLogger()
        num_logs = 100
        
        # Act
        start_time = time.time()
        
        tasks = []
        for i in range(num_logs):
            task = audit_logger.log_auth_event(
                db=db_session,
                event_type=AuditEventType.LOGIN_SUCCESS,
                user_id=1,
                ip_address="127.0.0.1",
                success=True,
                description=f"Test audit log {i}"
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Assert
        throughput = num_logs / total_time
        assert throughput > 200, f"Audit logging throughput too low: {throughput:.2f} logs/s"
        
        # Audit logging shouldn't significantly impact performance
        avg_time_per_log = total_time / num_logs
        assert avg_time_per_log < 0.01  # 10ms per log
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_session_cleanup_performance(self, db_session):
        """Test session cleanup performance with large datasets."""
        from src.services.session_service import SessionService
        from src.models.session import UserSession
        from datetime import datetime, timedelta
        
        # Arrange - Create many expired sessions
        session_service = SessionService()
        expired_sessions = []
        
        for i in range(1000):
            session = UserSession(
                session_id=f"expired_session_{i}",
                user_id=1,
                created_at=datetime.utcnow() - timedelta(days=2),
                expires_at=datetime.utcnow() - timedelta(days=1),
                is_active=False,
                ip_address="127.0.0.1",
                user_agent="TestAgent/1.0"
            )
            expired_sessions.append(session)
            db_session.add(session)
        
        await db_session.commit()
        
        # Act
        start_time = time.time()
        cleaned_count = await session_service.cleanup_expired_sessions(db_session)
        end_time = time.time()
        
        cleanup_time = end_time - start_time
        
        # Assert
        assert cleaned_count >= 1000
        assert cleanup_time < 5.0, f"Session cleanup took too long: {cleanup_time:.2f}s"
        
        throughput = cleaned_count / cleanup_time
        assert throughput > 200, f"Cleanup throughput too low: {throughput:.2f} sessions/s"
    
    @pytest.mark.performance
    @pytest.mark.slow
    def test_startup_time(self):
        """Test application startup time."""
        import subprocess
        import time
        
        # This would test actual application startup
        # For demonstration, we'll test import time
        start_time = time.time()
        
        # Import main application components
        from src.main import app
        from src.services.auth_service import AuthService
        from src.services.user_service import UserService
        from src.services.session_service import SessionService
        
        end_time = time.time()
        import_time = end_time - start_time
        
        # Application imports should be fast
        assert import_time < 2.0, f"Import time too slow: {import_time:.2f}s"
        
        print(f"Application import time: {import_time:.3f}s")
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest_asyncio.async
    async def test_large_payload_handling(self, async_client):
        """Test handling of large request payloads."""
        # Arrange - Create large device info payload
        large_device_info = {
            "device_type": "desktop",
            "os": "Windows",
            "browser": "Chrome",
            "screen_resolution": "1920x1080",
            "timezone": "America/New_York",
            "language": "en-US",
            # Add large data
            "large_data": "x" * 10000,  # 10KB of data
            "extensions": [f"extension_{i}" for i in range(100)],
            "fonts": [f"font_{i}" for i in range(50)]
        }
        
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "device_info": large_device_info
        }
        
        user = UserFactory()
        session = SessionFactory()
        
        with patch('src.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = (user, session, "access_token", "refresh_token")
            
            # Act
            start_time = time.time()
            response = await async_client.post("/api/v1/auth/login", json=login_data)
            end_time = time.time()
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            response_time = end_time - start_time
            assert response_time < 1.0, f"Large payload handling too slow: {response_time:.2f}s"