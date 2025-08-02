"""
Unit tests for Service Registry functionality.
Tests service discovery, health checking, and load balancing.
"""
import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch, MagicMock
from typing import Dict, Any

from src.services.service_registry import (
    ServiceRegistry,
    ServiceEndpoint,
    LoadBalancingStrategy
)


@pytest.mark.unit
class TestServiceEndpoint:
    """Test ServiceEndpoint data class."""
    
    def test_service_endpoint_creation(self):
        """Test ServiceEndpoint creation."""
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health",
            version="1.0.0"
        )
        
        assert endpoint.name == "test-service"
        assert endpoint.url == "http://test:8000"
        assert endpoint.health_check_url == "http://test:8000/health"
        assert endpoint.version == "1.0.0"
        assert endpoint.status == "unknown"
        assert endpoint.metadata == {}
    
    def test_service_endpoint_with_metadata(self):
        """Test ServiceEndpoint with metadata."""
        metadata = {"region": "us-west", "datacenter": "dc1"}
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health",
            version="1.0.0",
            metadata=metadata
        )
        
        assert endpoint.metadata == metadata
    
    def test_service_endpoint_is_healthy(self):
        """Test ServiceEndpoint health status checking."""
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        
        endpoint.status = "healthy"
        assert endpoint.is_healthy() is True
        
        endpoint.status = "unhealthy"
        assert endpoint.is_healthy() is False
        
        endpoint.status = "unknown"
        assert endpoint.is_healthy() is False


@pytest.mark.unit
class TestServiceRegistry:
    """Test ServiceRegistry functionality."""
    
    @pytest.fixture
    def registry(self):
        """Create service registry instance."""
        return ServiceRegistry()
    
    @pytest.fixture
    def sample_services(self):
        """Sample service endpoints for testing."""
        return {
            "auth": ServiceEndpoint(
                name="auth",
                url="http://auth:8000",
                health_check_url="http://auth:8000/health",
                version="1.0.0",
                status="healthy"
            ),
            "user": ServiceEndpoint(
                name="user",
                url="http://user:8000",
                health_check_url="http://user:8000/health",
                version="1.0.0",
                status="healthy"
            ),
            "orders": ServiceEndpoint(
                name="orders",
                url="http://orders:8000",
                health_check_url="http://orders:8000/health",
                version="1.0.0",
                status="unhealthy"
            )
        }
    
    async def test_registry_initialization(self, registry):
        """Test service registry initialization."""
        with patch.object(registry, '_load_service_configuration') as mock_load:
            mock_load.return_value = None
            await registry.initialize()
            mock_load.assert_called_once()
    
    async def test_register_service(self, registry):
        """Test registering a service."""
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        
        await registry.register_service(endpoint)
        
        assert "test-service" in registry._services
        assert registry._services["test-service"] == endpoint
    
    async def test_register_duplicate_service(self, registry):
        """Test registering a service that already exists."""
        endpoint1 = ServiceEndpoint(
            name="test-service",
            url="http://test1:8000",
            health_check_url="http://test1:8000/health"
        )
        endpoint2 = ServiceEndpoint(
            name="test-service",
            url="http://test2:8000",
            health_check_url="http://test2:8000/health"
        )
        
        await registry.register_service(endpoint1)
        await registry.register_service(endpoint2)  # Should replace
        
        assert registry._services["test-service"].url == "http://test2:8000"
    
    async def test_deregister_service(self, registry):
        """Test deregistering a service."""
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        
        await registry.register_service(endpoint)
        assert "test-service" in registry._services
        
        await registry.deregister_service("test-service")
        assert "test-service" not in registry._services
    
    async def test_deregister_nonexistent_service(self, registry):
        """Test deregistering a service that doesn't exist."""
        # Should not raise an exception
        await registry.deregister_service("nonexistent-service")
    
    async def test_get_service_endpoint(self, registry, sample_services):
        """Test getting service endpoint."""
        registry._services = sample_services
        
        endpoint = await registry.get_service_endpoint("auth")
        assert endpoint is not None
        assert endpoint.name == "auth"
        assert endpoint.url == "http://auth:8000"
        
        nonexistent = await registry.get_service_endpoint("nonexistent")
        assert nonexistent is None
    
    async def test_get_service_url(self, registry, sample_services):
        """Test getting service URL."""
        registry._services = sample_services
        
        url = await registry.get_service_url("auth")
        assert url == "http://auth:8000"
        
        nonexistent_url = await registry.get_service_url("nonexistent")
        assert nonexistent_url is None
    
    async def test_get_healthy_services(self, registry, sample_services):
        """Test getting list of healthy services."""
        registry._services = sample_services
        
        healthy = await registry.get_healthy_services()
        
        assert "auth" in healthy
        assert "user" in healthy
        assert "orders" not in healthy  # unhealthy
        assert len(healthy) == 2
    
    async def test_get_all_services_status(self, registry, sample_services):
        """Test getting status of all services."""
        registry._services = sample_services
        
        status = await registry.get_all_services_status()
        
        assert "auth" in status
        assert "user" in status
        assert "orders" in status
        assert status["auth"]["status"] == "healthy"
        assert status["orders"]["status"] == "unhealthy"
    
    @patch("httpx.AsyncClient")
    async def test_health_check_service_healthy(self, mock_client, registry):
        """Test health check for healthy service."""
        # Mock successful health check response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "healthy"}
        
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        
        await registry._health_check_service(endpoint)
        
        assert endpoint.status == "healthy"
        assert endpoint.last_health_check > 0
        assert endpoint.response_time > 0
    
    @patch("httpx.AsyncClient")
    async def test_health_check_service_unhealthy(self, mock_client, registry):
        """Test health check for unhealthy service."""
        # Mock failed health check response
        mock_response = MagicMock()
        mock_response.status_code = 503
        
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        
        await registry._health_check_service(endpoint)
        
        assert endpoint.status == "unhealthy"
        assert endpoint.last_health_check > 0
    
    @patch("httpx.AsyncClient")
    async def test_health_check_service_timeout(self, mock_client, registry):
        """Test health check with timeout."""
        # Mock timeout exception
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = asyncio.TimeoutError()
        mock_client.return_value = mock_client_instance
        
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        
        await registry._health_check_service(endpoint)
        
        assert endpoint.status == "unhealthy"
        assert endpoint.last_health_check > 0
    
    @patch("httpx.AsyncClient")
    async def test_health_check_service_connection_error(self, mock_client, registry):
        """Test health check with connection error."""
        # Mock connection error
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = Exception("Connection refused")
        mock_client.return_value = mock_client_instance
        
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        
        await registry._health_check_service(endpoint)
        
        assert endpoint.status == "unhealthy"
        assert endpoint.last_health_check > 0
    
    async def test_health_check_all_services(self, registry, sample_services):
        """Test health checking all services."""
        registry._services = sample_services
        
        with patch.object(registry, '_health_check_service') as mock_health_check:
            mock_health_check.return_value = None
            
            await registry.health_check_all_services()
            
            # Should call health check for each service
            assert mock_health_check.call_count == len(sample_services)
    
    async def test_start_health_monitoring(self, registry):
        """Test starting health monitoring task."""
        with patch.object(registry, '_health_monitoring_task') as mock_task:
            mock_task.return_value = None
            
            await registry.start_health_monitoring()
            
            assert registry._monitoring_task is not None
    
    async def test_stop_health_monitoring(self, registry):
        """Test stopping health monitoring task."""
        # Create a mock task
        mock_task = AsyncMock()
        registry._monitoring_task = mock_task
        
        await registry.stop_health_monitoring()
        
        mock_task.cancel.assert_called_once()
        assert registry._monitoring_task is None
    
    async def test_cleanup(self, registry):
        """Test registry cleanup."""
        # Set up monitoring task
        mock_task = AsyncMock()
        registry._monitoring_task = mock_task
        
        await registry.cleanup()
        
        mock_task.cancel.assert_called_once()


@pytest.mark.unit
class TestServiceRegistryLoadBalancing:
    """Test load balancing functionality."""
    
    @pytest.fixture
    def registry(self):
        """Service registry with load balancing."""
        return ServiceRegistry()
    
    @pytest.fixture
    def multiple_instances(self):
        """Multiple instances of the same service."""
        return [
            ServiceEndpoint(
                name="api-service",
                url="http://api1:8000",
                health_check_url="http://api1:8000/health",
                status="healthy",
                instance_id="api-1"
            ),
            ServiceEndpoint(
                name="api-service",
                url="http://api2:8000",
                health_check_url="http://api2:8000/health",
                status="healthy",
                instance_id="api-2"
            ),
            ServiceEndpoint(
                name="api-service",
                url="http://api3:8000",
                health_check_url="http://api3:8000/health",
                status="unhealthy",
                instance_id="api-3"
            )
        ]
    
    async def test_round_robin_load_balancing(self, registry, multiple_instances):
        """Test round-robin load balancing."""
        # Register multiple instances
        for instance in multiple_instances:
            await registry.register_service_instance(instance)
        
        # Get service URLs multiple times
        urls = []
        for _ in range(6):  # More than number of healthy instances
            url = await registry.get_service_url_load_balanced(
                "api-service", 
                LoadBalancingStrategy.ROUND_ROBIN
            )
            urls.append(url)
        
        # Should cycle through healthy instances
        healthy_urls = ["http://api1:8000", "http://api2:8000"]
        assert all(url in healthy_urls for url in urls if url)
        
        # Should have used both instances
        assert "http://api1:8000" in urls
        assert "http://api2:8000" in urls
    
    async def test_least_connections_load_balancing(self, registry, multiple_instances):
        """Test least connections load balancing."""
        # Register multiple instances
        for instance in multiple_instances:
            await registry.register_service_instance(instance)
        
        # Set different connection counts
        registry._service_instances["api-service"][0].active_connections = 5
        registry._service_instances["api-service"][1].active_connections = 2
        
        url = await registry.get_service_url_load_balanced(
            "api-service",
            LoadBalancingStrategy.LEAST_CONNECTIONS
        )
        
        # Should return instance with fewer connections
        assert url == "http://api2:8000"
    
    async def test_weighted_load_balancing(self, registry, multiple_instances):
        """Test weighted load balancing."""
        # Set weights
        multiple_instances[0].weight = 3
        multiple_instances[1].weight = 1
        
        for instance in multiple_instances:
            await registry.register_service_instance(instance)
        
        # Get URLs multiple times
        urls = []
        for _ in range(20):
            url = await registry.get_service_url_load_balanced(
                "api-service",
                LoadBalancingStrategy.WEIGHTED
            )
            urls.append(url)
        
        # Higher weight instance should be selected more often
        api1_count = urls.count("http://api1:8000")
        api2_count = urls.count("http://api2:8000")
        
        # With 3:1 weight ratio, api1 should be selected ~3x more
        assert api1_count > api2_count
    
    async def test_load_balancing_no_healthy_instances(self, registry):
        """Test load balancing when no healthy instances available."""
        unhealthy_instance = ServiceEndpoint(
            name="api-service",
            url="http://api1:8000",
            health_check_url="http://api1:8000/health",
            status="unhealthy"
        )
        
        await registry.register_service_instance(unhealthy_instance)
        
        url = await registry.get_service_url_load_balanced(
            "api-service",
            LoadBalancingStrategy.ROUND_ROBIN
        )
        
        assert url is None
    
    async def test_load_balancing_nonexistent_service(self, registry):
        """Test load balancing for non-existent service."""
        url = await registry.get_service_url_load_balanced(
            "nonexistent-service",
            LoadBalancingStrategy.ROUND_ROBIN
        )
        
        assert url is None


@pytest.mark.unit
class TestServiceRegistryMetrics:
    """Test service registry metrics and monitoring."""
    
    @pytest.fixture
    def registry(self):
        """Service registry instance."""
        return ServiceRegistry()
    
    async def test_service_metrics_collection(self, registry):
        """Test collection of service metrics."""
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health",
            status="healthy"
        )
        
        await registry.register_service(endpoint)
        
        # Simulate some requests
        await registry.record_request_metrics("test-service", 0.1, True)
        await registry.record_request_metrics("test-service", 0.2, True)
        await registry.record_request_metrics("test-service", 0.5, False)
        
        metrics = await registry.get_service_metrics("test-service")
        
        assert metrics["total_requests"] == 3
        assert metrics["successful_requests"] == 2
        assert metrics["failed_requests"] == 1
        assert metrics["average_response_time"] > 0
    
    async def test_service_metrics_aggregation(self, registry):
        """Test aggregation of metrics across services."""
        services = ["service1", "service2", "service3"]
        
        for service in services:
            endpoint = ServiceEndpoint(
                name=service,
                url=f"http://{service}:8000",
                health_check_url=f"http://{service}:8000/health"
            )
            await registry.register_service(endpoint)
            
            # Record some metrics
            for _ in range(5):
                await registry.record_request_metrics(service, 0.1, True)
        
        aggregated_metrics = await registry.get_aggregated_metrics()
        
        assert aggregated_metrics["total_services"] == 3
        assert aggregated_metrics["total_requests"] == 15
        assert aggregated_metrics["total_successful_requests"] == 15
    
    async def test_service_discovery_events(self, registry):
        """Test service discovery event logging."""
        events = []
        
        def event_handler(event_type: str, service_name: str, details: Dict[str, Any]):
            events.append({
                "type": event_type,
                "service": service_name,
                "details": details
            })
        
        registry.add_event_handler(event_handler)
        
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        
        await registry.register_service(endpoint)
        await registry.deregister_service("test-service")
        
        assert len(events) == 2
        assert events[0]["type"] == "service_registered"
        assert events[1]["type"] == "service_deregistered"
        assert events[0]["service"] == "test-service"


@pytest.mark.unit
class TestServiceRegistryConfiguration:
    """Test service registry configuration loading."""
    
    @pytest.fixture
    def registry(self):
        """Service registry instance."""
        return ServiceRegistry()
    
    async def test_load_from_environment(self, registry):
        """Test loading service configuration from environment."""
        env_config = {
            "SERVICE_AUTH_URL": "http://auth:8000",
            "SERVICE_USER_URL": "http://user:8000",
            "SERVICE_ORDERS_URL": "http://orders:8000"
        }
        
        with patch.dict("os.environ", env_config):
            await registry._load_service_configuration()
        
        # Should have registered services from environment
        assert "auth" in registry._services
        assert "user" in registry._services
        assert "orders" in registry._services
    
    async def test_load_from_config_file(self, registry):
        """Test loading service configuration from file."""
        config_data = {
            "services": [
                {
                    "name": "auth",
                    "url": "http://auth:8000",
                    "health_check_url": "http://auth:8000/health",
                    "version": "1.0.0"
                },
                {
                    "name": "user",
                    "url": "http://user:8000",
                    "health_check_url": "http://user:8000/health",
                    "version": "1.0.0"
                }
            ]
        }
        
        with patch("builtins.open"), \
             patch("json.load", return_value=config_data):
            await registry._load_from_config_file("services.json")
        
        assert len(registry._services) == 2
        assert "auth" in registry._services
        assert "user" in registry._services
    
    async def test_load_configuration_error_handling(self, registry):
        """Test error handling in configuration loading."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            # Should not raise exception
            await registry._load_from_config_file("nonexistent.json")
        
        # Registry should still be functional
        endpoint = ServiceEndpoint(
            name="test-service",
            url="http://test:8000",
            health_check_url="http://test:8000/health"
        )
        await registry.register_service(endpoint)
        assert "test-service" in registry._services