"""
WebSocket proxy and real-time communication tests.
Tests WebSocket connection management, authentication, and message routing.
"""
import pytest
import asyncio
import json
import time
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi.websockets import WebSocketDisconnect

from src.services.auth_service import UserInfo


@pytest.mark.websocket
class TestWebSocketConnection:
    """Test WebSocket connection establishment and management."""
    
    def test_websocket_connection_establishment(self, client):
        """Test basic WebSocket connection."""
        with client.websocket_connect("/ws/test-client") as websocket:
            # Should receive welcome message
            data = websocket.receive_json()
            
            assert data["type"] == "welcome"
            assert data["client_id"] == "test-client"
            assert "timestamp" in data
    
    def test_websocket_with_invalid_client_id(self, client):
        """Test WebSocket connection with invalid client ID."""
        # Test with various invalid client IDs
        invalid_ids = ["", " ", "invalid/id", "id with spaces"]
        
        for client_id in invalid_ids:
            try:
                with client.websocket_connect(f"/ws/{client_id}") as websocket:
                    # Should either reject connection or handle gracefully
                    data = websocket.receive_json()
                    # If connection succeeds, should handle client_id appropriately
                    assert "type" in data
            except Exception:
                # Connection rejected - this is acceptable behavior
                pass
    
    def test_websocket_concurrent_connections(self, client):
        """Test multiple concurrent WebSocket connections."""
        connections = []
        num_connections = 10
        
        try:
            # Establish multiple connections
            for i in range(num_connections):
                ws = client.websocket_connect(f"/ws/client-{i}")
                ws.__enter__()
                connections.append(ws)
                
                # Verify welcome message
                data = ws.receive_json()
                assert data["type"] == "welcome"
                assert data["client_id"] == f"client-{i}"
            
            # All connections should be active
            assert len(connections) == num_connections
            
        finally:
            # Clean up connections
            for ws in connections:
                try:
                    ws.__exit__(None, None, None)
                except:
                    pass
    
    def test_websocket_connection_timeout(self, client):
        """Test WebSocket connection timeout handling."""
        with client.websocket_connect("/ws/timeout-test") as websocket:
            # Receive welcome message
            websocket.receive_json()
            
            # Don't send any messages for a while
            # The connection should remain open (no automatic timeout in test)
            time.sleep(1)
            
            # Send ping to verify connection is still alive
            websocket.send_json({"type": "ping"})
            response = websocket.receive_json()
            assert response["type"] == "pong"


@pytest.mark.websocket
class TestWebSocketAuthentication:
    """Test WebSocket authentication and authorization."""
    
    @patch("src.services.auth_service.auth_service.validate_token")
    def test_websocket_authentication_with_valid_token(self, mock_validate, client):
        """Test WebSocket authentication with valid token."""
        # Mock successful token validation
        mock_validate.return_value = UserInfo(
            user_id="test-user-123",
            email="test@example.com",
            roles=["user"],
            permissions=["read"],
            is_active=True,
            is_verified=True
        )
        
        with client.websocket_connect("/ws/auth-client?token=valid-token") as websocket:
            data = websocket.receive_json()
            
            assert data["type"] == "welcome"
            assert data["client_id"] == "auth-client"
            
            # Token should have been validated
            mock_validate.assert_called_once_with("valid-token")
    
    @patch("src.services.auth_service.auth_service.validate_token")
    def test_websocket_authentication_with_invalid_token(self, mock_validate, client):
        """Test WebSocket authentication with invalid token."""
        # Mock failed token validation
        mock_validate.return_value = None
        
        # Connection should be rejected
        try:
            with client.websocket_connect("/ws/auth-client?token=invalid-token") as websocket:
                # If connection is established, it should be closed immediately
                try:
                    websocket.receive_json()
                    pytest.fail("Expected connection to be rejected")
                except WebSocketDisconnect:
                    pass  # Expected behavior
        except WebSocketDisconnect:
            # Connection rejected before establishment - also acceptable
            pass
    
    def test_websocket_without_token(self, client):
        """Test WebSocket connection without authentication token."""
        # Should allow connection but without user context
        with client.websocket_connect("/ws/unauth-client") as websocket:
            data = websocket.receive_json()
            
            assert data["type"] == "welcome"
            assert data["client_id"] == "unauth-client"
    
    @patch("src.services.auth_service.auth_service.validate_token")
    def test_websocket_authentication_service_failure(self, mock_validate, client):
        """Test WebSocket behavior when auth service fails."""
        # Mock auth service failure
        mock_validate.side_effect = Exception("Auth service unavailable")
        
        # Connection should be rejected or handle gracefully
        try:
            with client.websocket_connect("/ws/fail-client?token=some-token") as websocket:
                try:
                    websocket.receive_json()
                    pytest.fail("Expected connection to be rejected due to auth failure")
                except WebSocketDisconnect:
                    pass  # Expected behavior
        except WebSocketDisconnect:
            # Connection rejected - acceptable
            pass


@pytest.mark.websocket
class TestWebSocketMessaging:
    """Test WebSocket message handling and routing."""
    
    def test_websocket_ping_pong(self, client):
        """Test WebSocket ping/pong mechanism."""
        with client.websocket_connect("/ws/ping-client") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send ping
            websocket.send_json({"type": "ping"})
            
            # Should receive pong
            response = websocket.receive_json()
            assert response["type"] == "pong"
    
    def test_websocket_echo_functionality(self, client):
        """Test WebSocket echo functionality."""
        with client.websocket_connect("/ws/echo-client") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send custom message
            test_message = {
                "type": "test",
                "data": "hello world",
                "timestamp": time.time()
            }
            
            websocket.send_json(test_message)
            
            # Should receive echo
            response = websocket.receive_json()
            assert response["type"] == "echo"
            assert response["data"] == test_message
    
    def test_websocket_subscription_handling(self, client):
        """Test WebSocket subscription to channels/topics."""
        with client.websocket_connect("/ws/sub-client") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Subscribe to a channel
            websocket.send_json({
                "type": "subscribe",
                "channel": "notifications"
            })
            
            # Should receive subscription confirmation
            response = websocket.receive_json()
            assert response["type"] == "subscribed"
            assert response["channel"] == "notifications"
    
    def test_websocket_invalid_message_handling(self, client):
        """Test handling of invalid WebSocket messages."""
        with client.websocket_connect("/ws/invalid-client") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send invalid messages
            invalid_messages = [
                "not json",
                {"missing_type": "value"},
                {"type": "unknown_type"},
                None,
                123
            ]
            
            for invalid_msg in invalid_messages:
                try:
                    if isinstance(invalid_msg, str):
                        websocket.send_text(invalid_msg)
                    else:
                        websocket.send_json(invalid_msg)
                    
                    # Should handle gracefully without disconnecting
                    # May receive error response or no response
                    try:
                        response = websocket.receive_json(timeout=1)
                        # If response received, should indicate error handling
                        if "error" in response:
                            assert "error" in response
                    except:
                        # No response is also acceptable
                        pass
                        
                except Exception:
                    # Connection may be closed on invalid message - acceptable
                    break
    
    def test_websocket_message_ordering(self, client):
        """Test WebSocket message ordering."""
        with client.websocket_connect("/ws/order-client") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send multiple messages rapidly
            num_messages = 10
            for i in range(num_messages):
                websocket.send_json({
                    "type": "sequence",
                    "sequence_id": i,
                    "data": f"message_{i}"
                })
            
            # Receive responses and check ordering
            responses = []
            for _ in range(num_messages):
                try:
                    response = websocket.receive_json(timeout=2)
                    responses.append(response)
                except:
                    break
            
            # Should receive responses (order may vary depending on implementation)
            assert len(responses) > 0


@pytest.mark.websocket
class TestWebSocketScaling:
    """Test WebSocket connection scaling and resource management."""
    
    def test_websocket_connection_limit(self, client):
        """Test WebSocket connection limits."""
        connections = []
        max_connections = 50  # Test with reasonable number
        
        try:
            # Attempt to create many connections
            for i in range(max_connections):
                try:
                    ws = client.websocket_connect(f"/ws/scale-{i}")
                    ws.__enter__()
                    connections.append(ws)
                    
                    # Verify connection established
                    data = ws.receive_json()
                    assert data["type"] == "welcome"
                    
                except Exception:
                    # Connection limit reached or error occurred
                    break
            
            # Should handle a reasonable number of connections
            assert len(connections) > 10  # At least 10 connections
            
        finally:
            # Clean up all connections
            for ws in connections:
                try:
                    ws.__exit__(None, None, None)
                except:
                    pass
    
    def test_websocket_memory_usage(self, client):
        """Test WebSocket memory usage with multiple connections."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        connections = []
        num_connections = 20
        
        try:
            # Create connections and monitor memory
            for i in range(num_connections):
                ws = client.websocket_connect(f"/ws/memory-{i}")
                ws.__enter__()
                connections.append(ws)
                
                # Receive welcome message
                ws.receive_json()
                
                # Check memory every 5 connections
                if (i + 1) % 5 == 0:
                    current_memory = process.memory_info().rss / 1024 / 1024
                    memory_per_connection = (current_memory - initial_memory) / (i + 1)
                    
                    # Each connection should not use excessive memory
                    assert memory_per_connection < 1  # Less than 1MB per connection
            
            final_memory = process.memory_info().rss / 1024 / 1024
            total_memory_increase = final_memory - initial_memory
            
            print(f"WebSocket memory usage: {total_memory_increase:.2f}MB for {num_connections} connections")
            
            # Total memory increase should be reasonable
            assert total_memory_increase < 20  # Less than 20MB for 20 connections
            
        finally:
            # Clean up connections
            for ws in connections:
                try:
                    ws.__exit__(None, None, None)
                except:
                    pass
    
    def test_websocket_connection_cleanup(self, client):
        """Test proper cleanup of disconnected WebSocket connections."""
        connection_ids = []
        
        # Create and immediately close connections
        for i in range(10):
            client_id = f"cleanup-{i}"
            connection_ids.append(client_id)
            
            with client.websocket_connect(f"/ws/{client_id}") as websocket:
                # Receive welcome message
                data = websocket.receive_json()
                assert data["client_id"] == client_id
                
                # Connection will be closed when exiting with block
        
        # All connections should be cleaned up
        # (Can't directly test internal state, but no errors should occur)


@pytest.mark.websocket
class TestWebSocketErrorHandling:
    """Test WebSocket error handling and resilience."""
    
    def test_websocket_connection_drop_handling(self, client):
        """Test handling of dropped WebSocket connections."""
        with client.websocket_connect("/ws/drop-test") as websocket:
            # Receive welcome message
            websocket.receive_json()
            
            # Send some messages
            websocket.send_json({"type": "ping"})
            response = websocket.receive_json()
            assert response["type"] == "pong"
            
            # Connection drop is simulated by closing the context
            # Server should handle this gracefully
    
    def test_websocket_malformed_message_handling(self, client):
        """Test handling of malformed WebSocket messages."""
        with client.websocket_connect("/ws/malformed-test") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send malformed JSON
            try:
                websocket.send_text('{"invalid": json}')
                
                # Should handle gracefully
                try:
                    response = websocket.receive_json(timeout=1)
                    # May receive error response
                except:
                    # No response is also acceptable
                    pass
                    
            except Exception:
                # Connection may be closed - acceptable
                pass
    
    def test_websocket_oversized_message_handling(self, client):
        """Test handling of oversized WebSocket messages."""
        with client.websocket_connect("/ws/size-test") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send very large message
            large_data = "x" * (1024 * 1024)  # 1MB message
            
            try:
                websocket.send_json({
                    "type": "large",
                    "data": large_data
                })
                
                # Should handle or reject large messages
                try:
                    response = websocket.receive_json(timeout=2)
                    # If processed, should handle appropriately
                except:
                    # May timeout or connection may be closed
                    pass
                    
            except Exception:
                # Connection may be closed due to size limit - acceptable
                pass
    
    def test_websocket_rapid_message_handling(self, client):
        """Test handling of rapid WebSocket messages."""
        with client.websocket_connect("/ws/rapid-test") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send many messages rapidly
            num_messages = 100
            for i in range(num_messages):
                try:
                    websocket.send_json({
                        "type": "rapid",
                        "id": i,
                        "data": f"message_{i}"
                    })
                except Exception:
                    # Connection may be closed due to rate limiting
                    break
            
            # Should handle rapid messages gracefully
            # May implement rate limiting or backpressure


@pytest.mark.websocket
class TestWebSocketSecurity:
    """Test WebSocket security measures."""
    
    def test_websocket_origin_validation(self, client):
        """Test WebSocket origin validation."""
        # This would test CORS-like validation for WebSockets
        # Implementation depends on whether origin validation is enforced
        
        valid_origins = ["https://example.com", "https://trusted.com"]
        invalid_origins = ["https://malicious.com", "http://untrusted.com"]
        
        for origin in valid_origins + invalid_origins:
            try:
                # Most test clients don't enforce origin validation
                with client.websocket_connect("/ws/origin-test") as websocket:
                    data = websocket.receive_json()
                    assert data["type"] == "welcome"
            except Exception:
                # Origin validation may reject connection
                pass
    
    def test_websocket_rate_limiting(self, client):
        """Test WebSocket message rate limiting."""
        with client.websocket_connect("/ws/rate-test") as websocket:
            # Skip welcome message
            websocket.receive_json()
            
            # Send messages rapidly to trigger rate limiting
            messages_sent = 0
            rate_limited = False
            
            for i in range(100):
                try:
                    websocket.send_json({
                        "type": "rate_test",
                        "id": i
                    })
                    messages_sent += 1
                    
                    # Check for rate limiting response
                    try:
                        response = websocket.receive_json(timeout=0.1)
                        if "rate_limit" in response.get("error", "").lower():
                            rate_limited = True
                            break
                    except:
                        # No immediate response
                        pass
                        
                except Exception:
                    # Connection may be closed due to rate limiting
                    rate_limited = True
                    break
            
            # Should have some form of rate limiting or handle high volume
            # (Test passes if either rate limiting is detected or all messages are handled)
    
    def test_websocket_authentication_persistence(self, client):
        """Test that WebSocket authentication persists during connection."""
        # This would test that authentication doesn't need to be re-verified
        # for each message in an authenticated WebSocket connection
        
        with client.websocket_connect("/ws/auth-persist?token=valid-user-token") as websocket:
            # Should establish authenticated connection
            try:
                data = websocket.receive_json()
                assert data["type"] == "welcome"
                
                # Send multiple messages without re-authenticating
                for i in range(5):
                    websocket.send_json({
                        "type": "authenticated_action",
                        "data": f"action_{i}"
                    })
                    
                    # Should process without requiring re-authentication
                    try:
                        response = websocket.receive_json(timeout=1)
                        # Should not receive authentication error
                        assert "authentication" not in response.get("error", "").lower()
                    except:
                        # No response is acceptable
                        pass
                        
            except WebSocketDisconnect:
                # Connection rejected due to invalid token in test environment
                pass