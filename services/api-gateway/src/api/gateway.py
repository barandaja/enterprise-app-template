"""
Main gateway router that handles request routing to backend services.
Implements request proxying, load balancing, and service aggregation.
"""
import asyncio
import json
from typing import Dict, Any, Optional, List
import httpx
from fastapi import APIRouter, Request, Response, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
import structlog

from ..core.config import get_settings
from ..services.service_registry import ServiceRegistry
from ..services.circuit_breaker import CircuitBreakerManager, CircuitBreakerError

logger = structlog.get_logger()
settings = get_settings()

router = APIRouter(tags=["gateway"])


class RequestProxyHandler:
    """Handles proxying requests to backend services."""
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.request_timeout),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
        )
    
    async def proxy_request(
        self,
        request: Request,
        service_name: str,
        target_path: str,
        service_registry: ServiceRegistry,
        circuit_breaker_manager: CircuitBreakerManager
    ) -> Response:
        """Proxy HTTP request to backend service."""
        
        # Get service URL
        service_url = await service_registry.get_service_url(service_name)
        if not service_url:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Service {service_name} is not available"
            )
        
        # Build target URL
        target_url = f"{service_url.rstrip('/')}/{target_path.lstrip('/')}"
        if request.query_params:
            target_url += f"?{request.query_params}"
        
        # Prepare headers (exclude hop-by-hop headers)
        headers = dict(request.headers)
        hop_by_hop_headers = {
            "connection", "upgrade", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding"
        }
        headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop_headers}
        
        # Get request body
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
        
        # Make request with circuit breaker protection
        try:
            async def make_request():
                return await self.http_client.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body
                )
            
            response = await circuit_breaker_manager.call_with_circuit_breaker(
                service_name, make_request
            )
            
            # Create response
            response_headers = dict(response.headers)
            # Remove hop-by-hop headers
            response_headers = {
                k: v for k, v in response_headers.items() 
                if k.lower() not in hop_by_hop_headers
            }
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("content-type")
            )
            
        except CircuitBreakerError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Service {service_name} is temporarily unavailable"
            )
        except httpx.TimeoutException:
            logger.error(
                "Request timeout",
                service=service_name,
                url=target_url,
                timeout=settings.request_timeout
            )
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Backend service timeout"
            )
        except Exception as e:
            logger.error(
                "Proxy request failed",
                service=service_name,
                url=target_url,
                error=str(e)
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Backend service error"
            )


# Global proxy handler instance
proxy_handler = RequestProxyHandler()


@router.api_route(
    "/api/v1/auth/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
)
async def auth_service_proxy(
    path: str,
    request: Request
):
    """Proxy requests to auth service."""
    service_registry: ServiceRegistry = request.app.state.service_registry
    circuit_breaker_manager: CircuitBreakerManager = request.app.state.circuit_breaker_manager
    
    return await proxy_handler.proxy_request(
        request, "auth", f"auth/{path}", service_registry, circuit_breaker_manager
    )


@router.api_route(
    "/api/v1/users/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
)
async def user_service_proxy(
    path: str,
    request: Request
):
    """Proxy requests to user service."""
    service_registry: ServiceRegistry = request.app.state.service_registry
    circuit_breaker_manager: CircuitBreakerManager = request.app.state.circuit_breaker_manager
    
    return await proxy_handler.proxy_request(
        request, "user", f"users/{path}", service_registry, circuit_breaker_manager
    )


@router.api_route(
    "/api/v1/{service_name}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
)
async def dynamic_service_proxy(
    service_name: str,
    path: str,
    request: Request
):
    """Proxy requests to dynamically registered business services."""
    service_registry: ServiceRegistry = request.app.state.service_registry
    circuit_breaker_manager: CircuitBreakerManager = request.app.state.circuit_breaker_manager
    
    # Validate service exists
    service = await service_registry.get_service_endpoint(service_name)
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service {service_name} not found"
        )
    
    return await proxy_handler.proxy_request(
        request, service_name, path, service_registry, circuit_breaker_manager
    )


@router.get("/api/v1/services")
async def list_services(request: Request):
    """List all registered services and their status."""
    service_registry: ServiceRegistry = request.app.state.service_registry
    
    services_status = await service_registry.get_all_services_status()
    
    return {
        "services": services_status,
        "total": len(services_status),
        "healthy": len([s for s in services_status.values() if s["status"] == "healthy"]),
        "unhealthy": len([s for s in services_status.values() if s["status"] == "unhealthy"])
    }


@router.get("/api/v1/docs")
async def aggregated_docs(request: Request):
    """Aggregate OpenAPI documentation from all services."""
    if not settings.docs_aggregation_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documentation aggregation is disabled"
        )
    
    service_registry: ServiceRegistry = request.app.state.service_registry
    
    # Check cache first
    cache_key = "aggregated_docs"
    cached_docs = await request.app.state.redis_manager.get_json(cache_key)
    if cached_docs:
        return cached_docs
    
    aggregated_docs = {
        "openapi": "3.0.0",
        "info": {
            "title": "Enterprise API - Aggregated Documentation",
            "version": "1.0.0",
            "description": "Aggregated documentation from all microservices"
        },
        "servers": [
            {"url": "/api/v1", "description": "API Gateway"}
        ],
        "paths": {},
        "components": {
            "schemas": {},
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        }
    }
    
    # Collect docs from healthy services
    healthy_services = await service_registry.get_healthy_services()
    
    for service_name in healthy_services:
        try:
            service = await service_registry.get_service_endpoint(service_name)
            if not service:
                continue
            
            # Fetch OpenAPI spec from service
            docs_url = f"{service.url}/openapi.json"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(docs_url)
                
                if response.status_code == 200:
                    service_docs = response.json()
                    
                    # Merge paths with service prefix
                    if "paths" in service_docs:
                        for path, methods in service_docs["paths"].items():
                            prefixed_path = f"/{service_name}{path}"
                            aggregated_docs["paths"][prefixed_path] = methods
                    
                    # Merge schemas
                    if "components" in service_docs and "schemas" in service_docs["components"]:
                        for schema_name, schema_def in service_docs["components"]["schemas"].items():
                            prefixed_name = f"{service_name}_{schema_name}"
                            aggregated_docs["components"]["schemas"][prefixed_name] = schema_def
        
        except Exception as e:
            logger.warning(
                "Failed to fetch docs from service",
                service=service_name,
                error=str(e)
            )
            continue
    
    # Cache the aggregated docs
    await request.app.state.redis_manager.set_json(
        cache_key,
        aggregated_docs,
        ttl=settings.docs_cache_ttl
    )
    
    return aggregated_docs


class WebSocketManager:
    """Manages WebSocket connections and routing."""
    
    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {}
        self.user_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str, user_id: Optional[str] = None):
        """Connect a WebSocket client."""
        await websocket.accept()
        
        if client_id not in self.connections:
            self.connections[client_id] = []
        self.connections[client_id].append(websocket)
        
        if user_id:
            if user_id not in self.user_connections:
                self.user_connections[user_id] = []
            self.user_connections[user_id].append(websocket)
        
        logger.info(
            "WebSocket connected",
            client_id=client_id,
            user_id=user_id,
            total_connections=len(self.connections)
        )
    
    def disconnect(self, websocket: WebSocket, client_id: str, user_id: Optional[str] = None):
        """Disconnect a WebSocket client."""
        if client_id in self.connections:
            self.connections[client_id].remove(websocket)
            if not self.connections[client_id]:
                del self.connections[client_id]
        
        if user_id and user_id in self.user_connections:
            self.user_connections[user_id].remove(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
        
        logger.info(
            "WebSocket disconnected",
            client_id=client_id,
            user_id=user_id,
            total_connections=len(self.connections)
        )
    
    async def send_to_client(self, client_id: str, message: dict):
        """Send message to specific client."""
        if client_id in self.connections:
            disconnected = []
            for websocket in self.connections[client_id]:
                try:
                    await websocket.send_json(message)
                except:
                    disconnected.append(websocket)
            
            # Clean up disconnected sockets
            for ws in disconnected:
                self.connections[client_id].remove(ws)
    
    async def send_to_user(self, user_id: str, message: dict):
        """Send message to all connections for a user."""
        if user_id in self.user_connections:
            disconnected = []
            for websocket in self.user_connections[user_id]:
                try:
                    await websocket.send_json(message)
                except:
                    disconnected.append(websocket)
            
            # Clean up disconnected sockets
            for ws in disconnected:
                self.user_connections[user_id].remove(ws)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        for client_connections in self.connections.values():
            for websocket in client_connections:
                try:
                    await websocket.send_json(message)
                except:
                    pass  # Ignore failed sends for broadcast


# Global WebSocket manager
ws_manager = WebSocketManager()


@router.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """
    WebSocket endpoint for real-time communication with secure message-based authentication.
    
    Authentication flow:
    1. Client connects without auth (backward compatibility)
    2. Client sends 'auth' message with token
    3. Server validates token and responds with auth result
    4. Only authenticated connections can proceed
    """
    user_id = None
    authenticated = False
    auth_timeout = 30  # seconds to authenticate
    
    try:
        # Accept connection initially
        await websocket.accept()
        
        # Check for legacy token in query params (backward compatibility)
        legacy_token = websocket.query_params.get("token")
        if legacy_token:
            logger.warning(
                "WebSocket using deprecated query param authentication",
                client_id=client_id,
                deprecation_notice="Use message-based auth instead"
            )
            
            # Validate legacy token
            from ..services.auth_service import auth_service
            user_info = await auth_service.validate_token(legacy_token)
            if user_info:
                user_id = user_info.user_id
                authenticated = True
                
                # Send deprecation notice
                await websocket.send_json({
                    "type": "auth_deprecated",
                    "message": "Query parameter authentication is deprecated. Use message-based auth.",
                    "authenticated": True,
                    "user_id": user_id
                })
        
        if not authenticated:
            # Send authentication challenge
            await websocket.send_json({
                "type": "auth_required",
                "message": "Send auth message with token to authenticate",
                "timeout": auth_timeout
            })
            
            # Wait for authentication message with timeout
            auth_received = False
            start_time = asyncio.get_event_loop().time()
            
            while not auth_received and (asyncio.get_event_loop().time() - start_time) < auth_timeout:
                try:
                    # Wait for auth message with short timeout
                    auth_data = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
                    
                    if auth_data.get("type") == "auth":
                        token = auth_data.get("token")
                        if not token:
                            await websocket.send_json({
                                "type": "auth_error",
                                "error": "Missing token in auth message"
                            })
                            continue
                        
                        # Validate token
                        try:
                            from ..services.auth_service import auth_service
                            user_info = await auth_service.validate_token(token)
                            if user_info:
                                user_id = user_info.user_id
                                authenticated = True
                                auth_received = True
                                
                                await websocket.send_json({
                                    "type": "auth_success",
                                    "message": "Authentication successful",
                                    "user_id": user_id,
                                    "permissions": user_info.permissions,
                                    "roles": user_info.roles
                                })
                                
                                logger.info(
                                    "WebSocket authenticated successfully",
                                    client_id=client_id,
                                    user_id=user_id
                                )
                            else:
                                await websocket.send_json({
                                    "type": "auth_error", 
                                    "error": "Invalid or expired token"
                                })
                                
                        except Exception as e:
                            logger.error("WebSocket token validation failed", error=str(e))
                            await websocket.send_json({
                                "type": "auth_error",
                                "error": "Authentication failed"
                            })
                    else:
                        # Non-auth message received before authentication
                        await websocket.send_json({
                            "type": "auth_required",
                            "error": "Authentication required before sending messages"
                        })
                
                except asyncio.TimeoutError:
                    # Continue waiting for auth
                    continue
                except WebSocketDisconnect:
                    logger.debug("WebSocket disconnected during authentication", client_id=client_id)
                    return
                except Exception as e:
                    logger.error("Error during WebSocket authentication", error=str(e))
                    await websocket.send_json({
                        "type": "auth_error",
                        "error": "Authentication error occurred"
                    })
            
            # Check if authentication was successful
            if not authenticated:
                await websocket.send_json({
                    "type": "auth_timeout",
                    "error": "Authentication timeout"
                })
                await websocket.close(code=1008, reason="Authentication timeout")
                return
        
        # Connect authenticated user
        await ws_manager.connect(websocket, client_id, user_id)
        
        # Send welcome message
        await websocket.send_json({
            "type": "welcome",
            "client_id": client_id,
            "user_id": user_id,
            "timestamp": int(asyncio.get_event_loop().time()),
            "auth_method": "legacy_query" if legacy_token else "message_based"
        })
        
        # Handle incoming messages
        while True:
            try:
                data = await websocket.receive_json()
                
                # Route message based on type
                message_type = data.get("type")
                
                if message_type == "ping":
                    await websocket.send_json({"type": "pong"})
                elif message_type == "subscribe":
                    # Handle subscription to channels/topics
                    channel = data.get("channel")
                    if channel:
                        await websocket.send_json({
                            "type": "subscribed",
                            "channel": channel,
                            "user_id": user_id
                        })
                    else:
                        await websocket.send_json({
                            "type": "error",
                            "error": "Channel name required for subscription"
                        })
                elif message_type == "auth":
                    # Already authenticated
                    await websocket.send_json({
                        "type": "auth_info",
                        "message": "Already authenticated",
                        "user_id": user_id
                    })
                else:
                    # Echo message for now (with user context)
                    await websocket.send_json({
                        "type": "echo",
                        "data": data,
                        "user_id": user_id,
                        "timestamp": int(asyncio.get_event_loop().time())
                    })
            
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error("WebSocket message handling error", error=str(e), client_id=client_id)
                try:
                    await websocket.send_json({
                        "type": "error",
                        "error": "Message processing failed"
                    })
                except:
                    break
    
    except Exception as e:
        logger.error("WebSocket connection error", error=str(e), client_id=client_id)
        try:
            await websocket.close(code=1011, reason="Server error")
        except:
            pass
    
    finally:
        if authenticated:
            ws_manager.disconnect(websocket, client_id, user_id)
            logger.info("WebSocket disconnected", client_id=client_id, user_id=user_id)