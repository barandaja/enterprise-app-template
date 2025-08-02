"""
Main FastAPI application for User Service
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import logging
from contextlib import asynccontextmanager

from .core.config import settings
from .interfaces.event_interface import IEventBus
from .events.event_bus_factory import EventBusFactory
from .events.user_events import UserCreatedEvent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global event bus instance
event_bus: IEventBus = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    global event_bus
    
    # Startup
    logger.info("Starting User Service")
    
    # Initialize event bus
    event_bus = await EventBusFactory.create_event_bus(
        service_name=settings.SERVICE_NAME,
        service_role=settings.SERVICE_ROLE
    )
    logger.info("Event bus initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down User Service")


# Create FastAPI app
app = FastAPI(
    title="User Service",
    description="User management and profile service",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "user-service",
            "version": "1.0.0"
        }
    )

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "User Service is running"}

@app.get("/users/me")
async def get_current_user():
    """Get current user profile (placeholder)"""
    return {
        "id": "user123",
        "email": "user@example.com",
        "name": "Test User",
        "created_at": "2024-01-01T00:00:00Z"
    }


@app.post("/users")
async def create_user(email: str, username: str):
    """Create a new user and emit event"""
    # This is a placeholder - in real implementation, you'd save to database
    user_id = "user_" + str(len(email) + len(username))  # Simple ID generation
    
    # Emit user created event
    if event_bus:
        event = UserCreatedEvent(
            user_id=user_id,
            email=email,
            username=username
        )
        await event_bus.publish(event)
        logger.info(f"Published UserCreatedEvent for user {user_id}")
    
    return {
        "id": user_id,
        "email": email,
        "username": username,
        "created_at": "2024-01-01T00:00:00Z"
    }

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True if settings.ENVIRONMENT == "development" else False
    )