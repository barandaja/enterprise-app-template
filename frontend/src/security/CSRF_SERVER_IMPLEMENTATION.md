# CSRF Token Server-Side Implementation Guide

## Overview

The frontend CSRF implementation currently uses sessionStorage and cookies set via JavaScript. For production security, CSRF tokens should be set as httpOnly cookies by the server to prevent XSS attacks from accessing them.

## Required Server-Side Implementation

### 1. CSRF Token Generation (Backend)

```python
# auth_service/security/csrf.py
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional

class CSRFTokenManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
    
    def generate_token(self, session_id: str) -> str:
        """Generate a CSRF token bound to the session"""
        timestamp = int(datetime.utcnow().timestamp())
        data = f"{session_id}:{timestamp}:{secrets.token_urlsafe(32)}"
        
        # Create HMAC signature
        signature = hashlib.sha256(
            f"{data}:{self.secret_key}".encode()
        ).hexdigest()
        
        return f"{data}:{signature}"
    
    def validate_token(self, token: str, session_id: str, max_age: int = 3600) -> bool:
        """Validate CSRF token"""
        try:
            parts = token.split(":")
            if len(parts) != 4:
                return False
            
            stored_session_id, timestamp, nonce, signature = parts
            
            # Verify session binding
            if stored_session_id != session_id:
                return False
            
            # Check token age
            token_age = int(datetime.utcnow().timestamp()) - int(timestamp)
            if token_age > max_age:
                return False
            
            # Verify signature
            data = f"{stored_session_id}:{timestamp}:{nonce}"
            expected_signature = hashlib.sha256(
                f"{data}:{self.secret_key}".encode()
            ).hexdigest()
            
            return secrets.compare_digest(signature, expected_signature)
            
        except Exception:
            return False
```

### 2. FastAPI Middleware Implementation

```python
# auth_service/middleware/csrf.py
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
import json

class CSRFMiddleware:
    def __init__(self, app, csrf_manager: CSRFTokenManager):
        self.app = app
        self.csrf_manager = csrf_manager
        self.safe_methods = {"GET", "HEAD", "OPTIONS", "TRACE"}
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request = Request(scope, receive)
            
            # Skip CSRF for safe methods
            if request.method in self.safe_methods:
                await self.app(scope, receive, send)
                return
            
            # Get session ID from cookie
            session_id = request.cookies.get("session_id")
            if not session_id:
                response = JSONResponse(
                    status_code=403,
                    content={"error": "No session found"}
                )
                await response(scope, receive, send)
                return
            
            # Get CSRF token from header or form data
            csrf_token = request.headers.get("X-CSRF-Token")
            if not csrf_token:
                form = await request.form()
                csrf_token = form.get("csrf_token")
            
            # Validate CSRF token
            if not csrf_token or not self.csrf_manager.validate_token(csrf_token, session_id):
                response = JSONResponse(
                    status_code=403,
                    content={"error": "Invalid CSRF token"}
                )
                await response(scope, receive, send)
                return
            
            # Process request
            await self.app(scope, receive, send)
        else:
            await self.app(scope, receive, send)
```

### 3. Setting CSRF Cookie on Login

```python
# auth_service/routes/auth.py
from fastapi import Response

@router.post("/login")
async def login(
    credentials: LoginCredentials,
    response: Response,
    csrf_manager: CSRFTokenManager = Depends(get_csrf_manager)
):
    # ... authentication logic ...
    
    # Generate session ID
    session_id = secrets.token_urlsafe(32)
    
    # Generate CSRF token
    csrf_token = csrf_manager.generate_token(session_id)
    
    # Set httpOnly cookie for session
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=True,  # HTTPS only
        samesite="strict",
        max_age=3600,
        path="/"
    )
    
    # Set CSRF token cookie (readable by JS)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  # Must be readable by JavaScript
        secure=True,
        samesite="strict",
        max_age=3600,
        path="/"
    )
    
    return {"access_token": access_token, "token_type": "bearer"}
```

### 4. API Gateway CSRF Configuration

```python
# api_gateway/middleware/csrf.py
class GatewayCSRFMiddleware:
    """Forward CSRF tokens between client and services"""
    
    async def __call__(self, request: Request, call_next):
        # Extract CSRF token from cookie or header
        csrf_token = request.cookies.get("csrf_token")
        if not csrf_token:
            csrf_token = request.headers.get("X-CSRF-Token")
        
        # Forward to backend services
        if csrf_token and request.method not in ["GET", "HEAD", "OPTIONS"]:
            request.headers["X-CSRF-Token"] = csrf_token
        
        response = await call_next(request)
        return response
```

## Frontend Updates Required

### 1. Update CSRF Hook to Read from Cookie

```typescript
// src/security/csrf.ts
export function getCSRFToken(): string | null {
  // Read from cookie instead of sessionStorage
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'csrf_token') {
      return decodeURIComponent(value);
    }
  }
  return null;
}
```

### 2. Update API Client

```typescript
// src/services/api/client.ts
private async handleRequest(config: InternalAxiosRequestConfig): Promise<InternalAxiosRequestConfig> {
  // ... existing code ...
  
  // Add CSRF token from cookie
  const csrfToken = getCSRFToken();
  if (csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(config.method?.toUpperCase() || '')) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  
  return config;
}
```

## Security Benefits

1. **XSS Protection**: httpOnly session cookies cannot be accessed by JavaScript
2. **CSRF Protection**: Token validation ensures requests originate from your application
3. **Session Binding**: Tokens are cryptographically bound to sessions
4. **Time-Based Expiration**: Tokens expire after a configurable period
5. **Signature Verification**: Prevents token tampering

## Testing the Implementation

```bash
# Test CSRF protection
curl -X POST http://localhost:8000/api/user/update \
  -H "Content-Type: application/json" \
  -d '{"name": "Test"}' \
  # Should return 403 Forbidden

# Test with valid token
curl -X POST http://localhost:8000/api/user/update \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <token-from-cookie>" \
  -H "Cookie: session_id=<session-id>" \
  -d '{"name": "Test"}' \
  # Should succeed
```

## Implementation Checklist

- [ ] Implement CSRFTokenManager in auth service
- [ ] Add CSRF middleware to FastAPI app
- [ ] Update login endpoint to set cookies
- [ ] Configure API Gateway to forward CSRF tokens
- [ ] Update frontend to read from cookies
- [ ] Test CSRF protection on all state-changing endpoints
- [ ] Add CSRF token refresh mechanism
- [ ] Document CSRF token lifecycle