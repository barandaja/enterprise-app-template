# Security Headers Implementation Guide

## Overview

This guide documents the security headers that should be implemented for the application to protect against common web vulnerabilities.

## Required Security Headers

### 1. Content Security Policy (CSP)

Already implemented in `src/utils/env.ts` via META tags and should be enforced by the server.

**Server Configuration (nginx example):**
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' ${API_URL}; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
```

**FastAPI Implementation:**
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            f"connect-src 'self' {settings.API_URL}; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

### 2. Strict-Transport-Security (HSTS)

Forces browsers to use HTTPS connections.

**Server Configuration:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

**FastAPI:**
```python
response.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains; preload"
```

### 3. X-Frame-Options

Prevents clickjacking attacks by controlling iframe embedding.

**Server Configuration:**
```nginx
add_header X-Frame-Options "DENY" always;
```

**FastAPI:**
```python
response.headers['X-Frame-Options'] = "DENY"
```

### 4. X-Content-Type-Options

Prevents MIME type sniffing.

**Server Configuration:**
```nginx
add_header X-Content-Type-Options "nosniff" always;
```

**FastAPI:**
```python
response.headers['X-Content-Type-Options'] = "nosniff"
```

### 5. Referrer-Policy

Controls how much referrer information is sent with requests.

**Server Configuration:**
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**FastAPI:**
```python
response.headers['Referrer-Policy'] = "strict-origin-when-cross-origin"
```

### 6. Permissions-Policy

Controls browser features and APIs.

**Server Configuration:**
```nginx
add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(self), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;
```

**FastAPI:**
```python
response.headers['Permissions-Policy'] = (
    "accelerometer=(), camera=(), geolocation=(self), "
    "gyroscope=(), magnetometer=(), microphone=(), "
    "payment=(), usb=()"
)
```

## Complete FastAPI Middleware Implementation

```python
# security/headers.py
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from typing import Callable

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses
    """
    
    def __init__(self, app, api_url: str = ""):
        super().__init__(app)
        self.api_url = api_url
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Content Security Policy
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data: https:",
            f"connect-src 'self' {self.api_url}",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
        
        # Strict Transport Security (HSTS)
        response.headers['Strict-Transport-Security'] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = "nosniff"
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = "strict-origin-when-cross-origin"
        
        # Permissions Policy (Feature Policy)
        response.headers['Permissions-Policy'] = (
            "accelerometer=(), camera=(), geolocation=(self), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        )
        
        # Remove potentially dangerous headers
        response.headers.pop('X-Powered-By', None)
        response.headers.pop('Server', None)
        
        return response


def configure_security_headers(app: FastAPI, api_url: str = ""):
    """
    Configure security headers for the FastAPI application
    """
    app.add_middleware(SecurityHeadersMiddleware, api_url=api_url)
```

## Frontend Implementation

### 1. Meta Tags (Already Implemented)

The frontend already sets CSP via meta tags in `src/utils/env.ts`:

```typescript
export function setSecurityHeaders(): void {
  const cspContent = getCSPContent();
  
  // Set CSP meta tag
  let cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!cspMeta) {
    cspMeta = document.createElement('meta');
    cspMeta.httpEquiv = 'Content-Security-Policy';
    document.head.appendChild(cspMeta);
  }
  cspMeta.content = cspContent;
}
```

### 2. Additional Frontend Security Measures

```typescript
// src/security/headers.ts

/**
 * Security headers that should be validated on the frontend
 */
export interface SecurityHeaders {
  'content-security-policy': string;
  'strict-transport-security': string;
  'x-frame-options': string;
  'x-content-type-options': string;
  'referrer-policy': string;
  'permissions-policy': string;
}

/**
 * Validate that required security headers are present
 */
export function validateSecurityHeaders(headers: Headers): boolean {
  const requiredHeaders = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy'
  ];
  
  for (const header of requiredHeaders) {
    if (!headers.has(header)) {
      console.warn(`Missing security header: ${header}`);
      return false;
    }
  }
  
  return true;
}

/**
 * Check if running in secure context (HTTPS)
 */
export function isSecureContext(): boolean {
  return window.isSecureContext || window.location.protocol === 'https:';
}

/**
 * Initialize frontend security checks
 */
export function initializeSecurity(): void {
  // Warn if not running in secure context
  if (!isSecureContext() && process.env.NODE_ENV === 'production') {
    console.error('Application must be served over HTTPS in production');
  }
  
  // Check for mixed content
  if (window.location.protocol === 'https:') {
    // Monitor for mixed content warnings
    window.addEventListener('error', (event) => {
      if (event.message && event.message.includes('Mixed Content')) {
        console.error('Mixed content detected:', event);
        // Report to monitoring service
      }
    });
  }
}
```

## Testing Security Headers

### 1. Manual Testing

Use browser developer tools or curl:

```bash
# Check response headers
curl -I https://your-domain.com

# Check specific header
curl -I https://your-domain.com | grep -i "content-security-policy"
```

### 2. Automated Testing

```python
# tests/test_security_headers.py
import pytest
from fastapi.testclient import TestClient

def test_security_headers(client: TestClient):
    response = client.get("/")
    
    # Check all required headers
    assert 'content-security-policy' in response.headers
    assert 'strict-transport-security' in response.headers
    assert 'x-frame-options' in response.headers
    assert 'x-content-type-options' in response.headers
    assert 'referrer-policy' in response.headers
    assert 'permissions-policy' in response.headers
    
    # Validate header values
    assert response.headers['x-frame-options'] == 'DENY'
    assert response.headers['x-content-type-options'] == 'nosniff'
    assert 'max-age=31536000' in response.headers['strict-transport-security']
```

### 3. Online Tools

- [Security Headers](https://securityheaders.com/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [SSL Labs](https://www.ssllabs.com/ssltest/)

## Implementation Checklist

- [ ] Configure CSP headers on server (nginx/Apache/CDN)
- [ ] Implement SecurityHeadersMiddleware in FastAPI
- [ ] Enable HSTS with preload
- [ ] Set X-Frame-Options to DENY
- [ ] Enable X-Content-Type-Options: nosniff
- [ ] Configure appropriate Referrer-Policy
- [ ] Set restrictive Permissions-Policy
- [ ] Remove X-Powered-By and Server headers
- [ ] Test with online security header scanners
- [ ] Monitor CSP violations in production
- [ ] Document any CSP exceptions needed for third-party services