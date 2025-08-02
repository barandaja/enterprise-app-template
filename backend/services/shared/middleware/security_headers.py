"""
Security Headers Middleware
Implements comprehensive security headers including CSP for backend services
"""

from typing import Dict, List, Optional, Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import secrets
import hashlib
import base64
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware:
    """
    Middleware to add security headers to all responses
    """
    
    def __init__(
        self,
        app,
        csp_config: Optional[Dict[str, List[str]]] = None,
        enable_nonce: bool = True,
        report_uri: Optional[str] = None,
        report_only: bool = False
    ):
        self.app = app
        self.csp_config = csp_config or self._get_default_csp()
        self.enable_nonce = enable_nonce
        self.report_uri = report_uri
        self.report_only = report_only
    
    async def __call__(self, request: Request, call_next: Callable) -> Response:
        # Generate nonce for this request if enabled
        nonce = None
        if self.enable_nonce:
            nonce = self._generate_nonce()
            request.state.csp_nonce = nonce
        
        # Process the request
        response = await call_next(request)
        
        # Add security headers
        self._add_security_headers(response, nonce)
        
        return response
    
    def _get_default_csp(self) -> Dict[str, List[str]]:
        """Get default CSP configuration"""
        return {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'strict-dynamic'"],
            "style-src": ["'self'", "'unsafe-inline'"],  # Required for some frameworks
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "media-src": ["'self'"],
            "object-src": ["'none'"],
            "frame-src": ["'none'"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
            "upgrade-insecure-requests": []
        }
    
    def _generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce"""
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    def _build_csp_header(self, nonce: Optional[str] = None) -> str:
        """Build the CSP header value"""
        directives = []
        
        for directive, sources in self.csp_config.items():
            if directive == "script-src" and nonce:
                # Add nonce to script-src
                sources_with_nonce = sources + [f"'nonce-{nonce}'"]
                directives.append(f"{directive} {' '.join(sources_with_nonce)}")
            else:
                if sources:
                    directives.append(f"{directive} {' '.join(sources)}")
                else:
                    directives.append(directive)
        
        csp = "; ".join(directives)
        
        if self.report_uri:
            csp += f"; report-uri {self.report_uri}"
        
        return csp
    
    def _add_security_headers(self, response: Response, nonce: Optional[str] = None):
        """Add all security headers to the response"""
        # Content Security Policy
        csp_header_name = "Content-Security-Policy-Report-Only" if self.report_only else "Content-Security-Policy"
        response.headers[csp_header_name] = self._build_csp_header(nonce)
        
        # Other security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        
        # HSTS (only in production)
        if not self._is_development():
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )


    def _is_development(self) -> bool:
        """Check if running in development mode"""
        import os
        return os.getenv("ENVIRONMENT", "development") == "development"


class CSPReportHandler:
    """
    Handler for CSP violation reports
    """
    
    def __init__(self, storage_backend: Optional[Callable] = None):
        self.storage_backend = storage_backend or self._default_storage
        self.logger = logging.getLogger(__name__)
    
    async def handle_report(self, request: Request) -> JSONResponse:
        """Handle CSP violation report"""
        try:
            # Parse the report
            body = await request.body()
            report_data = json.loads(body)
            
            # Extract CSP report
            csp_report = report_data.get("csp-report", {})
            
            # Log the violation
            self.logger.warning(
                "CSP Violation",
                extra={
                    "document_uri": csp_report.get("document-uri"),
                    "violated_directive": csp_report.get("violated-directive"),
                    "blocked_uri": csp_report.get("blocked-uri"),
                    "source_file": csp_report.get("source-file"),
                    "line_number": csp_report.get("line-number"),
                    "column_number": csp_report.get("column-number"),
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            # Store the report
            await self.storage_backend(csp_report)
            
            return JSONResponse(
                status_code=204,
                content=None
            )
            
        except Exception as e:
            self.logger.error(f"Failed to process CSP report: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"error": "Failed to process report"}
            )
    
    async def _default_storage(self, report: dict):
        """Default storage implementation (logs only)"""
        self.logger.info(f"CSP Report: {json.dumps(report, indent=2)}")


def get_production_csp_config() -> Dict[str, List[str]]:
    """Get production CSP configuration"""
    return {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self'", "https:"],
        "font-src": ["'self'"],
        "connect-src": ["'self'", "https://api.yourcompany.com"],
        "media-src": ["'self'"],
        "object-src": ["'none'"],
        "frame-src": ["'none'"],
        "frame-ancestors": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "upgrade-insecure-requests": [],
        "block-all-mixed-content": []
    }


def get_development_csp_config() -> Dict[str, List[str]]:
    """Get development CSP configuration (more permissive)"""
    return {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'", "http://localhost:*"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https:", "http:"],
        "font-src": ["'self'", "data:"],
        "connect-src": ["'self'", "http://localhost:*", "ws://localhost:*"],
        "media-src": ["'self'"],
        "object-src": ["'none'"],
        "frame-src": ["'self'"],
        "frame-ancestors": ["'self'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"]
    }


# FastAPI app setup example:
"""
from fastapi import FastAPI
from .security_headers import SecurityHeadersMiddleware, CSPReportHandler, get_production_csp_config

app = FastAPI()

# Add security headers middleware
app.add_middleware(
    SecurityHeadersMiddleware,
    csp_config=get_production_csp_config(),
    enable_nonce=True,
    report_uri="/api/csp-report",
    report_only=False  # Set to True initially to test
)

# Add CSP report endpoint
csp_handler = CSPReportHandler()

@app.post("/api/csp-report")
async def csp_report(request: Request):
    return await csp_handler.handle_report(request)
"""