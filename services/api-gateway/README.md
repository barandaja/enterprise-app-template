# Enterprise API Gateway Service

A comprehensive, production-ready API Gateway built with FastAPI for enterprise microservices architecture. Provides centralized routing, authentication, rate limiting, circuit breaking, and monitoring for all backend services.

## 🚀 Key Features

### Core Gateway Features
- **Dynamic Service Routing**: Intelligent request routing with prefix-based rules and load balancing
- **JWT Authentication**: Comprehensive token validation with auth service integration and caching
- **Multi-tier Rate Limiting**: Global, per-user, per-IP, and per-endpoint rate limiting with Redis
- **Circuit Breaker Pattern**: Fault tolerance with automatic service failure detection
- **WebSocket Proxy**: Real-time communication with authentication and channel management
- **API Versioning**: Header and path-based versioning support

### Security & Compliance
- **Enterprise Security**: Request size limits, header validation, XSS/CSRF protection
- **GDPR/HIPAA/SOC2 Compliance**: Built-in compliance features and audit logging
- **Advanced Authentication**: Role-based access control and permission management
- **Security Headers**: Comprehensive security header injection

### Monitoring & Observability
- **Prometheus Metrics**: Comprehensive metrics for all gateway operations
- **Distributed Tracing**: Jaeger integration for request tracing
- **Health Monitoring**: Multi-level health checks for all components
- **Structured Logging**: JSON logging with correlation IDs

### Performance & Scalability
- **Sub-50ms Overhead**: Optimized routing with minimal latency
- **Connection Pooling**: Efficient backend service connections
- **Request Caching**: Intelligent caching with Redis
- **Async/Await**: Full asynchronous processing throughout

## 🏗️ Architecture Overview

The API Gateway follows a layered architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                        Client Requests                      │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                     Middleware Stack                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │   Logging   │ │  Security   │ │    CORS     │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │    Auth     │ │Rate Limiting│ │Circuit Brkr │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                    Service Registry                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │Auth Service │ │User Service │ │   Business  │         │
│  │             │ │             │ │   Services  │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Backend Services                          │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Technology Stack

- **Framework**: FastAPI with Uvicorn/Gunicorn
- **Database**: PostgreSQL with asyncpg
- **Cache**: Redis with connection pooling
- **Authentication**: JWT with python-jose
- **Monitoring**: Prometheus, Grafana, Jaeger
- **Testing**: pytest with comprehensive coverage
- **Deployment**: Docker, Kubernetes, Docker Compose

## ⚡ Quick Start

### Development Setup

```bash
# Clone and setup
git clone <repository>
cd api-gateway

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt

# Setup environment
cp .env.example .env
# Edit .env with your configuration

# Start dependencies (PostgreSQL, Redis)
docker-compose up -d postgres redis

# Run database migrations
alembic upgrade head

# Start the gateway
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

### Production Deployment

```bash
# Full stack deployment
docker-compose up -d

# Or build and deploy individual service
docker build -t api-gateway .
docker run -p 8000:8000 -e DATABASE_URL="..." -e REDIS_URL="..." api-gateway
```

## 📋 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | - | ✅ |
| `REDIS_URL` | Redis connection string | - | ✅ |
| `SECRET_KEY` | JWT secret key | - | ✅ |
| `AUTH_SERVICE_URL` | Authentication service URL | - | ✅ |
| `USER_SERVICE_URL` | User service URL | - | ✅ |
| `CORS_ORIGINS` | Allowed CORS origins | `["*"]` | ❌ |
| `GLOBAL_RATE_LIMIT_REQUESTS` | Global rate limit | `1000` | ❌ |
| `USER_RATE_LIMIT_REQUESTS` | Per-user rate limit | `100` | ❌ |
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | Circuit breaker threshold | `5` | ❌ |
| `MAX_REQUEST_SIZE` | Maximum request size | `10MB` | ❌ |

See `.env.example` for complete configuration options.

## 🔧 API Endpoints

### Health & Monitoring
- `GET /health` - Basic health check
- `GET /ready` - Kubernetes readiness probe
- `GET /health/detailed` - Comprehensive component health
- `GET /health/services` - Backend service health status
- `GET /health/startup` - Startup verification

### Metrics & Observability
- `GET /metrics` - Prometheus metrics
- `GET /metrics/json` - JSON format metrics
- `GET /metrics/performance` - Performance statistics
- `GET /metrics/health-score` - Overall system health score

### Service Management
- `GET /api/v1/services` - List registered services
- `GET /api/v1/docs` - Aggregated OpenAPI documentation

### Dynamic Routing
- `ALL /api/v1/auth/{path}` - Auth service proxy
- `ALL /api/v1/users/{path}` - User service proxy
- `ALL /api/v1/{service}/{path}` - Dynamic service proxy

### WebSocket
- `WS /ws/{client_id}` - WebSocket endpoint with authentication

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html --cov-report=term

# Run specific test categories
pytest tests/test_auth.py -v
pytest tests/test_rate_limiting.py -v
pytest tests/test_circuit_breaker.py -v

# Run integration tests
pytest tests/test_comprehensive_gateway.py -v

# Performance tests
pytest tests/test_performance.py -v
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end functionality
- **Performance Tests**: Load and latency testing
- **Security Tests**: Authentication and authorization
- **Compliance Tests**: GDPR, HIPAA, SOC2 compliance

## 📊 Monitoring & Observability

### Metrics Available

- **Request Metrics**: Latency, throughput, error rates
- **Service Health**: Backend service status and response times
- **Rate Limiting**: Current usage and limits by type
- **Circuit Breaker**: State and failure counts
- **Authentication**: Token validation success/failure rates
- **System Metrics**: Memory, CPU, connection pool status

### Dashboards

Access monitoring dashboards:
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Jaeger**: http://localhost:16686

### Alerting

Configure alerts for:
- High error rates (>5%)
- Circuit breakers opening
- Backend service failures
- Rate limit threshold breaches
- Authentication failures spikes

## 🔒 Security Features

### Authentication & Authorization
- JWT token validation with caching
- Role-based access control (RBAC)
- Permission-based authorization
- Session management and revocation
- Multi-factor authentication support

### Security Middleware
- Request size limits (configurable)
- Security headers injection
- CORS policy enforcement
- XSS and CSRF protection
- SQL injection prevention

### Rate Limiting
- **Global**: System-wide request limits
- **Per-User**: Individual user quotas
- **Per-IP**: IP-based rate limiting
- **Per-Endpoint**: Endpoint-specific limits
- **Burst Protection**: Temporary spike handling

### Circuit Breaker
- Automatic failure detection
- Configurable failure thresholds
- Half-open state testing
- Service recovery detection
- Metrics and alerting integration

## 🚀 Production Deployment

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  labels:
    app: api-gateway
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: api-gateway
        image: your-registry/api-gateway:1.0.0
        ports:
        - containerPort: 8000
          name: http
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: api-gateway-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: api-gateway-secrets
              key: redis-url
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: api-gateway-secrets
              key: secret-key
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /health/startup
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 30
```

## 📈 Performance Optimization

### Benchmarks

- **Routing Overhead**: < 50ms
- **Authentication**: < 100ms (with caching)
- **Rate Limiting**: < 10ms
- **Circuit Breaker**: < 5ms
- **Throughput**: > 10,000 req/sec

### Optimization Tips

1. **Enable Connection Pooling**
   ```python
   # Redis connection pool
   REDIS_POOL_SIZE=20
   
   # Database connection pool
   DATABASE_POOL_SIZE=20
   ```

2. **Configure Caching**
   ```python
   # Token validation cache
   CACHE_AUTH_TTL=600  # 10 minutes
   
   # Service health cache
   CACHE_DEFAULT_TTL=300  # 5 minutes
   ```

3. **Optimize Middleware Order**
   ```python
   # Most efficient order
   app.add_middleware(MetricsMiddleware)
   app.add_middleware(RequestLoggingMiddleware)
   app.add_middleware(SecurityMiddleware)
   app.add_middleware(AuthenticationMiddleware)
   app.add_middleware(RateLimitMiddleware)
   app.add_middleware(CircuitBreakerMiddleware)
   ```

## 🤝 Contributing

1. **Fork the Repository**
2. **Create Feature Branch**: `git checkout -b feature/amazing-feature`
3. **Commit Changes**: `git commit -m 'Add amazing feature'`
4. **Push to Branch**: `git push origin feature/amazing-feature`
5. **Open Pull Request**

### Contribution Guidelines

- Follow PEP 8 style guidelines
- Add tests for new functionality
- Update documentation
- Ensure all tests pass
- Add type hints
- Follow conventional commit messages

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [API Documentation](http://localhost:8000/docs)
- **Issues**: [GitHub Issues](https://github.com/your-org/api-gateway/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/api-gateway/discussions)
- **Email**: support@yourcompany.com

## 🎯 Roadmap

- [ ] GraphQL gateway support
- [ ] gRPC service integration
- [ ] Advanced load balancing algorithms
- [ ] Multi-tenant support
- [ ] API marketplace features
- [ ] Enhanced observability with OpenTelemetry
- [ ] Service mesh integration (Istio/Linkerd)